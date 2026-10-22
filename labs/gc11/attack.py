"""
attack.py: replay what attackers, legitimate users and an auditor can do against a twin of the TSG Helpdesk.

    python3 attack.py --twin today        # make attack:       ExampleCo as it runs today
    python3 attack.py --twin hardened     # make attack-safe:  what terraform/ builds
    python3 attack.py --twin eu-multiregion

Nothing is sent anywhere: twin.py decides each request with a teaching model of Google's rules.
"""

from __future__ import annotations

import argparse
import dataclasses
import sys

from twin import Decision, Deployment, Request, evaluate

SA = "serviceAccount:chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com"
SUMMARISER = "serviceAccount:ticket-summariser@example-chatbot-prod.iam.gserviceaccount.com"
DEFAULT_COMPUTE = "serviceAccount:100000000001-compute@developer.gserviceaccount.com"
GEMINI = "publishers/google/models/gemini-3.1-flash-lite"
LLAMA = "publishers/meta/models/llama3"


@dataclasses.dataclass
class Step:
    sid: str
    group: str                      # "A" attacker, "L" legitimate
    title: str
    build: object                   # function(Deployment) -> Request
    attacker: bool = True


def summariser_principal(d: Deployment) -> str:
    vm = d.vms().get("ticket-summariser")
    return f"serviceAccount:{vm['sa']}" if vm else SUMMARISER


STEPS = [
    Step("A1", "A", "Stolen JSON key of chatbot-runtime, from 203.0.113.66: GenerateContent on Gemini",
         lambda d: Request(SA, "sa_key", "203.0.113.66", "aiplatform.googleapis.com",
                           "aiplatform.endpoints.predict", f"{GEMINI}:predict")),
    Step("A2", "A", "Same key: deploy Llama 3 to a GPU endpoint (bills while it runs)",
         lambda d: Request(SA, "sa_key", "203.0.113.66", "aiplatform.googleapis.com",
                           "aiplatform.endpoints.deploy", f"{LLAMA}:deploy")),
    Step("A3", "A", "Prompt-injected Helpdesk copies the tickets table to a project outside ExampleCo",
         lambda d: Request(SA, "attached", "vm:helpdesk-vm", "bigquery.googleapis.com",
                           "bigquery.tables.getData", dataset="helpdesk_tickets", dest_project="projects/999999999999")),
    Step("A4", "A", "Prompt-injected Helpdesk posts ticket text to an attacker's HTTPS webhook",
         lambda d: Request(SA, "attached", "vm:helpdesk-vm", "webhook")),
    Step("A5", "A", "A developer's stolen laptop session mints a token for chatbot-runtime from 203.0.113.80",
         lambda d: Request(SA, "impersonate", "203.0.113.80", "aiplatform.googleapis.com",
                           "aiplatform.endpoints.predict", f"{GEMINI}:predict", caller="user:dev1@example.com")),
    Step("L1", "L", "Helpdesk VM: GenerateContent on the approved Gemini model as chatbot-runtime",
         lambda d: Request(SA, "attached", "vm:helpdesk-vm", "aiplatform.googleapis.com",
                           "aiplatform.endpoints.predict", f"{GEMINI}:predict"), attacker=False),
    Step("L2", "L", "Helpdesk VM: read ticket history from BigQuery",
         lambda d: Request(SA, "attached", "vm:helpdesk-vm", "bigquery.googleapis.com",
                           "bigquery.tables.getData", dataset="helpdesk_tickets"), attacker=False),
    Step("L3", "L", "Analyst in the office (198.51.100.21): query the tickets dataset",
         lambda d: Request("user:analyst2@example.com", "user", "198.51.100.21", "bigquery.googleapis.com",
                           "bigquery.tables.getData", dataset="helpdesk_tickets"), attacker=False),
    Step("L4", "L", "Ticket summariser VM: GenerateContent on the approved Gemini model",
         lambda d: Request(summariser_principal(d), "attached", "vm:ticket-summariser", "aiplatform.googleapis.com",
                           "aiplatform.endpoints.predict", f"{GEMINI}:predict"), attacker=False),
]


def run_step(step: Step, twin: str | Deployment) -> Decision:
    d = twin if isinstance(twin, Deployment) else Deployment.load(twin)
    return evaluate(step.build(d), d)


# ---- the auditor's four questions ---------------------------------------------------------------------------------
def questions(d: Deployment) -> list[tuple[str, str, bool, str]]:
    out = []
    da = d.data_access_logs_on()
    out.append(("Q1", "Can we see who called Gemini, as which identity, from which IP?", da,
                "Data Access (DATA_READ) audit logs for aiplatform.googleapis.com are on" if da else
                "Data Access audit logs are off for aiplatform.googleapis.com: no record of model calls"))
    rr = d.app.get("request_response_logging") or {}
    need = d.req.get("request_response_logging_min_sampling_rate", 1.0)
    rr_ok = bool(rr.get("enabled")) and float(rr.get("sampling_rate", 0)) >= need
    out.append(("Q2", "Can we see what each prompt and answer said?", rr_ok,
                f"request-response logging at {rr.get('sampling_rate')} to {rr.get('bigquery_destination')}" if rr_ok
                else ("request-response logging is off" if not rr.get("enabled") else
                      f"only a {rr.get('sampling_rate')} sample is logged")))
    loc = d.app.get("location")
    in_policy = loc in d.req.get("approved_locations", []) and loc != "global"
    out.append(("Q3", "Can we show EU tickets were processed only in the EU?", in_policy,
                f"calls use location '{loc}', an approved EU location" if in_policy else
                f"calls use location '{loc}': the global endpoint gives no data residency guarantee"))
    cmek = all(v["cmek"] for v in d.datasets().values()) and bool(d.datasets())
    out.append(("Q4", "Can we make stored prompts and tickets unreadable in one step (disable the key)?", cmek,
                "every dataset has a customer-managed default key" if cmek else
                "datasets use Google default encryption: there's no key of yours to disable"))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--twin", default="today", help="today | hardened | eu-multiregion | path to a twin folder")
    args = ap.parse_args(argv)
    d = Deployment.load(args.twin)
    print(f"--- GC11 lab · twin: {d.name} · TSG Helpdesk in {d.project} ---")
    print("    (twin.py: a teaching model of Google Cloud's rules; nothing is sent to Google)\n")
    counts = {"A": [0, 0], "L": [0, 0]}
    headers = {"A": "Attackers", "L": "Legitimate traffic · must keep working"}
    last = None
    for step in STEPS:
        if step.group != last:
            print(headers[step.group])
            last = step.group
        dec = run_step(step, d)
        counts[step.group][0] += dec.allowed
        counts[step.group][1] += 1
        print(f"  [{step.sid}] {'ALLOWED' if dec.allowed else 'DENIED '}  {step.title}")
        print(f"         why: {dec.why}")
        for n in dec.notes:
            if "DRY RUN" in n or (dec.allowed and step.attacker and n.startswith(("IAM", "path"))):
                print(f"         · {n}")
        if step.sid == "A5":
            print()
    print("\nThe auditor's questions")
    answered = 0
    for qid, q, ok, why in questions(d):
        answered += ok
        print(f"  [{qid}] {'YES' if ok else 'NO '}  {q}")
        print(f"         {why}")
    a, l = counts["A"], counts["L"]
    print(f"\n{a[0]} of {a[1]} attacker requests allowed; {l[0]} of {l[1]} legitimate requests allowed; "
          f"{answered} of 4 auditor questions answerable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
