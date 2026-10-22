"""
attack.py: replay what an attacker could do with ExampleCo's leaked credentials, and check legitimate traffic.

    python3 attack.py --mode vulnerable      # ExampleCo today
    python3 attack.py --mode safe            # with every file in fixes/ applied
    python3 attack.py --mode safe --verbose  # print every check, not just the verdict
    python3 attack.py --preview-org-policy gcp-twin/allowed-models-dryrun.json
                                             # no Organization? preview what an org policy file WOULD deny here

Nothing is sent to Google. Each request is checked by gcp_eval.py, a teaching model of Google Cloud's rules.
Every IP address is from the documentation ranges in RFC 5737; every name is fictional.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import tempfile

from gcp_eval import Corp, Request, evaluate

GEMINI_LITE = "publishers/google/models/gemini-3.1-flash-lite:predict"
GEMINI_FLASH = "publishers/google/models/gemini-3.5-flash:predict"
CLAUDE_OPUS = "publishers/anthropic/models/claude-opus-4-7:predict"
CLAUDE_HAIKU = "publishers/anthropic/models/claude-haiku-4-5:predict"
LLAMA_DEPLOY = "publishers/meta/models/llama3:deploy"

CI = "serviceAccount:ci-deployer@example-ci.iam.gserviceaccount.com"
ETL = "serviceAccount:legacy-etl@example-ci.iam.gserviceaccount.com"
CHATBOT = "serviceAccount:chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com"
AI = "aiplatform.googleapis.com"


@dataclasses.dataclass
class Step:
    sid: str
    group: str
    text: str
    req: Request
    attacker: bool = True


GROUPS = {
    "A": "Attacker 1 · API keys copied from a public repo and a public web page (from 203.0.113.50)",
    "B": "Attacker 2 · the leaked JSON key of legacy-etl, a service account nobody has used since March (from 203.0.113.77)",
    "C": "Attacker 3 · the authorization key ops-eval-key, bound to chatbot-runtime (from 203.0.113.90)",
    "L": "Legitimate traffic · must keep working after the fixes",
}

STEPS = [
    Step("A1", "A", "GenerateContent on the approved model, billed to the chatbot project",
         Request("apikey:chatbot-frontend", "example-chatbot-prod", AI, "GenerateContent",
                 model=GEMINI_LITE, source_ip="203.0.113.50")),
    Step("A2", "A", "GenerateContent on a bigger model nobody approved for prod (Gemini 3.5 Flash)",
         Request("apikey:chatbot-frontend", "example-chatbot-prod", AI, "GenerateContent",
                 model=GEMINI_FLASH, source_ip="203.0.113.50")),
    Step("A3", "A", "Gemini API with the store-locator key scraped from www.example.com",
         Request("apikey:store-locator-website", "example-legacy-web", "generativelanguage.googleapis.com",
                 "GenerateContent", source_ip="203.0.113.50")),
    Step("A4", "A", "Gemini API with the unrestricted chatbot key",
         Request("apikey:chatbot-frontend", "example-chatbot-prod", "generativelanguage.googleapis.com",
                 "GenerateContent", source_ip="203.0.113.50")),
    Step("B1", "B", "RawPredict on Claude Opus 4.7 in the sandbox (not approved anywhere)",
         Request(ETL, "example-ds-sandbox", AI, "RawPredict", "aiplatform.endpoints.predict",
                 model=CLAUDE_OPUS, source_ip="203.0.113.77")),
    Step("B2", "B", "Deploy Llama 3 to a GPU endpoint in prod (billed by the hour while it runs)",
         Request(ETL, "example-chatbot-prod", AI, "DeployModel", "aiplatform.endpoints.deploy",
                 model=LLAMA_DEPLOY, source_ip="203.0.113.77")),
    Step("B3", "B", "CreateServiceAccountKey for chatbot-runtime (a second way back in)",
         Request(ETL, "example-chatbot-prod", "iam.googleapis.com", "CreateServiceAccountKey",
                 "iam.serviceAccountKeys.create", source_ip="203.0.113.77")),
    Step("B4", "B", "CreateKey: an API key bound to chatbot-runtime (persistence that skips SA usage metrics)",
         Request(ETL, "example-chatbot-prod", "apikeys.googleapis.com", "CreateKey", "apikeys.keys.create",
                 source_ip="203.0.113.77",
                 bind_to_sa="chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com")),
    Step("C1", "C", "GenerateContent on Gemini 3.5 Flash as chatbot-runtime (it holds Agent Platform Admin)",
         Request("apikey:ops-eval-key", "example-chatbot-prod", AI, "GenerateContent",
                 "aiplatform.endpoints.predict", model=GEMINI_FLASH, source_ip="203.0.113.90")),
    Step("L1", "L", "Chatbot on Cloud Run: GenerateContent on the approved model as chatbot-runtime",
         Request(CHATBOT, "example-chatbot-prod", AI, "GenerateContent", "aiplatform.endpoints.predict",
                 model=GEMINI_LITE, source_ip="192.0.2.10"), attacker=False),
    Step("L2", "L", "Chatbot web tier: GenerateContent with the chatbot-frontend key from its egress IP",
         Request("apikey:chatbot-frontend", "example-chatbot-prod", AI, "GenerateContent",
                 model=GEMINI_LITE, source_ip="192.0.2.10"), attacker=False),
    Step("L3", "L", "Data scientist: GenerateContent on Gemini 3.5 Flash in the sandbox",
         Request("user:alice@example.com", "example-ds-sandbox", AI, "GenerateContent",
                 "aiplatform.endpoints.predict", model=GEMINI_FLASH, source_ip="198.51.100.20"), attacker=False),
    Step("L4", "L", "Data scientist: RawPredict on approved Claude Haiku 4.5 in the sandbox",
         Request("user:alice@example.com", "example-ds-sandbox", AI, "RawPredict",
                 "aiplatform.endpoints.predict", model=CLAUDE_HAIKU, source_ip="198.51.100.20"), attacker=False),
    Step("L5", "L", "Notebook: GenerateContent with ds-notebook-key from the office range",
         Request("apikey:ds-notebook-key", "example-ds-sandbox", AI, "GenerateContent",
                 model=GEMINI_LITE, source_ip="198.51.100.20"), attacker=False),
    Step("L6", "L", "CI pipeline: nightly eval, GenerateContent on the approved model in the sandbox",
         Request(CI, "example-ds-sandbox", AI, "GenerateContent", "aiplatform.endpoints.predict",
                 model=GEMINI_LITE, source_ip="192.0.2.30"), attacker=False),
    Step("L7", "L", "CI pipeline: deploy a new chatbot revision to Cloud Run",
         Request(CI, "example-chatbot-prod", "run.googleapis.com", "CreateService", "run.services.create",
                 source_ip="192.0.2.30"), attacker=False),
    Step("L8", "L", "Platform admin: CreateKey, a STANDARD key (not bound to a service account) in the sandbox",
         Request("user:bob@example.com", "example-ds-sandbox", "apikeys.googleapis.com", "CreateKey",
                 "apikeys.keys.create", source_ip="192.0.2.40"), attacker=False),
]

CHALLENGE_OPEN = {"A1", "B1"}


def run_step(step, mode, extra_org_policies=(), keys_file=None):
    corp = Corp(with_fixes=(mode == "safe"), extra_org_policies=extra_org_policies, keys_file=keys_file)
    return evaluate(corp, step.req)


def preview_file(path, tmpdir):
    """Copy an org policy file for local preview: ORGANIZATION_ID -> ExampleCo's org, dryRunSpec -> spec."""
    pol = json.loads(pathlib.Path(path).read_text())
    org_id = Corp().org["name"].split("/")[1]
    pol["name"] = pol["name"].replace("ORGANIZATION_ID", org_id)
    if "spec" not in pol and "dryRunSpec" in pol:
        pol["spec"] = pol.pop("dryRunSpec")
    out = pathlib.Path(tmpdir) / pathlib.Path(path).name
    out.write_text(json.dumps(pol))
    return out, pol["name"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["vulnerable", "safe"], default="vulnerable")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--preview-org-policy", metavar="FILE",
                    help="apply one org policy file on top of --mode and show what it would deny (local dry run)")
    args = ap.parse_args(argv)

    extra, preview_name = (), ""
    if args.preview_org_policy:
        tmp = tempfile.mkdtemp()
        f, preview_name = preview_file(args.preview_org_policy, tmp)
        extra = (f,)
        base = Corp(with_fixes=(args.mode == "safe"))
    corp = Corp(with_fixes=(args.mode == "safe"), extra_org_policies=extra)
    label = "VULNERABLE · ExampleCo today" if args.mode == "vulnerable" else \
        "SAFE · fixes applied: " + ", ".join(corp.applied_fixes)
    if preview_name:
        label = f"PREVIEW · {preview_name} on top of ExampleCo {'today' if args.mode == 'vulnerable' else 'with fixes'}"
    print(f"--- GC10 lab · {label} ---")
    print("    (gcp_eval.py: a teaching model of Google Cloud's rules; nothing is sent to Google)")
    counts = {True: [0, 0], False: [0, 0]}
    current = None
    for s in STEPS:
        if s.group != current:
            current = s.group
            print(f"\n{GROUPS[s.group]}")
        d = evaluate(corp, s.req)
        counts[s.attacker][0] += d.allowed
        counts[s.attacker][1] += 1
        flag = "   <-- still open: make challenge" if (args.mode == "safe" and d.allowed and s.attacker
                                                       and not preview_name) else ""
        if preview_name and not d.allowed and evaluate(base, s.req).allowed:
            flag = "   <-- newly denied by the previewed policy" + ("" if s.attacker else " (LEGITIMATE: fix the list first)")
        print(f"  [{s.sid}] {'ALLOWED' if d.allowed else 'DENIED '}  {s.text}{flag}")
        if args.verbose:
            for ok, t in d.checks:
                print(f"         {'ok ' if ok else 'NO '} {t}")
        else:
            print(f"         why: {d.why}")
    a, l = counts[True], counts[False]
    print(f"\n{a[0]} of {a[1]} attacker requests allowed; {l[0]} of {l[1]} legitimate requests allowed.")
    if preview_name:
        print("In Google's dry run (dryRunSpec), these denials are only audit-logged as violations; nothing is blocked.")


if __name__ == "__main__":
    main()
