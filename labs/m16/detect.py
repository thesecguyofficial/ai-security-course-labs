"""
detect.py: run a detection rule pack over one setup's telemetry and print the alerts.

    python3 detect.py hardened                 # the m16 pack (this module's rules) on the hardened telemetry
    python3 detect.py first-draft --pack soc-v1   # the SOC's old rules on what was collected before this module
    python3 detect.py hardened --json          # alerts as JSON (report.py and evaluate.py use this)

Two packs:
    soc-v1  three rules a SOC often starts with: InvokeModel volume, logging deleted, GuardDuty Medium and above
    m16     D01-D13 from lessons 16.2 to 16.5. D11 and D12 are YOUR challenge: they return nothing until you write them

Every rule reads only what a real SOC would have: the telemetry files of one setup, anycompany.json and
data/baselines.json. It never reads out/<setup>/truth.json (that's the answer key evaluate.py uses).
Each alert names an *entity*: the thing a responder acts on (an IAM user, an end user, a runtime session, a role).
The saved-query version of each rule, for CloudWatch Logs Insights, is in queries/.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

HERE = pathlib.Path(__file__).resolve().parent
COMPANY = json.loads((HERE / "anycompany.json").read_text())
BASELINES = {k: v for k, v in json.loads((HERE / "data" / "baselines.json").read_text()).items() if not k.startswith("_")}
TUNE = COMPANY["detection_tuning"]

AI_FINDINGS = ("Impact:IAMUser/AnomalousModelInvocation", "Impact:IAMUser/CostHarvesting",
               "Impact:IAMUser/PromptInjection.Direct")
INFERENCE = {"InvokeModel", "InvokeModelWithResponseStream", "Converse", "ConverseStream"}
RECON = {"ListFoundationModels", "GetFoundationModelAvailability", "GetModelInvocationLoggingConfiguration",
         "ListInferenceProfiles", "ListGuardrails"}
TAMPER = {"DeleteModelInvocationLoggingConfiguration", "PutModelInvocationLoggingConfiguration",
          "DeleteEnforcedGuardrailConfiguration", "DeleteGuardrail", "StopLogging", "DeleteTrail",
          "PutEventSelectors"}


# --------------------------------------------------------------------------------------------------- telemetry
class Telemetry:
    """One setup's files. A missing file means the setup never collected that source: the list is empty."""

    def __init__(self, setup: str):
        self.setup = setup
        folder = HERE / "out" / setup
        if not folder.exists():
            sys.exit(f"no telemetry in out/{setup}/: run  python3 simulate.py {setup}  first (or make simulate)")
        self.cloudtrail = load(folder / "cloudtrail.jsonl")
        self.invocations = load(folder / "invocations.jsonl")
        self.guardduty = load(folder / "guardduty.jsonl")
        self.spans = load(folder / "spans.jsonl")
        self.app = load(folder / "app.jsonl")

    @classmethod
    def from_build(cls, built: dict):
        """Telemetry straight from simulate.build() (the tests use this: no files needed)."""
        t = cls.__new__(cls)
        t.setup = built["setup"]["name"]
        t.cloudtrail, t.invocations, t.guardduty, t.spans, t.app = (built["out"][k] for k in
                                                                    ("cloudtrail", "invocations", "guardduty", "spans", "app"))
        return t


def load(path: pathlib.Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def principal_arn(ev: dict) -> str:
    """The IAM role or user behind a CloudTrail record (role ARN for assumed-role sessions)."""
    ui = ev.get("userIdentity", {})
    issuer = ui.get("sessionContext", {}).get("sessionIssuer", {})
    return issuer.get("arn") or ui.get("arn", "")


def role_of(arn: str) -> str:
    """arn:aws:sts::1:assumed-role/Role/session -> arn:aws:iam::1:role/Role (invocation logs carry the session ARN)."""
    m = re.match(r"arn:aws:sts::(\d+):assumed-role/([^/]+)/", arn)
    return f"arn:aws:iam::{m.group(1)}:role/{m.group(2)}" if m else arn


def short(arn: str) -> str:
    """The name a responder uses: the role or user name at the end of the ARN."""
    if ":assumed-role/" in arn:
        return arn.split("/")[1]
    return arn.rsplit("/", 1)[-1]


def bearer(ev: dict) -> bool:
    return bool((ev.get("additionalEventData") or {}).get("callWithBearerToken")
                or (ev.get("requestParameters") or {}).get("callWithBearerToken"))


def output_text(rec: dict) -> str:
    msg = rec.get("output", {}).get("outputBodyJson", {}).get("output", {}).get("message", {})
    return " ".join(c.get("text", "") for c in msg.get("content", []))


def alert(rule, title, severity, time, entity, entity_type, evidence, detail) -> dict:
    return {"rule": rule, "title": title, "severity": severity, "time": time, "entity": entity,
            "entity_type": entity_type, "evidence": list(evidence), "detail": detail}


# ------------------------------------------------------------------------------------------- pack soc-v1 (naive)
def n1_invokemodel_volume(t: Telemetry) -> list[dict]:
    """More than 100 InvokeModel calls in an hour from one principal (CloudTrail)."""
    buckets = defaultdict(list)
    for ev in t.cloudtrail:
        if ev["eventSource"] == "bedrock.amazonaws.com" and ev["eventName"] == "InvokeModel":
            buckets[(principal_arn(ev), ev["eventTime"][:13])].append(ev)
    return [alert("N1", "High InvokeModel volume", "MEDIUM", evs[0]["eventTime"], short(p), "principal",
                  [e["eventID"] for e in evs[:5]], f"{len(evs)} InvokeModel calls in hour {hour[11:]}:00")
            for (p, hour), evs in buckets.items() if len(evs) > 100]


def n2_logging_deleted(t: Telemetry) -> list[dict]:
    """Anyone calling DeleteModelInvocationLoggingConfiguration (CloudTrail)."""
    return [alert("N2", "Bedrock invocation logging deleted", "HIGH", ev["eventTime"], short(principal_arn(ev)),
                  "principal", [ev["eventID"]], f"errorCode={ev.get('errorCode')}")
            for ev in t.cloudtrail if ev["eventName"] == "DeleteModelInvocationLoggingConfiguration"]


def n3_guardduty_medium_plus(t: Telemetry) -> list[dict]:
    """GuardDuty findings with severity 4.0 or more: the pattern many teams copy from AWS's EventBridge example."""
    return [alert("N3", f"GuardDuty {f['type']}", "HIGH", f["updatedAt"],
                  f["resource"].get("accessKeyDetails", {}).get("userName", "?"), "principal", [f["id"]], f["title"])
            for f in t.guardduty if f["severity"] >= 4.0]


# ------------------------------------------------------------------------------------------------- pack m16
def d01_bearer_key_new_ip(t: Telemetry) -> list[dict]:
    """A Bedrock API key (callWithBearerToken) used from an address outside the office and VPCs (16.2, 16.5)."""
    known = set(COMPANY["office_and_vpc_ips"])
    by_user = defaultdict(list)
    for ev in t.cloudtrail:
        if ev["eventSource"].startswith("bedrock") and bearer(ev) and ev["sourceIPAddress"] not in known:
            by_user[principal_arn(ev)].append(ev)
    return [alert("D01", "Bedrock API key used from an unknown address", "HIGH", evs[0]["eventTime"], short(p),
                  "iam-user", [e["eventID"] for e in evs[:5]],
                  f"{len(evs)} calls from {sorted({e['sourceIPAddress'] for e in evs})}")
            for p, evs in by_user.items()]


def d02_recon(t: Telemetry) -> list[dict]:
    """Model and logging reconnaissance, or a probe that fails validation, by anyone who isn't a logging admin."""
    admins = set(COMPANY["logging_admins"])
    by_p = defaultdict(list)
    for ev in t.cloudtrail:
        p = principal_arn(ev)
        if p in admins or not ev["eventSource"].startswith("bedrock"):
            continue
        probe = ev["eventName"] in INFERENCE and ev.get("errorCode") == "ValidationException"
        if ev["eventName"] in RECON or probe:
            by_p[p].append(ev)
    return [alert("D02", "Bedrock reconnaissance", "MEDIUM", evs[0]["eventTime"], short(p), "principal",
                  [e["eventID"] for e in evs], ", ".join(e["eventName"] for e in evs))
            for p, evs in by_p.items()]


def d03_defence_tamper(t: Telemetry) -> list[dict]:
    """Logging, guardrail or trail changes by a non-admin, and any gateway policy engine leaving ENFORCE."""
    out = []
    for ev in t.cloudtrail:
        p = principal_arn(ev)
        if ev["eventName"] in TAMPER and p not in COMPANY["logging_admins"]:
            out.append(alert("D03", f"Defence change: {ev['eventName']}", "HIGH", ev["eventTime"], short(p),
                             "principal", [ev["eventID"]], f"errorCode={ev.get('errorCode')}"))
        if ev["eventName"] == "UpdateGateway":
            pec = (ev.get("requestParameters") or {}).get("policyEngineConfiguration")
            mode = (pec or {}).get("mode")
            if mode != "ENFORCE":
                out.append(alert("D03", "Gateway policy engine not in ENFORCE", "HIGH", ev["eventTime"], short(p),
                                 "principal", [ev["eventID"]],
                                 f"gateway {ev['requestParameters'].get('gatewayIdentifier')} mode={mode or 'removed'}"))
    return out


def d04_unapproved_inference(t: Telemetry) -> list[dict]:
    """Model inference (bedrock-runtime APIs or bedrock-mantle CreateInference) by a principal not on the list."""
    approved = set(COMPANY["approved_inference_principals"])
    by_p = defaultdict(list)
    for ev in t.cloudtrail:
        is_inf = (ev["eventSource"] == "bedrock.amazonaws.com" and ev["eventName"] in INFERENCE) or \
                 (ev["eventSource"] == "bedrock-mantle.amazonaws.com" and ev["eventName"] == "CreateInference")
        if is_inf and principal_arn(ev) not in approved:
            by_p[principal_arn(ev)].append(ev)
    return [alert("D04", "Model inference by an unapproved principal", "HIGH", evs[0]["eventTime"], short(p),
                  "principal", [e["eventID"] for e in evs[:5]],
                  f"{len(evs)} calls; sources {sorted({e['eventSource'] for e in evs})}")
            for p, evs in by_p.items()]


def d05_guardduty_ai(t: Telemetry) -> list[dict]:
    """Every GuardDuty AI Protection finding, whatever its severity. All three types default to Low."""
    approved = {short(a) for a in COMPANY["approved_inference_principals"]}
    out = []
    for f in t.guardduty:
        if f["type"] not in AI_FINDINGS:
            continue
        who = f["resource"]["accessKeyDetails"]["userName"]
        sev = "MEDIUM" if who in approved else "HIGH"
        out.append(alert("D05", f["type"], sev, f["updatedAt"], who, "principal", [f["id"]],
                         f"severity {f['severity']} (Low), count {f['service']['count']}; the IAM identity, "
                         "not the end user"))
    return out


def d06_token_spike(t: Telemetry) -> list[dict]:
    """Tokens per principal per hour above factor x the principal's 14-day baseline (or no baseline at all)."""
    hours = defaultdict(lambda: [0, []])
    for r in t.invocations:
        key = (role_of(r["identity"]["arn"]), r["timestamp"][:13])
        n = r["input"]["inputTokenCount"] + r["output"]["outputTokenCount"]
        hours[key][0] += n
        hours[key][1].append((n, r["requestId"]))
    out = []
    for (p, hour), (tokens, ids) in sorted(hours.items()):
        base = BASELINES.get(p)
        if base is None or tokens > TUNE["tokens_per_principal_per_hour_factor"] * base:
            why = "no baseline" if base is None else f"{tokens / base:.0f}x the baseline of {base:,}"
            top = [rid for _, rid in sorted(ids, reverse=True)[:5]]  # evidence: the five biggest calls
            out.append(alert("D06", "Model token spike", "MEDIUM", f"{hour}:00:00Z", short(p), "principal", top,
                             f"{tokens:,} tokens in hour {hour[11:]}:00 ({why})"))
    return out


def d07_prompt_attacks_per_user(t: Telemetry) -> list[dict]:
    """An end user with N or more guardrail interventions in 10 minutes (invocation logs + requestMetadata)."""
    n = TUNE["prompt_attacks_per_user_per_10_min"]
    per_user = defaultdict(list)
    for r in t.invocations:
        if r["output"]["outputBodyJson"].get("stopReason") == "guardrail_intervened":
            per_user[(r.get("requestMetadata") or {}).get("end_user", "unknown")].append(r)
    out = []
    for user, rs in per_user.items():
        for i in range(len(rs) - n + 1):
            if ts(rs[i + n - 1]["timestamp"]) - ts(rs[i]["timestamp"]) <= timedelta(minutes=10):
                out.append(alert("D07", "Repeated prompt attacks from one end user", "HIGH", rs[i]["timestamp"], user,
                                 "end-user", [r["requestId"] for r in rs], f"{len(rs)} guardrail interventions"))
                break
    return out


def d08_canary_in_output(t: Telemetry) -> list[dict]:
    """The system prompt's canary string appears in a model answer: a jailbreak got through."""
    canary = COMPANY["system_prompt_canary"]
    return [alert("D08", "System prompt canary in an answer", "HIGH", r["timestamp"],
                  (r.get("requestMetadata") or {}).get("end_user", short(r["identity"]["arn"])), "end-user",
                  [r["requestId"]], "the answer contains " + canary)
            for r in t.invocations if canary in output_text(r)]


def d09_deny_not_enforced(t: Telemetry) -> list[dict]:
    """Gateway spans where the policy engine said DENY in LOG_ONLY mode: tool calls that ran but shouldn't have."""
    by_s = defaultdict(list)
    for s in t.spans:
        a = s["attributes"]
        if a["aws.agentcore.policy.authorization_decision"] == "DENY" and a["aws.agentcore.gateway.policy.mode"] == "LOG_ONLY":
            by_s[s["lab.runtime_session_id"]].append(s)
    return [alert("D09", "Tool call denied by policy but executed (LOG_ONLY)", "HIGH", ss[0]["startTime"], sid,
                  "runtime-session", [s["spanId"] for s in ss], ", ".join(s["lab.tool"].split("___")[1] for s in ss))
            for sid, ss in by_s.items()]


def d10_mail_out(t: Telemetry) -> list[dict]:
    """The agent's send_email tool was called for an address outside the company domain."""
    dom = COMPANY["company_email_domain"]
    out = []
    for s in t.spans:
        to = str(s["lab.input"].get("to", ""))
        if s["lab.tool"].endswith("___send_email") and to and not to.lower().endswith("@" + dom):
            out.append(alert("D10", "Agent emailed outside the company", "HIGH", s["startTime"],
                             s["lab.runtime_session_id"], "runtime-session", [s["spanId"]],
                             f"to={to}; executed={s['lab.executed']}"))
    return out


def d11_kb_source_write(t: Telemetry) -> list[dict]:
    """CHALLENGE 1 (lessons 16.4 and 16.5). Knowledge base poisoning: someone who isn't the KB pipeline writes into
    the knowledge base's source bucket (S3 PutObject data event) or starts an ingestion job (StartIngestionJob).

    Return one alert per principal, with the principal's short name as the entity (use short(principal_arn(ev))),
    entity_type "principal", and the eventIDs as evidence. The pipeline's role is in COMPANY["kb"]["writers"],
    the bucket in COMPANY["kb"]["bucket"]. Normal traffic must not alert.
    """
    return []


def d12_wallet_per_end_user(t: Telemetry) -> list[dict]:
    """CHALLENGE 2 (lessons 16.1 and 16.5). Denial of wallet by one end user. Every call is made by the app's role,
    so GuardDuty and D06 can only name HelpdeskAppRole. Use the end user in requestMetadata (invocation logs) or
    signed_in_user (app log) to find an end user above COMPANY["detection_tuning"]["tokens_per_end_user_per_hour"]
    tokens (input + output) in any one hour.

    Return one alert per end user, entity = the end user ID, entity_type "end-user". Normal customers must not alert.
    """
    return []


def d13_unknown_link_in_answer(t: Telemetry) -> list[dict]:
    """A model answer sends users to a web domain outside the allow-list (often the visible effect of poisoned RAG)."""
    allowed = COMPANY["allowed_answer_domains"]
    by_dom = defaultdict(list)
    for r in t.invocations:
        for host in re.findall(r"https?://([a-z0-9.-]+)", output_text(r).lower()):
            if not any(host == a or host.endswith("." + a) for a in allowed):
                by_dom[host].append(r)
    return [alert("D13", "Answer links to an unknown domain", "MEDIUM", rs[0]["timestamp"], host, "domain",
                  [r["requestId"] for r in rs], f"{len(rs)} answers")
            for host, rs in by_dom.items()]


PACKS = {
    "soc-v1": [n1_invokemodel_volume, n2_logging_deleted, n3_guardduty_medium_plus],
    "m16": [d01_bearer_key_new_ip, d02_recon, d03_defence_tamper, d04_unapproved_inference, d05_guardduty_ai,
            d06_token_spike, d07_prompt_attacks_per_user, d08_canary_in_output, d09_deny_not_enforced, d10_mail_out,
            d11_kb_source_write, d12_wallet_per_end_user, d13_unknown_link_in_answer],
}
CHALLENGE_RULES = {"d11_kb_source_write", "d12_wallet_per_end_user"}


def run(t: Telemetry, pack: str = "m16", challenge: bool = True) -> list[dict]:
    """All alerts of one pack, oldest first. challenge=False skips D11 and D12 (the tests pin the shipped rules)."""
    alerts = []
    for rule in PACKS[pack]:
        if not challenge and rule.__name__ in CHALLENGE_RULES:
            continue
        alerts += rule(t)
    return sorted(alerts, key=lambda a: (a["time"], a["rule"]))


def show(alerts: list[dict], setup: str, pack: str):
    print(f"Pack {pack} on {setup} telemetry: {len(alerts)} alerts\n")
    for a in alerts:
        print(f"[{a['severity']:6}] {a['time'][11:16]} {a['rule']} {a['title']}")
        print(f"         entity {a['entity_type']}: {a['entity']}   ({a['detail']})")
    if not alerts:
        print("(no alerts)")


def main(argv: list[str]):
    args = [a for a in argv if not a.startswith("--")]
    setup = args[0] if args else "hardened"
    pack = argv[argv.index("--pack") + 1] if "--pack" in argv else "m16"
    if pack in args:
        args.remove(pack)
    alerts = run(Telemetry(setup), pack)
    if "--json" in argv:
        print(json.dumps(alerts, indent=1))
    else:
        show(alerts, setup, pack)


if __name__ == "__main__":
    main(sys.argv[1:])
