"""
report.py: from alert to incident report (lessons 16.5 and 16.6).

    python3 report.py pivot BedrockAPIKey-q4m8        # every record that mentions an entity, oldest first: your timeline
    python3 report.py cost BedrockAPIKey-q4m8         # tokens and an estimated cost (lab price list)
    python3 report.py check report/INCIDENT-REPORT.md --scenario S1    # is the report complete? (challenge 3)
    python3 report.py check report/EXAMPLE-S3-hijacked-agent.md --scenario S3   # the worked example passes

pivot and cost read the hardened telemetry (out/hardened/); add --setup first-draft to see how little the old logging
gives you. check reads only your Markdown file and the telemetry (to confirm the evidence IDs you cite exist).
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

import detect

HERE = pathlib.Path(__file__).resolve().parent
SECTIONS = ["Summary", "Severity and status", "Timeline (UTC)", "Scope", "Root cause", "Containment",
            "Eradication and recovery", "Evidence", "Detection gaps and new rules", "Lessons learned"]

# What each scenario's report must state, beyond the shared structure. (regex, what's missing if it doesn't match)
FACTS = {
    "S1": [(r"BedrockAPIKey-q4m8", "the IAM user that holds the leaked key"),
           (r"203\.0\.113\.50", "the first attacker address"), (r"203\.0\.113\.51", "the second attacker address"),
           (r"bedrock-mantle", "the bedrock-mantle calls (invocation logging doesn't record them)"),
           (r"(?i)(update|delete)-service-specific-credential|(Update|Delete)ServiceSpecificCredential",
            "the containment command for a long-term key"),
           (r"(?i)DeleteModelInvocationLoggingConfiguration", "the attempt to switch the logging off"),
           (r"\$\s?\d", "an estimated cost in US dollars"),
           (r"(?i)build log|CI log|pipeline log", "how the key leaked")],
    "S2": [(r"cust-8841", "the end user"), (r"(?i)canary|CANARY-M16-SYSPROMPT", "the leaked system prompt canary"),
           (r"(?i)guardrail", "what the guardrail did")],
    "S3": [(r"tsg-5120b0b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6", "the runtime session"),
           (r"LOG_ONLY", "the policy engine mode"), (r"tsg-ci-deployer", "who changed the gateway"),
           (r"ENFORCE", "the containment: back to ENFORCE"), (r"(?i)ticket 5120", "where the instruction came from")],
    "S4": [(r"cust-2290", "the end user"), (r"(?i)per-user|per user|end user", "an end-user limit")],
    "S5": [(r"ContractorUploadRole", "the role that wrote into the knowledge base"),
           (r"it/vpn-support-update\.md", "the poisoned object"), (r"(?i)StartIngestionJob|sync", "re-sync after removal")],
}


def all_ids(t: detect.Telemetry) -> set[str]:
    ids = set()
    ids |= {e["eventID"] for e in t.cloudtrail} | {r["requestId"] for r in t.invocations}
    ids |= {f["id"] for f in t.guardduty} | {s["spanId"] for s in t.spans}
    ids |= {a["request_id"] for a in t.app if "request_id" in a}
    return ids


def pivot(t: detect.Telemetry, entity: str) -> list[tuple[str, str, str, str]]:
    """(time, source, record ID, one-line summary) for every record that mentions the entity."""
    rows = []
    for e in t.cloudtrail:
        if entity in json.dumps(e):
            err = f" {e['errorCode']}" if e.get("errorCode") else ""
            rows.append((e["eventTime"], "cloudtrail", e["eventID"],
                         f"{e['eventSource'].split('.')[0]} {e['eventName']}{err} from {e['sourceIPAddress']}"))
    for r in t.invocations:
        if entity in json.dumps(r):
            rows.append((r["timestamp"], "invocation", r["requestId"],
                         f"{r['operation']} {r['modelId']} in={r['input']['inputTokenCount']} "
                         f"out={r['output']['outputTokenCount']} stop={r['output']['outputBodyJson'].get('stopReason')}"))
    for f in t.guardduty:
        if entity in json.dumps(f):
            rows.append((f["updatedAt"], "guardduty", f["id"], f"{f['type']} severity {f['severity']} count {f['service']['count']}"))
    for s in t.spans:
        if entity in json.dumps(s):
            a = s["attributes"]
            rows.append((s["startTime"], "span", s["spanId"],
                         f"{s['lab.tool'].split('___')[1]} {a['aws.agentcore.policy.authorization_decision']} "
                         f"mode={a['aws.agentcore.gateway.policy.mode']} input={json.dumps(s['lab.input'])}"))
    for a in t.app:
        if entity in json.dumps(a):
            rows.append((a["time"], "app", a.get("request_id", "-"), f"{a['path']} user={a.get('signed_in_user')}"))
    return sorted(rows)


def cost(t: detect.Telemetry, entity: str) -> dict:
    prices = json.loads((HERE / "anycompany.json").read_text())["lab_price_list"]
    recs = [r for r in t.invocations if entity in json.dumps(r)]
    tin = sum(r["input"]["inputTokenCount"] for r in recs)
    tout = sum(r["output"]["outputTokenCount"] for r in recs)
    mantle = sum(1 for e in t.cloudtrail if entity in json.dumps(e) and e["eventSource"] == "bedrock-mantle.amazonaws.com")
    usd = tin / 1000 * prices["input_per_1k"] + tout / 1000 * prices["output_per_1k"]
    return {"calls": len(recs), "input_tokens": tin, "output_tokens": tout, "usd_lab_prices": round(usd, 2),
            "mantle_calls_not_in_invocation_logs": mantle}


def check(text: str, scenario: str, ids: set[str]) -> list[str]:
    problems = []
    heads = re.findall(r"^## (.+?)\s*$", text, flags=re.M)
    for s in SECTIONS:
        if s not in heads:
            problems.append(f"missing section: ## {s}")
    if re.search(r"TODO|<fill|<[a-z][^>]*>", text):
        problems.append("placeholders left (TODO or <...>)")
    body = {}
    for i, h in enumerate(heads):
        start = text.index(f"## {h}")
        end = text.index(f"## {heads[i + 1]}") if i + 1 < len(heads) else len(text)
        body[h] = text[start + len(h) + 3:end].strip()
    for s in SECTIONS:
        if s in body and len(body[s]) < 20:
            problems.append(f"section '{s}' is empty or one word")
    stamps = re.findall(r"2026-10-20T\d\d:\d\d", body.get("Timeline (UTC)", ""))
    if len(stamps) < 5:
        problems.append(f"timeline: {len(stamps)} UTC timestamps (2026-10-20Thh:mm), need at least 5")
    cited = set(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32}|[0-9a-f]{16}|req-[0-9a-f]{8}",
                           body.get("Evidence", "")))
    real = cited & ids
    if len(real) < 3:
        problems.append(f"evidence: {len(real)} record IDs that exist in the telemetry (eventID, requestId, finding "
                        f"id, spanId or request_id), need at least 3" + (f"; not found: {sorted(cited - ids)[:3]}" if cited - ids else ""))
    for rx, what in FACTS.get(scenario, []):
        if not re.search(rx, text):
            problems.append(f"{scenario}: the report doesn't state {what}")
    return problems


def main(argv: list[str]):
    if not argv or argv[0] not in ("pivot", "cost", "check"):
        print(__doc__)
        sys.exit(2)
    setup = argv[argv.index("--setup") + 1] if "--setup" in argv else "hardened"
    t = detect.Telemetry(setup)
    if argv[0] == "pivot":
        rows = pivot(t, argv[1])
        for when, src, rid, what in rows:
            print(f"{when}  {src:10} {rid[:36]:36}  {what}")
        print(f"\n{len(rows)} records mention {argv[1]} in the {setup} telemetry")
    elif argv[0] == "cost":
        c = cost(t, argv[1])
        print(json.dumps(c, indent=1))
        print("usd_lab_prices uses the ILLUSTRATIVE price list in anycompany.json, not AWS's prices.")
    else:
        scenario = argv[argv.index("--scenario") + 1] if "--scenario" in argv else "S1"
        path = pathlib.Path(argv[1])
        if not path.exists():
            sys.exit(f"{path} not found. Start from the template:  cp report/TEMPLATE.md report/INCIDENT-REPORT.md")
        probs = check(path.read_text(), scenario, all_ids(t))
        for p in probs:
            print(f"  [ ] {p}")
        print(f"\n{path.name}: " + ("REPORT COMPLETE" if not probs else f"{len(probs)} things to fix"))
        sys.exit(1 if probs else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
