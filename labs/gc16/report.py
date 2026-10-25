"""
report.py: from alert to incident report (lessons 16.5 and 16.6).

    python3 report.py pivot etl-batch               # every record that mentions an entity, oldest first: your timeline
    python3 report.py cost etl-batch                # tokens and an estimated cost (lab price list)
    python3 report.py check report/INCIDENT-REPORT.md --scenario S1    # is the report complete? (challenge 3)
    python3 report.py check report/EXAMPLE-S3-hijacked-agent.md --scenario S3   # the worked example passes

pivot and cost read the hardened telemetry (out/hardened/); add --setup first-draft to see how little the old logging
gives you. check reads only your Markdown file and the telemetry (to confirm the evidence IDs you cite exist).

Pivot on a service account, an end user or an agent session. Request-response rows don't name the caller, so a pivot
on a service account finds them through the app log, and through the Data Access entries for the same model in the
same second (the "join" step). That's how it works in a real project too: the audit log names the caller, the prompt log
holds the words, and your app log or your labels tie them together.
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
    "S1": [(r"etl-batch", "the service account whose key leaked"),
           (r"203\.0\.113\.50", "the first attacker address"), (r"203\.0\.113\.51", "the second attacker address"),
           (r"(?i)claude|RawPredict", "the Claude calls (request-response logging wasn't on for Claude)"),
           (r"(?i)keys disable|keys delete|DisableServiceAccountKey|DeleteServiceAccountKey",
            "the containment command for the key"),
           (r"(?i)SetIamPolicy|auditConfigs", "the attempt to switch off Data Access audit logs"),
           (r"\$\s?\d", "an estimated cost in US dollars"),
           (r"(?i)build log|CI log|pipeline log", "how the key leaked")],
    "S2": [(r"cust-8841", "the end user"), (r"(?i)canary|CANARY-GC16-SYSPROMPT", "the leaked system prompt canary"),
           (r"(?i)model armor", "what Model Armor did")],
    "S3": [(r"7351126042550190080", "the agent session"), (r"DRY_RUN", "the gateway's enforcement mode"),
           (r"ci-deployer", "who changed the authorization extension"),
           (r"(?i)remove .*iamEnforcementMode|ENFORCE", "the containment: enforcement back on"),
           (r"(?i)ticket 5120", "where the instruction came from")],
    "S4": [(r"cust-2290", "the end user"), (r"(?i)per-user|per user|end user", "an end-user limit")],
    "S5": [(r"contractor-upload", "the service account that wrote into the RAG source"),
           (r"it/vpn-support-update\.md", "the poisoned object"), (r"(?i)ragFiles|RAG file|re-?import", "removal from the corpus")],
}


def all_ids(t: detect.Telemetry) -> set[str]:
    ids = {e["insertId"] for e in t.audit} | {r["request_id"] for r in t.requests}
    ids |= {a["insertId"] for a in t.armor} | {f["name"].rsplit("/", 1)[-1] for f in t.scc}
    ids |= {g["insertId"] for g in t.gateway} | {a["request_id"] for a in t.app if "request_id" in a}
    return ids


def _app_links(t: detect.Telemetry, entity: str) -> set[str]:
    """responseIds the app log ties to this entity (an end user, a session, an agent session)."""
    return {a["response_id"] for a in t.app if a.get("response_id") and entity in json.dumps(a)}


def pivot(t: detect.Telemetry, entity: str) -> list[tuple[str, str, str, str]]:
    """(time, source, record ID, one-line summary) for every record that mentions the entity."""
    rows = []
    seconds = set()
    for e in t.audit:
        if entity in json.dumps(e):
            pp = e["protoPayload"]
            err = f" status {pp['status']['code']}" if (pp.get("status") or {}).get("code") else ""
            rows.append((e["timestamp"], "audit", e["insertId"],
                         f"{pp['serviceName'].split('.')[0]} {pp['methodName'].rsplit('.', 1)[-1]}{err} "
                         f"from {pp['requestMetadata']['callerIp']}"))
            if pp["methodName"] in detect.INFERENCE:
                seconds.add((e["timestamp"], pp["resourceName"].rsplit("/", 1)[-1]))
    linked = _app_links(t, entity)
    for r in t.requests:
        rid = r["full_response"].get("responseId")
        if entity in json.dumps(r["full_request"]) or rid in linked or (r["logging_time"], r["model"]) in seconds:
            u = r["full_response"]["usageMetadata"]
            block = (r["full_response"].get("promptFeedback") or {}).get("blockReason")
            fin = block or r["full_response"]["candidates"][0].get("finishReason")
            rows.append((r["logging_time"], "request", r["request_id"],
                         f"{r['api_method']} {r['model']} tokens={u['totalTokenCount']} end={fin}"))
    for a in t.armor:
        if entity in json.dumps(a):
            rows.append((a["timestamp"], "armor", a["insertId"], a["jsonPayload"]["sanitizationResult"]["filterMatchState"]))
    for f in t.scc:
        if entity in json.dumps(f):
            rows.append((f["eventTime"], "scc", f["name"].rsplit("/", 1)[-1], f"{f['category']} severity {f['severity']}"))
    for g in t.gateway:
        if entity in json.dumps(g):
            rows.append((g["timestamp"], "gateway", g["insertId"],
                         f"{g['jsonPayload']['mcpInfo']['lab.tool']} policy={g['lab.policy_says']} "
                         f"mode={g['lab.enforcement']} input={json.dumps(g['lab.input'])}"))
    for a in t.app:
        if entity in json.dumps(a):
            rows.append((a["time"], "app", a.get("request_id", "-"), f"{a['path']} user={a.get('signed_in_user')}"))
    return sorted(rows)


def cost(t: detect.Telemetry, entity: str) -> dict:
    prices = json.loads((HERE / "exampleco.json").read_text())["lab_price_list"]
    recs = [r for r in t.requests if r["request_id"] in {x[2] for x in pivot(t, entity) if x[1] == "request"}]
    tin = sum(r["full_response"]["usageMetadata"]["promptTokenCount"] for r in recs)
    tout = sum(r["full_response"]["usageMetadata"].get("candidatesTokenCount", 0) for r in recs)
    claude = sum(1 for e in t.audit if entity in json.dumps(e) and e["protoPayload"]["methodName"].endswith("RawPredict")
                 and not (e["protoPayload"].get("status") or {}).get("code"))
    usd = tin / 1000 * prices["input_per_1k"] + tout / 1000 * prices["output_per_1k"]
    return {"calls": len(recs), "input_tokens": tin, "output_tokens": tout, "usd_lab_prices": round(usd, 2),
            "claude_calls_not_in_request_response_logs": claude}


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
    cited = set(re.findall(r"\b(?:[0-9a-f]{48}|[0-9a-f]{32}|[0-9a-f]{12}|\d{15,20}|req-[0-9a-f]{8})\b",
                           body.get("Evidence", "")))
    real = cited & ids
    if len(real) < 3:
        problems.append(f"evidence: {len(real)} record IDs that exist in the telemetry (audit insertId, request_id, "
                        f"SCC finding ID, gateway insertId or app request_id), need at least 3"
                        + (f"; not found: {sorted(cited - ids)[:3]}" if cited - ids else ""))
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
            print(f"{when}  {src:8} {rid[:32]:32}  {what}")
        print(f"\n{len(rows)} records mention {argv[1]} in the {setup} telemetry")
    elif argv[0] == "cost":
        c = cost(t, argv[1])
        print(json.dumps(c, indent=1))
        print("usd_lab_prices uses the ILLUSTRATIVE price list in exampleco.json, not Google's prices.")
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
