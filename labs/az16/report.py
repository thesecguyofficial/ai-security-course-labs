"""
report.py: from alert to incident report (lessons 16.5 and 16.6).

    python3 report.py pivot sp-contoso-ci          # every record that mentions an entity, oldest first: your timeline
    python3 report.py pivot 203.0.113.50           # pivot on an address too: the direct calls carry no identity
    python3 report.py cost                         # tokens per hour: the Foundry metric vs the gateway's LLM log
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
from collections import defaultdict

import detect

HERE = pathlib.Path(__file__).resolve().parent
SECTIONS = ["Summary", "Severity and status", "Timeline (UTC)", "Scope", "Root cause", "Containment",
            "Eradication and recovery", "Evidence", "Detection gaps and new rules", "Lessons learned"]
ID_RX = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\b[0-9a-f]{16}\b|req-[0-9a-f]{8}"

# What each scenario's report must state, beyond the shared structure. (regex, what's missing if it doesn't match)
FACTS = {
    "S1": [(r"sp-contoso-ci", "the service principal whose secret leaked"),
           (r"203\.0\.113\.50", "the first attacker address"), (r"203\.0\.113\.51", "the second attacker address"),
           (r"(?i)listKeys", "that the attacker listed the Foundry keys"),
           (r"(?i)keys regenerate|regenerateKey|Regenerate Key", "the containment: regenerate both keys"),
           (r"disableLocalAuth", "the follow-up: switch key access off"),
           (r"(?i)credential reset|reset the (client )?secret|new client secret|remove the secret|credential delete",
            "the containment for the service principal's secret"),
           (r"(?i)diagnosticSettings/delete|diagnostic setting", "the attempt to delete the diagnostic setting"),
           (r"(?i)gateway", "that the calls skipped the API Management gateway"),
           (r"\$\s?\d", "an estimated cost in US dollars"),
           (r"(?i)build log|CI log|pipeline log|run 7731", "how the secret leaked")],
    "S2": [(r"cust-8841", "the end user"), (r"(?i)canary|CANARY-AZ16-SYSPROMPT", "the leaked system prompt canary"),
           (r"(?i)prompt shields", "what Prompt Shields did")],
    "S3": [(r"conv-7f3a5120", "the conversation"), (r"require_approval", "the approval setting"),
           (r"sp-agent-deploy", "who changed the toolbox"), (r"agent-run-312", "the pipeline run that changed it"),
           (r"(?i)ticket 5120|T-5120", "where the instruction came from"),
           (r"archive@ticket-export\.example\.net", "where the mail went")],
    "S4": [(r"cust-2290", "the end user"), (r"(?i)per-user|per user|end user", "an end-user limit")],
    "S5": [(r"carol@contoso\.com", "the account that wrote into the knowledge base"),
           (r"it/vpn-support-update\.md", "the poisoned blob"),
           (r'(?i)@search\.action|"delete"|delete the document', "removing the document from the index itself")],
}


def all_ids(t: detect.Telemetry) -> set[str]:
    ids = set()
    for rows in (t.activity, t.foundry, t.gateway, t.blob):
        ids |= {r["CorrelationId"] for r in rows}
    ids |= {r["RequestId"] for r in t.llm} | {a["SystemAlertId"] for a in t.alerts}
    ids |= {s["span_id"] for s in t.traces} | {d["id"] for d in t.deploy}
    ids |= {a["request_id"] for a in t.app if "request_id" in a}
    return ids


def pivot(t: detect.Telemetry, entity: str) -> list[tuple[str, str, str, str]]:
    """(time, source, record ID, one-line summary) for every record that mentions the entity."""
    rows = []
    hit = lambda r: entity in json.dumps(r)  # noqa: E731
    for e in t.activity:
        if hit(e):
            rows.append((e["TimeGenerated"], "activity", e["CorrelationId"],
                         f"{e['OperationNameValue'].split('/', 1)[1]} {e['ActivityStatusValue']} by {e['Caller']} "
                         f"from {e['CallerIpAddress']}"))
    for r in t.foundry:
        if hit(r):
            rows.append((r["TimeGenerated"], "foundry", r["CorrelationId"],
                         f"{r['Category']} {r['OperationName']} {r['ResultSignature']} from {r['CallerIPAddress']}"))
    for r in t.gateway:
        if hit(r):
            rows.append((r["TimeGenerated"], "gateway", r["CorrelationId"],
                         f"{r['ApimSubscriptionId']} {r['ResponseCode']} {r['LastErrorReason']}".rstrip()))
    for r in t.llm:
        if hit(r):
            kind = "response" if r["ResponseMessages"] else "request"
            rows.append((r["TimeGenerated"], "llm", r["RequestId"], f"{kind} tokens={r['TotalTokens']}"))
    for a in t.alerts:
        if hit(a):
            rows.append((a["TimeGenerated"], "alert", a["SystemAlertId"], f"{a['AlertName']} ({a['AlertSeverity']})"))
    for s in t.traces:
        if hit(s):
            what = f"{s['lab.tool']} {s['gen_ai.tool.call.arguments']} approval={s['lab.approval']}" \
                if s["span"] == "execute_tool" else "invoke_agent"
            rows.append((s["time"], "trace", s["span_id"], what))
    for b in t.blob:
        if hit(b):
            rows.append((b["TimeGenerated"], "blob", b["CorrelationId"], f"{b['OperationName']} {b['ObjectKey']} by {b['RequesterUpn']}"))
    for d in t.deploy:
        if hit(d):
            rows.append((d["time"], "deploy", d["id"], f"{d['pipeline_run']} {d['change']} v{d['default_version']} "
                                                      f"require_approval={d['require_approval']} by {d['actor']}"))
    for a in t.app:
        if hit(a):
            rows.append((a["time"], "app", a.get("request_id", "-"), f"{a['path']} user={a.get('signed_in_user')}"))
    return sorted(rows)


def cost(t: detect.Telemetry) -> dict:
    """Per hour: TotalTokens from the Foundry metric (every call) vs tokens in the gateway's LLM log (gateway calls).
    The gap is traffic that skipped the gateway: nobody's log says who sent it."""
    prices = detect.COMPANY["lab_price_list"]
    llm = defaultdict(int)
    for r in t.llm:
        if r["ResponseMessages"] is None and r["CompletionTokens"]:
            continue
        llm[r["TimeGenerated"][:13]] += r["TotalTokens"]
    hours, gap = [], 0
    for m in t.metrics:
        h = m["TimeGenerated"][:13]
        g = m["Total"] - llm.get(h, 0)
        gap += g
        hours.append({"hour": h[11:] + ":00", "metric_total_tokens": m["Total"], "llm_log_tokens": llm.get(h, 0),
                      "not_in_llm_log": g})
    low, high = gap / 1000 * prices["input_per_1k"], gap / 1000 * prices["output_per_1k"]
    return {"hours": [h for h in hours if h["not_in_llm_log"]], "tokens_not_in_llm_log": gap,
            "usd_lab_prices_range": [round(low, 2), round(high, 2)]}


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
    cited = set(re.findall(ID_RX, body.get("Evidence", "")))
    real = cited & ids
    if len(real) < 3:
        problems.append(f"evidence: {len(real)} record IDs that exist in the telemetry (CorrelationId, RequestId, "
                        f"SystemAlertId, span_id, deploy id or request_id), need at least 3"
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
            print(f"{when}  {src:8} {rid[:36]:36}  {what[:110]}")
        print(f"\n{len(rows)} records mention {argv[1]} in the {setup} telemetry")
    elif argv[0] == "cost":
        c = cost(t)
        for h in c["hours"]:
            print(f"  {h['hour']}  metric {h['metric_total_tokens']:>9,}  LLM log {h['llm_log_tokens']:>9,}  "
                  f"not in the LLM log {h['not_in_llm_log']:>9,}")
        lo, hi = c["usd_lab_prices_range"]
        print(f"\n{c['tokens_not_in_llm_log']:,} tokens reached the model without passing the gateway: "
              f"${lo} to ${hi} at the lab's ILLUSTRATIVE prices (contoso.json), not Microsoft's.")
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
