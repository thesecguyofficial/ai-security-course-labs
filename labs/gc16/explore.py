#!/usr/bin/env python3
"""
explore.py: look at each idea of detection and response on Google Cloud on its own, before you run the lab (GC16
lab, "Understand the lab", README Step 1b).

What it does, said plainly: it builds the simulated day in memory with the lab's own simulate.py, and runs the lab's
own functions on it (a rule from detect.py, inventory.py, posture.py, report.py's pivot). It sends nothing, calls no
Google Cloud service, runs no gcloud command and writes no file (not even Python's __pycache__ or the out/ folder).
The company is fictional; project IDs, key IDs and addresses are lab placeholders.

    day         1. one day at ExampleCo: log entries, alerts, incidents
    audit       2. Cloud Audit Logs: an Admin Activity entry and a Data Access entry
    requests    3. a request-response logging row: the conversation itself
    flow        4. VPC Flow Logs: which address talked to which (illustrative lines)
    dns         5. Cloud DNS query logs: which VM looked up which name
    rule        6. a detection rule, read part by part, and the alert it raises
    finding     7. a Security Command Center finding, field by field
    inventory   8. an AI inventory: one asset from each of its three signals
    policy      9. posture: a framework control, a check you write, an organization policy
    query       10. a hunting query (BigQuery SQL), run on the day
    playbook    11. a playbook: the leaked key's first steps (printed, nothing runs)

    e.g. python3 explore.py day       (Windows: py explore.py day)
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter, defaultdict

sys.dont_write_bytecode = True  # read-only: importing the lab's modules must not write __pycache__/
import detect  # noqa: E402  (the lab's rules; nothing runs on import)
import inventory  # noqa: E402
import posture  # noqa: E402
import report  # noqa: E402
import simulate  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
W = 128  # every line fits a 132-column terminal
_DAY: dict = {}


def day(setup: str = "hardened") -> detect.Telemetry:
    """The simulated day for one logging setup, built in memory (nothing is written to out/)."""
    if setup not in _DAY:
        _DAY[setup] = simulate.build(setup)
    return detect.Telemetry.from_build(_DAY[setup])


def show(rows, a: int = 19, b: int = 34) -> None:
    for k, v, why in rows:
        line = f"  {k:<{a}}{v:<{b}} {why}".rstrip()
        print(line if len(line) <= W else line[: W - 3] + "...")


def cut(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def kind(e: dict) -> str:
    return "Admin Activity" if e["logName"].endswith("%2Factivity") else "Data Access"


def last(s: str) -> str:
    return s.rsplit(".", 1)[-1]


# ------------------------------------------------------------------------------------------------------- 1. day
def cmd_day(_args) -> None:
    t = day()
    print("One day at ExampleCo, 20 Oct 2026 (UTC), with the hardened logging. Fake company, fake values.")
    print()
    print("LOGS: records of what happened, one entry per event")
    files = [("audit.jsonl", t.audit, "Cloud Audit Logs: who called which Google Cloud API"),
             ("requests.jsonl", t.requests, "request-response logging: the prompt and the answer"),
             ("armor.jsonl", t.armor, "Model Armor: its verdict on each prompt"),
             ("scc.jsonl", t.scc, "findings: alerts that Security Command Center raised"),
             ("gateway.jsonl", t.gateway, "Agent Gateway: each tool call the agent made"),
             ("app.jsonl", t.app, "the web app's own log: which signed-in person")]
    for name, rows, what in files:
        print(f"  {name:<16}{len(rows):>6}  {what}")
    total = sum(len(r) for _, r, _ in files)
    print(f"  {'total':<16}{total:>6}")
    print()
    alerts = detect.run(t, "gc16")
    print("ALERTS: a rule matched, and a message tells a person to look")
    print(f"  {'detect.py rules':<16}{len(alerts):>6}  alerts from rules D01 to D13 (D11 and D12 are empty: your challenge)")
    print()
    print("INCIDENTS: confirmed, someone has to act (the lab's answer key; a real team decides this in triage)")
    names = [f"{k} {v['title'][0].lower()}{v['title'].split(' (')[0][1:]}" for k, v in simulate.SCENARIOS.items()]
    print(f"  {'simulate.py':<16}{len(simulate.SCENARIOS):>6}  " + ", ".join(names[:3]) + ",")
    print(" " * 26 + ", ".join(names[3:]))
    print()
    print(f"{total} entries, {len(alerts)} alerts, {len(simulate.SCENARIOS)} incidents.")


# ----------------------------------------------------------------------------------------------------- 2. audit
def cmd_audit(_args) -> None:
    t = day()
    adm = next(e for e in t.audit if detect.method(e) == "SetIamPolicy")
    dat = next(e for e in t.audit if kind(e) == "Data Access" and e["protoPayload"]["requestMetadata"]["callerIp"]
               == "203.0.113.51")

    def rows(e, what, where):
        pp = e["protoPayload"]
        st = (pp.get("status") or {}).get("code")
        return [("timestamp", e["timestamp"], "WHEN (UTC)"),
                ("serviceName", pp["serviceName"], "WHICH service"),
                ("methodName", cut(last(pp["methodName"]), 36), what),
                ("principalEmail", detect.short(detect.principal(e)) + "@...", "WHO: a service account"),
                ("serviceAccountKeyName", ".../keys/" + pp["authenticationInfo"]["serviceAccountKeyName"].rsplit("/", 1)[1][:8] + "...",
                 "WITH WHAT: one of its keys (the ID you disable)"),
                ("callerIp", pp["requestMetadata"]["callerIp"], where),
                ("status", f"code {st}" if st else "(empty)", "7 = PERMISSION_DENIED; empty = it worked")]

    print("Cloud Audit Logs write one entry per API call. Two kinds of entry, from the hardened setup:")
    print()
    print("ADMIN ACTIVITY: changes to settings. Always on, you can't switch it off")
    show(rows(adm, "WHAT: change the project's IAM policy", "FROM WHERE: an outside address"), a=23, b=38)
    print("  (the request sets auditConfigs to []: it tries to switch the Data Access logs off)")
    print()
    print("DATA ACCESS: reading data and using services, model calls included. Off by default for Agent Platform")
    show(rows(dat, "WHAT: run a model", "FROM WHERE: the second outside address"), a=23, b=38)
    print()
    c = Counter(kind(e) for e in t.audit)
    print(f"Hardened today: {c['Admin Activity']} Admin Activity entries, {c['Data Access']} Data Access entries.")
    f = Counter(kind(e) for e in day("first-draft").audit)
    print(f"First draft today: {f['Admin Activity']} Admin Activity entries, {f['Data Access']} Data Access entries "
          "(BigQuery only).")
    print("Neither kind of entry holds the prompt or the answer.")


# -------------------------------------------------------------------------------------------------- 3. requests
def cmd_requests(_args) -> None:
    t = day()
    r = next(x for x in t.requests if x["full_request"]["contents"][0]["parts"][0]["text"].startswith("Where is my order"))
    resp = r["full_response"]
    u = resp["usageMetadata"]
    lab = detect.labels(r)
    print("A request-response logging row (one row of the BigQuery table), from requests.jsonl")
    print()
    show([("logging_time", r["logging_time"], "WHEN (UTC)"),
          ("model", r["model"], "WHICH model"),
          ("api_method", r["api_method"], "which call the app made"),
          ("full_request text", json.dumps(cut(r["full_request"]["contents"][0]["parts"][0]["text"], 30)),
           "WHAT WAS SAID: the customer's message"),
          ("promptTokenCount", str(u["promptTokenCount"]), "tokens in (you pay per token)"),
          ("full_response text", json.dumps(cut(detect.answer_text(r), 30)), "the model's answer"),
          ("candidatesTokenCount", str(u["candidatesTokenCount"]), "tokens out"),
          ("finishReason", resp["candidates"][0]["finishReason"], "why it stopped: STOP = a normal answer"),
          ("labels.end_user", lab["end_user"], "WHICH PERSON: the app wrote this in"),
          ("WHO", "(no column)", "the table has no column for the calling account")], a=22, b=38)
    print()
    models = Counter(x["model"] for x in t.requests)
    claude = sum(1 for e in t.audit if detect.method(e).endswith("RawPredict") and not detect.failed(e))
    print(f"{len(t.requests)} rows today: " + ", ".join(f"{n} {m}" for m, n in models.items()) + ".")
    print(f"Not here: {claude} Claude calls (RawPredict). Logging is switched on per model, and Claude's isn't.")
    print(f"Model Armor wrote {len(t.armor)} verdicts on the same prompts. First draft: 0 rows of either (both off).")


# ------------------------------------------------------------------------------------------------------ 4. flow
FLOW_SAYS = [
    "someone on the internet connected to port 11434 (Ollama) on gpu-box-1",
    "SSH (port 22) from an unknown address: the firewall dropped it",
    "build-runner-2 sent HTTPS out: to WHICH service? Not in this line",
    "HTTPS out from an address with no VM details: not a Compute Engine VM",
]


def cmd_flow(_args) -> None:
    rows = [json.loads(x) for x in (HERE / "data" / "vpc-flow-logs.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    rows = [r for r in rows if "jsonPayload" in r]
    p = rows[0]["jsonPayload"]
    c = p["connection"]
    print("data/vpc-flow-logs.jsonl: VPC Flow Logs entries, Google's documented record format (cut). ILLUSTRATIVE.")
    print()
    print("Entry 1, field by field:")
    show([("src_ip", c["src_ip"], "FROM this address"), ("dest_ip", c["dest_ip"], "TO this address"),
          ("dest_port", str(c["dest_port"]), "on this port"), ("protocol", str(c["protocol"]), "6 = TCP"),
          ("reporter", p["reporter"], "DEST = the receiving VM reported it"),
          ("dest_instance", f"{p['dest_instance']['vm_name']} ({p['dest_instance']['project_id']})",
           "WHICH VM: Google adds its name"),
          ("bytes_sent", p["bytes_sent"], "how much (estimated from samples), never what"),
          ("start / end", f"{p['start_time'][11:19]} / {p['end_time'][11:19]}", "WHEN (UTC)")], a=15, b=30)
    print()
    print(f"  {'from':<16}{'to':<16}{'port':<7}{'result':<10}reading")
    for r, says in zip(rows, FLOW_SAYS):
        q = r["jsonPayload"]
        cc = q["connection"]
        res = "DROPPED" if q.get("disposition") == "DROPPED" else "sent"
        print(f"  {cc['src_ip']:<16}{cc['dest_ip']:<16}{cc['dest_port']:<7}{res:<10}{says}")
    print()
    print("Flow logs answer: who talked to whom, on which port, how much. Names of services and contents are not in them.")
    print("They are off until you enable them (per subnet, VPC network or organization), and they sample.")


# ------------------------------------------------------------------------------------------------------- 5. dns
def cmd_dns(_args) -> None:
    rows = [json.loads(x) for x in (HERE / "data" / "inventory" / "dns.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    p = rows[0]["jsonPayload"]
    print("data/inventory/dns.jsonl: Cloud DNS query logs, the lookups made inside ExampleCo's VPC networks (lab values)")
    print()
    print("One entry, field by field:")
    show([("timestamp", rows[0]["timestamp"], "WHEN (UTC)"),
          ("queryName", p["queryName"], "the NAME the machine looked up"),
          ("queryType", p["queryType"], "A = give me its IPv4 address"),
          ("responseCode", p["responseCode"], "the answer, NOERROR (lab value: real logs hold the number, 0)"),
          ("sourceIP", p["sourceIP"], "the machine's address"),
          ("vmInstanceName", p["vmInstanceName"], "WHICH VM: only for queries a Compute Engine VM made")],
         a=17, b=40)
    print()
    count = Counter((r["jsonPayload"].get("vmInstanceName") or "(not a VM)", r["jsonPayload"]["sourceIP"],
                     r["jsonPayload"]["queryName"].rstrip(".")) for r in rows)
    print(f"  {'VM':<16}{'address':<13}{'looked up':<42}{'times':>5}")
    for (vm, addr, name), n in sorted(count.items()):
        k = "outside AI service" if name in inventory.EXTERNAL_AI else "Google Cloud"
        print(f"  {vm:<16}{addr:<13}{name:<42}{n:>5}  {k}")
    print()
    print("The flow log said build-runner-2 sent HTTPS to 198.51.100.200. The DNS log says which NAME it looked up.")


# ------------------------------------------------------------------------------------------------------ 6. rule
def cmd_rule(_args) -> None:
    t = day()
    n = detect.TUNE["blocked_prompts_per_user_per_10_min"]
    print('detect.py, rule D07 "Repeated blocked prompts from one end user", read part by part')
    print()
    show([("reads", "requests.jsonl", "the request-response logging rows"),
          ("looks for", "blockReason = MODEL_ARMOR", "Model Armor blocked the prompt"),
          ("groups by", "labels.end_user", "the customer, as the app wrote it"),
          ("raises an alert", f"{n} or more in 10 minutes", "the threshold, from exampleco.json"),
          ("names", "the end user", "the thing you would act on")], a=17, b=36)
    print()
    per = defaultdict(list)
    for r in t.requests:
        if (r["full_response"].get("promptFeedback") or {}).get("blockReason") == "MODEL_ARMOR":
            per[detect.labels(r).get("end_user", "unknown")].append(r["logging_time"][11:16])
    hits = {a["entity"]: a for a in detect.d07_blocked_prompts_per_user(t)}
    print(f"Run on today's {len(t.requests)} request-response rows:")
    for user, times in sorted(per.items(), key=lambda kv: -len(kv[1])):
        span = f"{times[0]} to {times[-1]}" if len(times) > 1 else f"at {times[0]}"
        if user in hits:
            a = hits[user]
            out = f"ALERT [{a['severity']}] {a['rule']} {a['title']}"
        else:
            out = f"no alert (fewer than {n})"
        print(f"  {user:<11}{len(times)} blocked, {span:<16}{out}")
    print()
    print("A rule asks one question of every row. A yes is an alert, with a name on it. Triage decides if it's an incident.")


# --------------------------------------------------------------------------------------------------- 7. finding
def cmd_finding(_args) -> None:
    t = day()
    f = next(x for x in t.scc if x["category"].endswith("New Geography for AI Service"))
    a = f["access"]
    print("A Security Command Center finding (cut to the fields the lab reads), from scc.jsonl")
    print()
    show([("category", f["category"], "WHAT SCC thinks happened"),
          ("findingClass", f["findingClass"], "a possible active attack (not a misconfiguration)"),
          ("severity", f["severity"], "LOW, MEDIUM, HIGH or CRITICAL"),
          ("findingProvider", f["findingProvider"], "which detector raised it"),
          ("ruleName", f["sourceProperties"]["detectionCategory"]["ruleName"], "the detector's rule"),
          ("principalEmail", detect.short(a["principalEmail"]) + "@...", "WHO: the service account, not a person"),
          ("callerIp", a["callerIp"], "FROM WHERE"),
          ("methodName", last(a["methodName"]), "WHAT it called"),
          ("evidence", f"{len(f['sourceProperties']['evidence'])} audit insertIds", "the log entries behind it"),
          ("eventTime", f["eventTime"], "WHEN (UTC)")], a=17, b=45)
    print()
    print(f"Today's {len(t.scc)} AI threat findings:")
    for x in sorted(t.scc, key=lambda r: r["eventTime"]):
        print(f"  {x['eventTime'][11:16]}  {x['category']:<45} {x['severity']:<7}{detect.short(x['access']['principalEmail'])}")
    print()
    print("Both are LOW. A notification that forwards HIGH and CRITICAL only would send neither.")


# ------------------------------------------------------------------------------------------------- 8. inventory
def cmd_inventory(_args) -> None:
    inv = inventory.build()
    rows = inv["rows"]
    m = next(r for r in rows if r["armor_gap"] and r["sanctioned"])
    d = next(r for r in rows if r["category"] == "Outside AI API")
    e = inv["exposed"][0]

    def verdict(r):
        return f"-> {r['category']}  {r['name']}  {'approved' if r['sanctioned'] else 'NOT on the register'}"

    print("An AI inventory, built from three signals, then checked against the approved register")
    print()
    print("Signal 1  Security Command Center's AI inventory (Premium)  ->  models, endpoints, agents, MCP servers")
    print(f"          {m['category']} {m['name']} in {m['project']}, owner {m['owner']}")
    print(f"          {verdict(m)}, but not protected by Model Armor")
    print()
    print("Signal 2  Cloud DNS query logs (your check)  ->  an outside AI service")
    print(f"          {d['name'].split(' from ')[1]} looked up {d['name'].split(' from ')[0]} {d['queries']} times")
    print(f"          {verdict(d)}")
    print()
    print("Signal 3  a firewall rule (your check)  ->  a model server you run on a VM")
    print(f"          {e['rule']} allows 0.0.0.0/0 to port {e['port']} on {', '.join(e['vms'])} ({e['project']})")
    print(f"          -> self-hosted model server ({e['server']})  not in the AI inventory's categories")
    print()
    un = sum(not r["sanctioned"] for r in rows)
    print(f"{len(rows)} AI assets found; {un} are not on data/inventory/sanctioned.json, the approved register.")
    print("Found is not judged: the inventory doesn't say that a port is open to the internet. That's your check.")


# ---------------------------------------------------------------------------------------------------- 9. policy
def cmd_policy(_args) -> None:
    res = posture.run("first-draft")
    fw = next(r for r in res if r["check"] == "Enable Model Armor")
    c03 = next(r for r in res if r["id"] == "C03")
    p01 = next(r for r in res if r["id"] == "P01")
    print("Posture checks look at one setting each. Result: Compliant or NON_COMPLIANT. First-draft setup:")
    print()
    print("Framework control (Google wrote it, in SCC's AI framework): Enable Model Armor")
    print(f"  {'Compliant' if fw['compliant'] else 'NON_COMPLIANT':<15}Model Armor is on")
    print()
    print(f"Custom check (you write it): C03 {c03['check']}")
    print(f"  {'NON_COMPLIANT':<15}{c03['why']}")
    print()
    print(f"Organization policy (it prevents, it doesn't just report): {p01['check']}")
    print(f"  {'NON_COMPLIANT':<15}{p01['why']}")
    print()
    n = Counter(r["kind"] for r in res)
    print(f"Model Armor is on, and nothing records what it saw. This lab: {n['framework']} framework controls, "
          f"{n['custom']} custom checks, {n['org policy']} organization policies.")


# ----------------------------------------------------------------------------------------------------- 10. query
def cmd_query(_args) -> None:
    t = day()
    q = (HERE / "queries" / "d06-tokens-by-model.sql").read_text(encoding="utf-8").rstrip().splitlines()
    print("queries/d06-tokens-by-model.sql: BigQuery SQL on the request-response table")
    print()
    for ln in q[1:]:
        print("  " + cut(ln, W - 2))
    print()
    tot = defaultdict(lambda: [0, 0])
    for r in t.requests:
        k = (r["model"], r["logging_time"][11:13] + ":00")
        tot[k][0] += detect.tokens(r)
        tot[k][1] += 1
    print(f"The same question, asked of today's rows (top 5 of {len(tot)}):")
    print(f"  {'model':<24}{'hour':<7}{'tokens':>11}{'calls':>7}")
    for (m, h), (n, c) in sorted(tot.items(), key=lambda kv: -kv[1][0])[:5]:
        print(f"  {m:<24}{h:<7}{n:>11,}{c:>7}")
    print()
    print("The table has no caller column: it names the model. labels.end_user (16.1) is how you get to a person.")
    print("Hunting: you ask a question across the logs because you suspect something, not because an alert fired.")


# -------------------------------------------------------------------------------------------------- 11. playbook
def cmd_playbook(_args) -> None:
    t = day()
    d01 = detect.d01_key_unknown_ip(t)[0]
    ev = next(e for e in t.audit if e["insertId"] == d01["evidence"][0])
    key = ev["protoPayload"]["authenticationInfo"]["serviceAccountKeyName"]
    sa = detect.principal(ev)
    n = len(report.pivot(t, d01["entity"]))
    print("A playbook: the steps for one kind of incident, written before the day. Leaked service account key.")
    print("Printed only: nothing runs, nothing is sent.")
    print()
    print(f"  TRIGGER   {d01['rule']} alert at {d01['time'][11:16]}: {d01['entity']} key used from an unknown address "
          f"({', '.join(sorted({e['protoPayload']['requestMetadata']['callerIp'] for e in t.audit if detect.principal(e) == sa and e['protoPayload']['requestMetadata']['callerIp'] not in detect.COMPANY['office_and_vpc_ips']}))})")
    print(f"  1 CHECK   the key ID is the end of serviceAccountKeyName in the audit entry: {key.rsplit('/', 1)[1]}")
    print(f"  2 KEEP    copy the evidence before anything changes: {n} records mention {d01['entity']} (report.py pivot)")
    print("  3 CONTAIN the smallest thing that stops the damage: this one key, not the service account")
    print(f"            gcloud iam service-accounts keys disable {key.rsplit('/', 1)[1]} \\")
    print(f"                --iam-account={sa}")
    print("  4 WATCH   more calls after that? Someone holds a short-lived token: disable the account (stops the ETL job too)")
    print("  5 RECOVER delete the key, find how it leaked, run the job as an attached service account with no key")
    print("  6 WRITE   the incident report: report/TEMPLATE.md")
    print()
    print("Containment stops the damage growing. The report says what happened, and what changes so it can't again.")


COMMANDS = {
    "day": cmd_day, "audit": cmd_audit, "requests": cmd_requests, "flow": cmd_flow, "dns": cmd_dns, "rule": cmd_rule,
    "finding": cmd_finding, "inventory": cmd_inventory, "policy": cmd_policy, "query": cmd_query,
    "playbook": cmd_playbook,
}


def main(argv: list[str]) -> None:
    if not argv or argv[0] not in COMMANDS:
        if argv:
            raise SystemExit(f"unknown command; choose from: {', '.join(COMMANDS)}")
        print("explore.py: one idea at a time. It reads the lab's files; it sends nothing and writes nothing.")
        print()
        print(__doc__.split("\n\n", 2)[2].rstrip())
        return
    COMMANDS[argv[0]](argv[1:])


if __name__ == "__main__":
    main(sys.argv[1:])
