#!/usr/bin/env python3
"""
explore.py: look at each idea of detection and response on its own, before you run the lab (M16 lab, "Understand the
lab", README Step 1b).

What it does, said plainly: it builds the simulated day in memory with the lab's own simulate.py, and runs the lab's
own functions on it (a rule from detect.py, inventory.py, posture.py, report.py's pivot). It sends nothing, calls no
AWS service, runs no AWS command and writes no file (not even Python's __pycache__ or the out/ folder). The company is
fictional; every account number, address and key ID is a documentation example.

    day         1. one day at AnyCompany: log lines, alerts, incidents
    trail       2. CloudTrail: a management event and a data event
    invocation  3. a model invocation log record: the conversation itself
    flow        4. VPC flow logs: which address talked to which (illustrative lines)
    dns         5. DNS query logs: which machine looked up which name
    rule        6. a detection rule, read part by part, and the alert it raises
    finding     7. a GuardDuty AI Protection finding, field by field
    inventory   8. an AI inventory: one asset from each of its three signals
    config      9. AWS Config rules: a managed rule and one you write
    query       10. a hunting query (CloudWatch Logs Insights), run on the day
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


# ------------------------------------------------------------------------------------------------------- 1. day
def cmd_day(_args) -> None:
    t = day()
    print("One day at AnyCompany, 20 Oct 2026 (UTC), with the hardened logging. Fake company, fake values.")
    print()
    print("LOGS: records of what happened, one line per event")
    files = [("cloudtrail.jsonl", t.cloudtrail, "every AWS API call: who called what"),
             ("invocations.jsonl", t.invocations, "every model call through bedrock-runtime: prompt and answer"),
             ("guardduty.jsonl", t.guardduty, "findings: alerts that GuardDuty, an AWS service, raised"),
             ("spans.jsonl", t.spans, "the agent gateway's decision on each tool call"),
             ("app.jsonl", t.app, "the web app's own log: which signed-in person")]
    for name, rows, what in files:
        print(f"  {name:<20}{len(rows):>6}  {what}")
    total = sum(len(r) for _, r, _ in files)
    print(f"  {'total':<20}{total:>6}")
    print()
    alerts = detect.run(t, "m16")
    print("ALERTS: a rule matched, and a message tells a person to look")
    print(f"  {'detect.py rules':<20}{len(alerts):>6}  alerts from rules D01 to D13 (D11 and D12 are empty: your challenge)")
    print()
    print("INCIDENTS: confirmed, someone has to act (the lab's answer key; a real team decides this in triage)")
    names = [f"{k} {v['title'][0].lower()}{v['title'].split(' (')[0][1:]}" for k, v in simulate.SCENARIOS.items()]
    print(f"  {'simulate.py':<20}{len(simulate.SCENARIOS):>6}  " + ", ".join(names[:3]) + ",")
    print(" " * 30 + ", ".join(names[3:]))
    print()
    print(f"{total} lines, {len(alerts)} alerts, {len(simulate.SCENARIOS)} incidents.")


# ----------------------------------------------------------------------------------------------------- 2. trail
def who(ev: dict) -> str:
    return detect.short(detect.principal_arn(ev))


def cmd_trail(_args) -> None:
    t = day()
    mgmt = next(e for e in t.cloudtrail if e["eventName"] == "Converse" and who(e) == "HelpdeskAppRole")
    data = next(e for e in t.cloudtrail if e["eventSource"] == "bedrock-mantle.amazonaws.com")
    print("CloudTrail writes one record per AWS API call. Two kinds of record, from the hardened setup:")
    print()
    print("MANAGEMENT EVENT: logged by default")
    show([("eventTime", mgmt["eventTime"], "WHEN (UTC)"),
          ("eventSource", mgmt["eventSource"], "WHICH service: Bedrock"),
          ("eventName", mgmt["eventName"], "WHAT: run a model"),
          ("userIdentity", who(mgmt), "WHO: the support bot's role (every customer's chat)"),
          ("sourceIPAddress", mgmt["sourceIPAddress"], "FROM WHERE: inside the company network"),
          ("eventCategory", mgmt["eventCategory"], "")])
    print()
    print("DATA EVENT: off until you add it to a trail (extra cost)")
    show([("eventTime", data["eventTime"], "WHEN (UTC)"),
          ("eventSource", data["eventSource"], "WHICH service: bedrock-mantle, Bedrock's second endpoint"),
          ("eventName", data["eventName"], "WHAT: run a model"),
          ("userIdentity", who(data), "WHO: the IAM user that holds a Bedrock API key"),
          ("sourceIPAddress", data["sourceIPAddress"], "FROM WHERE: an outside address"),
          ("eventCategory", data["eventCategory"], "")])
    print()
    n_m = sum(e["eventCategory"] == "Management" for e in t.cloudtrail)
    by = Counter(e["eventSource"].split(".")[0] for e in t.cloudtrail if e["eventCategory"] == "Data")
    n_d = sum(by.values())
    print(f"Hardened today: {n_m} management events, {n_d} data events ("
          + ", ".join(f"{v} {k}" for k, v in by.most_common()) + ").")
    first = day("first-draft")
    print(f"First draft today: {sum(e['eventCategory'] == 'Management' for e in first.cloudtrail)} management events, "
          f"{sum(e['eventCategory'] == 'Data' for e in first.cloudtrail)} data events.")
    print("Neither kind of record holds the prompt or the answer.")


# ------------------------------------------------------------------------------------------------ 3. invocation
def cmd_invocation(_args) -> None:
    t = day()
    r = next(x for x in t.invocations if (x.get("requestMetadata") or {}).get("end_user")
             and x["input"]["inputBodyJson"]["messages"][0]["content"][0]["text"].startswith("Where is my order"))
    msg = r["input"]["inputBodyJson"]["messages"][0]["content"][0]["text"]
    print("A Bedrock model invocation log record (schemaType ModelInvocationLog), from invocations.jsonl")
    print()
    show([("timestamp", r["timestamp"], "WHEN (UTC)"),
          ("operation", r["operation"], "which API the app called"),
          ("modelId", cut(r["modelId"], 33), "WHICH model"),
          ("identity.arn", detect.short(r["identity"]["arn"]), "WHO, as AWS sees it: the app's role"),
          ("input text", json.dumps(cut(msg, 38)), "WHAT WAS SAID: the customer's message"),
          ("inputTokenCount", str(r["input"]["inputTokenCount"]), "tokens in (you pay per token)"),
          ("output text", json.dumps(cut(detect.output_text(r), 31)), "the model's answer"),
          ("outputTokenCount", str(r["output"]["outputTokenCount"]), "tokens out"),
          ("stopReason", r["output"]["outputBodyJson"]["stopReason"], "why it stopped: end_turn = a normal answer"),
          ("requestMetadata", json.dumps(r["requestMetadata"]["end_user"]), "WHICH PERSON: the app wrote this in"),
          ], a=19, b=40)
    print()
    mantle = sum(e["eventSource"].startswith("bedrock-mantle") for e in t.cloudtrail)
    print(f"{len(t.invocations)} records today. requestMetadata is the only field the caller writes; Bedrock fills the rest.")
    print(f"Not here: the {mantle} bedrock-mantle calls. Invocation logging covers the bedrock-runtime endpoint only.")
    print("First draft: 0 records. Invocation logging is off until you turn it on.")


# ------------------------------------------------------------------------------------------------------ 4. flow
FLOW_FIELDS = ["version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
               "packets", "bytes", "start", "end", "action", "log-status"]
FLOW_SAYS = [
    "someone on the internet reached port 11434 (Ollama) on the GPU box",
    "SSH (port 22) from an unknown address: a security group or network ACL refused it",
    "the analytics box sent HTTPS out: to WHICH service? Not in this line",
    "10.20.9.44 sent HTTPS out: the network interface ID leads to its owner",
]


def cmd_flow(_args) -> None:
    lines = [ln.split() for ln in (HERE / "data" / "vpc-flow-logs.txt").read_text().splitlines() if ln.strip()]
    print("data/vpc-flow-logs.txt: VPC flow log records, AWS's default format (version 2). ILLUSTRATIVE lab lines.")
    print()
    print("Line 1, field by field:")
    first = dict(zip(FLOW_FIELDS, lines[0]))
    show([(k, first[k], why) for k, why in [
        ("interface-id", "the network interface (the machine's network card in the VPC)"),
        ("srcaddr", "FROM this address"), ("dstaddr", "TO this address"), ("dstport", "on this port"),
        ("protocol", "6 = TCP"), ("packets", ""), ("bytes", "how much, never what: no contents"),
        ("action", "ACCEPT = let through, REJECT = refused")]], a=15, b=22)
    print()
    print(f"  {'from':<16}{'to':<16}{'port':<7}{'action':<8}reading")
    for f, says in zip(lines, FLOW_SAYS):
        r = dict(zip(FLOW_FIELDS, f))
        print(f"  {r['srcaddr']:<16}{r['dstaddr']:<16}{r['dstport']:<7}{r['action']:<8}{says}")
    print()
    print("Flow logs answer: who talked to whom, on which port, allowed or not. Names and contents are not in them.")


# ------------------------------------------------------------------------------------------------------- 5. dns
AI_DOMAINS = set(inventory.EXTERNAL_AI) | {"bedrock-runtime.us-east-1.amazonaws.com"}


def cmd_dns(_args) -> None:
    rows = [json.loads(x) for x in (HERE / "data" / "inventory" / "dns.jsonl").read_text().splitlines() if x.strip()]
    r = rows[0]
    print("data/inventory/dns.jsonl: Route 53 Resolver query logs, the DNS lookups made inside the VPC (lab values)")
    print()
    print("One record, field by field:")
    show([("query_timestamp", r["query_timestamp"], "WHEN (UTC)"),
          ("query_name", r["query_name"], "the NAME the machine looked up"),
          ("query_type", r["query_type"], "A = give me its IPv4 address"),
          ("rcode", r["rcode"], "the answer: NOERROR = the name exists"),
          ("srcaddr", r["srcaddr"], "the machine's address"),
          ("srcids.instance", r["srcids"]["instance"], "WHICH EC2 instance asked")], a=18, b=42)
    print()
    count = Counter((x.get("srcids", {}).get("instance") or "(not an instance)", x["srcaddr"], x["query_name"].rstrip("."))
                    for x in rows)
    print(f"  {'instance':<22}{'address':<13}{'looked up':<42}{'times':>5}")
    for (inst, addr, name), n in sorted(count.items()):
        kind = "outside AI service" if name in inventory.EXTERNAL_AI else "Bedrock (AWS)"
        print(f"  {inst:<22}{addr:<13}{name:<42}{n:>5}  {kind}")
    print()
    print("The flow log said 10.20.3.21 sent HTTPS to 198.51.100.200. The DNS log says which NAME it looked up first.")


# ------------------------------------------------------------------------------------------------------ 6. rule
def cmd_rule(_args) -> None:
    t = day()
    n = detect.TUNE["prompt_attacks_per_user_per_10_min"]
    print('detect.py, rule D07 "Repeated prompt attacks from one end user", read part by part')
    print()
    show([("reads", "invocations.jsonl", "the model invocation logs"),
          ("looks for", "stopReason = guardrail_intervened", "the guardrail blocked a message"),
          ("groups by", "requestMetadata.end_user", "the customer, as the app wrote it"),
          ("raises an alert", f"{n} or more in 10 minutes", "the threshold, from anycompany.json"),
          ("names", "the end user", "the thing you would act on")], a=17, b=36)
    print()
    per = defaultdict(list)
    for r in t.invocations:
        if r["output"]["outputBodyJson"].get("stopReason") == "guardrail_intervened":
            per[(r.get("requestMetadata") or {}).get("end_user", "unknown")].append(r["timestamp"][11:16])
    hits = {a["entity"]: a for a in detect.d07_prompt_attacks_per_user(t)}
    print("Run on today's 855 invocation log records:")
    for user, times in sorted(per.items(), key=lambda kv: -len(kv[1])):
        span = f"{times[0]} to {times[-1]}" if len(times) > 1 else f"at {times[0]}"
        if user in hits:
            a = hits[user]
            out = f"ALERT [{a['severity']}] {a['rule']} {a['title']}"
        else:
            out = f"no alert (fewer than {n})"
        print(f"  {user:<11}{len(times)} blocked, {span:<16}{out}")
    print()
    print("A rule asks one question of every record. A yes is an alert, with a name on it. Triage decides if it's an incident.")


# --------------------------------------------------------------------------------------------------- 7. finding
def cmd_finding(_args) -> None:
    t = day()
    f = next(x for x in t.guardduty if x["type"].endswith("PromptInjection.Direct"))
    res, svc = f["resource"], f["service"]
    flt = res["bedrockGuardrailDetails"]["contentPolicyFilters"][0]
    print("A GuardDuty AI Protection finding (GetFindings shape, cut to the fields the lab reads), from guardduty.jsonl")
    print()
    show([("type", f["type"], "WHAT GuardDuty thinks happened"),
          ("severity", f"{f['severity']}", "Low: 1.0 to 3.9 (Medium starts at 4.0)"),
          ("featureName", svc["featureName"], "which plan raised it (value illustrative)"),
          ("resourceType", res["resourceType"], "the finding is about a set of AWS credentials"),
          ("userName", res["accessKeyDetails"]["userName"], "WHO: the IAM identity, not the customer"),
          ("modelId", cut(res["modelDetails"][0]["modelId"], 37), "WHICH model"),
          ("guardrailAction", res["bedrockGuardrailDetails"]["guardrailAction"], "the guardrail stepped in"),
          ("filter", f"{flt['type']}, confidence {flt['confidence']}", "a prompt attack, high confidence"),
          ("count", str(svc["count"]), "how many times"),
          ("first / last seen", f"{svc['eventFirstSeen'][11:19]} / {svc['eventLastSeen'][11:19]}", "WHEN (UTC)")],
         a=19, b=39)
    print()
    print(f"Today's {len(t.guardduty)} AI Protection findings:")
    for x in t.guardduty:
        print(f"  {x['updatedAt'][11:16]}  {x['type']:<40} severity {x['severity']}  "
              f"{x['resource']['accessKeyDetails']['userName']:<20} count {x['service']['count']}")
    print()
    print("No trail needed: GuardDuty reads Bedrock, AgentCore and SageMaker AI activity through its own channel.")


# ------------------------------------------------------------------------------------------------- 8. inventory
def cmd_inventory(_args) -> None:
    inv = inventory.build()
    cis, sbom, dns, _reg = inventory.load()
    ci = next(c for c in cis if c["resourceId"].startswith("marketing_poc"))
    comp = next(c for c in sbom["i-0a1b2c3d4e5f60002"] if c["name"] == "ollama")
    n_dns = sum(q["query_name"] == "api.openai.com." for q in dns)
    row = {r["id"] + r["host"]: r for r in inv["rows"]}
    print("An AI inventory, built the way Security Hub's is: three signals, then a check against the approved register")
    print()
    print("Signal 1  AWS Config configuration item  ->  a managed AI resource")
    print(f"          resourceType {ci['resourceType']}   resourceId {ci['resourceId']}")
    print(f"          tags {json.dumps(ci['tags'])}")
    r = row[ci["resourceId"]]
    print(f"          -> {r['type']}  {r['id']}  {'approved' if r['sanctioned'] else 'NOT on the register'}")
    print()
    print("Signal 2  Amazon Inspector software list (SBOM) of an EC2 instance  ->  self-hosted AI")
    print(f"          i-0a1b2c3d4e5f60002: {comp['name']} {comp['version']} at {comp['path']}")
    r = row["inference-endpoint/ollamai-0a1b2c3d4e5f60002"]
    print(f"          -> {r['type']}  {r['id']}  {'approved' if r['sanctioned'] else 'NOT on the register'}")
    print()
    print("Signal 3  DNS lookups from an EC2 instance (GuardDuty)  ->  an outside AI service")
    print(f"          i-0a1b2c3d4e5f60001 looked up api.openai.com {n_dns} times")
    r = row["api.openai.comi-0a1b2c3d4e5f60001"]
    print(f"          -> {r['type']}  {r['id']}  {'approved' if r['sanctioned'] else 'NOT on the register'}")
    print()
    un = sum(not r["sanctioned"] for r in inv["rows"])
    print(f"{len(inv['rows'])} AI assets found; {un} are not on data/inventory/sanctioned.json, the approved register.")
    print("Found is not judged: the inventory lists the Ollama server, not that its port is open to the internet.")


# ---------------------------------------------------------------------------------------------------- 9. config
def cmd_config(_args) -> None:
    res = posture.run("first-draft")
    gw = [r for r in res if r["rule"] == "bedrockagentcore-gateway-authorizer-enabled"]
    c05 = next(r for r in res if r["rule"] == "C05")
    print("An AWS Config rule checks one setting on each resource. Result: COMPLIANT or NON_COMPLIANT. First-draft setup:")
    print()
    print("Managed rule (AWS wrote it): bedrockagentcore-gateway-authorizer-enabled")
    for r in gw:
        state = "COMPLIANT" if r["compliant"] else "NON_COMPLIANT"
        why = r["why"] or "an authorizer checks who calls the gateway"
        print(f"  {r['resource']:<30}{state:<15}{why}")
    print()
    print("Custom rule (you write it): C05 every gateway with a policy engine runs it in ENFORCE")
    print(f"  {'tsg-helpdesk-gw-a1b2c3d4e5':<30}{'NON_COMPLIANT':<15}{c05['why'].split(' on ')[0]}")
    print()
    n_man = len({r["rule"] for r in res if r["kind"] == "managed"})
    n_cus = len({r["rule"] for r in res if r["kind"] == "custom"})
    print(f"The Helpdesk gateway passes the managed rule and fails yours. This lab: {n_man} managed rules, {n_cus} custom.")


# ----------------------------------------------------------------------------------------------------- 10. query
def cmd_query(_args) -> None:
    t = day()
    q = (HERE / "queries" / "d06-tokens-by-principal.txt").read_text().rstrip()
    print("queries/d06-tokens-by-principal.txt: a CloudWatch Logs Insights query for the invocation log group")
    print()
    for ln in q.splitlines():
        print("  " + ln)
    print()
    tot = defaultdict(lambda: [0, 0, 0])
    for r in t.invocations:
        k = (detect.short(r["identity"]["arn"]), r["timestamp"][11:13] + ":00")
        tot[k][0] += r["input"]["inputTokenCount"]
        tot[k][1] += r["output"]["outputTokenCount"]
        tot[k][2] += 1
    print("The same question, asked of today's invocation logs (top 6 of " + str(len(tot)) + " rows):")
    print(f"  {'principal':<24}{'hour':<7}{'totalInput':>11}{'totalOutput':>12}{'calls':>7}")
    for (p, h), (i, o, c) in sorted(tot.items(), key=lambda kv: -kv[1][0])[:6]:
        print(f"  {p:<24}{h:<7}{i:>11,}{o:>12,}{c:>7}")
    print()
    print("Hunting: you ask a question across the logs because you suspect something, not because an alert fired.")


# -------------------------------------------------------------------------------------------------- 11. playbook
def ADDR(t) -> set:  # noqa: N802  the outside addresses the key was used from
    known = set(detect.COMPANY["office_and_vpc_ips"])
    return {e["sourceIPAddress"] for e in t.cloudtrail if who(e) == "BedrockAPIKey-q4m8" and e["sourceIPAddress"] not in known}


def cmd_playbook(_args) -> None:
    t = day()
    creds = json.loads((HERE / "data" / "iam-service-specific-credentials.json").read_text())["ServiceSpecificCredentials"]
    k = next(c for c in creds if c["UserName"] == "BedrockAPIKey-q4m8")
    d01 = next(a for a in detect.d01_bearer_key_new_ip(t))
    n = len(report.pivot(t, k["UserName"]))
    print("A playbook: the steps for one kind of incident, written before the day. Leaked long-term Bedrock API key.")
    print("Printed only: nothing runs, nothing is sent.")
    print()
    print(f"  TRIGGER   {d01['rule']} alert at {d01['time'][11:16]}: {d01['entity']} used from an unknown address ({', '.join(sorted(ADDR(t)))})")
    print(f"  1 CHECK   data/iam-service-specific-credentials.json: {k['UserName']}  {k['Status']}  "
          f"created {k['CreateDate'][:10]}  expires {k['ExpirationDate'] or 'never'}")
    print(f"  2 KEEP    copy the evidence before anything changes: {n} records mention the key (report.py pivot)")
    print("  3 CONTAIN the smallest thing that stops the damage: this one key, not the account")
    print(f"            aws iam update-service-specific-credential --user-name {k['UserName']} \\")
    print(f"                --service-specific-credential-id {k['ServiceSpecificCredentialId']} --status Inactive")
    print("  4 ASK     AWS's seven questions: access, infrastructure, AI changes, data stores, invocation,")
    print("            private data, agency")
    print("  5 RECOVER move the job to a short-term key; find how the key leaked")
    print("  6 WRITE   the incident report: report/TEMPLATE.md")
    print()
    print("Containment stops the damage growing. The report says what happened, and what changes so it can't again.")


COMMANDS = {
    "day": cmd_day, "trail": cmd_trail, "invocation": cmd_invocation, "flow": cmd_flow, "dns": cmd_dns,
    "rule": cmd_rule, "finding": cmd_finding, "inventory": cmd_inventory, "config": cmd_config, "query": cmd_query,
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
