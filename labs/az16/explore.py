#!/usr/bin/env python3
"""
explore.py: look at each idea of detection and response on Azure on its own, before you run the lab (AZ16 lab,
"Understand the lab", README Step 1b).

What it does, said plainly: it builds the simulated day in memory with the lab's own simulate.py, and runs the lab's
own functions on it (a rule from detect.py, inventory.py, posture.py, report.py's pivot and cost). It sends nothing,
calls no Azure service, runs no az command and writes no file (not even Python's __pycache__ or the out/ folder). The
company is fictional; the subscription ID, addresses and names are lab placeholders.

    day         1. one day at Contoso: log rows, alerts, incidents
    activity    2. the Activity log (who changed what) and a resource log (who used what)
    llm         3. the gateway's LLM log: the conversation itself
    flow        4. virtual network flow logs: which address talked to which (illustrative lines)
    dns         5. DNS query logs: which address looked up which name (illustrative lines)
    rule        6. a detection rule, read part by part, and the alert it raises
    alert       7. a Defender for AI services alert, field by field
    inventory   8. an AI inventory: one asset from each of its three signals
    policy      9. Azure Policy: a built-in definition and a check you write
    query       10. a hunting query (KQL), run on the day, and the tokens nobody logged
    playbook    11. a playbook: the leaked secret's first steps (printed, nothing runs)

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


def short_op(op: str) -> str:
    return op.split("/", 1)[1]


# ------------------------------------------------------------------------------------------------------- 1. day
def cmd_day(_args) -> None:
    t = day()
    print("One day at Contoso, 20 Oct 2026 (UTC), with the hardened logging. Fake company, fake values.")
    print()
    print("LOGS: records of what happened, one row per event (each file = one Log Analytics table)")
    files = [("activity.jsonl", t.activity, "AzureActivity: who changed or read settings (control plane)"),
             ("foundry.jsonl", t.foundry, "AzureDiagnostics: every call to the Foundry resource (resource log)"),
             ("gateway.jsonl", t.gateway, "ApiManagementGatewayLogs: every call through the AI gateway"),
             ("llm.jsonl", t.llm, "ApiManagementGatewayLlmLog: prompts, answers, tokens"),
             ("alerts.jsonl", t.alerts, "SecurityAlert: alerts that Defender for AI services raised"),
             ("traces.jsonl", t.traces, "Foundry agent spans: what the agent did"),
             ("blob.jsonl", t.blob, "StorageBlobLogs: writes into the knowledge base storage"),
             ("deploy.jsonl", t.deploy, "the agent pipeline's own change log"),
             ("metrics.jsonl", t.metrics, "AzureMetrics: tokens per hour, counted by the Foundry resource"),
             ("app.jsonl", t.app, "the web app's own log: which signed-in person")]
    for name, rows, what in files:
        print(f"  {name:<15}{len(rows):>6}  {what}")
    total = sum(len(r) for _, r, _ in files)
    print(f"  {'total':<15}{total:>6}")
    print()
    alerts = detect.run(t, "az16")
    n_def = sum(a["rule"] == "D04" for a in alerts)
    print("ALERTS: a rule matched, and a message tells a person to look")
    print(f"  {'detect.py rules':<15}{len(alerts):>6}  from rules D01 to D12 ({n_def} come from D04, which passes on every Defender alert; "
          "D11, D12: your challenge)")
    print()
    print("INCIDENTS: confirmed, someone has to act (the lab's answer key; a real team decides this in triage)")
    names = [f"{k} {v['title'][0].lower()}{v['title'][1:]}" for k, v in simulate.SCENARIOS.items()]
    print(f"  {'simulate.py':<15}{len(simulate.SCENARIOS):>6}  " + ", ".join(names[:3]) + ",")
    print(" " * 25 + ", ".join(names[3:]))
    print()
    print(f"{total} rows, {len(alerts)} alerts, {len(simulate.SCENARIOS)} incidents.")


# -------------------------------------------------------------------------------------------------- 2. activity
def cmd_activity(_args) -> None:
    t = day()
    act = next(e for e in t.activity if e["OperationNameValue"].endswith("LISTKEYS/ACTION")
               and e["CallerIpAddress"] == "203.0.113.50")
    res = next(r for r in t.foundry if r["CallerIPAddress"] == "203.0.113.50")
    print("Azure keeps two kinds of record about a resource. Both from the hardened setup:")
    print()
    print("ACTIVITY LOG (table AzureActivity): who changed or read the resource's settings. On by default, kept 90 days")
    show([("TimeGenerated", act["TimeGenerated"], "WHEN (UTC)"),
          ("OperationNameValue", cut(short_op(act["OperationNameValue"]), 33), "WHAT: read the Foundry resource's keys"),
          ("Caller", act["Caller"], "WHO: the CI pipeline's service principal"),
          ("CallerIpAddress", act["CallerIpAddress"], "FROM WHERE: an outside address"),
          ("ActivityStatusValue", act["ActivityStatusValue"], ""),
          ("_ResourceId", "...accounts/" + simulate.COMPANY["foundry"], "WHICH resource")], a=21, b=34)
    print()
    print("RESOURCE LOG (table AzureDiagnostics, category RequestResponse): every call made TO the resource.")
    print("Off until a diagnostic setting sends it to a workspace")
    show([("TimeGenerated", res["TimeGenerated"], "WHEN (UTC)"),
          ("OperationName", res["OperationName"], "WHAT: a chat call (lab placeholder name)"),
          ("CallerIPAddress", res["CallerIPAddress"], "FROM WHERE: the same outside address"),
          ("ResultSignature", res["ResultSignature"], "200 = the model answered"),
          ("WHO", "(no column)", "a key carries no identity: only the address")], a=21, b=34)
    print()
    direct = sum(r["CallerIPAddress"] != simulate.APIM_IP for r in t.foundry)
    print(f"Hardened today: {len(t.activity)} Activity log rows, {len(t.foundry)} resource log rows "
          f"({len(t.foundry) - direct} from the gateway, {direct} from elsewhere).")
    first = day("first-draft")
    print(f"First draft today: {len(first.activity)} Activity log rows, {len(first.foundry)} resource log rows.")
    print("Neither kind of record holds the prompt or the answer.")


# ------------------------------------------------------------------------------------------------------- 3. llm
def cmd_llm(_args) -> None:
    t = day()
    req = next(r for r in t.llm if r["RequestMessages"] and r["RequestMessages"][0]["content"].startswith("Where is my order"))
    resp = next(r for r in t.llm if r["CorrelationId"] == req["CorrelationId"] and r["ResponseMessages"])
    gw = next(r for r in t.gateway if r["CorrelationId"] == req["CorrelationId"])
    app = next(r for r in t.app if r.get("gateway_correlation_id") == req["CorrelationId"])
    print("The API Management AI gateway's LLM log (table ApiManagementGatewayLlmLog): one call, two rows")
    print()
    show([("TimeGenerated", req["TimeGenerated"], "WHEN (UTC)"),
          ("CorrelationId", req["CorrelationId"][:8] + "...", "joins this call's rows in every gateway table"),
          ("DeploymentName", req["DeploymentName"], "WHICH model deployment"),
          ("RequestMessages", json.dumps(cut(req["RequestMessages"][0]["content"], 32)), "row 1, WHAT WAS SAID: the customer"),
          ("ResponseMessages", json.dumps(cut(resp["ResponseMessages"][0]["content"], 32)), "row 2: the model's answer"),
          ("PromptTokens", str(req["PromptTokens"]), "tokens in (you pay per token)"),
          ("CompletionTokens", str(req["CompletionTokens"]), "tokens out"),
          ("WHO", "(no column)", "the LLM log has no caller column")], a=19, b=40)
    print()
    print("The caller is in the other tables, joined on CorrelationId:")
    show([("ApimSubscriptionId", gw["ApimSubscriptionId"], "ApiManagementGatewayLogs: WHICH app (its gateway key)"),
          ("signed_in_user", app["signed_in_user"], "your app log: WHICH PERSON, only if the app writes it")],
         a=19, b=40)
    print()
    direct = sum(r["CallerIPAddress"] != simulate.APIM_IP for r in t.foundry)
    calls = len({r["CorrelationId"] for r in t.llm})
    print(f"{len(t.llm)} rows today for {calls} calls. Not here: the {direct} calls that skipped the gateway with a key.")
    print("The gateway logs what passes through the gateway. First draft: 0 rows (Log LLM messages was off).")


# ------------------------------------------------------------------------------------------------------ 4. flow
TUPLE = ["time", "src", "dst", "srcport", "dstport", "protocol", "direction", "state", "encryption",
         "packets_sent", "bytes_sent", "packets_received", "bytes_received"]
FLOW_SAYS = [
    "someone on the internet connected to port 11434 (Ollama) on the GPU VM",
    "the same connection ended: about 48 KB went back to the internet",
    "SSH (port 22) from an unknown address: refused by the default deny rule",
    "the analytics VM sent HTTPS out: to WHICH service? Not in this line",
]


def cmd_flow(_args) -> None:
    rec = json.loads((HERE / "data" / "vnet-flow-logs.json").read_text())["records"][0]
    groups = rec["flowRecords"]["flows"][0]["flowGroups"]
    tuples = [(g["rule"], tp.split(",")) for g in groups for tp in g["flowTuples"]]
    print("data/vnet-flow-logs.json: virtual network flow logs (version 4), Microsoft's documented shape. ILLUSTRATIVE.")
    print()
    print(f"One record covers one VNet ({rec['targetResourceID'].rsplit('/', 1)[1]}) for one minute. "
          "Its first flow tuple, field by field:")
    rule, first = tuples[0]
    f = dict(zip(TUPLE, first))
    show([("rule", rule, "the NSG rule that allowed or denied it"),
          ("time", f["time"], "UNIX time in milliseconds"),
          ("src / dst", f"{f['src']} -> {f['dst']}", "FROM this address TO this address"),
          ("dstport", f["dstport"], "on this port"), ("protocol", f["protocol"], "6 = TCP"),
          ("direction", f["direction"], "I = inbound, O = outbound"),
          ("state", f["state"], "B = began, C = continuing, E = ended, D = denied"),
          ("encryption", f["encryption"], "NX = not encrypted (the default inside a VNet)"),
          ("packets, bytes", ",".join(first[9:]), "how much, never what: no contents")], a=16, b=32)
    print()
    print(f"  {'from':<16}{'to':<16}{'port':<7}{'dir':<5}{'state':<7}reading")
    for (_, tp), says in zip(tuples, FLOW_SAYS):
        r = dict(zip(TUPLE, tp))
        print(f"  {r['src']:<16}{r['dst']:<16}{r['dstport']:<7}{r['direction']:<5}{r['state']:<7}{says}")
    print()
    print("Flow logs answer: who talked to whom, on which port, allowed or not. Names and contents are not in them.")
    print("They land in a storage account. NSG flow logs, the older kind, retire on 30 Sep 2027.")


# ------------------------------------------------------------------------------------------------------- 5. dns
EXTERNAL_AI = {"api.openai.com", "api.anthropic.com", "api.mistral.ai", "huggingface.co"}


def cmd_dns(_args) -> None:
    rows = [json.loads(x) for x in (HERE / "data" / "dns-query-logs.jsonl").read_text().splitlines() if x.strip()]
    r = next(x for x in rows if x["QueryName"] == "api.openai.com.")
    print("data/dns-query-logs.jsonl: DNS query logs from a DNS resolver policy (table DNSQueryLogs). ILLUSTRATIVE.")
    print()
    print("One row, field by field:")
    show([("TimeGenerated", r["TimeGenerated"], "WHEN (UTC)"),
          ("QueryName", r["QueryName"], "the NAME the machine looked up"),
          ("QueryType", r["QueryType"], "A = give me its IPv4 address"),
          ("ResponseCode", str(r["ResponseCode"]), "the answer: 0 = NOERROR, the name resolved"),
          ("SourceIpAddress", r["SourceIpAddress"], "the machine's address"),
          ("VirtualNetworkId", "...virtualNetworks/" + r["VirtualNetworkId"].rsplit("/", 1)[1], "WHICH network: no VM name"),
          ("ResolverPolicyRuleAction", r["ResolverPolicyRuleAction"], "the policy let it through (it can also block)")],
         a=26, b=36)
    print()
    count = Counter((x["VirtualNetworkId"].rsplit("/", 1)[1], x["SourceIpAddress"], x["QueryName"].rstrip("."))
                    for x in rows)
    print(f"  {'network':<19}{'address':<13}{'looked up':<34}{'times':>5}")
    for (vnet, addr, name), n in sorted(count.items()):
        kind = "outside AI service" if name in EXTERNAL_AI else "Contoso's own gateway"
        print(f"  {vnet:<19}{addr:<13}{name:<34}{n:>5}  {kind}")
    print()
    print("The flow log said 10.20.6.8 sent HTTPS to 198.51.100.200. The DNS log says which NAME it looked up first.")
    print("Azure names the network, not the VM: map the address to its network card with Resource Graph.")


# ------------------------------------------------------------------------------------------------------ 6. rule
def cmd_rule(_args) -> None:
    t = day()
    n = detect.TUNE["content_filter_blocks_per_user_per_10_min"]
    print('detect.py, rule D06 "Repeated content-filter blocks for one end user", read part by part')
    print()
    show([("reads", "app.jsonl", "your app's own log (KQL twin: queries/d06-...kql)"),
          ("looks for", "content_filter_blocked = true", "Prompt Shields blocked a message"),
          ("groups by", "signed_in_user", "the customer, as the app wrote it"),
          ("raises an alert", f"{n} or more in 10 minutes", "the threshold, from contoso.json"),
          ("names", "the end user", "the thing you would act on")], a=17, b=36)
    print()
    per = defaultdict(list)
    for r in t.app:
        if r.get("content_filter_blocked"):
            per[r.get("signed_in_user") or "unknown"].append(r["time"][11:16])
    hits = {a["entity"]: a for a in detect.d06_content_filter_per_user(t)}
    print(f"Run on today's {len(t.app)} app log rows:")
    for user, times in sorted(per.items(), key=lambda kv: -len(kv[1])):
        span = f"{times[0]} to {times[-1]}" if len(times) > 1 else f"at {times[0]}"
        if user in hits:
            a = hits[user]
            out = f"ALERT [{a['severity']}] {a['rule']} {a['title']}"
        else:
            out = f"no alert (fewer than {n})"
        print(f"  {user:<11}{len(times)} blocked, {span:<16}{out}")
    others = len({r.get('signed_in_user') for r in t.app if r.get('path') == '/api/chat'}) - len(per)
    print(f"  {others} other customers: 0 blocked, no alert")
    print()
    print("A rule asks one question of every row. A yes is an alert, with a name on it. Triage decides if it's an incident.")


# ----------------------------------------------------------------------------------------------------- 7. alert
def cmd_alert(_args) -> None:
    t = day()
    a = next(x for x in t.alerts if x["AlertType"].startswith("AI.Azure_Jailbreak"))
    e = detect.ext(a)
    print("A Defender for AI services alert (table SecurityAlert, cut to the fields the lab reads), from alerts.jsonl")
    print()
    show([("AlertType", cut(a["AlertType"], 37), "WHAT Defender thinks happened"),
          ("AlertName", cut(a["AlertName"], 37), "the name the SOC sees"),
          ("AlertSeverity", a["AlertSeverity"], "Low, Medium or High"),
          ("Tactics", a["Tactics"], "the attacker's goal, in MITRE ATT&CK words"),
          ("CompromisedEntity", a["CompromisedEntity"], "the Foundry resource"),
          ("End user ID", e["End user ID"], "WHO: only because the app sent user context"),
          ("End user source IP", e["End user source IP"], "the customer's address, from the same context"),
          ("Alert count", str(e["Alert count"]), "how many blocked attempts"),
          ("StartTime / EndTime", f"{a['StartTime'][11:19]} / {a['EndTime'][11:19]}", "WHEN (UTC)")], a=21, b=39)
    print()
    print(f"Today's {len(t.alerts)} Defender for AI services alerts:")
    for x in sorted(t.alerts, key=lambda r: r["StartTime"]):
        who = detect.ext(x).get("End user ID") or x["CompromisedEntity"]
        print(f"  {x['StartTime'][11:16]}  {x['AlertSeverity']:<7}{cut(x['AlertName'], 62):<63}{who}")
    high = sum(x["AlertSeverity"] == "High" for x in t.alerts)
    print()
    print(f"Default email notifications go out for High only: {high} of {len(t.alerts)} would reach a person that way.")


# ------------------------------------------------------------------------------------------------- 8. inventory
def cmd_inventory(_args) -> None:
    inv = inventory.build()
    arg, bom, nsg = inventory.load("resource-graph.json"), inventory.load("ai-bom.json"), inventory.load("nsg.json")
    rows = {r["id"]: r for r in inv["rows"]}
    rg = next(r for r in arg["data"] if r["name"] == "mktg-hackathon-ai")
    w = next(x for x in bom["workloads"] if x["cloud"] == "AWS")
    rule = next(x for x in nsg["rules"] if x["destinationPortRange"] in inventory.SERVING_PORTS)

    def verdict(key):
        r = rows[key]
        return f"-> {r['type']}  {r['id']}  {'approved' if r['sanctioned'] else 'NOT on the register'}"

    print("An AI inventory, built from three signals, then checked against the approved register")
    print()
    print("Signal 1  Azure Resource Graph row  ->  an AI resource that exists in Azure")
    print(f"          type {rg['type']}   kind {rg['kind']}   name {rg['name']}")
    print(f"          tags {json.dumps(rg['tags'])}")
    print(f"          {verdict(rg['name'])}")
    print()
    print("Signal 2  Defender CSPM AI security posture (AI-SPM)  ->  AI in a connected AWS or Google Cloud account")
    print(f"          {w['cloud']}: {w['service']}, {w['resource']}")
    print(f"          {verdict(w['resource'])}")
    print()
    print("Signal 3  a network security group rule (your own check)  ->  a model server you run on a VM")
    print(f"          {rule['vm']}: {rule['nsg']}/{rule['name']} allows {rule['sourceAddressPrefix']} to port "
          f"{rule['destinationPortRange']}")
    print(f"          {verdict(rule['vm'])}")
    print()
    un = sum(not r["sanctioned"] for r in inv["rows"])
    print(f"{len(inv['rows'])} AI assets found; {un} are not on data/inventory/sanctioned.json, the approved register.")
    print(f"Agents: {inv['agents_hidden']} agent records not shown (agent discovery needs a Microsoft Agent 365 licence).")


# ---------------------------------------------------------------------------------------------------- 9. policy
def cmd_policy(_args) -> None:
    res = posture.run("first-draft")
    diag = next(r for r in res if r["rule"].startswith("Diagnostic logs") and r["resource"] == "contoso-foundry")
    c01 = next(r for r in res if r["rule"] == "C01")
    print("Azure Policy checks one setting on each resource. Result: Compliant or NON_COMPLIANT. First-draft setup:")
    print()
    print(f"Built-in definition (Microsoft wrote it): {diag['rule']} [{diag['version']}]")
    print(f"  {'contoso-foundry':<20}{'Compliant' if diag['compliant'] else 'NON_COMPLIANT':<15}"
          "a diagnostic setting with logs exists (it doesn't look at WHICH logs)")
    print()
    print(f"Custom check (you write it): C01 {posture.custom_checks()[0][1]}")
    for why in c01["why"].split("; "):
        name, rest = why.split(" ", 1)
        print(f"  {name:<20}{'NON_COMPLIANT':<15}{rest}")
    print()
    n_b = len({r["rule"] for r in res if r["kind"] == "builtin"})
    n_c = len({r["rule"] for r in res if r["kind"] == "custom"})
    print(f"The Foundry resource passes the built-in and fails yours. This lab: {n_b} built-in definitions, {n_c} custom checks.")


# ----------------------------------------------------------------------------------------------------- 10. query
def cmd_query(_args) -> None:
    t = day()
    q = (HERE / "queries" / "d05-token-spike-per-subscription.kql").read_text().rstrip().splitlines()
    print("queries/d05-token-spike-per-subscription.kql: KQL for a Log Analytics workspace (first lines)")
    print()
    for ln in q[4:10]:
        print("  " + cut(ln, W - 2))
    print("  ...")
    print()
    sub_of = {r["CorrelationId"]: r["ApimSubscriptionId"] for r in t.gateway}
    tot = defaultdict(lambda: [0, set()])
    for r in t.llm:
        k = (sub_of.get(r["CorrelationId"], "unknown"), r["TimeGenerated"][11:13] + ":00")
        if r["CorrelationId"] not in tot[k][1]:
            tot[k][0] += r["TotalTokens"]
            tot[k][1].add(r["CorrelationId"])
    print(f"The same question, asked of today's LLM log (top 5 of {len(tot)} rows):")
    print(f"  {'ApimSubscriptionId':<20}{'hour':<7}{'HourTokens':>11}{'calls':>7}")
    for (s, h), (n, ids) in sorted(tot.items(), key=lambda kv: -kv[1][0])[:5]:
        print(f"  {s:<20}{h:<7}{n:>11,}{len(ids):>7}")
    print()
    c = report.cost(t)
    metric = sum(m["Total"] for m in t.metrics)
    print(f"The Foundry resource's own TotalTokens metric counted {metric:,} tokens today; the LLM log holds "
          f"{metric - c['tokens_not_in_llm_log']:,}.")
    print(f"The gap, {c['tokens_not_in_llm_log']:,} tokens, is calls that skipped the gateway. Nobody's log says who sent them.")
    print()
    print("Hunting: you ask a question across the logs because you suspect something, not because an alert fired.")


# -------------------------------------------------------------------------------------------------- 11. playbook
def cmd_playbook(_args) -> None:
    t = day()
    d01 = detect.d01_workload_identity_new_ip(t)[0]
    ips = sorted({e["CallerIpAddress"] for e in t.activity if e["Caller"] == d01["entity"]
                  and e["CallerIpAddress"] not in detect.known_ips()})
    n_sp, n_ip = len(report.pivot(t, d01["entity"])), len(report.pivot(t, ips[0]))
    c = simulate.COMPANY
    print("A playbook: the steps for one kind of incident, written before the day. Leaked CI secret, then a Foundry key.")
    print("Printed only: nothing runs, nothing is sent.")
    print()
    print(f"  TRIGGER   {d01['rule']} alert at {d01['time'][11:16]}: {d01['entity']} used from an unknown address "
          f"({', '.join(ips)})")
    print(f"  1 KEEP    copy the evidence before anything changes: {n_sp} records mention {d01['entity']}, "
          f"{n_ip} mention {ips[0]} (report.py pivot)")
    print(f"  2 CONTAIN the secret: remove it from the service principal (not the whole identity)")
    print(f"            az ad sp credential delete --id <object ID of {d01['entity']}> --key-id <key id>")
    print("  3 CONTAIN the keys it listed: regenerate both (a key carries no name, so you can't tell which was used)")
    print(f"            az cognitiveservices account keys regenerate -n {c['foundry']} -g {c['resource_group']} --key-name Key1")
    print(f"            az cognitiveservices account keys regenerate -n {c['foundry']} -g {c['resource_group']} --key-name Key2")
    print("  4 ASK     what did the key do? The resource log has the calls, the metric has the tokens (query)")
    print("  5 RECOVER move every caller to Microsoft Entra ID and set disableLocalAuth to true; find how the secret leaked")
    print("  6 WRITE   the incident report: report/TEMPLATE.md")
    print()
    print("Containment stops the damage growing. The report says what happened, and what changes so it can't again.")


COMMANDS = {
    "day": cmd_day, "activity": cmd_activity, "llm": cmd_llm, "flow": cmd_flow, "dns": cmd_dns, "rule": cmd_rule,
    "alert": cmd_alert, "inventory": cmd_inventory, "policy": cmd_policy, "query": cmd_query, "playbook": cmd_playbook,
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
