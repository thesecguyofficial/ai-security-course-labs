#!/usr/bin/env python3
"""
explore.py: look at each idea of security operations on its own, before you break the first draft (M29 lab,
"Understand the lab", README Step 1b).

What it does, said plainly: it reads the lab's files (the org, one day of logs, the repos, the rules, the setups,
the triage log) and runs the lab's own pure functions on them (the rule matcher in detect.py, the register check
in hunt.py, the CVSS 3.1 formula below). It sends nothing, calls no cloud, runs no responder, starts no agent and
writes no file (not even Python's __pycache__ or the state/ folder). Every key string is a lab placeholder and every
account number and address is fake.

    event       1. one log event: a CloudTrail record, field by field
    rule        2. one detection rule, read part by part
    match       3. the rule against four logged calls: a match is an alert
    queue       4. one morning's alert queue, as the AI triage agent left it
    playbook    5. what the automated responder would do (nothing runs)
    dns         6. DNS lookups: which machine asked for which name
    inventory   7. every AI use in the logs, minus the approved-AI register
    timeline    8. a stolen key's first minutes (LLMjacking)
    decoy       9. the planted decoy key (a honeytoken)
    score       10. a CVSS score, metric by metric (default: CVE-2025-32711)
    agent       11. the AI triage agent: what it reads and what it may do
    compare     12. first draft against hardened: every setting that changed, and the cases it fixes (lab part 2)

    e.g. .venv/bin/python explore.py event       (Windows: .venv\\Scripts\\python explore.py event)
"""

from __future__ import annotations

import json
import math
import sys
import textwrap

sys.dont_write_bytecode = True  # read-only: importing the lab's modules must not write __pycache__/
import detect  # noqa: E402  (the lab's EventBridge stand-in; nothing runs on import)
import hunt  # noqa: E402
import scenarios  # noqa: E402
import triage  # noqa: E402
from lab import ASSUMPTIONS, DATA, ORG, load_setup, read_jsonl  # noqa: E402

W = 128  # every line fits a 132-column terminal


def acct(a: str) -> str:
    return ORG["accounts"].get(a, "?")


def who(rec: dict) -> str:
    return rec["userIdentity"].get("userName") or rec["userIdentity"]["arn"].split("/")[-2]


def call(rec: dict) -> str:
    return f"{rec['eventSource'].split('.')[0]}:{rec['eventName']}"


def show(rows: list[tuple[str, str, str]], a: int = 19, b: int = 30) -> None:
    for k, v, why in rows:
        line = f"  {k:<{a}}{v:<{b}} {why}".rstrip()
        print(line if len(line) <= W else line[: W - 3] + "...")


# ---------------------------------------------------------------------------------------------------- 1. event
def cmd_event(_args: list[str]) -> None:
    rec = scenarios.honeytoken_denied_invoke()[0]
    print("One CloudTrail record: someone used the decoy key to call Bedrock. Fake values, the field names AWS uses.")
    print()
    show([
        ("eventTime", rec["eventTime"], "WHEN (UTC)"),
        ("eventSource", rec["eventSource"], "WHICH service was called"),
        ("eventName", rec["eventName"], "WHAT was asked: run a model"),
        ("awsRegion", rec["awsRegion"], "WHERE: the AWS Region"),
        ("recipientAccountId", rec["recipientAccountId"], f"WHICH account: {acct(rec['recipientAccountId'])} (fake number)"),
        ("userIdentity", f"{rec['userIdentity']['type']} {who(rec)}", "WHO: the user behind the key"),
        ("  accessKeyId", rec["userIdentity"]["accessKeyId"], "WITH WHICH key: our decoy (a lab placeholder)"),
        ("sourceIPAddress", rec["sourceIPAddress"], "FROM WHERE (a documentation address, RFC 5737)"),
        ("userAgent", rec["userAgent"], "the caller's tool, as the CALLER says: they choose this text"),
        ("requestParameters", rec["requestParameters"]["modelId"], "the request's arguments: WHICH model (modelId)"),
        ("readOnly", json.dumps(rec["readOnly"]), "so this call does more than look (List and Get calls: true)"),
        ("errorCode", rec["errorCode"], "it FAILED: this user has no permissions"),
    ])


# ---------------------------------------------------------------------------------------------------- 2. rule
def honey(setup: str) -> dict:
    return next(r for r in load_setup(setup)["rules"] if r["name"] == "honeytoken-key-used")


def cmd_rule(_args: list[str]) -> None:
    r = honey("hardened")
    p = r["pattern"]
    print("setups/hardened/rules/honeytoken.json: a detection rule, read part by part")
    print()
    show([
        ("name", r["name"], "what the alert is called"),
        ("severity", r["severity"], "how urgent its alerts are"),
        ("state", "ENABLED_WITH_ALL_CLOUDTRAIL_", ""),
        ("", "MANAGEMENT_EVENTS", "also receives read-only calls (plain ENABLED doesn't)"),
        ("regions", str(r["regions"]), "deployed in every Region (in the lab, a rule sees only its Regions)"),
        ("pattern", "detail-type", f"= {p['detail-type'][0]}: an API call CloudTrail recorded"),
        ("", "detail.userIdentity.accessKeyId", f"= {p['detail']['userIdentity']['accessKeyId'][0]}: made with the decoy key"),
        ("", "(nothing else)", "any service, any call, any Region, failed or not"),
    ], a=10, b=32)
    print()
    print("An event that fits EVERY line of the pattern is a match. A match is an alert.")


# ---------------------------------------------------------------------------------------------------- 3. match
def cmd_match(_args: list[str]) -> None:
    rule = honey("hardened")
    events = (scenarios.normal_app_call() + scenarios.honeytoken_read_only()
              + scenarios.honeytoken_denied_invoke("ap-southeast-2", "10:01:40"))
    print("The hardened rule honeytoken-key-used, checked against four logged calls (detect.py, the lab's EventBridge stand-in)")
    print()
    for rec in events:
        hit, why = detect.rule_sees(rule, rec)
        err = " (denied)" if rec.get("errorCode") else ""
        verdict = "ALERT     " if hit else "no alert  "
        print(f"  {rec['eventTime'][11:19]}  {rec['awsRegion']:<15}{call(rec) + err:<38}{who(rec):<22}{verdict}{why}")
    print()
    print("The first call used the app's own key: no match, no alert. The other three used the decoy: three alerts.")


# ---------------------------------------------------------------------------------------------------- 4. queue
def cmd_queue(_args: list[str]) -> None:
    rows = read_jsonl(DATA / "triage-log.jsonl")
    print("data/triage-log.jsonl: one morning's alert queue, as the AI triage agent left it")
    print()
    print(f"  {'alert':<9}{'rule':<28}{'severity':<10}{'decision':<11}{'closed by':<11}userAgent (the caller wrote it)")
    for r in rows:
        ua = r["fields"]["userAgent"]
        ua = ua if len(ua) <= 58 else ua[:55] + "..."
        print(f"  {r['alert_id']:<9}{r['rule']:<28}{r['severity']:<10}{r['decision']:<11}{str(r['closed_by'] or '-'):<11}{ua}")
    closed = [r for r in rows if r["decision"] == "closed"]
    print()
    print(f"{len(rows)} alerts: {len(closed)} closed ({sum(r['closed_by'] == 'agent' for r in closed)} by the agent), "
          f"{len(rows) - len(closed)} escalated to a person.")


# ---------------------------------------------------------------------------------------------------- 5. playbook
SAYS = {
    "deactivate_key": ("the leaked key stops working", "contain"),
    "deny_user_sessions": ("a deny policy also stops sessions made with it", "contain"),
    "snapshot_evidence": ("copy the last hour of logs to the incident folder", "evidence"),
    "open_incident": ("a ticket for a person to investigate", "hand over"),
}


def cmd_playbook(_args: list[str]) -> None:
    hard, draft = load_setup("hardened")["responder"], load_setup("first-draft")["responder"]
    print('setups/hardened/setup.json "responder": what runs when a high alert arrives. Nothing runs here.')
    print()
    print(f"  starts    on each event, as the alert arrives  (first draft: a job every {draft['interval_s'] // 60} minutes)")
    for i, a in enumerate(hard["actions"], 1):
        what, kind = SAYS[a]
        print(f"  step {i}    {a:<20}{what:<52}{kind}")
    print("  never     the security team's own audit role   (the responder refuses to touch it)")
    print()
    print(f"Lab target: act within {ASSUMPTIONS['containment_slo_s'] // 60} minutes of the attacker's first call.")


# ---------------------------------------------------------------------------------------------------- 6. dns
def cmd_dns(_args: list[str]) -> None:
    rows = read_jsonl(DATA / "org-day" / "resolver-query-logs.jsonl")
    approved = {(r["account"], r["domain"]) for r in ORG["register"]["external"]}
    print("data/org-day/resolver-query-logs.jsonl: every DNS lookup the org's machines made today (fake values)")
    print()
    print(f"  {'time':<10}{'account':<19}{'machine (instance)':<23}{'looked up (query_name)':<42}AI provider?")
    for r in rows:
        name = r["query_name"].rstrip(".")
        if name not in ORG["ai_domains"]:
            ai = "no"
        else:
            ai = "yes, approved" if (r["account_id"], name) in approved else "yes, NOT in the register"
        print(f"  {r['query_timestamp'][11:19]:<10}{acct(r['account_id']):<19}{r['srcids']['instance']:<23}{name:<42}{ai}")
    print()
    print("DNS turns a name into an address. The log keeps the NAME, so it says who called which AI service.")


# ---------------------------------------------------------------------------------------------------- 7. inventory
def cmd_inventory(_args: list[str]) -> None:
    setup = load_setup("hardened")
    names = set(setup["hunt"]["event_names"])
    seen, rows = set(), []
    for rec in read_jsonl(DATA / "org-day" / "cloudtrail.jsonl"):
        if rec["eventSource"].startswith("bedrock") and rec["eventName"] in names and not rec["readOnly"]:
            key = (rec["recipientAccountId"], rec["awsRegion"], call(rec), hunt.model_of(rec))
            if key not in seen:
                seen.add(key)
                ok = hunt.registered_model(key[0], key[3])
                rows.append((acct(key[0]), key[1], key[2], key[3], "approved" if ok else "NOT in the register"))
    approved = {(r["account"], r["domain"]) for r in ORG["register"]["external"]}
    for r in read_jsonl(DATA / "org-day" / "resolver-query-logs.jsonl"):
        name = r["query_name"].rstrip(".")
        if name in ORG["ai_domains"]:
            ok = (r["account_id"], name) in approved
            rows.append((acct(r["account_id"]), r["region"], "dns lookup", name, "approved" if ok else "NOT in the register"))
    print("Inventory from the logs (every account, Region and inference event, plus DNS), checked against the register")
    print()
    print(f"  {'account':<19}{'Region':<11}{'how':<32}{'model or outside API':<38}register")
    for a, reg, how, what, verdict in rows:
        print(f"  {a:<19}{reg:<11}{how:<32}{what:<38}{verdict}")
    print()
    bad = sum(r[4] != "approved" for r in rows)
    print(f"{len(rows)} AI uses found, {bad} not in the register: that's the shadow AI. (Secret scanning adds keys in code.)")


# ---------------------------------------------------------------------------------------------------- 8. timeline
def cmd_timeline(_args: list[str]) -> None:
    t = scenarios.attack_timeline()
    print("The attacker's first minutes with the leaked helpdesk key (scenarios.attack_timeline(); nothing is called)")
    print()
    for c in t[:4]:
        kind = "long-term key" if c["kind"] == "long-term" else "session key  "
        note = {"GetSessionToken": "swaps the key for temporary session credentials",
                "InvokeModel": "runs a model, on the victim's bill"}[c["call"]]
        print(f"  {c['time'][11:19]}  {c['call']:<17}{kind} {c['key']:<22}{note}")
    print(f"  ...       {len(t) - 4} more InvokeModel calls, one every 30 seconds, until {t[-1]['time'][11:19]}")
    print()
    models = sum(c["call"] == "InvokeModel" for c in t)
    cost = len(t) * ASSUMPTIONS["lab_price_per_call_usd"]
    print(f"{len(t)} calls in 30 minutes: {models} model calls and {len(t) - models} session swap.")
    print(f"The lab prices every call at a made-up {ASSUMPTIONS['lab_price_per_call_usd']:.2f} USD: {cost:.2f} USD. Not a Bedrock price.")


# ---------------------------------------------------------------------------------------------------- 9. decoy
def cmd_decoy(_args: list[str]) -> None:
    d = ORG["decoys"][0]
    rows = read_jsonl(DATA / "repos" / "ops-scripts.history.jsonl")
    planted = next(r for r in rows if r["file"] == ".aws/credentials.lab")
    print(f"The decoy key, planted in the {planted['repo']} repo (commit {planted['commit']}, file {planted['file']}):")
    print()
    for line in planted["lines"]:
        print(f"  {line}")
    print()
    show([
        ("its user", d["user"], f"in {acct(d['account'])}"),
        ("permissions", "none", "in a real account: an IAM user with no policies at all"),
        ("used by", "nobody legitimate", "so ANY call with it is an alert, and a real one"),
        ("GetCallerIdentity", "works", "needs no permission: the thief learns account and user name"),
        ("every other call", "fails", "AccessDenied: no model, no data, and we get the alert"),
    ], a=19, b=22)


# ---------------------------------------------------------------------------------------------------- 10. score
ECHOLEAK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"
NAMES = {
    "AV": ("Attack Vector", {"N": ("Network", "reachable over the network"), "A": ("Adjacent", "same local network"),
                             "L": ("Local", "needs local access"), "P": ("Physical", "needs the device in hand")}),
    "AC": ("Attack Complexity", {"L": ("Low", "no special conditions"), "H": ("High", "needs conditions out of the attacker's control")}),
    "PR": ("Privileges Required", {"N": ("None", "no account needed"), "L": ("Low", "a normal account"), "H": ("High", "an admin account")}),
    "UI": ("User Interaction", {"N": ("None", "nobody has to click anything"), "R": ("Required", "a user must do something")}),
    "S": ("Scope", {"U": ("Unchanged", "the damage stays in the flawed component"),
                    "C": ("Changed", "the damage reaches beyond the flawed component")}),
    "C": ("Confidentiality", {"H": ("High", "data can be read"), "L": ("Low", "some data"), "N": ("None", "")}),
    "I": ("Integrity", {"H": ("High", "data can be changed"), "L": ("Low", "some data can be changed"), "N": ("None", "")}),
    "A": ("Availability", {"H": ("High", "service can be stopped"), "L": ("Low", "slowed"), "N": ("None", "")}),
}


def roundup(x: float) -> float:
    """CVSS 3.1 Roundup (specification, Appendix A): the smallest number, to 1 decimal place, >= x."""
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def base_score(m: dict) -> float:
    """The CVSS 3.1 base score formula from FIRST's specification, section 7.1."""
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
    ac = {"L": 0.77, "H": 0.44}[m["AC"]]
    changed = m["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
    ui = {"N": 0.85, "R": 0.62}[m["UI"]]
    cia = {"H": 0.56, "L": 0.22, "N": 0.0}
    iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    return roundup(min(1.08 * (impact + exploit), 10)) if changed else roundup(min(impact + exploit, 10))


def band(s: float) -> str:
    return "None" if s == 0 else "Low" if s < 4 else "Medium" if s < 7 else "High" if s < 9 else "Critical"


def cmd_score(args: list[str]) -> None:
    vector = args[0] if args else ECHOLEAK
    parts = vector.split("/")
    if parts[0] != "CVSS:3.1":
        raise SystemExit("explore.py score reads CVSS 3.1 base vectors, e.g. " + ECHOLEAK)
    m = dict(p.split(":", 1) for p in parts[1:])
    m = {k: v for k, v in m.items() if k in NAMES}
    if set(m) != set(NAMES):
        raise SystemExit("a 3.1 base vector needs all 8 metrics: AV AC PR UI S C I A")
    label = "  (CVE-2025-32711, EchoLeak: the base metrics of the vector Microsoft published)" if vector == ECHOLEAK else ""
    print(vector + label)
    print()
    for k in NAMES:
        name, values = NAMES[k]
        word, why = values[m[k]]
        print(f"  {k + ':' + m[k]:<6}{name:<21}{word:<11}{why}".rstrip())
    s = base_score(m)
    print()
    print(f"Base score, FIRST's CVSS 3.1 formula computed on this machine: {s:.1f} {band(s)}")
    print("Bands: 0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical")


# ---------------------------------------------------------------------------------------------------- 11. agent
def cmd_agent(_args: list[str]) -> None:
    d, h = load_setup("first-draft")["triage"], load_setup("hardened")["triage"]
    print('The AI triage agent: what it reads and what it may do (setups/*/setup.json "triage"; no model runs)')
    print()
    print(f"  {'':<16}{'first draft':<46}hardened")
    where = {"instructions": "inside its INSTRUCTIONS", "data": "in a DATA block, marked untrusted"}
    print(f"  {'the alert goes':<16}{where[d['alert_fields_in']]:<46}{where[h['alert_fields_in']]}")
    dt = textwrap.wrap(", ".join(d["tools"]), 44)
    ht = textwrap.wrap(", ".join(h["tools"]), 44)
    for i in range(max(len(dt), len(ht))):
        lab_ = "its tools" if i == 0 else ""
        print(f"  {lab_:<16}{(dt[i] if i < len(dt) else ''):<46}{ht[i] if i < len(ht) else ''}".rstrip())
    gates = {"none": "none", "outside-model": "outside the model: refuses any other tool"}
    print(f"  {'a gate':<16}{gates[d['gate']]:<46}{gates[h['gate']]}")
    instr, _data = triage.build_prompt(load_setup("hardened"), scenarios.clean_alert())
    print()
    print("Its instructions, hardened:")
    for line in textwrap.wrap(instr[0], W - 4):
        print("    " + line)


# ---------------------------------------------------------------------------------------------------- 12. compare
def cmd_compare(_args: list[str]) -> None:
    d, h = load_setup("first-draft"), load_setup("hardened")

    def accts(v):
        return f"all {len(ORG['accounts'])}" if v == "all" else ", ".join(acct(a) for a in v)

    def regs(v):
        return f"all {len(ORG['regions'])}" if v == "all" else ", ".join(v)

    def short(names):
        return ", ".join(n.split(".")[0] for n in names) or "none"

    extra = [n for n in h["hunt"]["event_names"] if n not in d["hunt"]["event_names"]]
    rows = [
        ("collect.accounts", accts(d["collect"]["accounts"]), accts(h["collect"]["accounts"]), "D1"),
        ("collect.regions", regs(d["collect"]["regions"]), regs(h["collect"]["regions"]), "D1, H3"),
        ("collect.data_events", short(d["collect"]["data_events"]), short(h["collect"]["data_events"]), "D3"),
        ("hunt.event_names", ", ".join(d["hunt"]["event_names"]), f"+ {len(extra)} more: Converse, CreateInference ...", "D2"),
        ("hunt.sources", ", ".join(d["hunt"]["sources"]), ", ".join(h["hunt"]["sources"]), "D4"),
        ("hunt.scan_history", f"{str(d['hunt']['scan_history']).lower()}: current files only",
         f"{str(h['hunt']['scan_history']).lower()}: every commit", "D5"),
        ("rules/", ", ".join(r["file"] for r in d["rules"]), f"{len(h['rules'])} rules (any call, all Regions)", "H1-3, N1, N2"),
        ("responder.mode", f"{d['responder']['mode']}, every {d['responder']['interval_s'] // 60} min, reads S3",
         f"on each {h['responder']['mode']}, reads EventBridge", "R1"),
        ("responder.actions", ", ".join(d["responder"]["actions"]), "+ deny_user_sessions + 2 more", "R2"),
        ("triage.alert_fields_in", d["triage"]["alert_fields_in"], h["triage"]["alert_fields_in"], "T1, T2"),
        ("triage.tools", f"{len(d['triage']['tools'])}, incl. close_alert, update_allowlist", ", ".join(h["triage"]["tools"]), "T1, T2"),
        ("triage.gate", d["triage"]["gate"], "outside the model", "T1, T2"),
    ]
    print("setups/first-draft against setups/hardened: every setting that changed, and the cases it fixes")
    print()
    print(f"  {'setting':<24}{'first draft':<42}{'hardened':<44}cases")
    for k, a, b, c in rows:
        print(f"  {k:<24}{a:<42}{b:<44}{c}")


COMMANDS = {
    "event": cmd_event, "rule": cmd_rule, "match": cmd_match, "queue": cmd_queue, "playbook": cmd_playbook,
    "dns": cmd_dns, "inventory": cmd_inventory, "timeline": cmd_timeline, "decoy": cmd_decoy, "score": cmd_score,
    "agent": cmd_agent, "compare": cmd_compare,
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
