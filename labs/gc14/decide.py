"""
decide.py: the decision table. For each proposed tool call in data/cases.json, ask every control in order who
decides, and print the answer.

    python3 decide.py --twin today                  # make table        (today's deployment)
    python3 decide.py --twin hardened               # make table-safe   (the hardened deployment)
    python3 decide.py --twin hardened --dry-run     # make dry-run      (hardened, gateway policy in DRY_RUN)
    python3 decide.py --twin hardened --rugpull     # make rugpull      (a re-registered MCP server adds a tool)
    python3 decide.py --twin hardened --outage      # make outage       (Model Armor unreachable)
    python3 decide.py --twin today --logs           # make logs         (gateway decisions as JSON lines)

The order of controls for one proposed call:
  1. Model Armor on the gateway screens the tools/call RESPONSE the proposal came from. If it blocks, the model
     never sees that text, so the proposal never happens.
  2. Memory Bank (memory cases): which scope is read, which topics may be written, when they expire.
  3. Your app: approval queue for write tools you marked.
  4. Agent Gateway: registry + Unified Access Policy (deny rules first, default deny), or DRY_RUN.
  5. IAM on the data: may the agent's principal read this dataset?
No model, no attack text: only decisions.
"""

from __future__ import annotations

import argparse
import copy
import json

from twin import (CASES, GatewayTwin, IamTwin, MemoryBankTwin, ModelArmorTwin, agent_principal, load_deployment,
                  load_registry)

DATASET = "//bigquery.googleapis.com/projects/{project}/datasets/{dataset}"
SOURCE_TOOL = {"C1": "get_ticket", "C2": "search_kb", "C3": "get_ticket", "C4": "get_ticket", "C5": "search_kb"}


def evaluate(dep: dict, registry: dict, case: dict, armor_up: bool = True, rugpull: bool = False,
             dry_run: bool = False) -> dict:
    dep = copy.deepcopy(dep)
    if dry_run:
        dep["gateway"]["iap_authz_extension"].setdefault("metadata", {})["iamEnforcementMode"] = "DRY_RUN"
    agent = dep["agent"]
    principal = agent_principal(dep)
    end_user = case["end_user"] if agent.get("_lab_end_user_from") == "verified_token" else case["request_user_id"]
    call = case.get("rugpull_call") if rugpull and case.get("rugpull_call") else case["call"]
    gw = GatewayTwin(dep, registry, ModelArmorTwin(armor_up))
    steps: list[tuple[str, str, str]] = []
    row = {"id": case["id"], "kind": case["kind"], "title": case["title"], "why": case["why"],
           "principal": principal, "end_user": end_user, "call": call, "steps": steps, "gateway_log": []}

    def finish(blocked: bool, leaked: bool | None = None):
        row["blocked"] = blocked
        row["succeeded"] = (not blocked) if leaked is None else leaked
        return row

    # 1. Model Armor on the response the proposal came from (only through a gateway that has it)
    if case["id"] in SOURCE_TOOL and gw.attached:
        verdict, why = gw.screen(case["screen"])
        src = SOURCE_TOOL[case["id"]]
        if verdict == "BLOCK":
            steps.append(("Model Armor", "BLOCKED", f"tools/call response of {src}: {why}; the model never saw it"))
            return finish(True)
        steps.append(("Model Armor", verdict, f"tools/call response of {src}: {why}"))

    # 2. Memory Bank
    if call["type"] in ("memory_read", "memory_write"):
        bank = MemoryBankTwin(dep)
        scope_user = case["request_user_id"] if agent.get("_lab_memory_scope_from") == "request_body" else case["end_user"]
        scope = {"app_name": "tsg_helpdesk", "user_id": scope_user}
        if call["type"] == "memory_read":
            got = bank.retrieve(scope)
            other = [m for m in got if m["scope"]["user_id"] != case["end_user"]]
            steps.append(("Memory Bank", f"retrieve scope user_id={scope_user}",
                          f"{len(got)} memories returned" + (f", belonging to {scope_user}" if other else "")))
            row["memories"] = got
            return finish(False, leaked=bool(other))
        res = bank.generate(scope, call["topic"])
        exp = res.get("expire_day")
        steps.append(("Memory Bank", res["action"], res.get("why") or
                      (f"topic {call['topic']}, scope {scope_user}, " + ("never expires (no TTL)" if exp is None
                                                                          else f"expires on day {exp}"))))
        return finish(res["action"] != "CREATED")

    # 3. Your app's approval queue
    tool = call.get("tool")
    if tool in agent.get("_lab_approval", {}):
        approved = case["kind"] == "legit"
        steps.append(("your app", "PAUSED", f"{tool} waits in the approval queue; a person "
                      + ("approved it" if approved else "rejected it")))
        if not approved:
            return finish(True)

    # 4. Agent Gateway
    if not gw.attached:
        steps.append(("Agent Gateway", "NOT ATTACHED", "no egress policy was evaluated"))
    elif not principal.startswith("principal://"):
        steps.append(("Agent Gateway", "DENIED", "the agent has no Agent Identity; unidentified agents are blocked"))
        return finish(True)
    else:
        if call["type"] == "url":
            attrs = gw.attributes(None, None, call["host"])
            target = f"https://{call['host']}{call.get('path', '/')}"
        else:
            attrs = gw.attributes(call["server"], tool, None)
            target = f"{call['server']}.{tool}"
        result, rule = gw.authorize(principal, attrs)
        entry = {"resource": {"type": "networkservices.googleapis.com/Gateway"},
                 "jsonPayload": {"authzPolicyInfo": {"result": result},
                                 "agentGatewayInfo": {"mcpInfo": {"method": "tools/call"}} if call["type"] == "mcp" else {}},
                 "lab": {"case": case["id"], "principal": principal, "target": target, "rule": rule,
                         "dry_run": gw.dry_run}}
        row["gateway_log"].append(entry)
        if result == "DENIED" and gw.dry_run:
            steps.append(("Agent Gateway", "DRY_RUN would deny", f"{target}: {rule} (logged, not blocked)"))
        elif result == "DENIED":
            steps.append(("Agent Gateway", "DENIED", f"{target}: {rule}"))
            return finish(True)
        else:
            steps.append(("Agent Gateway", "ALLOWED", f"{target}: {rule}"))

    # 5. IAM on the data
    if call["type"] == "mcp" and call["server"] == "bigquery":
        ds = DATASET.format(project=dep["project"], dataset=call["args"]["dataset"])
        ok, why = IamTwin(dep).allows(principal, "bigquery.tables.getData", ds)
        steps.append(("IAM (BigQuery)", "ALLOWED" if ok else "DENIED", f"dataset {call['args']['dataset']}: {why}"))
        if not ok:
            return finish(True)
    return finish(False)


def run(twin: str, rugpull=False, dry_run=False, armor_up=True, dep: dict | None = None) -> list[dict]:
    dep = dep or load_deployment(twin)
    reg = load_registry(rugpull)
    return [evaluate(dep, reg, c, armor_up=armor_up, rugpull=rugpull, dry_run=dry_run) for c in CASES]


def summary(rows: list[dict]) -> str:
    hij = [r for r in rows if r["kind"] == "hijack"]
    leg = [r for r in rows if r["kind"] == "legit"]
    return (f"{sum(r['succeeded'] for r in hij)} of {len(hij)} hijacked calls went through; "
            f"{sum(r['succeeded'] for r in leg)} of {len(leg)} legitimate calls completed.")


def show(rows: list[dict], title: str):
    print(f"--- GC14 decision table · {title} ---")
    print(f"agent principal: {rows[0]['principal']}\n")
    for r in rows:
        if r["kind"] == "legit":
            verdict = "completed" if r["succeeded"] else "BROKEN"
        else:
            verdict = "WENT THROUGH" if r["succeeded"] else "stopped"
        print(f"  {r['id']:<3} {r['kind']:<6} {r['title'][:52]:<52} {verdict}")
        print(f"      for {r['end_user']}; {r['why']}")
        for layer, decision, by in r["steps"]:
            print(f"      {layer:<15} {decision:<20} {by}")
    print("\n" + summary(rows))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--twin", choices=["today", "hardened"], default="today")
    ap.add_argument("--rugpull", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--outage", action="store_true")
    ap.add_argument("--logs", action="store_true")
    a = ap.parse_args()
    rows = run(a.twin, rugpull=a.rugpull, dry_run=a.dry_run, armor_up=not a.outage)
    if a.logs:
        print(f"--- gateway decisions · {a.twin} (one JSON line each; 'lab' holds our own fields) ---")
        for r in rows:
            for e in r["gateway_log"]:
                print(json.dumps(e))
        return
    extra = [x for x, on in (("rug pull", a.rugpull), ("DRY_RUN", a.dry_run), ("Model Armor outage", a.outage)) if on]
    show(rows, " · ".join([a.twin] + extra))


if __name__ == "__main__":
    main()
