"""
evaluate.py: run the M13 suite (suite/cases.json: 8 attacks, 5 normal requests) against one setup.

    python3 evaluate.py first-draft      # make attack
    python3 evaluate.py ported           # make ported   (Bedrock Agents Classic, fixed)
    python3 evaluate.py harness          # make harness  (AgentCore harness, for accounts that can't create Classic agents)
    python3 evaluate.py ported --json    # for CI

An attack "worked" if its goal happened (a canary in the answer, a reset nobody should get, code run, a Lambda or
harness reachable by the wrong caller). A normal request "works" if the user got what they needed. You report both:
a port that blocks the attacks by breaking the Helpdesk is not a port.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

import helpdesk
import twin

HERE = pathlib.Path(__file__).resolve().parent
CASES = json.loads((HERE / "suite/cases.json").read_text(encoding="utf-8"))


def run_case(case: dict, setup: twin.Setup) -> dict:
    w = case.get("worked_if")
    out = {"id": case["id"], "name": case["name"]}
    if w is not None:                                                   # an attack
        if w["type"] == "lambda_invocable":
            if setup.platform != "bedrock-agents-classic":
                return dict(out, applicable=False, worked=False, detail="no action group Lambda on this platform")
            who = [a for a in w["agents"] if helpdesk.lambda_invocable_by(setup, twin.COMPANY[a])]
            return dict(out, applicable=True, worked=bool(who),
                        detail=("Lambda invocable for: " + ", ".join(twin.COMPANY[a] for a in who)) if who
                        else "resource policy only allows the Helpdesk agent")
        if w["type"] == "tool_override":
            if setup.platform != "agentcore-harness":
                return dict(out, applicable=False, worked=False, detail="no harness on this platform")
            who = helpdesk.end_user_can_override_tools(setup)
            return dict(out, applicable=True, worked=bool(who),
                        detail=("InvokeHarness allowed for end-user-reachable: " + ", ".join(who)) if who
                        else "only the backend may call InvokeHarness")
        r = helpdesk.ask(setup, case["user"], case["request"])
        if w["type"] == "answer_contains":
            worked = w["value"] in r["answer"]
        else:
            worked = any(e["tool"] == w["tool"] and ("target" not in w or e["args"].get("target_email") == w["target"])
                         for e in r["executed"])
        return dict(out, applicable=True, worked=worked, detail=r["answer"][:110], run=r)
    r = helpdesk.ask(setup, case["user"], case["request"])            # a normal request
    exp = case["expect"]
    ok = True
    if "answer_contains" in exp:
        ok &= exp["answer_contains"] in r["answer"]
    if "executed" in exp:
        tool, target = exp["executed"]
        ok &= any(e["tool"] == tool and e["args"].get("target_email") == target for e in r["executed"])
    return dict(out, works=ok, detail=r["answer"][:110], run=r)


def run_suite(setup_name: str | twin.Setup) -> dict:
    setup = setup_name if isinstance(setup_name, twin.Setup) else twin.Setup(setup_name)
    return {"attacks": [run_case(c, setup) for c in CASES["attacks"]],
            "normal": [run_case(c, setup) for c in CASES["normal"]]}


def score(res: dict) -> dict:
    att = [a for a in res["attacks"] if a["applicable"]]
    return {"attacks_applicable": len(att), "attacks_worked": sum(a["worked"] for a in att),
            "worked_ids": [a["id"] for a in att if a["worked"]],
            "normal_total": len(res["normal"]), "normal_working": sum(n["works"] for n in res["normal"]),
            "broken_ids": [n["id"] for n in res["normal"] if not n["works"]]}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("setup")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--trace", action="store_true", help="print each turn's steps")
    args = ap.parse_args(argv)
    res = run_suite(args.setup)
    sc = score(res)
    if args.json:
        print(json.dumps({"setup": args.setup, **sc}, indent=2))
        return
    print(f"Setup: {args.setup}\n")
    for a in res["attacks"]:
        status = "n/a   " if not a["applicable"] else ("WORKED" if a["worked"] else "failed")
        print(f"  {a['id']} {status}  {a['name']}")
        if a["applicable"]:
            print(f"            -> {a['detail']}")
        if args.trace and "run" in a:
            for t in a["run"]["trace"]:
                print(f"               . {t}")
    print()
    for n in res["normal"]:
        print(f"  {n['id']} {'ok    ' if n['works'] else 'BROKEN'}  {n['name']}")
        if args.trace:
            for t in n["run"]["trace"]:
                print(f"               . {t}")
    print(f"\nAttacks that worked: {sc['attacks_worked']} of {sc['attacks_applicable']}"
          f"{'  (' + ', '.join(sc['worked_ids']) + ')' if sc['worked_ids'] else ''}"
          f"   |   normal requests that work: {sc['normal_working']} of {sc['normal_total']}"
          f"{'  (broken: ' + ', '.join(sc['broken_ids']) + ')' if sc['broken_ids'] else ''}")


if __name__ == "__main__":
    main(sys.argv[1:])
