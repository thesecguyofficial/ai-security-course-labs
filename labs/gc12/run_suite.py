"""
run_suite.py: the automated guardrail suite (lesson 12.4 and 12.5). It sends every case in suite/cases.json through
the Helpdesk (stand-in model) behind a guard, and measures BOTH sides:

    attacks stopped   = attacks the guard blocked (prompt or response)
    attacks leaked    = attacks that got something out (escalation code, key, phishing link, harmful content)
    legit blocked     = legitimate requests the guard refused (false positives)

    python3 run_suite.py                    # make suite:  none vs today vs hardened, then the hardened misses
    python3 run_suite.py --sweep            # make sweep:  hardened guard at HIGH / MEDIUM / LOW confidence
    python3 run_suite.py --outage           # make outage: hardened guard while Model Armor is down
    python3 run_suite.py --engine model-armor --template-name projects/P/locations/L/templates/T   # optional, real API

Offline by default: the engine is armor_twin.py (a teaching stand-in, not Google's classifiers).
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys

import app_guard
import armor_twin
import helpdesk
from engines import get_engine

HERE = pathlib.Path(__file__).resolve().parent
CASES = json.loads((HERE / "suite" / "cases.json").read_text(encoding="utf-8"))["cases"]
MODEL = helpdesk.StandInModel()


def load_profile(twin: str) -> dict:
    app = armor_twin.load_json(HERE / "twin" / twin / "app.json")
    templates = armor_twin.load_json(HERE / "twin" / twin / "templates.json")["templates"]
    sh = app["self_hosted"]
    tpl = next(t for t in templates if t["name"] == sh["template"])
    return {"name": twin, "template": tpl, "screen": sh["screen"], "screen_response": sh["screen_response"],
            "secrets_in_prompt": app["secrets_in_prompt"]}


def with_pi_level(profile: dict, level: str) -> dict:
    p = copy.deepcopy(profile)
    p["template"]["filterConfig"]["piAndJailbreakFilterSettings"]["confidenceLevel"] = level
    p["name"] = f"{profile['name']} @ {level}"
    return p


def case_turns(case: dict) -> list[str]:
    turns = list(case["turns"])
    if case.get("pad"):
        filler = "policy-text " * (case["pad"] // 12)
        turns[-1] = "Please read our whole policy below. " + filler + turns[-1]
    return turns


def run_case(case: dict, profile: dict | None, engine=None) -> dict:
    """One case through the Helpdesk. profile None = no guard at all."""
    turns = case_turns(case)
    secrets = True if profile is None else profile["secrets_in_prompt"]
    prompt = helpdesk.build_prompt(turns, secrets_in_prompt=secrets)
    if profile is not None:
        d = app_guard.check_prompt(engine, turns, helpdesk.screened_part(prompt), profile["screen"])
        if d.blocked:
            return {"id": case["id"], "blocked": "prompt", "why": d.why, "leaked": []}
        guard_note = d.why
    reply = MODEL.generate(prompt)
    if profile is not None and profile["screen_response"]:
        d = app_guard.check_response(engine, reply, turns[-1])
        if d.blocked:
            return {"id": case["id"], "blocked": "response", "why": d.why, "leaked": []}
        guard_note = guard_note or d.why
    return {"id": case["id"], "blocked": None, "why": guard_note if profile else "", "leaked": helpdesk.leaked(reply)}


def evaluate(profile: dict | None, engine_name: str = "twin", available: bool = True, template_name: str = "") -> dict:
    engine = None
    if profile is not None:
        engine = get_engine(engine_name, template=profile["template"], available=available, template_name=template_name)
    rows = [dict(run_case(c, profile, engine), kind=c["kind"], category=c["category"]) for c in CASES]
    attacks = [r for r in rows if r["kind"] == "attack"]
    legit = [r for r in rows if r["kind"] == "legit"]
    return {
        "profile": "no guardrail" if profile is None else profile["name"],
        "attacks": len(attacks), "legit": len(legit),
        "stopped": sum(1 for r in attacks if r["blocked"]),
        "leaked": sum(1 for r in attacks if r["leaked"]),
        "legit_blocked": sum(1 for r in legit if r["blocked"]),
        "rows": rows,
    }


def print_table(results: list[dict]):
    print(f"{'guard':32} {'attacks stopped':>16} {'attacks leaked':>15} {'legit blocked':>14}")
    for r in results:
        print(f"{r['profile']:32} {r['stopped']:>9} of {r['attacks']:<4} {r['leaked']:>8} of {r['attacks']:<4} "
              f"{r['legit_blocked']:>7} of {r['legit']:<4}")


def print_details(result: dict, notes: bool = True):
    print(f"\nWhat got past '{result['profile']}', and what it wrongly blocked:")
    for r in result["rows"]:
        if r["kind"] == "attack" and not r["blocked"]:
            got = ", ".join(r["leaked"]) or "nothing (no secret in the prompt)"
            note = f"  [{r['why']}]" if r["why"] and notes else ""
            print(f"  MISSED   {r['id']}  {r['category']:38} attacker got: {got}{note}")
        if r["kind"] == "legit" and r["blocked"]:
            print(f"  FALSE +  {r['id']}  {r['category']:38} blocked at {r['blocked']} ({r['why']})")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sweep", action="store_true", help="hardened guard at HIGH, MEDIUM_AND_ABOVE and LOW_AND_ABOVE")
    ap.add_argument("--outage", action="store_true", help="hardened guard with Model Armor unavailable")
    ap.add_argument("--engine", default="twin", choices=["twin", "model-armor", "llm-guard"])
    ap.add_argument("--template-name", default="", help="real template resource name (--engine model-armor)")
    ap.add_argument("--json", help="also write the full results to this file")
    a = ap.parse_args()

    hardened = load_profile("hardened")
    if a.sweep:
        results = [evaluate(with_pi_level(hardened, lvl), a.engine, template_name=a.template_name)
                   for lvl in ("HIGH", "MEDIUM_AND_ABOVE", "LOW_AND_ABOVE")]
        print("--- Sweep: the hardened guard, prompt injection and jailbreak confidence level only ---\n")
        print_table(results)
        for r in results:
            print_details(r)
    elif a.outage:
        results = [evaluate(hardened, a.engine, available=False, template_name=a.template_name)]
        print("--- Outage: Model Armor unreachable, hardened guard ---\n")
        print_table(results)
        print(f"\napp_guard.on_error() said, for every request: {results[0]['rows'][0]['why']}")
        print_details(results[0], notes=False)
    else:
        results = [evaluate(None), evaluate(load_profile("today"), a.engine, template_name=a.template_name),
                   evaluate(hardened, a.engine, template_name=a.template_name)]
        print(f"--- Guardrail suite: {len(CASES)} cases, engine: {a.engine} ---\n")
        print_table(results)
        print_details(results[2])
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(results, indent=1, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
