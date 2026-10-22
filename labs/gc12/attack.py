"""
attack.py: replay four attacks and two legitimate requests against the Helpdesk's Gemini path on Agent Platform,
with Model Armor inline (agent_platform.py, an offline model of the integration). Lessons 12.1 and 12.3.

    python3 attack.py --twin today              # make attack
    python3 attack.py --twin hardened           # make attack-safe
    python3 attack.py --twin hardened --outage  # make outage-inline: Model Armor unreachable
"""

from __future__ import annotations

import argparse
import json
import sys

import agent_platform
import helpdesk
from run_suite import CASES, case_turns

PICK = [("S1", "A01"), ("S2", "A05"), ("S3", "A02"), ("S4", "A06"), ("L1", "L01"), ("L2", "L14")]


def run(twin: str, outage: bool = False) -> list[dict]:
    app, project = agent_platform.load_project(twin)
    by_id = {c["id"]: c for c in CASES}
    out = []
    for sid, cid in PICK:
        case = by_id[cid]
        turns = case_turns(case)
        req = {"prompt": helpdesk.build_prompt(turns, app["secrets_in_prompt"]),
               "model_armor_config": app["inline"]["model_armor_config"],
               "safety_settings": app["inline"]["safety_settings"]}
        r = agent_platform.generate_content(req, project, available=not outage)
        resp = r.get("response", {})
        content = (resp.get("candidates") or [{}])[0].get("content", "")
        blocked = r.get("error") or resp.get("promptFeedback", {}).get("blockReason") or \
            ((resp.get("candidates") or [{}])[0].get("finishReason") not in (None, "STOP") and
             (resp.get("candidates") or [{}])[0].get("finishReason"))
        out.append({"sid": sid, "case": cid, "kind": case["kind"], "category": case["category"],
                    "source": r["source"], "blocked": blocked or None, "leaked": helpdesk.leaked(content),
                    "log": r["log"], "notes": r.get("notes", [])})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--twin", default="today", choices=["today", "hardened"])
    ap.add_argument("--outage", action="store_true", help="Model Armor unreachable")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rows = run(a.twin, a.outage)
    if a.json:
        print(json.dumps(rows, indent=1, ensure_ascii=False))
        return 0
    print(f"--- Agent Platform + Model Armor (inline) · twin: {a.twin}{' · OUTAGE' if a.outage else ''} ---")
    print(f"screening in force: {rows[0]['source']}\n")
    last_notes = None
    for r in rows:
        verdict = f"BLOCKED ({r['blocked']})" if r["blocked"] else "ANSWERED"
        print(f"  {r['sid']} {r['kind']:6} {r['category']:36} {verdict}")
        if r["leaked"]:
            print(f"           attacker got: {', '.join(r['leaked'])}")
        if r["notes"] and r["notes"] == last_notes:
            print("           note: (same as above)")
        else:
            for n in r["notes"]:
                print(f"           note: {n}")
        last_notes = r["notes"]
        print(f"           sanitize log entries: {len(r['log'])}")
    attacks = [r for r in rows if r["kind"] == "attack"]
    legit = [r for r in rows if r["kind"] == "legit"]
    print(f"\n{sum(1 for r in attacks if not r['blocked'])} of {len(attacks)} attacks reached the model; "
          f"{sum(1 for r in attacks if r['leaked'])} of {len(attacks)} got something out; "
          f"{sum(1 for r in legit if not r['blocked'])} of {len(legit)} legitimate requests answered; "
          f"{sum(len(r['log']) for r in rows)} sanitize log entries written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
