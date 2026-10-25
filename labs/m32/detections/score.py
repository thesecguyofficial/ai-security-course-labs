#!/usr/bin/env python3
"""Score your detection rules: did every incident fire, and how many false alerts, on several simulated days?

    python3 detections/score.py                      # seeds 1, 2, 3 (make detect-check)
    python3 detections/score.py --seeds 4 5 6 -v     # other days, with each alert marked TRUE or FALSE

Pass mark (self-check D1): on every seed, each of S1 to S5 has at least one alert, and there are at most
2 false alerts (an alert on a request that belongs to no incident). The answer key comes from attack_sim.py.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import attack_sim  # noqa: E402
import detect      # noqa: E402

MAX_FALSE = 2


def score(rules: list[dict], seed: int) -> dict:
    events, truth = attack_sim.generate(seed)
    alerts = detect.run(rules, events)
    owner = {rid: story for story, rids in truth.items() for rid in rids}
    hits = {s: 0 for s in truth}
    false = set()
    for a in alerts:
        story = owner.get(a["request_id"])
        a["verdict"] = story or "FALSE"
        if story:
            hits[story] += 1
        else:
            false.add((a["rule"], a["request_id"]))
    missed = [s for s, n in hits.items() if n == 0]
    return {"seed": seed, "alerts": len(alerts), "hits": hits, "missed": missed, "false_alerts": len(false),
            "passed": not missed and len(false) <= MAX_FALSE, "detail": alerts}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", default=str(HERE / "rules.json"))
    ap.add_argument("--seeds", nargs="+", type=int, default=[1, 2, 3])
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--json", help="write the scores as JSON")
    a = ap.parse_args(argv)
    rules = json.loads(pathlib.Path(a.rules).read_text(encoding="utf-8"))["rules"]
    problems = detect.validate(rules)
    if problems:
        print("rules.json has problems:\n  " + "\n  ".join(problems))
        return 2
    results = []
    for seed in a.seeds:
        r = score(rules, seed)
        results.append(r)
        mark = "PASS" if r["passed"] else "FAIL"
        hits = " ".join(f"{s}:{n}" for s, n in r["hits"].items())
        print(f"[{mark}] seed {seed}: {hits}  false alerts {r['false_alerts']} (max {MAX_FALSE})"
              + (f"  missed {', '.join(r['missed'])}" if r["missed"] else ""))
        if a.verbose:
            for x in r["detail"]:
                print(f"         {x['verdict']:<5} {x['rule']} {x['ts']} {x['user']} {x['event']} {x['detail']}")
    if a.json:
        pathlib.Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.json).write_text(json.dumps([{k: v for k, v in r.items() if k != "detail"} for r in results],
                                                   indent=2) + "\n", encoding="utf-8")
    ok = all(r["passed"] for r in results)
    print(f"DETECTIONS {'PASSED' if ok else 'FAILED'} on seeds {', '.join(map(str, a.seeds))}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
