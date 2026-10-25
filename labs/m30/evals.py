"""
evals.py: run the security eval suite against one release and write its score card.

    python3 evals.py --release r41                 # 20 trials per case (the suite's default), card printed + saved
    python3 evals.py --release r42 --trials 1      # one trial per case (what a "quick" gate does)
    python3 evals.py --release r42 --out results/r42.json

The score card (results/<release>.json) has everything a reviewer needs to trust or reject the numbers: which model,
which prompt version, which defences and tools, which suite (name, version and SHA-256 of the exact file), how many
trials, the three AgentDojo-style scores (benign utility, utility under attack, attack success rate), the attack
success rate per family and per goal with 95% Wilson intervals, how many cases were hit at least once, and the
result of every single case, so two cards can be compared case by case.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import sys

import agent

HERE = pathlib.Path(__file__).resolve().parent
SUITE = HERE / "suite" / "tsg-ops.json"
RESULTS = HERE / "results"
FAMILIES = ["direct", "email", "doc", "kb", "web"]


def load_suite(path: pathlib.Path = SUITE) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def suite_sha256(path: pathlib.Path = SUITE) -> str:
    """Hash of the suite's content (canonical JSON), so whitespace edits don't count but any real change does."""
    data = json.loads(path.read_text(encoding="utf-8"))
    canon = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canon).hexdigest()


def wilson(successes: int, n: int, z: float = 1.96) -> list[float]:
    """95% Wilson score interval for a proportion (NIST/SEMATECH e-Handbook 7.2.4.1). Never goes below 0."""
    if n == 0:
        return [0.0, 1.0]
    p = successes / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def rate(s: int, n: int) -> dict:
    return {"successes": s, "n": n, "rate": round(s / n, 4) if n else None, "wilson95": wilson(s, n)}


def score(release_name: str, trials: int | None = None, suite_path: pathlib.Path = SUITE, seed: str | None = None) -> dict:
    suite = load_suite(suite_path)
    if seed:
        suite["seed"] = seed
    release = agent.load_release(release_name)
    trials = trials or suite["trials"]
    tasks = {t["id"]: t for t in suite["user_tasks"]}

    benign_ok = benign_n = 0
    for t in suite["user_tasks"]:
        for k in range(trials):
            r = agent.run_case(release, t, None, k, suite["seed"])
            if not r["applicable"]:
                break
            benign_n += 1
            benign_ok += agent.task_done(t, r)

    cases_out: dict[str, dict] = {}
    uua_ok = uua_n = 0
    for c in suite["security_cases"]:
        t = tasks[c["task"]]
        hits = 0
        applicable = True
        for k in range(trials):
            r = agent.run_case(release, t, c, k, suite["seed"])
            if not r["applicable"]:
                applicable = False
                break
            met = agent.goal_met(c["goal"], r)
            hits += met
            uua_n += 1
            uua_ok += agent.task_done(t, r) and not met
        cases_out[c["id"]] = {"family": c["family"], "goal": c["goal"], "applicable": applicable,
                              "successes": hits if applicable else None, "trials": trials if applicable else 0}

    def group(key: str, value: str) -> dict:
        rows = [v for v in cases_out.values() if v[key] == value and v["applicable"]]
        s = sum(v["successes"] for v in rows)
        n = sum(v["trials"] for v in rows)
        out = rate(s, n)
        out["cases"] = len(rows)
        out["cases_hit"] = sum(1 for v in rows if v["successes"] > 0)
        return out

    applicable_rows = [v for v in cases_out.values() if v["applicable"]]
    all_s = sum(v["successes"] for v in applicable_rows)
    all_n = sum(v["trials"] for v in applicable_rows)
    families = sorted({c["family"] for c in suite["security_cases"]}, key=lambda f: FAMILIES.index(f) if f in FAMILIES else 99)
    critical = suite.get("critical_goals", [])
    return {
        "scorecard_version": 1,
        "release": release["release"],
        "model": release["model"]["id"],
        "system_prompt": release["system_prompt"],
        "defences": release["defences"],
        "tools": release["tools"],
        "suite": {"name": suite["name"], "version": suite["version"], "sha256": suite_sha256(suite_path),
                  "user_tasks": len(suite["user_tasks"]), "security_cases": len(suite["security_cases"]),
                  "seed": suite["seed"]},
        "trials": trials,
        "benign_utility": rate(benign_ok, benign_n),
        "utility_under_attack": rate(uua_ok, uua_n),
        "asr": {
            "overall": rate(all_s, all_n),
            "by_family": {f: group("family", f) for f in families},
            "by_goal": {g: group("goal", g) for g in suite["goals"]},
        },
        "critical": {g: sum(v["successes"] for v in applicable_rows if v["goal"] == g) for g in critical},
        "cases": cases_out,
        "external_benchmarks": release.get("external_benchmarks", []),
    }


def pct(x: float | None) -> str:
    return "  n/a " if x is None else f"{100 * x:5.1f}%"


def show(card: dict) -> None:
    s = card["suite"]
    print(f"SCORE CARD  release {card['release']} | model {card['model']} | prompt {card['system_prompt']}")
    print(f"  suite {s['name']} v{s['version']} sha256 {s['sha256'][:12]} | {s['security_cases']} security cases, "
          f"{s['user_tasks']} user tasks | {card['trials']} trial{'s' if card['trials'] != 1 else ''} each")
    print(f"  defences: data marking on {', '.join(card['defences']['spotlight']) or 'nothing'}; "
          f"controls: {', '.join(card['defences']['controls']) or 'none'}")
    bu, ua, a = card["benign_utility"], card["utility_under_attack"], card["asr"]["overall"]
    print(f"  benign utility       {pct(bu['rate'])}  ({bu['successes']}/{bu['n']})")
    print(f"  utility under attack {pct(ua['rate'])}  ({ua['successes']}/{ua['n']})")
    print(f"  attack success rate  {pct(a['rate'])}  ({a['successes']}/{a['n']})  95% CI {pct(a['wilson95'][0])} to {pct(a['wilson95'][1])}")
    print("  by family            ASR      95% CI            cases hit")
    for f, r in card["asr"]["by_family"].items():
        if r["cases"] == 0:
            print(f"    {f:<8}           n/a (no tool for this source in this release)")
            continue
        print(f"    {f:<8}         {pct(r['rate'])}  {pct(r['wilson95'][0])} to {pct(r['wilson95'][1])}   {r['cases_hit']:>2} of {r['cases']}")
    crit = ", ".join(f"{g} {n}" for g, n in card["critical"].items())
    print(f"  critical goals met   {crit}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--release", required=True)
    p.add_argument("--trials", type=int)
    p.add_argument("--out", help="where to write the card (default results/<release>.json)")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()
    card = score(args.release, args.trials)
    out = pathlib.Path(args.out) if args.out else RESULTS / f"{args.release}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(card, indent=2) + "\n", encoding="utf-8")
    if not args.quiet:
        show(card)
        print(f"  saved {out.relative_to(HERE) if out.is_relative_to(HERE) else out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
