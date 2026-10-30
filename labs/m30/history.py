"""
history.py: read the gate's audit log and flag the quiet ways a security gate gets weakened.

    python3 history.py                                   # this lab's own log (state/gate-events.jsonl)
    python3 history.py --file data/gate-history.jsonl    # four weeks of a team's gate log (fake), with findings

Each line of the log is one gate run (written by gate.py): time, baseline, candidate, model, verdict, the suite's
SHA-256 and size, trials, the policy file's SHA-256, and which rules failed or were skipped. The checks:

  H1 suite shrank       fewer security cases than the run before: someone deleted tests
  H2 fewer trials       trials per case went down: cheaper, and blinder
  H3 policy changed     the thresholds file changed: fine if reviewed, a finding if nobody can say who and why
  H4 rerun to green     the same candidate STOPPED, then SHIPPED on a later run with the same model:
                        what changed in between? (retrying until the dice say yes)
  H5 rules skipped      a rule that was skipped passed everything
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent


def read(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        sys.exit(f"no log at {path} yet: run `make gate` first, or use --file data/gate-history.jsonl")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def findings(rows: list[dict]) -> list[str]:
    out = []
    rows = sorted(rows, key=lambda r: r["time"])
    for prev, cur in zip(rows, rows[1:]):
        if cur["security_cases"] < prev["security_cases"]:
            out.append(f"H1 suite shrank   {cur['time']}  {prev['security_cases']} -> {cur['security_cases']} cases "
                       f"(suite {prev['suite_sha256'][:8]} -> {cur['suite_sha256'][:8]}) on candidate {cur['candidate']}")
        if cur["trials"] < prev["trials"]:
            out.append(f"H2 fewer trials   {cur['time']}  {prev['trials']} -> {cur['trials']} trials per case on candidate {cur['candidate']}")
        if cur["policy_sha256"] != prev["policy_sha256"]:
            out.append(f"H3 policy changed {cur['time']}  {prev['policy_sha256'][:8]} -> {cur['policy_sha256'][:8]}: "
                       "find the reviewed pull request that changed gate-policy.json")
    stopped: dict[tuple, dict] = {}
    for r in rows:
        key = (r["candidate"], r["model"])
        if r["verdict"] == "STOP":
            stopped.setdefault(key, r)
        elif key in stopped:
            first = stopped.pop(key)
            same = first["suite_sha256"] == r["suite_sha256"] and first["policy_sha256"] == r["policy_sha256"]
            out.append(f"H4 rerun to green {r['time']}  {r['candidate']} STOPPED at {first['time']} "
                       f"({', '.join(first['rules_failed'])}), SHIPPED now"
                       + (" with the same suite and policy: what changed?" if same else ""))
    for r in rows:
        if r.get("rules_skipped"):
            out.append(f"H5 rules skipped  {r['time']}  {', '.join(r['rules_skipped'])} on candidate {r['candidate']} ({r['verdict']})")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--file", default=str(HERE / "state" / "gate-events.jsonl"))
    args = p.parse_args()
    rows = read(pathlib.Path(args.file))
    print(f"{len(rows)} gate runs in {pathlib.Path(args.file).name}: "
          f"{sum(r['verdict'] == 'SHIP' for r in rows)} SHIP, {sum(r['verdict'] == 'STOP' for r in rows)} STOP")
    found = findings(rows)
    for f in found:
        print(f"  {f}")
    if not found:
        print("  no findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
