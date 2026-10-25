"""
audit.py: spot it. Read the decision log the agents write, the way an investigator would (lessons 22.1 and 22.4).

    python3 score.py --log --agent dual        # writes state/decisions.jsonl (one line per read and per sink attempt)
    python3 audit.py show                      # what each session read and tried to send
    python3 audit.py hunt                      # three questions over the log (Q3 is the challenge)
    python3 audit.py hunt --file data/hunt-decisions.jsonl     # the saved log the tests use

Each line has a session number, the agent, the task (UT0... for user requests; AgentDojo also runs each attacker
goal on its own as IT0..., which the hunt skips), and either
  {"event": "read", "tool": ..., "untrusted": true/false, "sources": [...]}   or
  {"event": "sink", "tool": ..., "targets": [...], "verdict": RAN | ALLOW | DENY, "rule": ..., "reason": ...}
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).parent
DEFAULT_LOG = HERE / "state" / "decisions.jsonl"
STAFF_DOMAIN = "@tsg.example"


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def sessions(events: list[dict]) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = defaultdict(list)
    for e in events:
        if not e["task"].startswith("IT"):
            out[e["session"]].append(e)
    return dict(out)


def refusals_by_rule(events) -> Counter:
    return Counter(e["rule"] for e in events if e.get("event") == "sink" and e["verdict"] == "DENY"
                   and not e["task"].startswith("IT"))


def outside_sends(events) -> list[dict]:
    """Sinks that RAN or were ALLOWED with a target outside the company: data that left."""
    out = []
    for e in events:
        if e.get("event") != "sink" or e["verdict"] == "DENY" or e["task"].startswith("IT"):
            continue
        outside = [t for t in e["targets"] if t and not str(t).endswith(STAFF_DOMAIN)]
        if outside:
            out.append({**e, "outside": outside})
    return out


def trifecta_sessions(events) -> list[int]:
    """CHALLENGE part 3 (lesson 22.1, "how to spot it"): the trifecta in a log.

    Return the session numbers (sorted) where the agent READ something untrusted and, LATER in the same session,
    attempted a sink (whatever its verdict: RAN, ALLOW or DENY) with at least one target outside the company
    (not ending in STAFF_DOMAIN). Skip sessions whose task starts with "IT" (sessions() already does).
    Test: python3 run_tests.py --challenge
    """
    return []


def show(events):
    for sid, evs in sessions(events).items():
        head = evs[0]
        print(f"session {sid:>3}  {head['agent']:<18} {head['task']}")
        for e in evs:
            if e["event"] == "read":
                print(f"    read  {e['tool']:<14} {'UNTRUSTED' if e['untrusted'] else 'trusted':<10} {', '.join(e['sources'])}")
            else:
                print(f"    sink  {e['tool']:<14} {e['verdict']:<10} -> {', '.join(map(str, e['targets']))}"
                      + (f"  [{e['rule']}]" if e["verdict"] == "DENY" else ""))


def hunt(events):
    print("Q1. Which rules refused calls, and how often?")
    for rule, n in refusals_by_rule(events).most_common():
        print(f"    {n:>3}  {rule}")
    print("Q2. Which calls sent something outside the company (and ran)? Count per agent and address:")
    sent = Counter((e["agent"], e["tool"], t) for e in outside_sends(events) for t in e["outside"])
    for (agent, tool, target), n in sorted(sent.items()):
        print(f"    {n:>3}  {agent:<14} {tool:<11} -> {target}")
    if not sent:
        print("    none")
    print("Q3. Which sessions read untrusted content and then tried to send outside? (challenge)")
    found = trifecta_sessions(events)
    print("    " + (", ".join(map(str, found)) if found else "none found (write trifecta_sessions in audit.py)"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["show", "hunt"])
    ap.add_argument("--file", type=Path, default=DEFAULT_LOG)
    args = ap.parse_args()
    events = load(args.file)
    show(events) if args.what == "show" else hunt(events)


if __name__ == "__main__":
    main()
