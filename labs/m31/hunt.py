"""
hunt.py: an investigator's questions over a morning of spend-guard decisions.

    python3 hunt.py                                # the recorded morning in data/hunt-log.jsonl
    python3 hunt.py --file state/decisions.jsonl   # your own run

Each line of the log is one decision by the spend guard (the same fields guard.py writes): ts, user, agent, task_id,
merchant_host, pay_to, amount, asset, network, decision (ALLOW / DENY / DEFER), rule, after_untrusted.
"""

import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

from x402lab import fmt

HERE = Path(__file__).resolve().parent


def read(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def known_payees():
    return set(json.loads((HERE / "data" / "payee-history.json").read_text())["known_payees"])


def refusals_by_rule(entries):
    """Q1: what did the guard refuse or hold, and why?"""
    return Counter(e["rule"] for e in entries if e["decision"] in ("DENY", "DEFER"))


def new_payees_paid(entries, known):
    """Q2: money that went to a payee nobody here had paid in the last 30 days."""
    return [e for e in entries if e["decision"] == "ALLOW" and e["pay_to"] not in known]


def bursts(entries, window=60, threshold=4):
    """Q3: one agent asking to pay four or more times inside a minute."""
    by_agent = defaultdict(list)
    for e in entries:
        by_agent[e["agent"]].append(e["ts"])
    out = {}
    for agent, times in by_agent.items():
        times.sort()
        for i in range(len(times)):
            n = sum(1 for t in times[i:] if t - times[i] < window)
            if n >= threshold:
                out[agent] = max(out.get(agent, 0), n)
    return out


def find_injected_purchases(entries, known):
    """
    Q4, CHALLENGE 3 (lesson 31.1): the injected-purchase pattern.
    Return the sorted list of task_ids where the guard ALLOWED or DEFERRED a payment that came AFTER the agent read
    untrusted content in that task (after_untrusted is true) AND went to a payee not in `known`.
    A DENY is not a purchase. This is a reason to look, not proof of an attack.
    """
    return []   # replace this line


def main(argv):
    path = argv[argv.index("--file") + 1] if "--file" in argv else HERE / "data" / "hunt-log.jsonl"
    entries = read(path)
    known = known_payees()
    print(f"{len(entries)} decisions in {os.path.relpath(path)}\n")
    print("Q1  refused or held, by rule:")
    for rule, n in refusals_by_rule(entries).most_common():
        print(f"      {n:>3}  {rule}")
    print("Q2  paid to a payee not seen in the last 30 days:")
    for e in new_payees_paid(entries, known):
        print(f"      {e['task_id']}  {e['agent']}  {fmt(e['amount'])} {e['asset']} to {e['pay_to']}"
              f"{'  (after reading untrusted content)' if e['after_untrusted'] else ''}")
    print("Q3  bursts (4+ payment decisions by one agent inside 60 s):")
    for agent, n in bursts(entries).items():
        print(f"      {agent}: {n} in one minute")
    print("Q4  injected-purchase pattern (challenge):")
    found = find_injected_purchases(entries, known)
    print("      " + (", ".join(found) if found else "(not written yet: see CHALLENGE 3 in hunt.py)"))


if __name__ == "__main__":
    main(sys.argv[1:])
