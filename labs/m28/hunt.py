"""
hunt.py: questions an investigator asks of KMS events in CloudTrail (lesson 28.4, "spot it").

    python3 hunt.py                                  # make hunt: the morning in data/hunt-cloudtrail.jsonl
    python3 hunt.py --file state/cloudtrail.jsonl    # the events your own last run wrote

Field names are the ones in a real CloudTrail KMS event: eventSource, eventName, userIdentity.arn (or invokedBy for
an AWS service), requestParameters.keyId and encryptionContext, errorCode. The fixture is invented for the lab: it
shows a normal day of the hardened pipeline plus two things you should notice.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter

import lab

RAW_KEY = "arn:aws:kms:us-east-1:123456789012:key/d2e8e3d7-5171-7003-8a49-bf0df5e7d330"
EXPECTED_RAW_READERS = [lab.REDACTOR, lab.MACIE, lab.BREAK_GLASS, lab.ERASURE]


def load(path) -> list[dict]:
    return [json.loads(line) for line in open(path) if line.strip()]


def who(e: dict) -> str:
    u = e["userIdentity"]
    return u.get("arn") or f"service:{u.get('invokedBy')}"


def q1_by_key(events) -> dict:
    """Q1: per key, who called what, and how often it was refused."""
    out: dict[str, Counter] = {}
    for e in events:
        if e["eventSource"] != "kms.amazonaws.com":
            continue
        c = out.setdefault(e["requestParameters"]["keyId"], Counter())
        c[(lab.short(who(e)), e["eventName"], "refused" if e.get("errorCode") else "ok")] += 1
    return out


def q2_break_glass(events) -> list[dict]:
    """Q2: every use of the break-glass role. Each one should match an incident ticket."""
    return [e for e in events if who(e) == lab.BREAK_GLASS]


def find_raw_key_readers(events, raw_key_arn=RAW_KEY, expected=EXPECTED_RAW_READERS) -> list[tuple[str, int, int]]:
    """CHALLENGE 3: principals OUTSIDE `expected` that called Decrypt on the raw-log key, allowed or refused.

    Return a list of (principal ARN, allowed count, refused count), sorted by ARN. Refused calls count too: someone
    tried. AWS service principals that only call GenerateDataKey (Bedrock writing logs) are not readers.
    No solution is included in this repo.
    """
    raise NotImplementedError("challenge 3: write find_raw_key_readers()")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(lab.DATA / "hunt-cloudtrail.jsonl"))
    events = load(ap.parse_args().file)
    print(f"{len(events)} KMS events")
    print("Q1  Calls per key:")
    for key, c in q1_by_key(events).items():
        print(f"    {key}")
        for (p, name, res), n in sorted(c.items()):
            print(f"      {p:<32} {name:<16} {res:<8} x{n}")
    print("Q2  Break-glass uses (match each to an incident ticket):")
    for e in q2_break_glass(events):
        print(f"    {e['eventTime']}  {e['requestParameters']['encryptionContext']['aws:s3:arn'].rsplit('/', 1)[-1]}")
    try:
        found = find_raw_key_readers(events)
        print("Q3  Unexpected readers of the raw-log key:")
        for p, ok, refused in found:
            print(f"    {lab.short(p):<20} allowed x{ok}  refused x{refused}")
    except NotImplementedError:
        print("Q3  (not answered yet: challenge 3, write find_raw_key_readers() in hunt.py)")


if __name__ == "__main__":
    main()
