"""
hunt.py: investigate one morning on the first draft, from the two APIs' audit logs.

    python3 hunt.py                        # make hunt
    python3 hunt.py data/incident/api-audit.jsonl

Every row is one API call: which API, the operation, the user the token named, the agent that presented it
(azp), the token's audience (aud) and its ID (jti). The file was recorded from real lab runs
(tools/make_incident.py).

Q1  Which single token was accepted by more than one API?            (find_shared_tokens, done)
Q2  Which calls carried a token that was valid for more than one service? (find_broad_audience, done)
Q3  Which token was used for more than one write ("send" or DELETE)? (find_replays: CHALLENGE 2, yours)
"""

from __future__ import annotations

import collections
import json
import pathlib
import sys

WRITES = {"send", "DELETE"}


def load(path: str | pathlib.Path) -> list[dict]:
    return [json.loads(line) for line in pathlib.Path(path).read_text().splitlines() if line.strip()]


def find_shared_tokens(rows: list[dict]) -> dict[str, list[str]]:
    """jti -> the APIs that accepted it, for tokens accepted by more than one API."""
    seen = collections.defaultdict(set)
    for r in rows:
        if r.get("result") == "ok" and r.get("jti"):
            seen[r["jti"]].add(r["api"])
    return {jti: sorted(apis) for jti, apis in seen.items() if len(apis) > 1}


def find_broad_audience(rows: list[dict]) -> list[dict]:
    """Accepted calls whose token named more audiences than the API that took it."""
    out = []
    for r in rows:
        aud = r.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if r.get("result") == "ok" and auds != [r["api"]]:
            out.append({"ts": r["ts"], "api": r["api"], "op": r["op"], "jti": r.get("jti"), "aud": auds})
    return out


def find_replays(rows: list[dict]) -> list[dict]:
    """CHALLENGE 2: tokens used for more than one successful write.

    Return one dict per token: {"jti": ..., "writes": <number of successful writes>, "first_ts": ..., "last_ts": ...},
    sorted by first_ts. A write is a row whose "op" is in WRITES and whose "result" is "ok".
    """
    return []  # TODO


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    path = argv[0] if argv else pathlib.Path(__file__).resolve().parent / "data" / "incident" / "api-audit.jsonl"
    rows = load(path)
    print(f"{len(rows)} audit rows from {path}\n")
    print("Q1 one token, several APIs:")
    for jti, apis in find_shared_tokens(rows).items():
        print(f"   jti {jti}: accepted by {', '.join(apis)}")
    print("Q2 tokens valid for more than the API that took them:")
    for r in find_broad_audience(rows):
        print(f"   {r['ts']} {r['api']:<11} {r['op']:<6} jti {r['jti']}  aud has {len(r['aud'])} entries")
    print("Q3 tokens used for more than one write:")
    replays = find_replays(rows)
    for r in replays:
        print(f"   jti {r['jti']}: {r['writes']} writes between {r['first_ts']} and {r['last_ts']}")
    if not replays:
        print("   (nothing yet: write find_replays(), challenge 2)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
