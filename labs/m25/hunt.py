"""
hunt.py: read a morning of deploy-gate log lines like an investigator (lesson 25.5, "spot it"; lab 25.6).

    python3 hunt.py                                   # data/deploy-history.jsonl, two pipelines, one morning
    python3 hunt.py --file state/deploy-log.jsonl     # your own runs

Each line is what deploy.py writes: time, setup, release, decision (deployed | refused), and for deploys
verify (verified | failed | skipped), signer_key_sha256, weights_sha256, warnings; for refusals, reason.
"""

from __future__ import annotations

import argparse
import collections

import lab


def find_unverified_deploys(rows: list[dict]) -> list[dict]:
    """CHALLENGE 3: every deploy that went ahead WITHOUT a verified signature.

    Return [{"time": ..., "release": ..., "setup": ..., "verify": ...}] for each row with decision "deployed" and
    verify other than "verified", oldest first. These are the fail-open deploys: the gate saw a problem and
    shipped anyway. Until you write it, the hunt finds nothing.
    """
    return []


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default="data/deploy-history.jsonl")
    a = ap.parse_args()
    rows = lab.read_jsonl(lab.HERE / a.file)
    trusted = lab.read_json(lab.DATA / "hunt-trusted-key.json")["ci_key_sha256"]
    deployed = [r for r in rows if r["decision"] == "deployed"]

    print(f"{len(rows)} deploy-gate decisions in {a.file}: {len(deployed)} deployed, {len(rows) - len(deployed)} refused")
    print("\nQ1  Deploys by signature result:")
    for k, n in sorted(collections.Counter(r.get("verify") for r in deployed).items()):
        print(f"    {k:<9} {n}")
    print("\nQ2  Refusals and why:")
    for r in rows:
        if r["decision"] == "refused":
            print(f"    {r['time']}  {r['setup']}  {r['release']:<13} {r['reason'][:90]}")
    print("\nQ3  Deploys signed by a key that is NOT our CI key:")
    odd = [r for r in deployed if r.get("verify") == "verified" and r.get("signer_key_sha256") != trusted]
    for r in odd:
        print(f"    {r['time']}  {r['setup']}  {r['release']:<13} key {r['signer_key_sha256'][:16]}...")
    print("    (none)" if not odd else "    -> a gate that trusts the key shipped with the model (first draft)")
    print("\nQ4  Deploys that went ahead without a verified signature (challenge 3):")
    found = find_unverified_deploys(rows)
    for r in found:
        print(f"    {r['time']}  {r['setup']}  {r['release']:<13} verify={r['verify']}")
    if not found:
        print("    (nothing found yet: write find_unverified_deploys() in hunt.py)")


if __name__ == "__main__":
    main()
