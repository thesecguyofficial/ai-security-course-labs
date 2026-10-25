"""
receipts.py: the PEP's audit log. One signed receipt per decision, each linked to the one before (a hash chain).

A receipt binds the action (tool + exact arguments), the context (who, which ticket, which setup and mode), the
decision (ALLOW / DENY / DEFER, the policies that decided, any errors) and the outcome (did the tool run, what it
returned). Editing, deleting or reordering a line breaks the chain; a forged line has no valid signature.

LAB SHORTCUT: receipts are signed with HMAC-SHA256 and a key in state/receipt.key, because Python's standard library
has no Ed25519. A real system signs with a private key held by the PEP (Ed25519 or ECDSA P-256, ideally in a KMS or
HSM) so anyone with the public key can verify a receipt without being able to forge one.

    python3 receipts.py show [--last 10]     # read the log
    python3 receipts.py verify               # check every signature and the chain
    python3 receipts.py hunt                 # questions an investigator asks (denials, LOG_ONLY flips, held calls)
"""

from __future__ import annotations

import argparse
import hmac
import os
import secrets
import sys

import lab

GENESIS = "0" * 64


def _path():
    return lab.state_dir() / "receipts.jsonl"


def _key(name: str) -> bytes:
    p = lab.state_dir() / name
    if not p.exists():
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    return bytes.fromhex(p.read_text().strip())


def _body(rec: dict) -> str:
    return lab.canonical({k: v for k, v in rec.items() if k not in ("hash", "sig")})


def read_all() -> list[dict]:
    return lab.read_jsonl(_path())


def append(rec: dict) -> dict:
    rows = read_all()
    rec = dict(rec)
    rec["seq"] = len(rows) + 1
    rec["prev"] = rows[-1]["hash"] if rows else GENESIS
    body = _body(rec)
    rec["hash"] = lab.sha256(body)
    rec["sig"] = hmac.new(_key("receipt.key"), body.encode(), "sha256").hexdigest()
    lab.append_jsonl(_path(), rec)
    return rec


def verify(rows: list[dict] | None = None) -> list[str]:
    """Return a list of problems; empty means every receipt is signed and the chain is intact."""
    rows = read_all() if rows is None else rows
    problems, prev = [], GENESIS
    key = _key("receipt.key") if rows else b""
    for i, r in enumerate(rows, 1):
        body = _body(r)
        if r.get("seq") != i:
            problems.append(f"line {i}: sequence number {r.get('seq')} (expected {i}): a receipt was removed or moved")
        if r.get("prev") != prev:
            problems.append(f"line {i}: does not link to the receipt before it (chain broken)")
        if lab.sha256(body) != r.get("hash"):
            problems.append(f"line {i}: content changed after it was written (hash mismatch)")
        if not hmac.compare_digest(hmac.new(key, body.encode(), "sha256").hexdigest(), r.get("sig", "")):
            problems.append(f"line {i}: signature invalid")
        prev = r.get("hash")
    return problems


def window(principal: str, now: float) -> dict:
    """The counters the hardened PEP hands to the policy. Counted from our own receipts, per signed-in user."""
    rows = read_all()
    refunds = sum(1 for r in rows if r["principal"] == principal and r["tool"] == "issue_refund"
                  and r["decision"] == "ALLOW" and now - r["t"] < 3600)
    denials = sum(1 for r in rows if r["principal"] == principal and r["decision"] == "DENY" and now - r["t"] < 600)
    return {"refunds_1h": refunds, "denials_10m": denials}


# ---------------------------------------------------------------------------------------------------- hunting
def find_probing(rows: list[dict]) -> list[dict]:
    """CHALLENGE (lesson 21.4): signed-in users with 3 or more DENY decisions inside any 10-minute window.

    Return one dict per user: {"principal": ..., "denials": <the most in one window>, "first_time": <iso time of the
    first denial in that window>}, sorted by first_time. An agent that keeps trying calls it isn't allowed to make is
    the pattern Dogwood's "block an action after an earlier denial" example cuts off. Replace the line below.
    """
    raise NotImplementedError("challenge: write find_probing() in receipts.py")


def hunt(rows: list[dict]) -> None:
    print("Q1  Calls that were refused (DENY):")
    for r in rows:
        if r["decision"] == "DENY":
            print(f"    #{r['seq']:<3} {r['time']}  {r['principal']:<6} {r['tool']:<14} {r['reason'][:70]}")
    print("Q2  Calls the policy refused that ran anyway (LOG_ONLY):")
    for r in rows:
        if r["mode"] == "LOG_ONLY" and r["decision"] != "ALLOW" and r["ran"]:
            print(f"    #{r['seq']:<3} {r['time']}  {r['principal']:<6} {r['tool']:<14} would be {r['decision']}")
    print("Q3  Calls held for a human (DEFER):")
    for r in rows:
        if r["decision"] == "DEFER":
            print(f"    #{r['seq']:<3} {r['time']}  {r['principal']:<6} {r['tool']:<14} approval {r.get('approval_id')}")
    try:
        found = find_probing(rows)
        print("Q4  Users probing for permissions (3+ denials in 10 minutes):")
        for f in found:
            print(f"    {f['principal']}: {f['denials']} denials from {f['first_time']}")
    except NotImplementedError as e:
        print(f"Q4  (not answered yet: {e})")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["show", "verify", "hunt"])
    ap.add_argument("--last", type=int, default=0)
    ap.add_argument("--file", help="read receipts from this file instead of state/receipts.jsonl")
    a = ap.parse_args()
    rows = lab.read_jsonl(lab.pathlib.Path(a.file)) if a.file else read_all()
    if a.command == "show":
        for r in rows[-a.last:] if a.last else rows:
            ran = "ran" if r["ran"] else "not run"
            print(f"#{r['seq']:<3} {r['time']} {r['mode']:<8} {r['principal']:<6} {r['tool']:<14} {r['decision']:<5} "
                  f"{ran:<7} policies={','.join(r['policies']) or '-'}  {r['reason'][:60]}")
    elif a.command == "verify":
        if a.file:
            sys.exit("verify works on state/receipts.jsonl only (the key is in state/)")
        problems = verify(rows)
        print(f"{len(rows)} receipts: " + ("chain intact, every signature valid" if not problems else "PROBLEMS"))
        for p in problems:
            print("  " + p)
        sys.exit(1 if problems else 0)
    else:
        hunt(rows)


if __name__ == "__main__":
    main()
