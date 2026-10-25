"""
approvals.py: the human approval step ("human deferral"). The agent never sees this tool and can't call it.

When a policy says a call needs a person (Cedar annotation @on_deny("defer")), the PEP files an approval request
holding the EXACT canonical arguments and their SHA-256. A supervisor reviews it here. Approving signs a binding:
who asked, which ticket, which tool, which arguments, who approved, when it expires.

The hardened PEP accepts an approval only when: the signature is valid, the hash matches the arguments of the call
being made now, the requester is the signed-in user, the approver is a supervisor and not the requester, it is less
than 15 minutes old, and it hasn't been used. Then it is marked used (one approval, one call).

LAB SHORTCUT: HMAC-SHA256 with a key in state/approval.key. A real approval service signs with its own private key and
the PEP holds only the public key, so the PEP (or an attacker inside it) can check approvals but never mint one.

    python3 approvals.py list
    python3 approvals.py approve APR-0001 --as alice
    python3 approvals.py reject APR-0001 --as alice
"""

from __future__ import annotations

import argparse
import hmac
import json
import sys

import lab
import receipts

FIELDS = ("id", "requester", "ticket", "tool", "args_sha256", "approver", "decided_t", "expires_t")


def _path():
    return lab.state_dir() / "approvals.json"


def load() -> dict:
    p = _path()
    return json.loads(p.read_text()) if p.exists() else {}


def _save(db: dict) -> None:
    _path().write_text(json.dumps(db, indent=2, ensure_ascii=False))


def _sign(rec: dict) -> str:
    binding = lab.canonical({k: rec[k] for k in FIELDS})
    return hmac.new(receipts._key("approval.key"), binding.encode(), "sha256").hexdigest()


def request(requester: str, ticket: str, tool: str, args: dict) -> dict:
    """File (or reuse) a pending approval for exactly these arguments."""
    db = load()
    args_c = lab.canonical(args)
    digest = lab.sha256(args_c)
    for rec in db.values():
        if (rec["status"] == "pending" and rec["requester"] == requester and rec["tool"] == tool
                and rec["args_sha256"] == digest):
            return rec
    rec = {"id": f"APR-{len(db) + 1:04d}", "requester": requester, "ticket": ticket, "tool": tool,
           "args": json.loads(args_c), "args_sha256": digest, "status": "pending",
           "requested_t": lab.CLOCK.now(), "approver": None, "decided_t": None, "expires_t": None, "sig": None}
    db[rec["id"]] = rec
    _save(db)
    return rec


def decide(approval_id: str, approver: str, approve: bool = True) -> dict:
    db = load()
    rec = db.get(approval_id)
    if rec is None:
        raise ValueError(f"no approval {approval_id}")
    if rec["status"] != "pending":
        raise ValueError(f"{approval_id} is {rec['status']}, not pending")
    if lab.STAFF.get(approver, {}).get("role") != "supervisor":
        raise ValueError(f"{approver} is not a supervisor")
    if approver == rec["requester"]:
        raise ValueError("four-eyes rule: you can't approve a request you made")
    now = lab.CLOCK.now()
    rec.update(status="approved" if approve else "rejected", approver=approver, decided_t=now,
               expires_t=now + lab.APPROVAL_TTL_S)
    rec["sig"] = _sign(rec)
    _save(db)
    return rec


def get(approval_id: str) -> dict | None:
    return load().get(approval_id)


def find_bound(requester: str, ticket: str, tool: str, args: dict) -> dict | None:
    """The hardened PEP's lookup: an approval for THIS user, ticket, tool and these exact arguments, or nothing."""
    digest = lab.sha256(lab.canonical(args))
    now = lab.CLOCK.now()
    for rec in load().values():
        if (rec["status"] == "approved" and rec["requester"] == requester and rec["ticket"] == ticket
                and rec["tool"] == tool and rec["args_sha256"] == digest and now < rec["expires_t"]
                and rec["approver"] != requester and rec["sig"]
                and hmac.compare_digest(rec["sig"], _sign(rec))):
            return rec
    return None


def mark_used(approval_id: str) -> None:
    db = load()
    db[approval_id]["status"] = "used"
    _save(db)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["list", "approve", "reject"])
    ap.add_argument("approval_id", nargs="?")
    ap.add_argument("--as", dest="who", help="the supervisor making the decision (alice)")
    a = ap.parse_args()
    if a.command == "list":
        db = load()
        if not db:
            print("no approval requests")
        for rec in db.values():
            print(f"{rec['id']}  {rec['status']:<8} {rec['requester']:<6} {rec['ticket']}  {rec['tool']} "
                  f"{json.dumps(rec['args'])}  sha256={rec['args_sha256'][:12]}...")
        return
    if not a.approval_id or not a.who:
        sys.exit("usage: approvals.py approve|reject APR-0001 --as alice")
    try:
        rec = decide(a.approval_id, a.who, a.command == "approve")
    except ValueError as e:
        sys.exit(f"refused: {e}")
    print(f"{rec['id']} {rec['status']} by {rec['approver']}, valid until {lab.iso(rec['expires_t'])} "
          f"for {rec['tool']} {json.dumps(rec['args'])} only")


if __name__ == "__main__":
    main()
