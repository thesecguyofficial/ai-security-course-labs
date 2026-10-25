"""
mandate.py: what the user agreed to, signed on a trusted surface, and the human approvals for bigger purchases.

The idea comes from AP2 (github.com/google-agentic-commerce/AP2, docs/ap2/): the user approves a set of constraints
(allowed payees, an amount range, a budget, an expiry) on a "Trusted Surface" that MUST be non-agentic, and every
check of those constraints runs in deterministic code. Real AP2 mandates are SD-JWTs signed with the user's key;
here a mandate is plain JSON with an HMAC from the lab's "surface" key, so you can read every field.

    python3 mandate.py issue                 # write the lab's standard mandate to state/mandates/
    python3 mandate.py show MND-0001         # print it and check its signature
    python3 mandate.py approvals             # list approval requests
    python3 mandate.py approve APR-0001      # approve one, on the trusted surface (bound to that exact payment)
"""

import hashlib
import json
import sys

from x402lab import ASSET, NETWORK, STATE, Clock, canonical, check_sig, fmt, load, save, sign, to_atomic

STANDARD = {
    "mandate_id": "MND-0001",
    "user": "alice",
    "agent": "agent:research-assistant",
    "payees": ["acct:weather-co", "acct:market-co", "acct:shop-co"],
    "asset": ASSET,
    "network": NETWORK,
    "per_payment_max": to_atomic("5.00"),
    "budget_max": to_atomic("5.00"),
    "approval_over": to_atomic("2.00"),
    "expires_at": 1_800_000_000 + 7 * 24 * 3600,
}


def issue(fields=None):
    m = dict(STANDARD, **(fields or {}))
    body = {k: v for k, v in m.items() if k != "sig"}
    m["sig"] = sign("surface", body)
    (STATE / "mandates").mkdir(parents=True, exist_ok=True)
    (STATE / "mandates" / f"{m['mandate_id']}.json").write_text(json.dumps(m, indent=1, sort_keys=True))
    return m


def from_store(mandate_id):
    path = STATE / "mandates" / f"{mandate_id}.json"
    return json.loads(path.read_text()) if path.exists() else None


def signature_ok(m):
    body = {k: v for k, v in m.items() if k != "sig"}
    return check_sig("surface", body, m.get("sig"))


# ---------------------------------------------------------------- approvals bound to one exact payment

def payment_hash(req, resource_url):
    """What the user approves: this payee, this amount, this asset, this network, for this resource."""
    bound = {"payTo": req["payTo"], "amount": str(req["amount"]), "asset": req["asset"],
             "network": req["network"], "resource": resource_url}
    return hashlib.sha256(canonical(bound).encode()).hexdigest()


def request_approval(task_id, req, resource_url, clock):
    reqs = load("approvals.json", [])
    apr = {"id": f"APR-{len(reqs) + 1:04d}", "task_id": task_id, "hash": payment_hash(req, resource_url),
           "summary": f"{fmt(req['amount'])} {req['asset']} to {req['payTo']} for {resource_url}",
           "status": "pending", "requested_at": clock.now}
    save("approvals.json", reqs + [apr])
    return apr["id"]


def approve(apr_id, clock):
    reqs = load("approvals.json", [])
    for a in reqs:
        if a["id"] == apr_id and a["status"] == "pending":
            a["status"] = "approved"
            a["valid_until"] = clock.now + 600
            a["sig"] = sign("surface", {"id": a["id"], "hash": a["hash"], "valid_until": a["valid_until"]})
            save("approvals.json", reqs)
            return a
    return None


def use_approval(task_id, req, resource_url, clock):
    """Return the approval id if an approved, unused, unexpired approval covers exactly this payment."""
    reqs = load("approvals.json", [])
    h = payment_hash(req, resource_url)
    for a in reqs:
        if a["task_id"] == task_id and a["hash"] == h and a["status"] == "approved" and clock.now < a["valid_until"] \
                and check_sig("surface", {"id": a["id"], "hash": a["hash"], "valid_until": a["valid_until"]}, a.get("sig")):
            a["status"] = "used"
            save("approvals.json", reqs)
            return a["id"]
    return None


def main(argv):
    clock = Clock()
    if not argv or argv[0] == "issue":
        m = issue()
        print(f"issued {m['mandate_id']} for {m['user']}: payees {m['payees']}, up to {fmt(m['per_payment_max'])} per payment, "
              f"budget {fmt(m['budget_max'])}, approval over {fmt(m['approval_over'])} {m['asset']}, expires {m['expires_at']}")
    elif argv[0] == "show":
        m = from_store(argv[1])
        print(json.dumps(m, indent=1, sort_keys=True) if m else "no such mandate")
        if m:
            print("signature:", "valid" if signature_ok(m) else "INVALID")
    elif argv[0] == "approvals":
        for a in load("approvals.json", []):
            print(f"{a['id']}  {a['status']:<8} {a['summary']}")
    elif argv[0] == "approve":
        a = approve(argv[1], clock)
        print(f"{argv[1]} approved on the trusted surface, valid 10 minutes, for this exact payment only" if a else "nothing to approve")
    else:
        print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
