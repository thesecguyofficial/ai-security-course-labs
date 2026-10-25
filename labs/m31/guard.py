"""
guard.py: the spend guard. It stands between the agent and the wallet, the way a policy enforcement point stands in
front of a tool (Module 21). The agent never holds the wallet key: it asks the guard, and the guard signs only what
the user's mandate and the task allow.

Each setup is a JSON file of design choices in setups/: first-draft.json and hardened.json.

Decisions: ALLOW (sign and pay), DENY (refuse) or DEFER (hold for the user to approve on the trusted surface).
Every decision is one line in state/decisions.jsonl.
"""

import json
from pathlib import Path

import mandate as mandates
from x402lab import MERCHANTS, Wallet, fmt, load, save, STATE

SETUPS = Path(__file__).resolve().parent / "setups"


def load_setup(name):
    return json.loads((SETUPS / f"{name}.json").read_text())


def log(entry):
    STATE.mkdir(parents=True, exist_ok=True)
    with open(STATE / "decisions.jsonl", "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


class SpendGuard:
    def __init__(self, setup, clock):
        self.name = setup
        self.cfg = load_setup(setup)
        self.clock = clock

    # -------------------------------------------------------------- where the facts come from
    def mandate_for(self, task, offered):
        # Like AP2, the agent carries the mandate and presents it. Who carries it doesn't matter; the signature does.
        if offered is not None:
            return offered
        return mandates.from_store(task["mandate_id"])

    def expected_pay_to(self, host, req):
        if self.cfg["payee_source"] == "registry":
            return MERCHANTS.get(host, {}).get("pay_to")  # who this merchant registered as, from onboarding
        return req["payTo"]                               # first draft: whatever the 402 says

    # -------------------------------------------------------------- the decision
    def decide(self, task, host, req, resource_url, offered_mandate=None, idem_key=None):
        c = self.cfg
        m = self.mandate_for(task, offered_mandate)
        amount = int(req["amount"])
        spend = load("spend.json", [])

        def deny(rule, reason):
            return {"decision": "DENY", "rule": rule, "reason": reason}

        if not m:
            return deny("mandate", "no mandate for this task")
        if c["verify_mandate_sig"] and not mandates.signature_ok(m):
            return deny("mandate_signature", "mandate is not signed by the trusted surface")
        if c["check_expiry"] and self.clock.now >= int(m["expires_at"]):
            return deny("mandate_expired", f"mandate {m['mandate_id']} expired at {m['expires_at']}")
        if c["check_asset"] and (req["asset"] != m["asset"] or req["network"] != m["network"]):
            return deny("asset_network", f"{req['asset']} on {req['network']} is not what the mandate allows "
                                         f"({m['asset']} on {m['network']})")
        expected = self.expected_pay_to(host, req)
        if req["payTo"] != expected:
            return deny("pay_to_mismatch", f"402 says payTo {req['payTo']}, {host} registered {expected}")
        if c["check_payee"] and req["payTo"] not in m["payees"]:
            return deny("payee_not_in_mandate", f"{req['payTo']} is not an allowed payee")
        if c["task_scope"]:
            if host not in task.get("merchants", []):
                return deny("merchant_not_in_task", f"{host} is not a merchant this task names")
            if amount > to_int(task.get("max_price")):
                return deny("over_task_price", f"{fmt(amount)} is more than this task's ceiling {fmt(task['max_price'])}")
        if c["idempotency"] and idem_key and any(s.get("idem_key") == idem_key for s in spend):
            return deny("already_paid", f"step {idem_key} was already paid (a retry, not a new purchase)")
        if c["task_scope"] and sum(1 for s in spend if s["task_id"] == task["task_id"]) >= int(task.get("max_payments", 1)):
            return deny("task_payment_limit", f"this task allows {task.get('max_payments', 1)} payment(s)")
        if amount > int(m["per_payment_max"]):
            return deny("over_per_payment_max", f"{fmt(amount)} is over the per-payment limit {fmt(m['per_payment_max'])}")
        if c["budget"]:
            spent = sum(s["amount"] for s in spend if s["mandate_id"] == m["mandate_id"])
            if spent + amount > int(m["budget_max"]):
                return deny("over_budget", f"{fmt(spent)} spent + {fmt(amount)} is over the budget {fmt(m['budget_max'])}")
        if c.get("max_timeout_seconds"):
            pass   # CHALLENGE 2 (lesson 31.1): refuse to sign when req["maxTimeoutSeconds"] is longer than this
        if m.get("per_payee_daily_max"):
            pass   # CHALLENGE 1 (lesson 31.1): refuse when this payee's total today + amount is over the limit
        if c["approvals"] and amount > int(m["approval_over"]):
            used = mandates.use_approval(task["task_id"], req, resource_url, self.clock)
            if not used:
                apr = mandates.request_approval(task["task_id"], req, resource_url, self.clock)
                return {"decision": "DEFER", "rule": "approval_over", "approval_id": apr,
                        "reason": f"{fmt(amount)} is over {fmt(m['approval_over'])}: held for the user to approve ({apr})"}
            return {"decision": "ALLOW", "rule": "approved", "reason": f"approved by the user ({used})", "mandate_id": m["mandate_id"]}
        why = "within the mandate and the task" if c["task_scope"] else "not expired and under the per-payment limit"
        return {"decision": "ALLOW", "rule": "within_mandate", "reason": why, "mandate_id": m["mandate_id"]}

    def pay(self, task, host, req, resource, offered_mandate=None, read_untrusted=False, idem_key=None):
        d = self.decide(task, host, req, resource["url"], offered_mandate, idem_key)
        payload = None
        if d["decision"] == "ALLOW":
            payload = Wallet(task.get("wallet", "acct:buyer-alice"), self.clock).sign_payment(req, resource)
            save("spend.json", load("spend.json", []) + [{
                "mandate_id": d.get("mandate_id"), "task_id": task["task_id"], "url": resource["url"], "idem_key": idem_key,
                "pay_to": req["payTo"], "amount": int(req["amount"]), "at": self.clock.now}])
        log({"ts": self.clock.now, "setup": self.name, "user": task.get("user"), "agent": task.get("agent"),
             "task_id": task["task_id"], "idem_key": idem_key, "merchant_host": host, "resource": resource["url"], "pay_to": req["payTo"],
             "amount": int(req["amount"]), "asset": req["asset"], "network": req["network"],
             "max_timeout": req.get("maxTimeoutSeconds"), "decision": d["decision"], "rule": d["rule"],
             "reason": d["reason"], "after_untrusted": read_untrusted,
             "nonce": payload["payload"]["authorization"]["nonce"] if payload else None})
        return d, payload


def to_int(v):
    return int(v) if v is not None else 0
