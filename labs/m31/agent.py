"""
agent.py: the research assistant agent and its stand-in "model".

The model is plain Python, not AI, so every run is identical. It does what a model that has been successfully
prompt-injected would do: it obeys every LAB-PLACEHOLDER-INJECTED-INSTRUCTION comment in a page it reads. Those
comments are lab placeholders that only this file understands; they are not working payloads for any real agent.

    python3 agent.py <setup> <task-id> [--wire]     # run one task from data/tasks.json, step by step
    python3 agent.py hardened T-READ-SHOES --wire   # also print the raw x402 headers, decoded
"""

import json
import re
import sys
from pathlib import Path

import mandate as mandates
from guard import SpendGuard
from x402lab import Clock, Facilitator, Merchant, b64, fetch_page, fmt, unb64

TASKS = Path(__file__).resolve().parent / "data" / "tasks.json"
DIRECTIVE = re.compile(r"<!--\s*LAB-PLACEHOLDER-INJECTED-INSTRUCTION\s+(\{.*?\})\s*-->")


def tasks():
    return {t["task_id"]: t for t in json.loads(TASKS.read_text())}


def model_plan(task, page_text=None):
    """The stand-in model: the user's request first, then whatever the page told it to do."""
    steps = []
    if task["kind"] == "buy":
        steps.append({"action": "buy", "url": task["url"], "tries": task.get("repeat", 1)})
    if task.get("buy_url"):
        steps.append({"action": "buy", "url": task["buy_url"], "user": True})
    if page_text:
        for raw in DIRECTIVE.findall(page_text):
            steps.append(json.loads(raw))
    return steps


class Run:
    def __init__(self, setup, clock=None, merchant_variants=None, out=print, wire=False):
        self.setup = setup
        self.clock = clock or Clock()
        self.guard = SpendGuard(setup, self.clock)
        f = self.guard.cfg["facilitator"]
        self.facilitator = Facilitator(self.clock, check_nonce=f["check_nonce"], check_time=f["check_time"])
        self.variants = merchant_variants or {}
        self.out = out
        self.wire = wire
        self.offered_mandate = None
        self.read_untrusted = False
        self.results = []

    def merchant(self, host):
        return Merchant(host, self.facilitator, **self.variants.get(host, {}))

    def buy(self, task, url, idem_key):
        host, path = url.split("://", 1)[1].split("/", 1)
        path = "/" + path
        m = self.merchant(host)
        status, headers, _ = m.handle("GET", path)
        self.out(f"  GET {url} -> {status}")
        if status != 402:
            return {"url": url, "outcome": f"http {status}"}
        required = unb64(headers["PAYMENT-REQUIRED"])
        req = required["accepts"][0]
        if self.wire:
            self.out("    PAYMENT-REQUIRED (decoded): " + json.dumps(required["accepts"][0], sort_keys=True))
        d, payload = self.guard.pay(task, host, req, required["resource"], self.offered_mandate, self.read_untrusted,
                                    idem_key=idem_key)
        self.out(f"    guard: {d['decision']} [{d['rule']}] {d['reason']}")
        if d["decision"] != "ALLOW":
            return {"url": url, "outcome": d["decision"], "rule": d["rule"], "approval_id": d.get("approval_id")}
        hdr = {"PAYMENT-SIGNATURE": b64(payload)}
        if self.wire:
            a = payload["payload"]["authorization"]
            self.out(f"    PAYMENT-SIGNATURE (decoded authorization): to={a['to']} value={a['value']} "
                     f"validBefore={a['validBefore']} nonce={a['nonce'][:18]}...")
        status, headers, body = m.handle("GET", path, hdr)
        resp = unb64(headers["PAYMENT-RESPONSE"]) if "PAYMENT-RESPONSE" in headers else None
        if self.wire and resp:
            self.out("    PAYMENT-RESPONSE (decoded): " + json.dumps(resp, sort_keys=True))
        if status == 200:
            self.out(f"  GET {url} + PAYMENT-SIGNATURE -> 200, paid {fmt(req['amount'])} {req['asset']} to {req['payTo']} "
                     f"({resp['transaction']}, lab ledger only, no money moved)")
            return {"url": url, "outcome": "PAID", "amount": int(req["amount"]), "pay_to": req["payTo"], "payload": payload}
        reason = unb64(headers["PAYMENT-REQUIRED"]).get("error") if "PAYMENT-REQUIRED" in headers else resp.get("errorReason")
        self.out(f"  GET {url} + PAYMENT-SIGNATURE -> {status}, refused by the merchant's facilitator: {reason}")
        return {"url": url, "outcome": "REFUSED", "reason": reason}

    def run(self, task):
        self.out(f"TASK {task['task_id']} for {task['user']} ({self.setup}): {task['text']}")
        page = None
        if task["kind"] == "read":
            status, _, page = fetch_page(task["url"])
            self.read_untrusted = True
            self.out(f"  GET {task['url']} -> {status} (a page sellers write: untrusted)")
        n_step = 0
        for step in model_plan(task, page):
            if step["action"] == "buy":
                if task["kind"] == "read" and not step.get("user"):
                    self.out(f"  model obeys a placeholder in the page: buy {step['url']}" +
                             (f" x{step.get('times', 1)}" if step.get("times", 1) > 1 else ""))
                # Each purchase step gets its own idempotency key. A retry of the same step (a timeout) reuses it;
                # a new step, even for the same item, gets a new one.
                for _ in range(step.get("times", 1)):
                    n_step += 1
                    for _ in range(step.get("tries", 1)):
                        self.results.append(self.buy(task, step["url"], f"{task['task_id']}:{n_step}"))
            elif step["action"] == "use_mandate":
                self.offered_mandate = step["mandate"]
                self.out(f"  model obeys a placeholder in the page: present a mandate it wrote itself "
                         f"(budget {fmt(step['mandate']['budget_max'])}, per payment {fmt(step['mandate']['per_payment_max'])})")
        if task["kind"] == "read" and not self.results:
            self.out("  model: summary written, nothing bought")
        return self.results


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return
    setup, task_id = argv[0], argv[1]
    t = tasks()[task_id]
    if not mandates.from_store(t["mandate_id"]):
        mandates.issue()
    Run(setup, wire="--wire" in argv).run(t)


if __name__ == "__main__":
    main(sys.argv[1:])
