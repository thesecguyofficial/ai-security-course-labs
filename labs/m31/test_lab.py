"""The proof for lab 31.3. Run with:  python3 run_tests.py   (make test)"""

import json
import unittest

import suite
from suite import fresh_state, run_task, setup_world


def decisions():
    import x402lab
    path = x402lab.STATE / "decisions.jsonl"
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


def rules(kind="DENY"):
    return [d["rule"] for d in decisions() if d["decision"] == kind]


class LabTests(unittest.TestCase):
    maxDiff = None

    def test_01_first_draft(self):
        """01 first draft: 9 of 10 attacks work (only the expired mandate is refused), 5 of 5 normal requests work"""
        r = suite.run("first-draft")
        worked = sorted(s for s, (k, _, ok, _) in r.items() if k == "attack" and ok)
        self.assertEqual(worked, sorted(["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A9", "A10"]))
        self.assertTrue(all(ok for k, _, ok, _ in r.values() if k == "normal"))

    def test_02_hardened(self):
        """02 hardened: 0 of 10 attacks work, 5 of 5 normal requests still work"""
        r = suite.run("hardened")
        self.assertEqual([s for s, (k, _, ok, _) in r.items() if k == "attack" and ok], [])
        self.assertEqual(sum(1 for k, _, ok, _ in r.values() if k == "normal" and ok), 5)

    def _deny_rule(self, sid):
        with fresh_state():
            setup_world()
            dict((s, fn) for s, _, _, fn in suite.SCENARIOS)[sid]("hardened", lambda *_: None)
            return rules()

    def test_03_injected_buy(self):
        """03 A1 injected buy: refused because the payee is not in the user's mandate"""
        self.assertEqual(self._deny_rule("A1"), ["payee_not_in_mandate"])

    def test_04_price_switch(self):
        """04 A2 price switch: refused by the task's own price ceiling, not by the 5.00 per-payment limit"""
        self.assertEqual(self._deny_rule("A2"), ["over_task_price"])

    def test_05_drip(self):
        """05 A3 drip: one paid, the 9 injected repeats refused by the task's payment count (a 5.00 budget alone would allow all 10)"""
        self.assertEqual(self._deny_rule("A3"), ["task_payment_limit"] * 9)

    def test_06_double_settle(self):
        """06 A4 double settle: the facilitator refuses the second settle of the same nonce"""
        import x402lab
        with fresh_state():
            setup_world()
            clock = x402lab.Clock()
            f = x402lab.Facilitator(clock)
            run_task("hardened", "T-WEATHER", {"weather.tsg.example": {"double_settle": True}}, clock=clock)
            s = x402lab.load("settlements.json", [])
            self.assertEqual(len(s), 1)
            self.assertEqual(x402lab.Ledger().balance("acct:weather-co"), 10000)

    def test_07_stale_replay(self):
        """07 A5 replay after two hours: refused as expired (validBefore) and, once settled, as a reused nonce"""
        import x402lab
        from agent import tasks
        from guard import SpendGuard
        with fresh_state():
            setup_world()
            clock = x402lab.Clock()
            g = SpendGuard("hardened", clock)
            m = x402lab.Merchant("weather.tsg.example", x402lab.Facilitator(clock))
            _, h, _ = m.handle("GET", "/api/today")
            req = x402lab.unb64(h["PAYMENT-REQUIRED"])
            _, payload = g.pay(tasks()["T-WEATHER"], "weather.tsg.example", req["accepts"][0], req["resource"])
            sig = {"PAYMENT-SIGNATURE": x402lab.b64(payload)}
            self.assertEqual(m.handle("GET", "/api/today", sig)[0], 200)
            again = m.handle("GET", "/api/today", sig)
            self.assertEqual(x402lab.unb64(again[1]["PAYMENT-REQUIRED"])["error"], "lab_nonce_already_used")
            clock.advance(7200)
            late = m.handle("GET", "/api/today", sig)
            self.assertEqual(x402lab.unb64(late[1]["PAYMENT-REQUIRED"])["error"],
                             "invalid_exact_lab_payload_authorization_valid_before")

    def test_08_pay_to_swap(self):
        """08 A6 payTo rewritten in the 402: refused, the registry says who the merchant is"""
        self.assertEqual(self._deny_rule("A6"), ["pay_to_mismatch"])

    def test_09_forged_mandate(self):
        """09 A7 a mandate the model wrote: refused, it isn't signed by the trusted surface"""
        self.assertEqual(self._deny_rule("A7"), ["mandate_signature"])

    def test_10_expired(self):
        """10 A8 expired mandate: refused"""
        self.assertEqual(self._deny_rule("A8"), ["mandate_expired"])

    def test_11_retry(self):
        """11 A9 retry of the same step: refused by the idempotency key, paid once"""
        self.assertEqual(self._deny_rule("A9"), ["already_paid"])

    def test_12_asset_switch(self):
        """12 A10 another asset and network: refused, the mandate pins LABUSD on lab:local"""
        self.assertEqual(self._deny_rule("A10"), ["asset_network"])

    def test_13_wire_format(self):
        """13 the 402 carries a base64 PAYMENT-REQUIRED with x402Version 2 and the spec's field names"""
        import x402lab
        status, h, _ = x402lab.Merchant("weather.tsg.example", x402lab.Facilitator(x402lab.Clock())).handle("GET", "/api/today")
        self.assertEqual(status, 402)
        body = x402lab.unb64(h["PAYMENT-REQUIRED"])
        self.assertEqual(body["x402Version"], 2)
        self.assertEqual(set(body["accepts"][0]),
                         {"scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra"})
        self.assertEqual(body["accepts"][0]["amount"], "10000")

    def test_14_verify_is_read_only(self):
        """14 verify() is read only: calling it twice moves nothing and uses no nonce"""
        import x402lab
        with fresh_state():
            clock = x402lab.Clock()
            f = x402lab.Facilitator(clock)
            req = x402lab.Merchant("weather.tsg.example", f).requirements("/api/today")
            p = x402lab.Wallet("acct:buyer-alice", clock).sign_payment(req, {"url": "http://weather.tsg.example/api/today"})
            self.assertTrue(f.verify(p, req)["isValid"])
            self.assertTrue(f.verify(p, req)["isValid"])
            self.assertEqual(x402lab.load("nonces.json", []), [])
            self.assertEqual(x402lab.Ledger().balance("acct:weather-co"), 0)

    def test_15_facilitator_checks(self):
        """15 the facilitator refuses a changed amount, a changed recipient and a bad signature"""
        import copy
        import x402lab
        with fresh_state():
            clock = x402lab.Clock()
            f = x402lab.Facilitator(clock)
            req = x402lab.Merchant("weather.tsg.example", f).requirements("/api/today")
            p = x402lab.Wallet("acct:buyer-alice", clock).sign_payment(req, {"url": "u"})
            bigger = dict(req, amount="20000")
            self.assertEqual(f.verify(p, bigger)["invalidReason"], "invalid_exact_lab_payload_authorization_value_mismatch")
            other = dict(req, payTo="acct:someone-else")
            self.assertEqual(f.verify(p, other)["invalidReason"], "invalid_exact_lab_payload_recipient_mismatch")
            forged = copy.deepcopy(p)
            forged["payload"]["authorization"]["to"] = "acct:someone-else"
            self.assertEqual(f.verify(forged, other)["invalidReason"], "invalid_exact_lab_payload_signature")

    def test_16_approval_bound(self):
        """16 an approval covers one exact payment, once: a different amount needs a new approval"""
        import mandate
        import x402lab
        with fresh_state():
            setup_world()
            clock = x402lab.Clock()
            _, res = run_task("hardened", "T-QUARTERLY", clock=clock)
            self.assertEqual(res[0]["outcome"], "DEFER")
            mandate.approve(res[0]["approval_id"], clock)
            _, res = run_task("hardened", "T-QUARTERLY", {"market.tsg.example": {"price_override": "2.90"}}, clock=clock)
            self.assertEqual(res[0]["outcome"], "DEFER")       # 2.90 is not the 3.00 the user approved
            _, res = run_task("hardened", "T-QUARTERLY", clock=clock)
            self.assertEqual(res[0]["outcome"], "PAID")
            self.assertEqual([a["status"] for a in x402lab.load("approvals.json", [])], ["used", "pending"])

    def test_17_mandate_tamper(self):
        """17 changing any field of a signed mandate breaks its signature"""
        import mandate
        with fresh_state():
            m = mandate.issue()
            self.assertTrue(mandate.signature_ok(m))
            self.assertFalse(mandate.signature_ok(dict(m, budget_max=m["budget_max"] * 100)))

    def test_18_budget(self):
        """18 the budget counts every payment under the mandate: 1.50 + 0.45 is over a 1.90 budget"""
        with fresh_state():
            setup_world({"budget_max": 1_900_000})
            run_task("hardened", "T-REPORT")
            run_task("hardened", "T-SAMPLE")
            self.assertEqual(rules(), ["over_budget"])

    def test_19_no_signature_without_allow(self):
        """19 the wallet signs nothing the guard refused: no nonce is used on DENY"""
        import x402lab
        with fresh_state():
            setup_world()
            run_task("hardened", "T-READ-SHOES")
            self.assertEqual(x402lab.load("nonce-counter.json", 0), 0)

    def test_20_log_fields(self):
        """20 every decision is logged with the fields an investigator needs"""
        with fresh_state():
            setup_world()
            run_task("hardened", "T-READ-SAMPLE")
            d = decisions()
            self.assertEqual(len(d), 10)
            need = {"ts", "user", "agent", "task_id", "idem_key", "merchant_host", "pay_to", "amount", "asset",
                    "network", "decision", "rule", "reason", "after_untrusted", "nonce"}
            self.assertTrue(all(need <= set(x) for x in d))
            self.assertTrue(all(x["after_untrusted"] for x in d))

    def test_21_hunt(self):
        """21 hunt Q1 to Q3 on the recorded morning"""
        import hunt
        e = hunt.read(hunt.HERE / "data" / "hunt-log.jsonl")
        self.assertEqual(hunt.refusals_by_rule(e)["task_payment_limit"], 5)
        self.assertEqual([x["task_id"] for x in hunt.new_payees_paid(e, hunt.known_payees())], ["T-1007", "T-1011"])
        self.assertEqual(hunt.bursts(e), {"agent:shopping-helper": 6})

    def test_22_clean_page(self):
        """22 a clean page: nothing is bought, nothing is logged"""
        with fresh_state():
            setup_world()
            _, res = run_task("hardened", "T-READ-CLEAN")
            self.assertEqual(res, [])
            self.assertEqual(decisions(), [])


if __name__ == "__main__":
    unittest.main()
