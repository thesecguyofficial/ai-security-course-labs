"""The challenge for lab 31.3. These tests fail until you finish the three CHALLENGE parts. Run: make challenge"""

import json
import unittest

from suite import fresh_state, run_task, setup_world
from test_lab import rules


class ChallengeTests(unittest.TestCase):
    def test_c1_per_payee_daily(self):
        """C1 a per-payee daily limit: a second 1.50 report from the same merchant breaks a 2.00-a-day limit"""
        with fresh_state():
            setup_world({"per_payee_daily_max": 2_000_000})
            run_task("challenge", "T-REPORT")
            run_task("challenge", "T-REPORT-B")
            self.assertEqual(rules(), ["per_payee_daily_max"])

    def test_c2_long_lived_authorization(self):
        """C2 refuse to sign an authorization that would stay valid for 30 days (maxTimeoutSeconds over 300)"""
        with fresh_state():
            setup_world()
            run_task("challenge", "T-WEATHER", {"weather.tsg.example": {"max_timeout": 30 * 24 * 3600}})
            self.assertEqual(rules(), ["max_timeout"])

    def test_c3_find_injected_purchases(self):
        """C3 find_injected_purchases() on the recorded morning finds T-1007 and T-1010"""
        import hunt
        e = hunt.read(hunt.HERE / "data" / "hunt-log.jsonl")
        self.assertEqual(hunt.find_injected_purchases(e, hunt.known_payees()), ["T-1007", "T-1010"])

    def test_c4_find_injected_rules(self):
        """C4 find_injected_purchases(): a DEFER counts, a DENY doesn't, a known payee doesn't, no untrusted read doesn't"""
        import hunt
        base = {"ts": 0, "agent": "a", "asset": "LABUSD", "amount": 1, "rule": "r"}
        e = [dict(base, task_id="T-A", decision="DEFER", pay_to="acct:new", after_untrusted=True),
             dict(base, task_id="T-B", decision="DENY", pay_to="acct:new", after_untrusted=True),
             dict(base, task_id="T-C", decision="ALLOW", pay_to="acct:old", after_untrusted=True),
             dict(base, task_id="T-D", decision="ALLOW", pay_to="acct:new", after_untrusted=False)]
        self.assertEqual(hunt.find_injected_purchases(e, {"acct:old"}), ["T-A"])


if __name__ == "__main__":
    unittest.main()
