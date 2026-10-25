"""
test_challenge.py: the three-part challenge (make challenge). These tests fail until you finish it. No solution is
included in this repo.

1. Lesson 21.2: write a Cedar policy setups/hardened/policies/refund_within_order_total.cedar so the refunds on one
   order can never add up to more than the order cost (A13). The PEP already gives you resource.refunded_cents.
2. Lesson 21.3: write a Cedar policy setups/hardened/policies/stop_after_denial.cedar: after any refused call in the
   last 10 minutes, this user's agent may not issue refunds (A14). The PEP gives you context.window.denials_10m.
3. Lesson 21.4: write find_probing() in receipts.py (users with 3+ denials inside 10 minutes).
"""

from __future__ import annotations

import os
import tempfile
import unittest

import cedarpy

import lab
import pdp
import receipts
import suite


class Challenge(unittest.TestCase):
    def test_c1_policies_validate(self):
        """challenge: both new policies exist, carry @id(<file name>) and validate against the schema"""
        d = lab.SETUPS / "hardened" / "policies"
        for name in ("refund_within_order_total", "stop_after_denial"):
            self.assertTrue((d / f"{name}.cedar").exists(), f"missing {name}.cedar")
        text, _ = pdp.load_policy_text(d)
        self.assertTrue(cedarpy.validate_policies(text, lab.SCHEMA.read_text()).validation_passed)

    def test_c2_order_total(self):
        """challenge 1: A13 (two refunds adding up to more than the order) is stopped"""
        self.assertFalse(suite.run_case("hardened", suite.CHALLENGE[0]))

    def test_c3_after_denial(self):
        """challenge 2: A14 (a refund right after a refusal) is stopped"""
        self.assertFalse(suite.run_case("hardened", suite.CHALLENGE[1]))

    def test_c4_still_works(self):
        """challenge: all 12 attacks still stopped and 6 of 6 normal requests still work"""
        r = suite.evaluate("hardened")
        self.assertFalse(any(r["attacks"].values()), r["attacks"])
        self.assertTrue(all(r["normal"].values()), r["normal"])

    def test_c5_find_probing(self):
        """challenge 3: find_probing() names bob (4 denials from 09:18:30Z) in data/hunt-receipts.jsonl, not alice"""
        rows = lab.read_jsonl(lab.DATA / "hunt-receipts.jsonl")
        self.assertEqual(receipts.find_probing(rows),
                         [{"principal": "bob", "denials": 4, "first_time": "2027-02-13T09:18:30Z"}])


if __name__ == "__main__":
    unittest.main()
