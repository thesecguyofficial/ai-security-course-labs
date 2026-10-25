"""
test_challenge.py: the three-part challenge (make challenge). These tests fail until you finish it. No solution is
included in this repo.

1. Lesson 29.1: write find_new_models() in hunt.py ("models that no one in the account uses").
2. Lesson 29.4: add a rule file setups/hardened/rules/decoy-api-key.json that fires when the decoy Bedrock API key
   is used (case H4). The key itself is never in the log: match what IS there.
3. Lesson 29.6: write find_suspicious_closures() in triage.py (alerts the agent closed although a caller-controlled
   field held instruction-like text).
"""

from __future__ import annotations

import unittest

import hunt
import suite
import triage
from lab import DATA, load_setup, read_json, read_jsonl


class Challenge(unittest.TestCase):
    def test_c1_new_models(self):
        """challenge 1: find_new_models() lists the 4 models first used today, earliest time each"""
        rows = read_jsonl(DATA / "org-day" / "cloudtrail.jsonl")
        got = hunt.find_new_models(rows, read_json(DATA / "baseline-models.json"))
        self.assertEqual(got, [
            {"account": "222222222222", "model": "deepseek.r1-v1:0", "first_seen": "2027-04-10T09:41:17Z"},
            {"account": "222222222222", "model": "meta.llama4-scout-17b-instruct-v1:0",
             "first_seen": "2027-04-10T15:22:09Z"},
            {"account": "333333333333", "model": "openai.gpt-oss-120b", "first_seen": "2027-04-10T16:40:33Z"},
            {"account": "444444444444", "model": "amazon.nova-premier-v1:0", "first_seen": "2027-04-10T13:05:51Z"},
        ])

    def test_c2_rule_exists(self):
        """challenge 2: the new rule is all-Regions and sees read-only events too"""
        rules = {r["file"]: r for r in load_setup("hardened")["rules"]}
        self.assertTrue("decoy-api-key.json" in rules, "missing setups/hardened/rules/decoy-api-key.json")
        self.assertEqual(rules["decoy-api-key.json"]["regions"], "all")
        self.assertEqual(rules["decoy-api-key.json"]["state"], "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS")

    def test_c3_h4_caught(self):
        """challenge 2: case H4 (decoy Bedrock API key used on bedrock-mantle) is caught"""
        self.assertFalse(suite.run_case("hardened", suite.CHALLENGE[0]))

    def test_c4_still_good(self):
        """challenge: all 15 cases still caught and 5 of 5 normal cases still work"""
        r = suite.evaluate("hardened")
        self.assertFalse(any(r["missed"].values()), r["missed"])
        self.assertTrue(all(r["normal"].values()), r["normal"])

    def test_c5_suspicious_closures(self):
        """challenge 3: find_suspicious_closures() names AL-0412 and AL-0419, not the human-closed AL-0414"""
        rows = read_jsonl(DATA / "triage-log.jsonl")
        self.assertEqual(triage.find_suspicious_closures(rows), ["AL-0412", "AL-0419"])


if __name__ == "__main__":
    unittest.main()
