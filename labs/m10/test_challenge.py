"""
test_challenge.py: `make challenge`. Three of these fail until you finish the challenge (README, Step 7).

1. Close the bedrock-mantle gap in fixes/scp-model-allowlist.json (separate IAM namespace, model in a condition key).
2. Make fixes/scp-bedrock-api-keys.json refuse sandbox keys that NEVER expire (no age in the request at all).
3. Write rule_mantle_inference() in hunt.py.
No solution is included.
"""

import unittest

import attack
import hunt

STEP = {s.sid: s for s in attack.STEPS}


class T6_Challenge(unittest.TestCase):
    def test_18_mantle_unapproved_model_denied(self):
        """challenge: the stolen chatbot role can't run an unapproved model on bedrock-mantle"""
        self.assertFalse(attack.run_step(STEP["B4"], "safe").allowed, "B4 is still ALLOWED: the allow-list ignores bedrock-mantle")

    def test_19_mantle_approved_model_still_allowed(self):
        """challenge: the chatbot's approved model on bedrock-mantle still works"""
        self.assertTrue(attack.run_step(STEP["L4"], "safe").allowed)

    def test_20_never_expiring_key_denied(self):
        """challenge: a sandbox Bedrock API key with no expiry at all is refused"""
        self.assertFalse(attack.run_step(STEP["C1"], "safe").allowed,
                         "C1 is still ALLOWED: NumericGreaterThan is false when the age key is missing")

    def test_21_hunt_sees_mantle(self):
        """challenge: rule_mantle_inference flags the 20 unapproved CreateInference data events"""
        records, _ = hunt.hunt()
        base = hunt.build_baseline(records, hunt.dt.datetime(2026, 10, 14, tzinfo=hunt.dt.timezone.utc))
        hits = hunt.rule_mantle_inference(records, base, None)
        events = [e for h in hits for e in h.events]
        self.assertEqual(len(events), 20, f"{len(events)} of 20 unapproved mantle events flagged")
        self.assertTrue(all(h.rule == "H09" for h in hits))

    def test_22_hunt_mantle_no_false_positives(self):
        """challenge: the chatbot's hourly approved-model mantle calls are not flagged"""
        records, _ = hunt.hunt()
        base = hunt.build_baseline(records, hunt.dt.datetime(2026, 10, 14, tzinfo=hunt.dt.timezone.utc))
        events = [e for h in hunt.rule_mantle_inference(records, base, None) for e in h.events]
        self.assertFalse([e for e in events if e["requestParameters"]["model"] == "anthropic.claude-haiku-4-5"])


if __name__ == "__main__":
    unittest.main()
