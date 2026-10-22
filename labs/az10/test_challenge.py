"""
test_challenge.py: `make challenge`. Three of these fail until you finish the challenge (README, Step 7);
the fourth fails only if your H07 rule is too broad.

1. fixes/policy-assignments.json: make the gpt-5 asset ID match gpt-5 only (B4 and B8 must be denied).
2. fixes/estate.json: turn key access off on the sandbox resource too (A3 must get 401).
3. hunt.py: write rule_content_filter_change() (H07).
No solution is included.
"""

import unittest

import attack
import hunt

STEP = {s.sid: s for s in attack.STEPS}
CI = "00001111-aaaa-2222-bbbb-3333cccc4444"


class T6_Challenge(unittest.TestCase):
    def test_18_allowlist_is_exact(self):
        """challenge: gpt-5.4 and gpt-5.2 v2 are denied, and the approved gpt-5 rollout still works"""
        for sid in ("B4", "B8"):
            self.assertFalse(attack.run_step(STEP[sid], "safe").allowed, f"{sid} is still ALLOWED: the gpt-5 asset ID is a prefix")
        self.assertTrue(attack.run_step(STEP["L2"], "safe").allowed)

    def test_19_sandbox_key_refused(self):
        """challenge: the leaked SANDBOX key gets 401, and the data scientist (Entra ID) still works"""
        self.assertFalse(attack.run_step(STEP["A3"], "safe").allowed, "A3 is still ALLOWED: sandbox key access is on")
        self.assertTrue(attack.run_step(STEP["L3"], "safe").allowed)

    def test_20_hunt_content_filter_change(self):
        """challenge: H07 flags the content-filter change made with the stolen CI secret"""
        logs, _ = hunt.hunt()
        hits = hunt.rule_content_filter_change(logs, hunt.parse("2026-10-14T00:00:00Z"))
        self.assertEqual([(h.rule, h.who) for h in hits], [("H07", CI)],
                         "rule_content_filter_change() must return one H07 hit for the CI identity")
        self.assertEqual(len(hits[0].evidence), 1)

    def test_21_hunt_content_filter_admin_ok(self):
        """challenge: a content-filter change by the platform admin is NOT flagged"""
        logs, _ = hunt.hunt()
        for e in logs.activity:
            if "raiPolicies" in e["operationName"]["value"]:
                e["caller"] = "platform-admin@contoso.com"
        self.assertEqual(hunt.rule_content_filter_change(logs, hunt.parse("2026-10-14T00:00:00Z")), [])


if __name__ == "__main__":
    unittest.main()
