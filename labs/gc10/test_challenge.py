"""
test_challenge.py: `make challenge`. Three of these fail until you finish the challenge (README, Step 7).

1. Give the chatbot-frontend key an application restriction (fixes/api-keys.json) so a copied key fails elsewhere.
2. Write an organization-level vertexai.allowedModels allow-list (fixes/orgpolicy-org-allowed-models.json).
3. Write rule_ai_enabled_in_unapproved_project() (H09) in hunt.py.
No solution is included.
"""

import unittest

import attack
import hunt

STEP = {s.sid: s for s in attack.STEPS}


class T6_Challenge(unittest.TestCase):
    def test_20_copied_frontend_key_fails_elsewhere(self):
        """challenge: the chatbot-frontend key copied from the repo is refused from the attacker's IP"""
        self.assertFalse(attack.run_step(STEP["A1"], "safe").allowed,
                         "A1 is still ALLOWED: the key has an API restriction but no application restriction")

    def test_21_frontend_still_works(self):
        """challenge: the chatbot web tier still works with the same key from 192.0.2.10"""
        self.assertTrue(attack.run_step(STEP["L2"], "safe").allowed)

    def test_22_org_allow_list_stops_claude_in_the_sandbox(self):
        """challenge: legacy-etl can't run Claude Opus 4.7 in the sandbox, even with its org-wide IAM grant"""
        self.assertFalse(attack.run_step(STEP["B1"], "safe").allowed,
                         "B1 is still ALLOWED: nothing above the sandbox allow-lists models")

    def test_23_sandbox_work_still_runs(self):
        """challenge: data science and the CI eval keep their approved sandbox models"""
        for sid in ("L3", "L4", "L5", "L6"):
            self.assertTrue(attack.run_step(STEP[sid], "safe").allowed, sid)

    def test_24_h09_flags_the_attackers_enable(self):
        """challenge: H09 flags Agent Platform being enabled in example-ci (not approved for AI)"""
        records, hits = hunt.hunt()
        h09 = [h for h in hits if h.rule == "H09"]
        events = [e for h in h09 for e in h.events]
        self.assertEqual(len(events), 1, f"{len(events)} of 1 EnableService event flagged")
        self.assertEqual(hunt.project(events[0]), "example-ci")

    def test_25_h09_ignores_the_sandbox(self):
        """challenge: H09 does not flag alice enabling Agent Platform in the approved sandbox"""
        records, hits = hunt.hunt()
        events = [e for h in hits if h.rule == "H09" for e in h.events]
        self.assertFalse([e for e in events if hunt.project(e) == "example-ds-sandbox"])


if __name__ == "__main__":
    unittest.main()
