"""
test_challenge.py: `make challenge`. Three of these fail until you finish the challenge (README, Step 7).

1. Enforce the VPC Service Controls perimeter in twin/hardened/plan.json, without locking out the office analysts.
2. Write rule_rep_endpoint_private_path() (GC11-16) in checker.py.
3. Take durable caching off the table for the Helpdesk project (twin/hardened/app.json, cache_config).
No solution is included.
"""

import unittest

import attack
import checker

STEP = {s.sid: s for s in attack.STEPS}


class T7_Challenge(unittest.TestCase):
    def test_22_perimeter_blocks_the_copy(self):
        """challenge: the hijacked Helpdesk's copy to an outside project is DENIED by the enforced perimeter"""
        d = attack.run_step(STEP["A3"], "hardened")
        self.assertFalse(d.allowed, "A3 is still ALLOWED: the perimeter is only in dry run")
        self.assertIn("VPC Service Controls (enforced)", d.why)

    def test_23_office_analysts_still_work(self):
        """challenge: the office analysts can still query the tickets dataset once the perimeter is enforced"""
        self.assertTrue(attack.run_step(STEP["L3"], "hardened").allowed,
                        "L3 is DENIED: add an access level for 198.51.100.0/24 and an ingress rule for BigQuery")

    def test_24_helpdesk_still_works(self):
        """challenge: the Helpdesk and the summariser keep working inside the perimeter"""
        for sid in ("L1", "L2", "L4"):
            self.assertTrue(attack.run_step(STEP[sid], "hardened").allowed, sid)

    def test_25_gc11_16_flags_rep_endpoint(self):
        """challenge: GC11-16 flags the eu-multiregion twin (rep endpoint, only PGA / global-API PSC)"""
        rules = [f.rule for f in checker.run("eu-multiregion")]
        self.assertEqual(rules.count("GC11-16"), 1, "GC11-16 didn't fire on twin/eu-multiregion")

    def test_26_gc11_16_quiet_elsewhere(self):
        """challenge: GC11-16 stays quiet on the today and hardened twins"""
        for twin in ("today", "hardened"):
            self.assertNotIn("GC11-16", sorted({f.rule for f in checker.run(twin)}), twin)

    def test_27_no_durable_cache(self):
        """challenge: the hardened twin no longer allows durable caching (no GC11-11)"""
        rules = sorted({f.rule for f in checker.run("hardened")})
        self.assertNotIn("GC11-11", rules, "set cache_config in twin/hardened/app.json")


if __name__ == "__main__":
    unittest.main()
