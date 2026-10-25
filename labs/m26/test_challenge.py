"""The M26 challenge. These tests fail until you finish the three parts in the README. No solution is included."""

import pathlib
import unittest

import cachetest
import hunt
import scan

HERE = pathlib.Path(__file__).resolve().parent
FIRST, HARD = str(HERE / "stacks" / "first-draft"), str(HERE / "stacks" / "hardened")


class TestChallenge(unittest.TestCase):
    def test_c1_ray_rule(self):
        """C1 (26.1) scan: RAY-01 flags the first draft's Ray head and stays quiet on the hardened one"""
        first = [f for f in scan.scan(FIRST) if f.rule == "RAY-01"]
        self.assertTrue(first, "write check_ray() in scan.py")
        self.assertTrue(all("ray-head" in f.where for f in first))
        self.assertEqual([f.where for f in scan.scan(HARD) if f.rule == "RAY-01"], [])

    def test_c2_client_cannot_pick_another_tenants_cache(self):
        """C2 (26.2) cache: a tenant's own apps still share a group, but globex can't join acme's group by name"""
        res, _ = cachetest.run("hardened", challenge=True)
        self.assertGreater(res["group_same_tenant"]["cached_tokens"], 0, "acme's two apps must still share")
        self.assertEqual(cachetest.leaked(res["group_guessed"], "globex"), 0, "fix salt_for() in gateway.py")

    def test_c3_management_calls(self):
        """C3 (26.0, 26.1) hunt: find_management_calls() lists every management call not from the pipeline"""
        records = hunt.load(HERE / "data" / "gateway-log.jsonl")
        calls = hunt.find_management_calls(records, {"10.0.9.5"})
        self.assertEqual([(ip, p) for _, ip, p in calls],
                         [("198.51.100.7", "/api/pull"), ("198.51.100.7", "/api/delete"),
                          ("10.0.3.3", "/update_weights")])


if __name__ == "__main__":
    unittest.main()
