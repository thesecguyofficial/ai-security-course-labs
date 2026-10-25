"""
test_challenge.py: the three-part challenge (make challenge). These tests fail until you finish it. No solution is
included in this repo.

1. Lesson 25.2: write gates.slice_gate() so a quant that keeps the overall numbers but drops one slice is refused
   (data/community-quant-v2.json, case C1).
2. Lessons 25.3 to 25.5: write deploy.check_lineage() so a release built from a base nobody approved is refused
   (data/unapproved-base.json, case C2), using the ML-BOM's pedigree and data/approved-bases.json.
3. Lesson 25.5: write hunt.find_unverified_deploys() (deploys that went ahead without a verified signature).
"""

from __future__ import annotations

import unittest

import ci
import deploy
import gates
import hunt
import lab
import suite


def setUpModule():
    ci.build()
    lab.ensure_keys()


class Challenge(unittest.TestCase):
    def test_c1_slice_gate(self):
        """challenge 1: slice_gate() names the data-export slice for community-quant-v2"""
        cases = gates.load_evals()
        import toymodel
        m = gates.compare(gates.evaluate(toymodel.load(suite.BASE), cases),
                          gates.evaluate(toymodel.load(lab.MODELS / "community-quant-v2"), cases), cases)
        rules = lab.setup_config("hardened", "ci")["gate"]
        self.assertEqual(gates.overall_gate(m, rules), [], "v2 should pass the overall gate")
        problems = gates.slice_gate(m, rules)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("data-export", problems[0])

    def test_c2_quant_case(self):
        """challenge 1: case C1 (community quant v2 through CI) is stopped"""
        self.assertFalse(suite.run_case("hardened", suite.c1_slice_quant))

    def test_c3_lineage(self):
        """challenge 2: case C2 (a release from an unapproved base) is refused at deploy"""
        self.assertFalse(suite.run_case("hardened", suite.c2_unapproved_base))
        self.assertNotEqual(deploy.check_lineage({"components": [{"type": "machine-learning-model"}]},
                                                 lab.read_json(lab.DATA / "approved-bases.json")["approved"]), [],
                            "a model with no pedigree at all must be refused too")

    def test_c4_still_works(self):
        """challenge: all 7 attacks still stopped and 3 of 3 normal releases still deploy"""
        r = suite.evaluate("hardened")
        self.assertFalse(any(r["attacks"].values()), r["attacks"])
        self.assertTrue(all(r["normal"].values()), r["normal"])

    def test_c5_hunt(self):
        """challenge 3: find_unverified_deploys() finds 1.1.0-hotfix (failed) and 1.1.2 (skipped), oldest first"""
        rows = lab.read_jsonl(lab.DATA / "deploy-history.jsonl")
        self.assertEqual(hunt.find_unverified_deploys(rows), [
            {"time": "2027-03-12T08:40:02Z", "release": "1.1.0-hotfix", "setup": "pipeline-b", "verify": "failed"},
            {"time": "2027-03-12T09:47:55Z", "release": "1.1.2", "setup": "pipeline-b", "verify": "skipped"},
        ])


if __name__ == "__main__":
    unittest.main()
