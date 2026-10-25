"""test_challenge.py: the three-part challenge (make challenge). These tests fail until you finish it. No solution is
included in this repo.

1. Lesson 27.2: write rules E2 and D3 in checker.py. configs/second-draft.json passes every rule as shipped, yet it
   has two gaps: a custom endpoint policy that still allows every resource, and a DNS walled garden left in ALERT.
2. Lesson 27.2: write burst_of_blocked_names() in alerts.py (5+ distinct blocked names from one source in 10 minutes).
3. Lesson 27.1: write shared_sessions() in alerts.py (one session ID used by more than one signed-in user).
"""

from __future__ import annotations

import os
import tempfile
import unittest

import alerts
import checker
import lab


class Challenge(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["M27_STATE"] = self._tmp.name

    def tearDown(self):
        os.environ.pop("M27_STATE", None)
        self._tmp.cleanup()

    def test_c1_second_draft(self):
        """challenge 1: the checker finds exactly E2 (s3 endpoint resources '*') and D3 (default ALERT) in the second draft"""
        found = checker.review(lab.load_config("second-draft"))
        self.assertEqual(sorted(f.rule for f in found), ["D3", "E2"])
        self.assertIn("s3", [f.detail for f in found if f.rule == "E2"][0])

    def test_c2_still_clean(self):
        """challenge 1: the hardened config still has 0 findings with the new rules"""
        self.assertEqual(checker.review(lab.load_config("hardened")), [])

    def test_c3_burst(self):
        """challenge 2: burst_of_blocked_names() pages on 10.0.1.25 only (6 distinct names from 09:10:00Z)"""
        rows = lab.read_jsonl(lab.DATA / "morning-resolver-log.jsonl")
        self.assertEqual(alerts.burst_of_blocked_names(rows),
                         [{"srcaddr": "10.0.1.25", "distinct_blocked": 6, "first_time": "2027-03-27T09:10:00Z"}])

    def test_c4_shared_sessions(self):
        """challenge 3: shared_sessions() finds cis-0003, used by alice and chen"""
        rows = lab.read_jsonl(lab.DATA / "app-sessions.jsonl")
        self.assertEqual(alerts.shared_sessions(rows), [{"session_id": "cis-0003", "users": ["alice", "chen"]}])


if __name__ == "__main__":
    unittest.main()
