"""
test_challenge.py: `make challenge`. These FAIL until you write containment.py (Step 3) and the three-part
challenge (Step 5). No solution is included.

  Step 3: the four controls in containment.py (replay contains the recording and the variants).
  Challenge 1 (24.2): find_unlabelled_crossings() in trace.py.
  Challenge 2 (24.3): memory_residue() in containment.py (what the kill-switch must quarantine).
  Challenge 3 (24.4): detect and circuit_breaker stay precise on a benign broadcast (a negative control).
"""

import unittest

import containment
import replay
import trace


class TC_Challenge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.txn = trace.load("transcript.jsonl")
        cls.attack = trace.events("a1", cls.txn)
        cls.variants = [e for e in trace.load("variants.jsonl", trace.HERE / "data") if e.get("session") == "va"]

    def test_07_recorded_contained(self):
        """step 3: the recorded attack is contained, all 5 controls fire, 0 false positives"""
        r = replay.score_attack(self.attack)
        self.assertTrue(r["contained"], "the external send still executes")
        self.assertEqual(r["missed"], [], f"controls not firing: {r['missed']}")
        self.assertEqual(replay.false_positives(self.txn), [], "false positives on normal runs")

    def test_08_variants_contained(self):
        """step 3: the ADAPTED variants are contained too, all 5 controls fire (behaviour, not wording)"""
        r = replay.score_attack(self.variants)
        self.assertTrue(r["contained"], "a variant send still executes")
        self.assertEqual(r["missed"], [], f"controls not firing on variants: {r['missed']}")

    def test_09_find_unlabelled_crossings(self):
        """challenge 1: find_unlabelled_crossings lists the two instruction-bearing hand-offs t02 and t03"""
        self.assertEqual(trace.find_unlabelled_crossings(self.attack), ["t02", "t03"])

    def test_10_memory_residue(self):
        """challenge 2: memory_residue finds t02, the memory-channel write the kill-switch must quarantine"""
        self.assertEqual(containment.memory_residue(self.attack, replay.CONFIG), ["t02"])

    def test_11_precise_on_benign_broadcast(self):
        """challenge 3: a benign status sent to two agents must not trip the breaker or the detection"""
        broadcast = [
            {"id": "b1", "session": "nb", "kind": "handoff", "from": "planner", "to": "mailer", "channel": "task",
             "message": "Notify: maintenance window confirmed for Saturday 02:00 IST."},
            {"id": "b2", "session": "nb", "kind": "handoff", "from": "planner", "to": "intake", "channel": "task",
             "message": "Notify: maintenance window confirmed for Saturday 02:00 IST."},
        ]
        self.assertFalse(containment.circuit_breaker(broadcast, replay.CONFIG))
        self.assertEqual(containment.detect(broadcast, replay.CONFIG), [])


if __name__ == "__main__":
    unittest.main()
