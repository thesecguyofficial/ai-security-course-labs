"""
test_lab.py: `make test`. The recorded multi-agent run is coherent and inert, and the provided trace reads the
propagation correctly. These pass out of the box, before you write any containment.
"""

import json
import re
import unittest

import trace


class TC_Lab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.txn = trace.load("transcript.jsonl")
        cls.attack = trace.events("a1", cls.txn)
        cls.gt = json.loads((trace.RECORDING / "ground_truth.json").read_text(encoding="utf-8"))

    def test_01_entry_point(self):
        """trace: the instruction entered at t01, when the intake agent read email E-77"""
        ep = trace.entry_point(self.attack)
        self.assertEqual(ep["id"], "t01")
        self.assertEqual(ep["agent"], "intake")

    def test_02_propagation_path(self):
        """trace: the instruction crossed two boundaries, t02 (intake->planner) and t03 (planner->mailer)"""
        ids = [h["id"] for h in trace.propagation_path(self.attack)]
        self.assertEqual(ids, ["t02", "t03"])

    def test_03_sink_action(self):
        """trace: the sink is t04, the mailer sending to an outside domain"""
        sa = trace.sink_action(self.attack)
        self.assertEqual(sa["id"], "t04")
        self.assertEqual(sa["agent"], "mailer")
        self.assertTrue(sa["to"].endswith("attacker.example"))

    def test_04_ground_truth_is_coherent(self):
        """recording: ground_truth ids exist, and no normal item is on the attack path"""
        ids = {e["id"] for e in self.txn}
        for key in ("entry_point", "sink_action"):
            self.assertIn(self.gt[key], ids)
        for hid in self.gt["propagation_handoffs"]:
            self.assertIn(hid, ids)
        path = set(self.gt["propagation_handoffs"]) | {self.gt["entry_point"], self.gt["sink_action"]}
        normal = set(self.gt["normal"]["handoffs"]) | set(self.gt["normal"]["tool_calls"])
        self.assertEqual(path & normal, set())

    def test_05_recording_is_inert(self):
        """recording: the injected instruction is a marked LAB-INJECT placeholder in an HTML comment, using .example"""
        t01 = next(e for e in self.txn if e["id"] == "t01")
        self.assertRegex(t01["content"], r"<!--.*LAB-INJECT.*-->")
        self.assertIn("attacker.example", t01["content"])

    def test_06_normal_runs_carry_no_instruction(self):
        """recording: the normal runs n1 and n2 contain no instruction-bearing hand-off (including a benign repeat)"""
        for e in self.txn:
            if e.get("kind") == "handoff" and e.get("session") in ("n1", "n2"):
                self.assertFalse(trace.instruction_bearing(e["message"]), e["id"])


if __name__ == "__main__":
    unittest.main()
