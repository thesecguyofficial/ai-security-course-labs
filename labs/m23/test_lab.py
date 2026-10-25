"""
test_lab.py: `make test`. The recorded trace is coherent and inert, and the provided investigation reads it
correctly. These pass out of the box, before you write any defence.
"""

import json
import re
import unittest

import investigate


class TC_Lab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = investigate.load("app-log.jsonl")
        cls.egress = investigate.load("egress.jsonl")
        cls.gt = json.loads((investigate.TRACE / "ground_truth.json").read_text(encoding="utf-8"))

    def test_01_entry_point(self):
        """investigate: the malicious input entered via retrieved ticket T-4821 (event e07), not the user's message"""
        ep = investigate.entry_point(self.app)
        self.assertEqual(ep["id"], "e07")
        self.assertEqual(ep["source"], "ticket:T-4821")

    def test_02_reached_for(self):
        """investigate: the model reached for a send_email (e09) and a data-bearing URL (e10)"""
        ids = sorted(r["id"] for r in investigate.reached_for(self.app))
        self.assertEqual(ids, ["e09", "e10"])

    def test_03_tempo(self):
        """investigate: account rohan.v made 21 failed sign-ins in a short window"""
        t = investigate.tempo(self.app)
        self.assertEqual([(r["account"], r["attempts"]) for r in t], [("rohan.v", 21)])

    def test_04_loud_egress_beacon(self):
        """investigate: ci-runner-07 made 14 model-API calls and is not a model caller"""
        b = investigate.find_egress_beacon(self.egress)
        self.assertEqual(b, [{"host": "ci-runner-07", "calls": 14}])

    def test_05_ground_truth_is_coherent(self):
        """trace: every id in ground_truth exists, and no normal item is also a finding"""
        app_ids = {e["id"] for e in self.app}
        for fkey, f in self.gt["findings"].items():
            if "event" in f:
                self.assertIn(f["event"], app_ids, fkey)
        for eid in self.gt["normal"]["content_events"] + self.gt["normal"]["tool_calls"] + self.gt["normal"]["model_outputs"]:
            self.assertIn(eid, app_ids)
        finding_events = {f["event"] for f in self.gt["findings"].values() if "event" in f}
        normal_events = set(self.gt["normal"]["content_events"] + self.gt["normal"]["tool_calls"] + self.gt["normal"]["model_outputs"])
        self.assertEqual(finding_events & normal_events, set())

    def test_06_trace_is_inert(self):
        """trace: the injected instruction is a marked LAB-INJECT placeholder inside an HTML comment, using .example"""
        e07 = next(e for e in self.app if e["id"] == "e07")
        self.assertRegex(e07["text"], r"<!--.*LAB-INJECT.*-->")
        self.assertIn("attacker.example", e07["text"])
        # No real, routable exfiltration host: every address in the poisoned text is a reserved .example name.
        for host in re.findall(r"https?://([^/\s]+)", e07["text"]):
            self.assertTrue(host.endswith(".example"), host)


if __name__ == "__main__":
    unittest.main()
