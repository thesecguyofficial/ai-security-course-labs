"""
test_challenge.py: `make challenge`. These tests FAIL until you do the two-part challenge (README, step 9).
No solution is included.

  1. (20.6) Write allowed_recipient() in services.py so the hardened mail API only sends to the user's own
     address (the token's `email` claim). A8 must be blocked, and every normal request must still work.
  2. (20.3) Write find_replays() in hunt.py: tokens used for more than one successful write.
"""

import pathlib
import unittest

import evaluate
import hunt
import services


class TC_Challenge(unittest.TestCase):
    def test_21_a8_blocked(self):
        """challenge 1: hardened A8 is blocked (no email to evil.example)"""
        ok, evidence, _ = evaluate.run_one("hardened", evaluate.a8_injected_recipient)
        self.assertFalse(ok, evidence)

    def test_22_normal_still_work(self):
        """challenge 1: hardened N1 to N3 still work (Alice still gets her own email)"""
        for tid, fn in evaluate.NORMAL.items():
            ok, evidence, _ = evaluate.run_one("hardened", fn)
            self.assertTrue(ok, f"{tid}: {evidence}")

    def test_23_rule_uses_the_token(self):
        """challenge 1: the rule follows the token's email claim, not a hard-coded name"""
        self.assertTrue(services.allowed_recipient({"email": "carol@example.com"}, "carol@example.com"))
        self.assertFalse(services.allowed_recipient({"email": "carol@example.com"}, "alice@example.com"))
        self.assertFalse(services.allowed_recipient({}, "alice@example.com"))
        self.assertFalse(services.allowed_recipient({"email": "carol@example.com"}, "Carol@example.com.evil.example"))

    def test_24_find_replays(self):
        """challenge 2: find_replays() finds the one token used for 3 sends"""
        rows = hunt.load(pathlib.Path(__file__).parent / "data" / "incident" / "api-audit.jsonl")
        found = hunt.find_replays(rows)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["writes"], 3)
        self.assertEqual(found[0]["first_ts"], 1800000074)
        self.assertEqual(found[0]["last_ts"], 1800000185)

    def test_25_replays_ignore_reads_and_refusals(self):
        """challenge 2: reads and refused calls are not writes"""
        rows = [{"api": "tickets-api", "op": "GET", "result": "ok", "jti": "a", "ts": 1},
                {"api": "tickets-api", "op": "GET", "result": "ok", "jti": "a", "ts": 2},
                {"api": "mail-api", "op": "send", "result": "ok", "jti": "b", "ts": 3},
                {"api": "mail-api", "op": "send", "result": "refused", "jti": "b", "ts": 4}]
        self.assertEqual(hunt.find_replays(rows), [])


if __name__ == "__main__":
    unittest.main()
