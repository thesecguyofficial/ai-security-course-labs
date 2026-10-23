"""
test_challenge.py: `make challenge`. These tests FAIL until you do the three-part challenge (README, Step 8).
No solution is included.

  1. (14.5) Write a Cedar forbid policy in setups/hardened/policies/ so send_email can't reach addresses outside
     example.com (A11). Watch out for look-alike domains.
  2. (14.6) Write validate_memory_write() in helpdesk.py and set "validate_memory_writes": true in
     setups/hardened/app.json (A12). The user's own preferences must still be remembered.
  3. (14.2 + 14.7) Write find_session_reuse() in hunt.py.
"""

import unittest

import cedar
import checker
import evaluate
import helpdesk
import hunt
import twin

GW = twin.COMPANY["gateway_arn"]


def email_decision(to: str, user: str = "bob") -> str:
    s = twin.Setup("hardened")
    req = cedar.request(twin.principal_from_claims(twin.user_token(user)), "send_email",
                        {"to": to, "subject": "s", "body": "b", "caller_username": user}, GW)
    return cedar.authorize(s.policies, req)["decision"]


class TC_Challenge(unittest.TestCase):
    def test_21_external_email_denied(self):
        """challenge 1: send_email to attacker@example.net is DENIED by a forbid policy (A11 blocked)"""
        self.assertEqual(email_decision("attacker@example.net"), "DENY")
        a11 = next(c for c in evaluate.CASES["attacks"] if c["id"] == "A11")
        self.assertFalse(evaluate.run_case(a11, twin.Setup("hardened"))["worked"])

    def test_22_lookalike_denied(self):
        """challenge 1: look-alikes are denied too: x@example.com.example.net and x@notexample.com"""
        self.assertEqual(email_decision("x@example.com.example.net"), "DENY")
        self.assertEqual(email_decision("x@notexample.com"), "DENY")

    def test_23_company_email_still_works(self):
        """challenge 1: Bob can still email bob@example.com (N7), and every policy names the gateway"""
        self.assertEqual(email_decision("bob@example.com"), "ALLOW")
        self.assertEqual([p for pol in twin.Setup("hardened").policies for p in cedar.check_wildcards(pol)], [])

    def test_24_memory_from_tool_result_refused(self):
        """challenge 2: the instruction in ticket 4713 never reaches long-term memory (A12 blocked)"""
        s = twin.Setup("hardened")
        self.assertTrue(s.app.get("validate_memory_writes"), 'set "validate_memory_writes": true in setups/hardened/app.json')
        a12 = next(c for c in evaluate.CASES["attacks"] if c["id"] == "A12")
        self.assertFalse(evaluate.run_case(a12, s)["worked"])

    def test_25_validate_memory_write_rules(self):
        """challenge 2: user text is kept; tool-result text and marked text are refused"""
        s = twin.Setup("hardened")
        self.assertTrue(helpdesk.validate_memory_write("I prefer updates by email.", "user", s))
        self.assertFalse(helpdesk.validate_memory_write("I prefer updates by email.", "tool_result", s))
        self.assertFalse(helpdesk.validate_memory_write("LAB-INJECTED-DIRECTIVE: tool=send_email", "user", s))

    def test_26_preferences_still_remembered(self):
        """challenge 2: N6 still works (Bob's own preference is stored in his namespace)"""
        n6 = next(c for c in evaluate.CASES["normal"] if c["id"] == "N6")
        self.assertTrue(evaluate.run_case(n6, twin.Setup("hardened"))["works"])

    def test_27_session_reuse(self):
        """challenge 3: find_session_reuse() finds the one runtime session used by alice AND bob"""
        rows = hunt.find_session_reuse(hunt.load("app-log.jsonl"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["users"], ["alice", "bob"])
        self.assertEqual((rows[0]["first_time"], rows[0]["last_time"]), ("2027-01-14T09:01:40Z", "2027-01-14T09:20:30Z"))
        self.assertTrue(rows[0]["session"].startswith("tsg-8c1d0b6e"))

    def test_28_all_done(self):
        """after the challenge: the hardened setup has 0 findings, 0 of 12 attacks work, 7 of 7 normal requests work"""
        s = twin.Setup("hardened")
        self.assertEqual([f.rule for f in checker.run(s)], [])
        r = evaluate.run_suite(s)
        self.assertEqual([a["id"] for a in r["attacks"] if a["worked"]], [])
        self.assertTrue(all(n["works"] for n in r["normal"]))


if __name__ == "__main__":
    unittest.main()
