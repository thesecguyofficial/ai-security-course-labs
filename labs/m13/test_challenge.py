"""
test_challenge.py: `make challenge`. Five of these tests FAIL until you do the three-part challenge (README, Step 8).
No solution is included.

  1. (13.1 + M12) screen_chunks() in helpdesk.py, then set "screen_retrieved_chunks": true in setups/ported/app.json
     and setups/harness/app.json: hidden instructions never reach the model, the visible text still does
  2. (13.2) rule_20 in checker.py: flag end-user-reachable principals that may call bedrock-agentcore:InvokeHarness
  3. (13.2) authorise_write() in helpdesk.py: confirmation is not authorisation
"""

import copy
import json
import unittest

import checker
import evaluate
import helpdesk
import twin


SHIPPED_FRONTEND = {
    "arn": "arn:aws:iam::111122223333:role/tsg-web-frontend", "end_user_reachable": True,
    "policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["bedrock-agentcore:InvokeHarness",
               "bedrock-agentcore:InvokeAgentRuntime"], "Resource": "arn:aws:bedrock-agentcore:us-east-1:111122223333:harness/*"}]}}


def screened(name):
    s = twin.Setup(name).copy()
    s.app["screen_retrieved_chunks"] = True
    return s


class TC_Challenge(unittest.TestCase):
    def test_20_no_hidden_instruction_reaches_the_model(self):
        """challenge 1: with screening on, the poisoned note no longer makes the model ask for ANY reset (ported and harness)"""
        for name in ("ported", "harness"):
            r = helpdesk.ask(screened(name), "bob@example.com", "What's new in the VPN client?")
            self.assertEqual((r["executed"], r["denied"]), ([], []), name)

    def test_21_visible_text_survives(self):
        """challenge 1: the vendor note's visible text is still there (N5 still works) and the marker is gone"""
        s = screened("ported")
        resp = twin.retrieve(s, "What's new in the VPN client?", user_context={"userId": "bob@example.com"})
        kept = helpdesk.screen_chunks(copy.deepcopy(resp["retrievalResults"]), s)
        text = " ".join(c["content"]["text"] for c in kept)
        self.assertIn("VPN client 7.2 is rolling out", text)
        self.assertNotIn("LAB-INJECTED-DIRECTIVE", text)

    def test_22_rule_20_flags_the_web_frontend(self):
        """challenge 2: M13-20 (HIGH) names tsg-web-frontend, which the browser controls and which may call InvokeHarness"""
        s = twin.Setup("harness").copy()
        s.invokers = json.loads((twin.HERE / "setups/harness/invokers.json").read_text())   # as shipped
        s.invokers["principals"].setdefault("tsg-web-frontend", SHIPPED_FRONTEND)
        found = [f for f in checker.run(s) if f.rule == "M13-20"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "HIGH")
        self.assertIn("tsg-web-frontend", found[0].message)

    def test_23_rule_20_no_false_positive(self):
        """challenge 2: M13-20 stays quiet when only the backend can invoke the harness, and on Classic setups"""
        s = twin.Setup("harness").copy()
        for p in s.invokers["principals"].values():
            p["end_user_reachable"] = False
        self.assertEqual(checker.rule_20(s), [])
        self.assertEqual(checker.rule_20(twin.Setup("ported")), [])

    def test_24_confirmation_is_not_authorisation(self):
        """challenge 3: Bob confirms a reset of the CEO's MFA and it is still refused (A5 fails, ported and harness)"""
        a5 = next(c for c in evaluate.CASES["attacks"] if c["id"] == "A5")
        for name in ("ported", "harness"):
            self.assertFalse(evaluate.run_case(a5, twin.Setup(name))["worked"], name)

    def test_25_legitimate_resets_still_work(self):
        """challenge 3: Bob can still reset his own MFA, and Alice (IT) can still reset the CEO's"""
        for name in ("ported", "harness"):
            ok = {n["id"]: n["works"] for n in evaluate.run_suite(name)["normal"]}
            self.assertTrue(ok["N2"] and ok["N4"], name)

    def test_26_what_is_left(self):
        """after the challenge: ported has 0 findings and 0 attacks; on the harness, A8 is either flagged by your rule or fixed"""
        self.assertEqual(checker.run("ported"), [])
        self.assertEqual(evaluate.score(evaluate.run_suite("ported"))["worked_ids"], [])
        left = evaluate.score(evaluate.run_suite("harness"))["worked_ids"]
        found = [(f.rule, f.severity) for f in checker.run("harness")]
        self.assertIn((left, found), [(["A8"], [("M13-20", "HIGH")]), ([], [])])


if __name__ == "__main__":
    unittest.main()
