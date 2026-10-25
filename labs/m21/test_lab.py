"""
test_lab.py: the proof for lab M21 (make test).

"first draft:" tests assert the attacks WORK against the first draft (a test that can never fail proves nothing).
"hardened:" tests assert each control holds and normal work still gets done. "cedar:" tests pin the engine behaviour
the lessons rely on. "audit:" tests prove the receipts catch tampering. Every test uses its own empty state folder.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

import cedarpy

import approvals
import lab
import pdp
import receipts
import suite
import tools
from helpdesk import run_ticket
from pep import PEP, Session

SAM = Session("bob", "T-502", "sam@customer.example")
BIG = '{"order_id": "O-1002", "amount_cents": 25000, "currency": "USD"}'


class LabTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["M21_STATE"] = self._tmp.name
        lab.CLOCK.set(suite.START)

    def tearDown(self):
        lab.CLOCK.set(None)
        os.environ.pop("M21_STATE", None)
        self._tmp.cleanup()


class FirstDraft(LabTest):
    def test_01_eleven_of_twelve_attacks_work(self):
        """first draft: 11 of 12 attacks work (only the obvious $950 try is held), and 6 of 6 normal requests work"""
        r = suite.evaluate("first-draft")
        self.assertEqual([c for c, hit in r["attacks"].items() if not hit], ["A2"])
        self.assertTrue(all(r["normal"].values()))

    def test_02_parser_differential(self):
        """first draft: duplicate key, the policy sees 5000 cents and the tool pays 95000"""
        out = PEP("first-draft").handle(Session("bob", "T-605", "mallory@attacker.example"), "issue_refund",
                                        '{"order_id": "O-3001", "amount_cents": 5000, "currency": "USD", '
                                        '"amount_cents": 95000}')
        self.assertEqual(out.decision, "ALLOW")
        self.assertEqual(tools.ledger()[0]["paid_cents"], 95000)

    def test_03_no_decision_treated_as_allow(self):
        """first draft: a number Cedar can't hold gives NoDecision, and 'not Deny' is read as allow"""
        out = PEP("first-draft").handle(Session("bob", "T-612", "mallory@attacker.example"), "issue_refund",
                                        '{"order_id": "O-3001", "amount_cents": 1180591620717411303424, "currency": "USD"}')
        self.assertEqual(out.decision, "ALLOW")
        self.assertIn("not a Deny", out.reason)

    def test_04_missing_attribute_skips_the_forbid(self):
        """first draft: amount left out, the forbid errors and is skipped; the tool refunds the full $1,200"""
        out = PEP("first-draft").handle(Session("bob", "T-606", "mallory@attacker.example"), "issue_refund",
                                        '{"order_id": "O-3001", "currency": "USD"}')
        self.assertEqual(out.decision, "ALLOW")
        self.assertEqual(tools.ledger()[0]["paid_cents"], 120000)
        r = receipts.read_all()[0]
        self.assertTrue(any("amount_cents" in e for e in r["errors"]), r["errors"])


class Hardened(LabTest):
    def test_05_every_attack_stopped(self):
        """hardened: 0 of 12 attacks work and 6 of 6 normal requests still work"""
        r = suite.evaluate("hardened")
        self.assertFalse(any(r["attacks"].values()), r["attacks"])
        self.assertTrue(all(r["normal"].values()), r["normal"])

    def test_06_over_limit_is_deferred_not_run(self):
        """hardened: a $250 refund is held for a supervisor (DEFER) and not run"""
        out = PEP("hardened").handle(SAM, "issue_refund", BIG)
        self.assertEqual((out.decision, out.ran), ("DEFER", False))
        self.assertEqual(tools.ledger(), [])

    def test_07_four_eyes(self):
        """hardened: only a supervisor approves, and never their own request (alice's $250 needs someone else)"""
        out = PEP("hardened").handle(SAM, "issue_refund", BIG)
        for who in ("bob", "dana"):
            with self.assertRaises(ValueError):
                approvals.decide(out.approval_id, who)
        mine = PEP("hardened").handle(Session("alice", "T-502", "sam@customer.example"), "issue_refund", BIG)
        self.assertEqual(mine.decision, "DEFER")
        with self.assertRaisesRegex(ValueError, "four-eyes"):
            approvals.decide(mine.approval_id, "alice")

    def test_08_approval_bound_to_exact_arguments(self):
        """hardened: an approval for $250 does not cover $240 or another order; the exact call runs once"""
        pep = PEP("hardened")
        a = pep.handle(SAM, "issue_refund", BIG).approval_id
        approvals.decide(a, "alice")
        other = pep.handle(SAM, "issue_refund", '{"order_id": "O-1002", "amount_cents": 24000, "currency": "USD"}')
        self.assertEqual(other.decision, "DEFER")
        self.assertNotEqual(other.approval_id, a)
        self.assertEqual(pep.handle(SAM, "issue_refund", BIG).decision, "ALLOW")
        self.assertNotEqual(pep.handle(SAM, "issue_refund", BIG).decision, "ALLOW", "approval reused")
        self.assertEqual([r["paid_cents"] for r in tools.ledger()], [25000])

    def test_09_approval_expires(self):
        """hardened: an approval is good for 15 minutes"""
        pep = PEP("hardened")
        approvals.decide(pep.handle(SAM, "issue_refund", BIG).approval_id, "alice")
        lab.CLOCK.advance(16 * 60)
        self.assertEqual(pep.handle(SAM, "issue_refund", BIG).decision, "DEFER")

    def test_10_tampered_approval_rejected(self):
        """hardened: editing the arguments of a signed approval in approvals.json breaks its signature"""
        pep = PEP("hardened")
        a = pep.handle(SAM, "issue_refund", BIG).approval_id
        approvals.decide(a, "alice")
        p = lab.state_dir() / "approvals.json"
        db = json.loads(p.read_text())
        bigger = {"order_id": "O-1002", "amount_cents": 95000, "currency": "USD"}
        db[a]["args"], db[a]["args_sha256"] = bigger, lab.sha256(lab.canonical(bigger))
        p.write_text(json.dumps(db))
        out = pep.handle(SAM, "issue_refund", json.dumps(bigger))
        self.assertNotEqual(out.decision, "ALLOW")

    def test_11_fourth_refund_in_an_hour(self):
        """hardened: the 4th refund inside an hour is refused by max_3_refunds_per_hour; an hour later it works"""
        pep = PEP("hardened")
        s = Session("bob", "T-603", "mallory@attacker.example")
        call = '{"order_id": "O-3001", "amount_cents": 1000, "currency": "USD"}'
        got = [pep.handle(s, "issue_refund", call).decision for _ in range(4)]
        self.assertEqual(got, ["ALLOW", "ALLOW", "ALLOW", "DENY"])
        self.assertIn("max_3_refunds_per_hour", receipts.read_all()[-1]["policies"])
        lab.CLOCK.advance(3601)
        self.assertEqual(pep.handle(s, "issue_refund", call).decision, "ALLOW")

    def test_12_server_annotations_not_trusted(self):
        """hardened: a third-party tool that says readOnlyHint=true is refused; nothing reaches the partner"""
        out = PEP("hardened").handle(SAM, "partner_sync_orders", "{}")
        self.assertEqual(out.decision, "DENY")
        self.assertEqual(tools.partner_outbox(), [])

    def test_13_negative_and_wrong_currency(self):
        """hardened: a negative refund and a refund in another currency are forbidden by refund_amount_sane"""
        pep = PEP("hardened")
        s = Session("bob", "T-501", "sam@customer.example")
        for args in ('{"order_id": "O-1001", "amount_cents": -5000, "currency": "USD"}',
                     '{"order_id": "O-1001", "amount_cents": 4000, "currency": "JPY"}'):
            out = pep.handle(s, "issue_refund", args)
            self.assertEqual(out.decision, "DENY")
            self.assertIn("refund_amount_sane", out.policies)

    def test_14_fail_closed_when_policies_break(self):
        """hardened: a policy file with a syntax error refuses every call; the first draft allows every call"""
        with tempfile.TemporaryDirectory() as d:
            old = lab.SETUPS
            try:
                shutil.copytree(old, d, dirs_exist_ok=True)
                for setup in ("hardened", "first-draft"):
                    (lab.pathlib.Path(d) / setup / "policies" / "zz_broken.cedar").write_text(
                        '@id("zz_broken")\npermit (principal, action resource);')
                lab.SETUPS = lab.pathlib.Path(d)
                s = Session("bob", "T-501", "sam@customer.example")
                call = '{"order_id": "O-1001", "amount_cents": 4500, "currency": "USD"}'
                self.assertEqual(PEP("hardened").handle(s, "issue_refund", call).decision, "DENY")
                self.assertEqual(PEP("first-draft").handle(s, "issue_refund", call).decision, "ALLOW")
            finally:
                lab.SETUPS = old

    def test_15_log_only_runs_refused_calls(self):
        """hardened in LOG_ONLY: the refused call runs, and the receipt records what the policy would have done"""
        out = PEP("hardened", mode="LOG_ONLY").handle(Session("bob", "T-601", "mallory@attacker.example"),
                                                      "issue_refund",
                                                      '{"order_id": "O-2001", "amount_cents": 9000, "currency": "USD"}')
        self.assertEqual((out.decision, out.ran), ("DENY", True))
        self.assertEqual(tools.ledger()[0]["order_id"], "O-2001")
        self.assertEqual(receipts.read_all()[0]["mode"], "LOG_ONLY")

    def test_16_injection_end_to_end(self):
        """hardened: the injected $950 ticket ends with no refund paid and one approval waiting for a human"""
        run = run_ticket(PEP("hardened"), "bob", "T-602", quiet=True)
        self.assertEqual([s.decision for s in run.steps], ["ALLOW", "DEFER", "ALLOW"])
        self.assertEqual(tools.ledger(), [])
        self.assertEqual([a["status"] for a in approvals.load().values()], ["pending"])


class CedarEngine(LabTest):
    def test_17_hardened_policies_validate_against_schema(self):
        """cedar: every hardened policy validates against schema/tsg.cedarschema"""
        text, defer = pdp.load_policy_text(lab.SETUPS / "hardened" / "policies")
        self.assertTrue(cedarpy.validate_policies(text, lab.SCHEMA.read_text()).validation_passed)
        self.assertEqual(defer, {"refund_over_100_needs_approval"})

    def test_18_validator_catches_unguarded_optional(self):
        """cedar: reading an optional argument without `has` fails validation, before anything is deployed"""
        bad = ('@id("x")\nforbid (principal, action == TSG::Action::"issue_refund", resource)\n'
               'when { context.input.reason == "goodwill" };')
        self.assertFalse(cedarpy.validate_policies(bad, lab.SCHEMA.read_text()).validation_passed)

    def test_19_valid_is_not_safe(self):
        """cedar: the first draft's policies VALIDATE against the schema too: valid policies can still be wrong"""
        text, _ = pdp.load_policy_text(lab.SETUPS / "first-draft" / "policies")
        self.assertTrue(cedarpy.validate_policies(text, lab.SCHEMA.read_text()).validation_passed)

    def test_20_cloud_policies_parse(self):
        """cedar: the guided build's Cedar policies parse (placeholders filled in)"""
        for f in sorted((lab.LAB / "cloud" / "policies").glob("*.cedar")):
            text = f.read_text().replace("GATEWAY_ARN", "arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/x")
            json.loads(cedarpy.policies_to_json_str(text))


class Audit(LabTest):
    def _some_receipts(self):
        run_ticket(PEP("hardened"), "bob", "T-501", quiet=True)

    def test_21_chain_verifies(self):
        """audit: every receipt is signed and linked to the one before"""
        self._some_receipts()
        self.assertEqual(receipts.verify(), [])
        self.assertEqual(len(receipts.read_all()), 3)

    def test_22_edit_and_delete_detected(self):
        """audit: changing a decision, or deleting a receipt, is detected"""
        self._some_receipts()
        p = lab.state_dir() / "receipts.jsonl"
        lines = p.read_text().splitlines()
        p.write_text("\n".join([lines[0].replace('"ALLOW"', '"DENY"')] + lines[1:]) + "\n")
        self.assertTrue(any("changed" in x for x in receipts.verify()))
        p.write_text("\n".join([lines[0], lines[2]]) + "\n")
        self.assertTrue(receipts.verify())


@unittest.skipUnless(shutil.which("opa"), "opa not installed (optional)")
class OpaParity(LabTest):
    def test_23_opa_agrees_with_cedar(self):
        """opa: the same PEP with OPA deciding gives the same results as Cedar on all 18 cases"""
        self.assertEqual(suite.evaluate("hardened", engine="opa"), suite.evaluate("hardened"))


if __name__ == "__main__":
    unittest.main()
