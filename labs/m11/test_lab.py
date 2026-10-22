"""
test_lab.py: the proof behind `make test`.

The first tests run against the FIRST DRAFT and expect the problems to be there: a test that has never failed proves
nothing. The rest check every M11 control in the HARDENED plan, one lesson at a time, and that the Helpdesk still works.
Nothing here talks to AWS.
"""

import copy
import json
import pathlib
import re
import unittest

import attack
import checker
import plan as P
from iam_eval import DEFAULT_ENDPOINT_POLICY, Request, evaluate

HERE = pathlib.Path(__file__).resolve().parent
DRAFT = P.load("twin/first-draft.plan.json")
HARD = P.load("twin/hardened.plan.json")


def step(sid, mode):
    plan = DRAFT if mode == "first-draft" else HARD
    s = next(x for x in attack.steps_for(plan) if x.sid == sid)
    return s, attack.run_step(s, mode, plan)


def rules(findings, severity=None):
    return {f.rule for f in findings if severity is None or f.severity == severity}


def run_rules(plan):
    return [f for r in checker.RULES for f in r(plan)]


class T1_FirstDraft(unittest.TestCase):
    def test_01_checker_finds_the_high_risks(self):
        """first draft: the checker flags 7 HIGH controls (wildcards, any model, default endpoint policy, NAT, no key, deputy, global)"""
        high = rules(checker.run("twin/first-draft.plan.json"), "HIGH") - {"M11-17"}  # M11-17 is the challenge
        self.assertEqual(high, {"M11-01", "M11-02", "M11-05", "M11-06", "M11-08", "M11-12", "M11-15"})

    def test_02_every_attack_works(self):
        """first draft: all 7 attacks and mistakes are allowed"""
        for sid in ("X1", "X2", "X3", "X4", "X5", "X6", "X7"):
            self.assertTrue(step(sid, "first-draft")[1].allowed, sid)

    def test_03_outsider_through_default_endpoint_policy(self):
        """first draft: an outsider's own keys work through the endpoint, and AnyCompany has no record of it"""
        s, d = step("X1", "first-draft")
        self.assertTrue(d.allowed)
        self.assertIn("AnyCompany: nothing", " ".join(attack.records(s, DRAFT, d)))

    def test_04_mantle_call_leaves_no_trace(self):
        """first draft: a bedrock-mantle call from the VPC works and leaves no CloudTrail record and no prompt log"""
        s, d = step("X7", "first-draft")
        self.assertTrue(d.allowed)
        seen = " ".join(attack.records(s, DRAFT, d))
        self.assertIn("CloudTrail: NOTHING", seen)
        self.assertIn("NOT captured", seen)


class T2_Hardened(unittest.TestCase):
    def test_05_checker_clean(self):
        """hardened: the checker finds nothing"""
        self.assertEqual(checker.run("twin/hardened.plan.json"), [])

    def test_06_least_privilege(self):
        """11.1 hardened: the stolen role can't pick another model, Region, setting or purchase"""
        full_access_only = [("FullAWSAccess", P.load("org/FullAWSAccess.json"))]
        for sid in ("X2", "X3", "X5", "X6"):
            s, d = step(sid, "hardened")
            self.assertFalse(d.allowed, sid)
            # The role ALONE must refuse it, whatever the org SCPs say (defence in depth: each layer holds by itself).
            alone = attack.evaluate_all(s.checks, attack.identity_policies("helpdesk", HARD), full_access_only)
            self.assertIn("no identity policy allows it", alone.reason, sid)

    def test_07_private_network(self):
        """11.2 hardened: the endpoint refuses outsiders, the VPC has no way out, a mantle call can't leave"""
        s, d = step("X1", "hardened")
        self.assertFalse(d.allowed)
        self.assertIn("endpoint policy", d.reason)
        self.assertFalse(P.resources(HARD, "aws_nat_gateway") or P.resources(HARD, "aws_internet_gateway"))
        self.assertIn("no network path", step("X7", "hardened")[1].reason)

    def test_08_encryption(self):
        """11.3 hardened: prompt logs, both buckets and the trail use customer managed keys with rotation on"""
        lg = checker._prompt_log_group(HARD)
        self.assertIn("aws_kms_key.prompts", " ".join(P.references(HARD, lg["address"], "kms_key_id")))
        for k in P.resources(HARD, "aws_kms_key"):
            self.assertTrue(k["values"]["enable_key_rotation"], k["address"])
        self.assertIn("aws_kms_key.audit", " ".join(P.references(HARD, "aws_cloudtrail.ai_data_events", "kms_key_id")))
        self.assertFalse([f for f in run_rules(HARD) if f.rule in ("M11-08", "M11-13", "M11-14")])

    def test_09_logging(self):
        """11.4 hardened: text logging with a large-data bucket, 30-day retention, a guarded role, a trail with network activity"""
        lc = P.one(HARD, "aws_bedrock_model_invocation_logging_configuration")["values"]["logging_config"][0]
        self.assertTrue(lc["text_data_delivery_enabled"])
        self.assertTrue(lc["cloudwatch_config"][0]["large_data_delivery_s3_config"])
        self.assertEqual(checker._prompt_log_group(HARD)["values"]["retention_in_days"], 30)
        self.assertTrue(attack._trail_selects(HARD, "NetworkActivity"))
        self.assertFalse([f for f in run_rules(HARD) if f.rule in ("M11-09", "M11-10", "M11-11", "M11-12", "M11-16")])

    def test_10_residency(self):
        """11.5 hardened: the app uses the us. profile; every Region its call can touch is a US Region"""
        s, d = step("L1", "hardened")
        self.assertTrue(attack.app_target(HARD).startswith("us."))
        allowed = set(attack.COMPANY["data_residency"]["allowed_processing_regions"])
        self.assertTrue({r.context["aws:RequestedRegion"] for r in s.checks} <= allowed)
        self.assertFalse(step("X4", "hardened")[1].allowed)

    def test_11_helpdesk_still_works(self):
        """both plans: the Helpdesk's own call and the security admin's check are allowed"""
        for mode in ("first-draft", "hardened"):
            for sid in ("L1", "L2"):
                self.assertTrue(step(sid, mode)[1].allowed, f"{sid} {mode}")

    def test_12_region_guard_blocks_global(self):
        """11.5 org SCP: even a team allowed to call any model can't use a global profile (unspecified is not allowed)"""
        checks = attack.invoke("data-science", "global.anthropic.claude-haiku-4-5-20251001-v1:0")
        d = attack.evaluate_all(checks, attack.identity_policies("data-science", HARD), attack.scps("hardened"))
        self.assertFalse(d.allowed)
        self.assertIn("explicit Deny in SCP scp-region-guard", d.reason)


class T3_Teaching(unittest.TestCase):
    def test_13_endpoint_policy_rules(self):
        """iam_eval: the default endpoint policy lets anyone through; a bare account ID means its root user only"""
        allow_all = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        out = Request("arn:aws:iam::777788889999:user/personal-admin", "bedrock:InvokeModel", "*")
        self.assertTrue(evaluate(out, [("own", allow_all)], [], False, ("default", DEFAULT_ENDPOINT_POLICY)).allowed)
        acct_only = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "111122223333"}, "Action": "*", "Resource": "*"}]}
        role = Request("arn:aws:iam::111122223333:role/tsg-helpdesk-app", "bedrock:InvokeModel", "*")
        self.assertFalse(evaluate(role, [("own", allow_all)], [], False, ("acct", acct_only)).allowed)

    def test_14_checker_reads_the_plan(self):
        """checker: remove the endpoint policy from the hardened plan and M11-05 fires (it reads values, not names)"""
        mutated = copy.deepcopy(HARD)
        for r in P.resources(mutated, "aws_vpc_endpoint"):
            r["values"]["policy"] = None
        for r in mutated["configuration"]["root_module"]["resources"]:
            if r["address"] == "aws_vpc_endpoint.bedrock_runtime":
                r["expressions"].pop("policy", None)
        self.assertIn("M11-05", rules(checker.rule_endpoint_policy(mutated)))

    def test_15_documentation_values_only(self):
        """safety: only AWS documentation account IDs, no access keys, no real-looking secrets in the lab"""
        allowed = {"111122223333", "444455556666", "777788889999", "123456789012"}
        for f in HERE.rglob("*"):
            if f.is_dir() or f.suffix not in (".json", ".tf", ".py", ".md") or ".terraform" in f.parts:
                continue
            text = f.read_text()
            for acct in re.findall(r"(?<![0-9])[0-9]{12}(?![0-9])", text):
                self.assertIn(acct, allowed, f"{f.name}: {acct}")
            self.assertFalse(re.search(r"\b(AKIA|ASIA|ABSK)[A-Z0-9]{12,}", text), f.name)


if __name__ == "__main__":
    unittest.main()
