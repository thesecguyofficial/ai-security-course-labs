"""
test_challenge.py: `make challenge`. Three of these fail until you finish the challenge (README, Step 6).

1. org/scp-region-guard.json: us-east-1 only for everything, EXCEPT the Helpdesk's approved US profile routing
   to its destination Regions (lesson 11.5: the documented bedrock:InferenceProfileArn exception).
2. policies/endpoint-policy-mantle.json: next sprint's bedrock-mantle endpoint lets only AnyCompany principals
   run only the approved mantle model (lesson 11.2).
3. checker.py: write rule_trail_covers_mantle() (M11-17, lesson 11.4).
No solution is included.
"""

import copy
import unittest

import attack
import checker
import plan as P
from iam_eval import evaluate_all

HARD = P.load("twin/hardened.plan.json")
DRAFT = P.load("twin/first-draft.plan.json")
MANTLE_EP = ("endpoint-policy-mantle", P.load("policies/endpoint-policy-mantle.json"))


def scp_decision(who, checks):
    return evaluate_all(checks, attack.identity_policies(who, HARD), attack.scps("hardened"))


def mantle_decision(who, model):
    in_org = attack.principal(who)["account"] in attack.ORG_ACCOUNTS
    return evaluate_all(attack.mantle(who, model), attack.identity_policies(who, HARD), attack.scps("hardened"),
                        scps_apply=in_org, endpoint_policy=MANTLE_EP)


class T4_Challenge(unittest.TestCase):
    def test_16_region_guard_us_east_1_only(self):
        """challenge 11.5: outside us-east-1, AnyCompany can't create buckets or call models directly"""
        s3 = attack.call("data-science", "s3:CreateBucket", "arn:aws:s3:::anycompany-example-bucket", region="us-west-2")
        self.assertFalse(scp_decision("data-science", s3).allowed, "s3:CreateBucket in us-west-2 is still allowed")
        direct = attack.invoke("data-science", "anthropic.claude-haiku-4-5-20251001-v1:0", region="us-east-2")
        self.assertFalse(scp_decision("data-science", direct).allowed,
                         "a direct InvokeModel in us-east-2 (no profile) is still allowed")

    def test_17_region_guard_keeps_the_helpdesk_working(self):
        """challenge 11.5: the Helpdesk's us. profile still routes to us-east-2 and us-west-2"""
        s, d = next((x, attack.run_step(x, "hardened", HARD)) for x in attack.steps_for(HARD) if x.sid == "L1")
        self.assertTrue(d.allowed, d.reason)

    def test_18_region_guard_still_blocks_global(self):
        """challenge 11.5: a global profile is still refused"""
        checks = attack.invoke("data-science", "global.anthropic.claude-haiku-4-5-20251001-v1:0")
        self.assertFalse(scp_decision("data-science", checks).allowed)

    def test_19_mantle_endpoint_policy(self):
        """challenge 11.2: through the mantle endpoint, outsiders and unapproved models are refused"""
        self.assertFalse(mantle_decision("outsider", "anthropic.claude-haiku-4-5").allowed,
                         "an outsider's keys still work through the mantle endpoint")
        self.assertFalse(mantle_decision("ops-tools", "anthropic.claude-opus-4-7").allowed,
                         "an unapproved model still works through the mantle endpoint")

    def test_20_mantle_endpoint_keeps_approved_model(self):
        """challenge 11.2: AnyCompany's ops tool can still use the approved mantle model"""
        self.assertTrue(mantle_decision("ops-tools", attack.COMPANY["approved"]["mantle_model"]).allowed)

    def test_21_rule_m11_17_flags_missing_mantle_events(self):
        """challenge 11.4: M11-17 flags the first draft, and a hardened plan whose trail lost its mantle selector"""
        self.assertEqual([f.rule for f in checker.rule_trail_covers_mantle(DRAFT)], ["M11-17"],
                         "rule_trail_covers_mantle() finds nothing in the first draft, which has no trail at all")
        mutated = copy.deepcopy(HARD)
        for t in P.resources(mutated, "aws_cloudtrail"):
            t["values"]["advanced_event_selector"] = [
                s for s in t["values"]["advanced_event_selector"]
                if not any("AWS::BedrockMantle::Project" in (f.get("equals") or []) for f in s["field_selector"])]
        self.assertEqual([f.rule for f in checker.rule_trail_covers_mantle(mutated)], ["M11-17"],
                         "a trail WITHOUT the AWS::BedrockMantle::Project selector is not flagged")

    def test_22_rule_m11_17_no_false_positive(self):
        """challenge 11.4: M11-17 stays quiet on the hardened plan"""
        self.assertEqual(checker.rule_trail_covers_mantle(HARD), [])


if __name__ == "__main__":
    unittest.main()
