"""
test_lab.py: the proof behind `make test`.

The first tests attack AnyCompany's setup AS IT IS TODAY and expect the attacks to WORK: a test that has never
failed proves nothing. The rest prove the checker finds the over-broad policies, the SCP fixes hold without breaking
legitimate traffic, and the CloudTrail hunt finds the LLMjacking timeline without flagging normal days.
"""

import json
import pathlib
import re
import unittest

import attack
import hunt
import policy_checker
from iam_eval import Request, evaluate

HERE = pathlib.Path(__file__).resolve().parent
STEP = {s.sid: s for s in attack.STEPS}


def allowed(sid, mode):
    return attack.run_step(STEP[sid], mode).allowed


class T1_Vulnerable(unittest.TestCase):
    def test_01_leaked_key_runs_any_model(self):
        """vulnerable: a leaked long-term API key lists models, checks logging and runs an unapproved model, on both endpoints"""
        for sid in ("A1", "A2", "A3", "A4"):
            self.assertTrue(allowed(sid, "vulnerable"), sid)

    def test_02_leaked_key_can_buy_capacity(self):
        """vulnerable: the console default policy on that key (AmazonBedrockLimitedAccess) can buy Provisioned Throughput"""
        self.assertTrue(allowed("A5", "vulnerable"))

    def test_03_stolen_role_deletes_logging_and_uses_global_profile(self):
        """vulnerable: the chatbot's stolen role can delete invocation logging and route to any Region via a global profile"""
        self.assertTrue(allowed("B1", "vulnerable"))
        self.assertTrue(allowed("B2", "vulnerable"))

    def test_04_deny_list_only_catches_what_it_names(self):
        """vulnerable: the DeepSeek deny-list SCP blocks DeepSeek and nothing else"""
        self.assertFalse(allowed("B3", "vulnerable"))
        self.assertTrue(allowed("A3", "vulnerable"))

    def test_05_naive_hunt_misses_converse_and_mantle(self):
        """vulnerable: an InvokeModel-only detection sees 1 attacker event and misses Converse, ConverseStream and mantle"""
        records, hits = hunt.hunt(naive=True)
        caught = {id(e) for h in hits for e in h.events}
        attack_events = hunt.attacker_activity(records)
        self.assertEqual(sum(id(e) in caught for e in attack_events), 1)
        missed = {e["eventName"] for e in attack_events if id(e) not in caught}
        self.assertTrue({"Converse", "ConverseStream", "CreateInference"} <= missed)


class T2_Checker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = policy_checker.run()
        cls.rules = {(f.rule, f.where.split(" ")[0]) for f in cls.findings}

    def test_06_checker_finds_each_over_broad_setting(self):
        """checker: flags bedrock:* on *, any-model invoke, unlimited key creation, a never-expiring prod key, the org-level gaps"""
        expected = {("M10-01", "identity/helpdesk-app-role.json"), ("M10-02", "identity/data-science-role.json"),
                    ("M10-03", "identity/platform-admin-role.json"), ("M10-05", "BedrockAPIKey-x7k2"),
                    ("M10-06", "BedrockAPIKey-x7k2"), ("M10-07", "BedrockAPIKey-x7k2"), ("M10-04", "identity/helpdesk-app-role.json"),
                    ("M10-08", "org"), ("M10-09", "scps/deny-deepseek.json"), ("M10-10", "org"), ("M10-11", "org")}
        self.assertTrue(expected <= self.rules, expected - self.rules)

    def test_07_checker_no_false_positives_on_least_privilege(self):
        """checker: the CI role, the security admin and the least-privilege chatbot policy get zero findings"""
        self.assertFalse([f for f in self.findings if "ci-deployer" in f.where or "security-admin" in f.where])
        lp = json.loads((HERE / "fixes/helpdesk-app-role.least-privilege.json").read_text())
        self.assertEqual(policy_checker.check_identity_policy("lp", lp), [])

    def test_08_checker_warns_on_blunt_allowlist(self):
        """checker: warns that 'Deny bedrock:* except these models' also blocks guardrails, knowledge bases and profiles"""
        blunt = json.loads((HERE / "examples/blunt-allowlist-scp.json").read_text())
        self.assertIn("M10-12", {f.rule for f in policy_checker.check_scp("blunt", blunt)})


class T3_Safe(unittest.TestCase):
    def test_09_long_term_key_blocked_in_prod(self):
        """safe: the leaked prod key is refused on bedrock-runtime and bedrock-mantle, for every call"""
        for sid in ("A1", "A2", "A3", "A4", "A5"):
            self.assertFalse(allowed(sid, "safe"), sid)

    def test_10_logging_protected(self):
        """safe: only SecurityAdmin can change invocation logging; the stolen chatbot role cannot delete it"""
        self.assertFalse(allowed("B1", "safe"))
        self.assertTrue(allowed("L6", "safe"))

    def test_11_unapproved_models_blocked(self):
        """safe: unapproved models are refused on bedrock-runtime, by model ARN and through a global profile"""
        self.assertFalse(allowed("B2", "safe"))
        r = Request("arn:aws:iam::111122223333:role/DataScienceRole", "bedrock:InvokeModel",
                    "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-opus-4-7", {"aws:PrincipalAccount": "111122223333"})
        self.assertFalse(evaluate(r, attack.identity_policies("DataScienceRole"), attack.scps_for("safe")).allowed)

    def test_12_legit_traffic_still_works(self):
        """safe: approved profile (4 checks), guardrail, knowledge base, mantle, sandbox key and capacity purchase all still work"""
        for s in attack.STEPS:
            if s.legit:
                self.assertTrue(allowed(s.sid, "safe"), s.sid)

    def test_13_key_age_capped(self):
        """safe: a 365-day sandbox key is refused, a 30-day one is allowed"""
        self.assertFalse(allowed("C2", "safe"))
        self.assertTrue(allowed("L7", "safe"))

    def test_14_missing_condition_key_rules(self):
        """evaluator: a missing key makes NumericGreaterThan false and Null:true true, as the IAM docs say"""
        base = {"Effect": "Deny", "Action": "x:Y", "Resource": "*"}
        allow = [("a", {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})]
        gt = {"Statement": [dict(base, Condition={"NumericGreaterThan": {"k:Age": "30"}})]}
        null = {"Statement": [dict(base, Condition={"Null": {"k:Age": "true"}})]}
        r = Request("arn:aws:iam::111122223333:role/R", "x:Y")
        self.assertTrue(evaluate(r, allow, [("gt", gt)] + allow).allowed)
        self.assertFalse(evaluate(r, allow, [("null", null)] + allow).allowed)


class T4_Hunt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records, cls.hits = hunt.hunt()
        cls.by_rule = {}
        for h in cls.hits:
            cls.by_rule.setdefault(h.rule, []).append(h)

    def test_15_hunt_finds_the_timeline(self):
        """hunt: key creation (never expires), recon, probe, log tampering, enablement, unapproved models, new source, volume"""
        for rule in ("H01", "H02", "H03", "H04", "H05", "H06", "H07", "H08"):
            self.assertIn(rule, self.by_rule, rule)
        self.assertTrue(any("NEVER expires" in " ".join(h.evidence) for h in self.by_rule["H01"]))
        self.assertTrue(any("bearer" in h.title for h in self.by_rule["H07"]))

    def test_16_hunt_quiet_on_normal_days(self):
        """hunt: nothing from 12 and 13 October (normal traffic, the security admin's daily logging check) is flagged"""
        flagged = [e for h in self.hits if h.rule != "H01" for e in h.events if e["eventTime"] < "2026-10-14"]
        self.assertEqual(flagged, [])


class T5_Hygiene(unittest.TestCase):
    def test_17_only_documentation_values(self):
        """data: only AWS documentation account IDs, RFC 5737 IPs and ...EXAMPLE key IDs appear anywhere in the lab"""
        allowed_accounts = {"111122223333", "444455556666", "123456789012"}
        doc_ip = re.compile(r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$")
        for f in list(HERE.rglob("*.json")) + list(HERE.rglob("*.py")) + list(HERE.rglob("*.md")):
            if ".venv" in f.parts:
                continue
            text = f.read_text()
            for acct in re.findall(r"(?<![\d.])\d{12}(?![\d.])", text):
                self.assertIn(acct, allowed_accounts, f"{f.name}: {acct}")
            for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
                self.assertRegex(ip, doc_ip, f"{f.name}: {ip}")
            for key in re.findall(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b", text):
                self.assertTrue(key.endswith("EXAMPLE"), f"{f.name}: {key}")


if __name__ == "__main__":
    unittest.main()
