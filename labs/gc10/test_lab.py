"""
test_lab.py: the proof behind `make test`.

The first tests attack ExampleCo's setup AS IT IS TODAY and expect the attacks to WORK: a test that has never failed
proves nothing. The rest prove the checker finds the mistakes, the fixes hold without breaking legitimate traffic, and
the audit-log hunt finds both intrusions without flagging the normal days.
"""

import json
import pathlib
import re
import tempfile
import unittest

import attack
import hunt
import policy_checker
from gcp_eval import Corp, Request, evaluate

HERE = pathlib.Path(__file__).resolve().parent
STEP = {s.sid: s for s in attack.STEPS}


def allowed(sid, mode):
    return attack.run_step(STEP[sid], mode).allowed


class T1_Vulnerable(unittest.TestCase):
    def test_01_unrestricted_key_runs_any_model(self):
        """vulnerable: the unrestricted key from the public repo runs the approved model AND an unapproved one"""
        self.assertTrue(allowed("A1", "vulnerable"))
        self.assertTrue(allowed("A2", "vulnerable"))

    def test_02_website_key_reaches_gemini(self):
        """vulnerable: the store-locator key from the public web page can call the Gemini API"""
        self.assertTrue(allowed("A3", "vulnerable"))

    def test_03_gemini_api_rejects_unrestricted_standard_keys(self):
        """vulnerable: Google's own rule stops one attack: the Gemini API rejects unrestricted standard keys"""
        d = attack.run_step(STEP["A4"], "vulnerable")
        self.assertFalse(d.allowed)
        self.assertIn("rejects requests from unrestricted standard keys", d.why)

    def test_04_dormant_service_account_does_everything(self):
        """vulnerable: legacy-etl's leaked key runs Claude, deploys Llama, and mints a SA key and a bound API key"""
        for sid in ("B1", "B2", "B3", "B4"):
            self.assertTrue(allowed(sid, "vulnerable"), sid)

    def test_05_authorization_key_acts_as_the_service_account(self):
        """vulnerable: the authorization key authenticates as chatbot-runtime and inherits its Admin role"""
        d = attack.run_step(STEP["C1"], "vulnerable")
        self.assertTrue(d.allowed)
        self.assertIn("authenticates as chatbot-runtime", d.why)
        self.assertIn("roles/aiplatform.admin", d.why)

    def test_06_naive_hunt_misses_streaming_and_admin_actions(self):
        """vulnerable: a GenerateContent-only detection covers 65 of 99 attacker entries"""
        records, hits = hunt.hunt(naive=True)
        caught = {id(e) for h in hits for e in h.events}
        atk = hunt.attacker_activity(records)
        self.assertEqual((sum(id(e) in caught for e in atk), len(atk)), (65, 99))
        missed = {hunt.method(e).rsplit(".", 1)[-1] for e in atk if id(e) not in caught}
        self.assertEqual(missed, {"StreamGenerateContent", "DeployModel", "CreateServiceAccountKey", "CreateKey",
                                  "EnableService"})


class T2_Checker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = policy_checker.run()
        cls.fixed = policy_checker.run(with_fixes=True)

    def test_07_checker_finds_every_planted_mistake(self):
        """checker: 18 findings across rules GC10-01 to GC10-16 (none for GC10-02 and GC10-13)"""
        rules = {f.rule for f in self.findings}
        expected = {f"GC10-{n:02d}" for n in range(1, 17)} - {"GC10-02", "GC10-13"}
        self.assertEqual(rules, expected)
        self.assertEqual(len(self.findings), 18)

    def test_08_secret_scan_finds_the_planted_key(self):
        """checker: the API key string in repo/chatbot/settings.py is found, and only there"""
        hits = [f for f in self.findings if f.rule == "GC10-16"]
        self.assertEqual([h.where for h in hits], ["repo/chatbot/settings.py:9"])

    def test_09_org_policy_lint(self):
        """checker: a malformed allowedModels value and a 501-value policy are flagged before you set them"""
        bad = {"name": "organizations/123456789012/policies/vertexai.allowedModels",
               "spec": {"rules": [{"values": {"allowedValues": ["gemini-3.5-flash", "publishers/google/models/x:invoke"]}}]}}
        self.assertEqual(sum(f.rule == "GC10-13" for f in policy_checker.check_org_policy_file(bad)), 2)
        big = {"name": "folders/1/policies/vertexai.allowedModels",
               "spec": {"rules": [{"values": {"allowedValues": [f"publishers/google/models/m{i}:predict" for i in range(501)]}}]}}
        self.assertTrue(any("limit is 500" in f.what for f in policy_checker.check_org_policy_file(big)))

    def test_10_fixes_clear_the_worst(self):
        """checker: with fixes/ applied, the basic-role, Admin-role, unrestricted-key, bound-key and constraint findings are gone"""
        gone = {"GC10-01", "GC10-04", "GC10-05", "GC10-06", "GC10-08", "GC10-09", "GC10-10"}
        self.assertFalse(gone & {f.rule for f in self.fixed})


class T3_Fixes(unittest.TestCase):
    def test_11_safe_mode_stops_seven_of_nine(self):
        """safe: the fixes deny A2, A3, A4, B2, B3, B4 and C1"""
        for sid in ("A2", "A3", "A4", "B2", "B3", "B4", "C1"):
            self.assertFalse(allowed(sid, "safe"), sid)

    def test_12_legitimate_traffic_survives(self):
        """safe: all 8 legitimate requests work before AND after the fixes"""
        for s in attack.STEPS:
            if not s.attacker:
                self.assertTrue(allowed(s.sid, "vulnerable"), s.sid)
                self.assertTrue(allowed(s.sid, "safe"), s.sid)

    def test_13_explicit_deny_beats_allow(self):
        """org policy: an explicit deny wins over an allow, and inheritFromParent merges the lists"""
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "org.json"
            p.write_text(json.dumps({"name": "organizations/123456789012/policies/vertexai.allowedModels",
                                     "spec": {"rules": [{"values": {"allowedValues": [
                                         "publishers/meta/models/llama3:deploy",
                                         "publishers/google/models/gemini-3.5-flash:predict"]}}]}}))
            corp = Corp(extra_org_policies=[p])
            # the sandbox project's deny-list (inheritFromParent: true) still denies llama3:deploy
            self.assertFalse(corp.model_allowed("example-ds-sandbox", "publishers/meta/models/llama3:deploy")[0])
            self.assertTrue(corp.model_allowed("example-ds-sandbox", "publishers/google/models/gemini-3.5-flash:predict")[0])
            self.assertFalse(corp.model_allowed("example-ds-sandbox", "publishers/anthropic/models/claude-opus-4-7:predict")[0])

    def test_14_no_policy_means_everything_allowed(self):
        """org policy: with no vertexai.allowedModels anywhere, all models and actions are allowed (Google's default)"""
        ok, why = Corp().model_allowed("example-chatbot-prod", "publishers/anthropic/models/claude-opus-4-7:tune")
        self.assertTrue(ok)
        self.assertIn("no vertexai.allowedModels policy anywhere", why)

    def test_15_ip_restriction_blocks_other_callers(self):
        """API keys: an IP restriction refuses callers outside the range and the key's API restriction holds"""
        corp = Corp()
        inside = Request("apikey:ds-notebook-key", "example-ds-sandbox", "aiplatform.googleapis.com", "GenerateContent",
                         model="publishers/google/models/gemini-3.5-flash:predict", source_ip="198.51.100.99")
        outside = Request(**{**inside.__dict__, "source_ip": "203.0.113.5"})
        other_api = Request(**{**inside.__dict__, "service": "generativelanguage.googleapis.com", "model": ""})
        self.assertTrue(evaluate(corp, inside).allowed)
        self.assertFalse(evaluate(corp, outside).allowed)
        self.assertFalse(evaluate(corp, other_api).allowed)


class T4_Hunt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records, cls.hits = hunt.hunt()

    def test_16_full_hunt_covers_every_attacker_entry(self):
        """hunt: the rules cover all 99 attacker entries in the file"""
        caught = {id(e) for h in self.hits for e in h.events}
        atk = hunt.attacker_activity(self.records)
        self.assertEqual(sum(id(e) in caught for e in atk), 99)

    def test_17_no_finding_is_only_normal_activity(self):
        """hunt: every finding contains at least one attacker entry (the normal days raise nothing)"""
        atk = {id(e) for e in hunt.attacker_activity(self.records)}
        for h in self.hits:
            self.assertTrue(any(id(e) in atk for e in h.events), f"{h.rule} {h.text}")

    def test_18_dormant_and_bound_key_rules(self):
        """hunt: H02 flags legacy-etl (227 days dormant) and H03 rates the bound key HIGH"""
        h02 = [h for h in self.hits if h.rule == "H02"]
        self.assertEqual([h.who for h in h02], ["legacy-etl@example-ci.iam.gserviceaccount.com"])
        self.assertIn("227 days", h02[0].text)
        self.assertEqual([h.severity for h in self.hits if h.rule == "H03"], ["HIGH"])


class T5_Hygiene(unittest.TestCase):
    def test_19_only_documentation_values(self):
        """hygiene: only RFC 5737 IPs, example.com identities and Google's documented example key string"""
        doc_nets = ("192.0.2.", "198.51.100.", "203.0.113.")
        for f in HERE.rglob("*"):
            if not f.is_file() or f.suffix not in {".json", ".jsonl", ".py", ".md", ".txt"} or "__pycache__" in f.parts:
                continue
            text = f.read_text(errors="ignore")
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
                if ip in ("0.0.0.0", "127.0.0.1") or ip.startswith(doc_nets) or f.name == "test_lab.py":
                    continue
                self.fail(f"{f.name}: non-documentation IP {ip}")
            for key in policy_checker.API_KEY_PATTERN.findall(text):
                self.assertEqual(key, "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe", f.name)
            for email in re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", text):
                self.assertTrue(email.endswith(("example.com", ".gserviceaccount.com", "thesecguy.com")), f"{f.name}: {email}")


if __name__ == "__main__":
    unittest.main()
