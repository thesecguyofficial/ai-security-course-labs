"""
test_lab.py: the proof behind `make test`.

The first tests attack Contoso's setup AS IT IS TODAY and expect the attacks to WORK: a test that has never failed
proves nothing. The rest prove the checker finds the risky settings, the fixes hold without breaking legitimate
work, and the hunt finds both intrusions on 14 October without flagging normal days.
"""

import json
import pathlib
import re
import unittest

import attack
import checker
import hunt
import secret_scan
from azure_model import PolicyEval, deployment_fields, load

HERE = pathlib.Path(__file__).resolve().parent
STEP = {s.sid: s for s in attack.STEPS}
OAI = "azureml://registries/azure-openai/models/"


def run(sid, mode):
    return attack.run_step(STEP[sid], mode)


class T1_Vulnerable(unittest.TestCase):
    def test_01_leaked_keys_work(self):
        """vulnerable: keys copied from the public repo list models and chat on BOTH Foundry resources, no role checked"""
        for sid in ("A1", "A2", "A3"):
            self.assertTrue(run(sid, "vulnerable").allowed, sid)

    def test_02_contributor_reads_the_key_rbac_bypass(self):
        """vulnerable: Contributor can't call the model with Entra ID (no data actions) but CAN list the keys"""
        self.assertFalse(run("B1", "vulnerable").allowed)
        self.assertTrue(run("B2", "vulnerable").allowed)

    def test_03_audit_lets_unapproved_model_through(self):
        """vulnerable: the approved-models policy is on Audit, so the unapproved Fabrikam model deploys (logged only)"""
        d = run("B3", "vulnerable")
        self.assertTrue(d.allowed)
        self.assertEqual(d.status, "Audit")

    def test_04_publisher_wildcard_approves_every_openai_model(self):
        """vulnerable: allowedPublishers=['OpenAI'] makes gpt-5.4 and gpt-5.2 v2 compliant without any audit"""
        for sid in ("B4", "B8"):
            d = run(sid, "vulnerable")
            self.assertTrue(d.allowed, sid)
            self.assertEqual(d.status, "200", sid)

    def test_05_contributor_changes_filters_and_keys_but_not_roles(self):
        """vulnerable: the CI identity can replace content filters and re-enable keys, but NotActions stop role assignments"""
        self.assertTrue(run("B5", "vulnerable").allowed)
        self.assertTrue(run("B7", "vulnerable").allowed)
        self.assertFalse(run("B6", "vulnerable").allowed)

    def test_06_naive_hunt_sees_only_the_bill(self):
        """vulnerable: the daily usage check fires once, for the whole day, and says nothing about keys or deployments"""
        _, hits = hunt.hunt(is_naive=True)
        self.assertEqual([h.rule for h in hits], ["N01"])


class T2_Checker(unittest.TestCase):
    def test_07_checker_finds_every_rule(self):
        """checker: Contoso today triggers all 14 rules (AZ10-01 to AZ10-14)"""
        rules = {f.rule for f in checker.run()}
        self.assertEqual(rules, {f"AZ10-{n:02d}" for n in range(1, 15)})

    def test_08_fixes_leave_only_the_challenge(self):
        """checker: with fixes/, only the challenge findings can remain (sandbox keys, gpt-5 asset ID)"""
        allowed = {("AZ10-01", "contoso-sandbox-ai"), ("AZ10-02", "platform-admin on contoso-sandbox-ai"),
                   ("AZ10-02", "data-science on contoso-sandbox-ai"), ("AZ10-09", "allow-only-approved-models")}
        left = {(f.rule, f.where) for f in checker.run(with_fixes=True)}
        self.assertTrue(left <= allowed, left - allowed)


class T3_Fixes(unittest.TestCase):
    def test_09_prod_key_refused(self):
        """safe: with disableLocalAuth=true the leaked PROD key gets 401"""
        for sid in ("A1", "A2"):
            d = run(sid, "safe")
            self.assertFalse(d.allowed, sid)
            self.assertEqual(d.status, "401", sid)

    def test_10_ci_identity_cut_to_its_job(self):
        """safe: the CI identity can't list keys, change filters or account settings, and Deny stops the Fabrikam model"""
        for sid in ("B2", "B5", "B7"):
            self.assertFalse(run(sid, "safe").allowed, sid)
        d = run("B3", "safe")
        self.assertFalse(d.allowed)
        self.assertIn("POLICY allow-only-approved-models: Deny", d.why[-1])

    def test_11_policy_stops_even_owner(self):
        """safe: Owner is allowed by RBAC, but the key-access policy (Deny) refuses re-enabling keys"""
        d = run("B9", "safe")
        self.assertFalse(d.allowed)
        self.assertIn("deny-ai-key-access", d.why[-1])
        self.assertTrue(run("B9", "vulnerable").allowed)

    def test_12_legitimate_work_survives(self):
        """safe and vulnerable: the five legitimate requests are allowed in both modes"""
        for mode in ("vulnerable", "safe"):
            for sid in ("L1", "L2", "L3", "L4", "L5"):
                self.assertTrue(run(sid, mode).allowed, f"{sid} {mode}")

    def test_13_policy_rule_matches_microsoft_examples(self):
        """policy: the real rule reproduces Microsoft's examples (no slash = prefix; '/' = one model; '/versions/1' = one version)"""
        defn = load("contoso/policy-definitions/approved-models.json")

        def compliant(allowed, model, version):
            m = {"publisher": "OpenAI", "assetId": f"{OAI}{model}/versions/{version}"}
            params = {"effect": {"value": "Deny"}, "allowedPublishers": {"value": []}, "allowedAssetIds": {"value": allowed}}
            return PolicyEval(defn, params, deployment_fields(m)).effect() is None
        self.assertTrue(compliant([OAI + "gpt-5"], "gpt-5.2", "1"))
        self.assertTrue(compliant([OAI + "gpt-5"], "gpt-5.4", "1"))
        self.assertFalse(compliant([OAI + "gpt-5/"], "gpt-5.4", "1"))
        self.assertTrue(compliant([OAI + "gpt-5/"], "gpt-5", "7"))
        self.assertTrue(compliant([OAI + "gpt-5.2/versions/1"], "gpt-5.2", "1"))
        self.assertFalse(compliant([OAI + "gpt-5.2/versions/1"], "gpt-5.2", "2"))


class T4_Hunt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logs, cls.hits = hunt.hunt()

    def test_14_hunt_finds_both_intrusions(self):
        """hunt: keys listed, unapproved model, failed role grab, token spikes, new IPs, new-IP control plane"""
        rules = sorted(h.rule for h in self.hits if h.rule != "H07")   # H07 is the challenge
        self.assertEqual(rules, ["H01", "H02", "H03", "H04", "H04", "H05", "H05", "H06"])
        ci = "00001111-aaaa-2222-bbbb-3333cccc4444"
        self.assertTrue(all(h.who == ci for h in self.hits if h.rule in ("H01", "H02", "H03", "H06")))

    def test_15_no_false_positives(self):
        """hunt: nothing from Contoso's own IPs, and nothing on the normal days 9-13 October"""
        text = "\n".join(e for h in self.hits for e in h.evidence)
        self.assertNotRegex(text, r"198\.51\.100\.|192\.0\.2\.")
        self.assertTrue(all(h.when >= "2026-10-14" for h in self.hits))

    def test_16_secret_scan_finds_the_three_leaks(self):
        """secret scan: the public repo snapshot leaks the prod key, the sandbox key and the CI client secret"""
        kinds = sorted(x["kind"] for x in secret_scan.scan(HERE / "contoso" / "repo-snapshot"))
        self.assertEqual(len(kinds), 3)
        self.assertEqual(len(set(kinds)), 3)


class T5_DataHygiene(unittest.TestCase):
    def test_17_only_documentation_values(self):
        """data: only Microsoft documentation example GUIDs (or built-in role/policy IDs), RFC 5737 IPs, EXAMPLE secrets"""
        doc_guids = {"aaaabbbb-0000-cccc-1111-dddd2222eeee", "aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e",
                     "bbbbbbbb-1111-2222-3333-cccccccccccc", "cccccccc-2222-3333-4444-dddddddddddd",
                     "00001111-aaaa-2222-bbbb-3333cccc4444", "eeee4444-ff55-6666-77aa-888888bbbbbb",
                     "ffff5555-aa66-7777-88bb-999999cccccc", "aaaa0000-bb11-2222-33cc-444444dddddd"}
        builtin = {"8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "b24988ac-6180-42a0-ab88-20f7382dd24c",
                   "acdd72a7-3385-48ef-bd42-f606fba81ae7", "25fbc0a9-bd7c-42a3-aa1a-3b75d497ee68",
                   "64702f94-c441-49e6-a78b-ef80e0188fee", "eed3b665-ab3a-47b6-8f48-c9382fb1dad6",
                   "aafe3651-cb78-4f68-9f81-e7e41509110f", "71ef260a-8f18-47b7-abcb-62d0673d94dc",
                   "53ca6127-db72-4b80-b1b0-d745d6d5456d", "e47c6f54-e4a2-4754-9501-8e0985b135e1",
                   "c883944f-8b7b-4483-af10-35834be79c4a", "eadc314b-1a2d-4efa-be10-5d325db5065e"}
        guid = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
        ipv4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
        files = [p for p in HERE.rglob("*") if p.is_file() and p.suffix in (".json", ".env", ".sh", ".yml", ".bicep", ".md", ".py")
                 and "__pycache__" not in p.parts]
        for f in files:
            text = f.read_text()
            for g in guid.findall(text):
                self.assertIn(g.lower(), doc_guids | builtin, f"{f.name}: {g}")
            for m in ipv4.finditer(text):
                a, b, c = (int(x) for x in m.groups()[:3])
                self.assertIn((a, b, c), ((192, 0, 2), (198, 51, 100), (203, 0, 113)),
                              f"{f.name}: non-documentation IP {m.group(0)}")
        for f in (HERE / "contoso" / "repo-snapshot").rglob("*"):
            if f.is_file():
                for x in secret_scan.scan(f.parent):
                    self.assertIn("EXAMPL", x["value"])


if __name__ == "__main__":
    unittest.main()
