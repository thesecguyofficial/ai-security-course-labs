"""
test_lab.py: the proof behind `make test`.

The first tests attack the TSG Helpdesk AS IT RUNS TODAY and expect the attacks to WORK: a test that has never
failed proves nothing. The rest prove the checker finds every gap, the hardened twin stops the attacks without
breaking legitimate traffic, and terraform/ declares the same controls as the hardened twin.
"""

import ipaddress
import json
import pathlib
import re
import tempfile
import unittest

import attack
import checker
import dryrun_report
from twin import Deployment, Request, evaluate

HERE = pathlib.Path(__file__).resolve().parent
STEP = {s.sid: s for s in attack.STEPS}


def allowed(sid, twin):
    return attack.run_step(STEP[sid], twin).allowed


def tf_text():
    return "\n".join(p.read_text() for p in sorted((HERE / "terraform").glob("*.tf")))


class T1_Today(unittest.TestCase):
    def test_01_stolen_key_calls_and_deploys(self):
        """today: chatbot-runtime's leaked JSON key calls Gemini AND deploys a GPU model from the internet"""
        self.assertTrue(allowed("A1", "today"))
        d = attack.run_step(STEP["A2"], "today")
        self.assertTrue(d.allowed)
        self.assertTrue(any("roles/aiplatform.user" in n for n in d.notes))

    def test_02_hijacked_helpdesk_exfiltrates_two_ways(self):
        """today: a prompt-injected Helpdesk copies tickets to another org's project and posts them to a webhook"""
        self.assertTrue(allowed("A3", "today"))
        self.assertTrue(allowed("A4", "today"))

    def test_03_project_level_token_creator(self):
        """today: any helpdesk developer can mint a token for chatbot-runtime (Token Creator on the project)"""
        self.assertTrue(allowed("A5", "today"))

    def test_04_auditor_answers_nothing(self):
        """today: none of the auditor's four questions can be answered"""
        self.assertEqual([q[2] for q in attack.questions(Deployment.load("today"))], [False] * 4)


class T2_Checker(unittest.TestCase):
    def test_05_checker_finds_every_planted_gap(self):
        """checker: 16 findings on today's twin, rules GC11-01 to GC11-15 except GC11-10 (no key exists yet)"""
        findings = checker.run("today")
        expected = {f"GC11-{n:02d}" for n in range(1, 16)} - {"GC11-10"}
        self.assertEqual({f.rule for f in findings}, expected)
        self.assertEqual(len(findings), 16)

    def test_06_hardened_leaves_only_the_challenge(self):
        """checker: the hardened twin has at most 2 findings, both challenge items (dry-run perimeter, durable cache)"""
        findings = checker.run("hardened")
        left = {(f.rule, f.severity) for f in findings}
        self.assertLessEqual(left, {("GC11-08", "WARNING"), ("GC11-11", "MEDIUM")})
        self.assertEqual(len(findings), len(left))

    def test_07_checker_reads_terraform_show_json(self):
        """checker: resources inside child_modules (real `terraform show -json` output) are found too"""
        plan = json.loads((HERE / "twin/today/plan.json").read_text())
        root = plan["planned_values"]["root_module"]
        plan["planned_values"]["root_module"] = {"resources": [], "child_modules": [
            {"address": "module.helpdesk", "resources": root["resources"]}]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(plan, fh)
        findings = checker.run("today", plan=fh.name)
        self.assertEqual(len(findings), 16)
        pathlib.Path(fh.name).unlink()


class T3_Hardened(unittest.TestCase):
    def test_08_no_key_nothing_to_steal(self):
        """hardened: no user-managed key exists, so the stolen-key attacks have nothing to use"""
        for sid in ("A1", "A2"):
            d = attack.run_step(STEP[sid], "hardened")
            self.assertFalse(d.allowed, sid)
            self.assertIn("no user-managed key", d.why)

    def test_09_custom_role_cant_deploy(self):
        """hardened: even from the Helpdesk VM, the predict-only custom role can't deploy a model"""
        d = Deployment.load("hardened")
        r = Request(attack.SA, "attached", "vm:helpdesk-vm", "aiplatform.googleapis.com",
                    "aiplatform.endpoints.deploy", "publishers/meta/models/llama3:deploy")
        dec = evaluate(r, d)
        self.assertFalse(dec.allowed)
        self.assertIn("IAM", dec.why)

    def test_10_no_route_to_the_internet(self):
        """hardened: the hijacked Helpdesk can't reach an attacker's webhook (deny-all egress, no NAT, no external IP)"""
        d = attack.run_step(STEP["A4"], "hardened")
        self.assertFalse(d.allowed)
        self.assertIn("egress firewall", d.why)

    def test_11_token_creator_removed(self):
        """hardened: developers can no longer mint tokens for chatbot-runtime"""
        self.assertFalse(allowed("A5", "hardened"))

    def test_12_perimeter_sees_the_copy(self):
        """hardened: the cross-project copy is never silent: dry run logs it (until you enforce the perimeter)"""
        d = attack.run_step(STEP["A3"], "hardened")
        seen = d.why + " ".join(d.notes)
        self.assertIn("RESOURCE_NOT_IN_SAME_SERVICE_PERIMETER", seen)
        if d.allowed:
            self.assertIn("DRY RUN", seen)

    def test_13_legitimate_traffic_survives(self):
        """hardened: the Helpdesk, its BigQuery reads, the office analysts and the summariser all still work"""
        for sid in ("L1", "L2", "L3", "L4"):
            self.assertTrue(allowed(sid, "hardened"), sid)

    def test_14_model_calls_go_through_psc(self):
        """hardened: the Helpdesk reaches Gemini through the Private Service Connect endpoint, not the internet"""
        d = attack.run_step(STEP["L1"], "hardened")
        self.assertTrue(any("Private Service Connect endpoint 10.100.0.2" in n for n in d.notes))

    def test_15_auditor_answers_everything(self):
        """hardened: all four auditor questions can be answered"""
        self.assertEqual([q[2] for q in attack.questions(Deployment.load("hardened"))], [True] * 4)


class T4_Residency(unittest.TestCase):
    def test_16_global_endpoint_is_flagged(self):
        """residency: the global endpoint is a HIGH finding today and gone in the hardened twin"""
        self.assertIn("GC11-14", {f.rule for f in checker.run("today")})
        self.assertNotIn("GC11-14", {f.rule for f in checker.run("hardened")})

    def test_17_eu_multiregion_breaks_the_private_path(self):
        """residency: switching to aiplatform.eu.rep.googleapis.com breaks the Helpdesk (PGA and the global PSC bundle don't cover rep endpoints)"""
        d = attack.run_step(STEP["L1"], "eu-multiregion")
        self.assertFalse(d.allowed)
        self.assertIn("rep.googleapis.com", d.why)


class T5_DryRunReport(unittest.TestCase):
    def test_18_report_groups_the_week(self):
        """dry run: 44 would-be denials in 5 groups; 42 are the office analysts (fix them before enforcing)"""
        rows = dryrun_report.dry_run_entries(dryrun_report.load(HERE / "logs/vpcsc-dryrun-week.jsonl"))
        groups = dryrun_report.summarise(rows)
        self.assertEqual((len(rows), len(groups)), (44, 5))
        analysts = sum(g["count"] for k, g in groups.items() if k[0].startswith("analyst"))
        self.assertEqual(analysts, 42)


class T6_Terraform(unittest.TestCase):
    def test_19_terraform_declares_every_hardened_control(self):
        """terraform: every resource type in the hardened twin is declared in terraform/, and nothing risky is"""
        tf = tf_text()
        declared = set(re.findall(r'^resource "(\w+)"', tf, re.M))
        twin_types = {r["type"] for r in Deployment.load("hardened").resources()}
        self.assertEqual(twin_types - declared, set())
        for banned in ("google_service_account_key", "google_compute_router_nat"):
            self.assertNotIn(banned, declared)
        self.assertNotRegex(tf, r"(?m)^\s*access_config\s*\{")

    def test_20_terraform_control_values(self):
        """terraform: predict-only role, DATA_READ logs, vpc-sc PSC bundle, PGA, CMEK datasets, rotation, dry-run perimeter"""
        tf = tf_text()
        for pattern in (r'permissions\s*=\s*\["aiplatform\.endpoints\.predict"\]',
                        r'service\s*=\s*"aiplatform\.googleapis\.com"', r'log_type\s*=\s*"DATA_READ"',
                        r'target\s*=\s*"vpc-sc"', r'purpose\s*=\s*"PRIVATE_SERVICE_CONNECT"',
                        r'private_ip_google_access\s*=\s*true', r'dns_name\s*=\s*"googleapis\.com\."',
                        r'name\s*=\s*"\*\.googleapis\.com\."', r'rotation_period\s*=\s*"\d+s"',
                        r'use_explicit_dry_run_spec\s*=\s*true', r'roles/cloudkms\.cryptoKeyEncrypterDecrypter'):
            self.assertRegex(tf, pattern)
        self.assertEqual(len(re.findall(r"default_encryption_configuration\s*\{", tf)), 2)

    def test_21_no_real_looking_data(self):
        """safety: only documentation/private IPs, example.com identities, no key material, in every lab file"""
        ok_nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                                     "10.0.0.0/8", "0.0.0.0/32")]
        files = [p for p in HERE.rglob("*") if p.is_file() and p.suffix in (".json", ".jsonl", ".py", ".tf", ".sh",
                                                                             ".tftpl", ".md", ".example")]
        for p in files:
            text = p.read_text()
            for ip in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text):
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                self.assertTrue(any(addr in n for n in ok_nets), f"{p.name}: {ip}")
            for email in re.findall(r"[\w.+-]+@([\w.-]+\.\w+)", text):
                self.assertTrue(email.endswith(("example.com", "gserviceaccount.com", "thesecguy.com",
                                                "your-domain.example")), f"{p.name}: {email}")
            self.assertFalse(("BEGIN " + "PRIVATE KEY") in text, p.name)
            self.assertFalse(re.search("AI" + r"za[0-9A-Za-z_-]{35}", text), p.name)


if __name__ == "__main__":
    unittest.main()
