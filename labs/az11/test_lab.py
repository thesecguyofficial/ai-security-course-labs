"""
test_lab.py: `make test`. Proves four things, one test per control:
the attacks work on Contoso version 1, the hardened build stops them, legitimate traffic survives, and the
logs answer the questions they should. The terraform/ folder is checked against fixes/plan.json so the offline
twin and the real build can't drift apart.
"""

import re
import unittest
from pathlib import Path

import attack
import checker
import hunt
from foundry_twin import PE_IP, PUBLIC_IP, PolicyEval, Twin, load

HERE = Path(__file__).resolve().parent
STEP = {s.sid: s for s in attack.STEPS}
TF = "\n".join(p.read_text() for p in sorted((HERE / "terraform").glob("*.tf")))


def rules(mode: str) -> set[str]:
    return {f.rule for f in checker.run(Twin(mode))}


class T1_Vulnerable(unittest.TestCase):
    def test_01_internet_token(self):
        """vulnerable: a stolen app token works from the internet on two of the resource's hostnames"""
        for sid in ("A1", "A2"):
            d = attack.run_step(STEP[sid], "vulnerable")
            self.assertTrue(d.allowed, sid)
            self.assertIn("PUBLIC endpoint", " ".join(d.why))

    def test_02_dns_gap_inside_vnet(self):
        """vulnerable: with one privatelink zone of three, two hostnames resolve PUBLICLY even inside the VNet"""
        t = Twin("vulnerable")
        src = {"kind": "vnet", "network": "vnet-helpdesk", "ip": "10.20.1.10"}
        answers = [t.resolve(src, h)[0] for h in t.hostnames()]
        self.assertEqual(answers.count(PE_IP), 1)
        self.assertEqual(answers.count(PUBLIC_IP), 2)

    def test_03_identity_and_ci(self):
        """vulnerable: the HR app's shared identity calls the helpdesk model; the CI secret re-opens the network and kills logging"""
        for sid in ("A3", "A6", "A7"):
            self.assertTrue(attack.run_step(STEP[sid], "vulnerable").allowed, sid)

    def test_04_approved_models_ignores_sku(self):
        """vulnerable: the approved-models policy on Deny lets an approved model through as GlobalStandard and GlobalBatch"""
        for sid in ("A4", "A5"):
            d = attack.run_step(STEP[sid], "vulnerable")
            self.assertTrue(d.allowed, sid)
            self.assertIn("compliant", " ".join(d.why))

    def test_05_no_logs_no_answers(self):
        """vulnerable: no diagnostic setting on the Foundry resource, so 'what did the attacker ask?' has no answer"""
        self.assertIn("NO ANSWER", "\n".join(attack.review("vulnerable")))


class T2_Checker(unittest.TestCase):
    def test_06_checker_vulnerable(self):
        """checker: Contoso version 1 triggers AZ11-01, 02, 03, 05, 06, 07, 08, 10, 12, 13 and 14"""
        self.assertEqual(rules("vulnerable"), {"AZ11-01", "AZ11-02", "AZ11-03", "AZ11-05", "AZ11-06", "AZ11-07",
                                               "AZ11-08", "AZ11-10", "AZ11-12", "AZ11-13", "AZ11-14"})

    def test_07_checker_fixed(self):
        """checker: the hardened build leaves only the challenge findings (AZ11-05, AZ11-13) and the accepted AZ11-14"""
        self.assertTrue(rules("safe") <= {"AZ11-05", "AZ11-13", "AZ11-14"})
        self.assertIn("AZ11-14", rules("safe"))

    def test_08_checker_catches_regressions(self):
        """checker: flipping any one hardened setting back is caught (keys, public access, purge protection, CMK grant, logs)"""
        cases = [("azurerm_cognitive_account.foundry", "local_auth_enabled", True, "AZ11-04"),
                 ("azurerm_cognitive_account.foundry", "public_network_access_enabled", True, "AZ11-02"),
                 ("azurerm_key_vault.cmk", "purge_protection_enabled", False, "AZ11-08")]
        for addr, key, val, rule in cases:
            t = Twin("safe")
            t.plan.res[addr]["values"][key] = val
            self.assertIn(rule, {f.rule for f in checker.run(t)}, key)
        t = Twin("safe")
        del t.plan.res["azurerm_role_assignment.cmk_crypto_user"]
        self.assertIn("AZ11-09", {f.rule for f in checker.run(t)})
        t = Twin("safe")
        t.plan.res["azurerm_monitor_diagnostic_setting.foundry"]["values"]["enabled_log"] = [{"category": "Audit"}]
        self.assertIn("AZ11-11", {f.rule for f in checker.run(t)})


class T3_Safe(unittest.TestCase):
    def test_09_internet_refused(self):
        """safe: the same stolen token is refused at the network, before identity is even checked"""
        for sid in ("A1", "A2"):
            d = attack.run_step(STEP[sid], "safe")
            self.assertFalse(d.allowed, sid)
            self.assertIn("public network access is Disabled", " ".join(d.why))

    def test_10_private_dns_all_hostnames(self):
        """safe: inside the VNet all three hostnames resolve to the private endpoint; legitimate calls L1-L4 work in both modes"""
        t = Twin("safe")
        src = {"kind": "vnet", "network": "vnet-helpdesk", "ip": "10.20.1.10"}
        self.assertEqual({t.resolve(src, h)[0] for h in t.hostnames()}, {PE_IP})
        for mode in ("vulnerable", "safe"):
            for sid in ("L1", "L2", "L3", "L4"):
                self.assertTrue(attack.run_step(STEP[sid], mode).allowed, f"{sid} {mode}")

    def test_11_ci_cannot_open_or_blind(self):
        """safe: the CI identity can deploy, but can't re-open the network or delete the diagnostic setting"""
        for sid in ("A6", "A7"):
            self.assertFalse(attack.run_step(STEP[sid], "safe").allowed, sid)
        self.assertFalse(attack.run_step(STEP["A4"], "safe").allowed, "GlobalStandard must be denied")

    def test_12_network_policy_backstop(self):
        """safe: even an Owner who flips publicNetworkAccess to Enabled with defaultAction Allow is refused by policy (Deny)"""
        t = Twin("safe")
        effs = t.policy_effects(STEP["A6"].fields)
        self.assertIn(("deny-ai-public-network", "Deny"), effs)

    def test_13_cmk_wiring(self):
        """safe: CMK uses a same-region vault with purge protection, and the key's identity is granted BEFORE CMK is enabled"""
        t = Twin("safe")
        self.assertTrue(t.acct["customer_managed_key"])
        self.assertEqual(t.plan.depends_on(t.account), ["time_sleep.rbac"])
        self.assertIn("azurerm_role_assignment.cmk_crypto_user", t.plan.depends_on("time_sleep.rbac"))
        self.assertNotIn("AZ11-09", rules("safe"))
        self.assertIn("NOTHING TO PULL", "\n".join(attack.review("vulnerable")))
        self.assertIn("inaccessible until the key is restored", "\n".join(attack.review("safe")))

    def test_14_vpn_dns_gotcha(self):
        """safe: a developer on the VPN without DNS forwarding resolves the PUBLIC address and is refused (fix DNS, not access)"""
        out = "\n".join(attack.review("safe"))
        self.assertIn("REFUSED", out)
        self.assertIn("never by re-opening public access", out)


class T4_PolicyLogsBuild(unittest.TestCase):
    def test_15_microsoft_snippet_has_no_effect(self):
        """policy: Microsoft's deployment-type snippet has no then block; Contoso's copy adds one and denies GlobalStandard"""
        f = {"type": "Microsoft.CognitiveServices/accounts/deployments",
             "Microsoft.CognitiveServices/accounts/deployments/sku.name": "GlobalStandard"}
        with self.assertRaises(ValueError):
            PolicyEval(load("policy-definitions/microsoft-sample-deployment-type.json"), {}, f).effect()
        self.assertEqual(PolicyEval(load("fixes/policies/deny-global-deployments.json"), {}, f).effect(), "deny")

    def test_16_hunt_finds_attacker(self):
        """hunt: the gateway logs name the outside caller, the override attempt and the bulk paste; normal traffic is quiet"""
        hits = hunt.hunt()
        self.assertEqual({e.caller for e in hits}, {"203.0.113.50"})
        self.assertEqual(len(hits), 3)
        joined = " ".join(h for e in hits for h in e.hits)
        for rule in ("H01", "H02", "H03"):
            self.assertIn(rule, joined)

    def test_17_terraform_matches_twin(self):
        """build: terraform/ sets every control the twin relies on, with the same values as fixes/plan.json"""
        must = [r'public_network_access_enabled = false', r'local_auth_enabled\s+= false', r'purge_protection_enabled\s+= true',
                r'rbac_authorization_enabled\s+= true', r'subresource_names\s+= \["account"\]', r'category = "RequestResponse"',
                r'category = "Audit"', r'role_definition_name = "Key Vault Crypto User"', r'depends_on = \[time_sleep.rbac\]',
                r'default\s+= "DataZoneStandard"', r'scope\s+= azurerm_cognitive_account.foundry.id',
                r'roleDefinitions/53ca6127-db72-4b80-b1b0-d745d6d5456d', r'role_definition_id = local.foundry_user_role_id']
        for m in must:
            self.assertRegex(TF, m)
        for z in load("contoso/standards.json")["foundry_private_dns_zones"]:
            self.assertIn(f'"{z}"', TF)
        t = Twin("safe")
        self.assertEqual(t.acct["public_network_access_enabled"], False)
        self.assertEqual(t.acct["local_auth_enabled"], False)
        tf_types = set(re.findall(r'^resource "([a-z_]+)" "([a-z_]+)"', TF, re.M))
        plan_types = {(r["type"], r["name"]) for r in t.plan.res.values() if not r.get("_contoso_only")}
        self.assertEqual(tf_types, plan_types)

    def test_18_only_documentation_values(self):
        """data: only documentation GUIDs or built-in IDs, RFC 5737 public IPs, private 10.x addresses, no secrets"""
        doc_guids = {"aaaabbbb-0000-cccc-1111-dddd2222eeee", "aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e",
                     "bbbbbbbb-1111-2222-3333-cccccccccccc", "eeee4444-ff55-6666-77aa-888888bbbbbb",
                     "ffff5555-aa66-7777-88bb-999999cccccc"}
        builtin = {"53ca6127-db72-4b80-b1b0-d745d6d5456d", "a97b65f3-24c7-4388-baec-2e87135dc908",
                   "25fbc0a9-bd7c-42a3-aa1a-3b75d497ee68", "12338af0-0e69-4776-bea7-57ae8d297424",
                   "14b46e9e-c2b7-41b4-b07b-48a6ebf60603", "aafe3651-cb78-4f68-9f81-e7e41509110f",
                   "037eea7a-bd0a-46c5-9a66-03aea78705d3", "1b4d1c4e-934c-4703-944c-27c82c06bebb",
                   "67121cc7-ff39-4ab8-b7e3-95b84dab487d", "d6759c02-b87f-42b7-892e-71b3f471d782",
                   "71ef260a-8f18-47b7-abcb-62d0673d94dc", "b24988ac-6180-42a0-ab88-20f7382dd24c"}
        guid = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
        ipv4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
        for f in HERE.rglob("*"):
            if not f.is_file() or "__pycache__" in f.parts or f.suffix not in (".json", ".py", ".md", ".tf", ".sh"):
                continue
            text = f.read_text()
            for g in guid.findall(text):
                self.assertIn(g.lower(), doc_guids | builtin, f"{f.name}: {g}")
            for m in ipv4.finditer(text):
                a, b, c = (int(x) for x in m.groups()[:3])
                ok = (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113)) or a == 10 or (a, b) == (169, 254) or a == 0
                self.assertTrue(ok, f"{f.name}: non-documentation IP {m.group(0)}")
            self.assertNotRegex(text, r"(?i)(api[-_]?key|client_secret|password)\s*[:=]\s*['\"][A-Za-z0-9+/=]{16,}")


if __name__ == "__main__":
    unittest.main()
