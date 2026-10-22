"""test_lab.py: 18 tests. They prove version 1 can be hijacked, that the hardened build holds where it should, and
that the twin follows the Microsoft rules it claims to model. Run: python3 run_tests.py (make test)."""

import copy
import json
import os
import re
import unittest

import attack
import checker
import hunt
import twin

HERE = os.path.dirname(os.path.abspath(__file__))
CHALLENGE = {"A6", "A8"}           # left open in fixes/ on purpose: challenges 1 and 2


def worked(setup_name):
    return {r["id"] for r in attack.run(setup_name, quiet=True)["results"] if r["kind"] == "attack" and r["worked"]}


def failed(setup_name):
    return {r["id"] for r in attack.run(setup_name, quiet=True)["results"] if r["kind"] == "legit" and r["failed"]}


class Lab(unittest.TestCase):
    longMessage = False

    def test_01_contoso_hijackable(self):
        """01 version 1: all 11 attacks work, all 5 legitimate requests still work"""
        self.assertEqual(worked("contoso"), {f"A{i}" for i in range(1, 12)})
        self.assertEqual(failed("contoso"), set())

    def test_02_demo_review_fixes(self):
        """02 v1.1 (guardrail name fixed, per-user memory, require_approval 'always', egress in Audit) stops only A7, A11"""
        self.assertEqual(worked("v1.1"), {f"A{i}" for i in range(1, 12)} - {"A7", "A11"})

    def test_03_hardened_holds(self):
        """03 hardened build: everything but the two challenges blocked; no legitimate request fails"""
        self.assertEqual(worked("fixes") - CHALLENGE, set())
        self.assertEqual(failed("fixes"), set())

    def test_04_checker_contoso(self):
        """04 checker finds 24 issues in version 1, 13 of them HIGH"""
        F, _ = checker.check("contoso")
        self.assertEqual(len(F), 24)
        self.assertEqual(sum(1 for f in F if f[1] == "HIGH"), 13)
        for rule in ("AZ14-01", "AZ14-03", "AZ14-06", "AZ14-10", "AZ14-12", "AZ14-15", "AZ14-18", "AZ14-19", "AZ14-21"):
            self.assertIn(rule, {f[0] for f in F}, f"{rule} missing")

    def test_05_checker_fixes(self):
        """05 checker: hardened build has 0 findings and 2 notes (egress is preview; MCP response screening unclear)"""
        F, notes = checker.check("fixes")
        self.assertEqual(F, [])
        self.assertEqual([n[0] for n in notes], ["AZ14-N2", "AZ14-N3"])

    def test_06_require_approval_is_not_enforcement(self):
        """06 require_approval 'always' on the toolbox does nothing if the hosted agent's code ignores it"""
        cfg = twin.setup("v1.1")
        r = twin.run_turn(cfg, "bob", "VPN client certificate renewal")
        self.assertTrue(any("collect@attacker.example" in e for e in r["executed"]))
        self.assertTrue(any("doesn't enforce" in n for n in r["notes"]))

    def test_07_rbac_scope_alone_stops_delete(self):
        """07 even if delete_blob is offered again, a container-scoped Reader role gets 403 on hr-exports"""
        cfg = twin.setup("fixes")
        cfg["deployment"]["agents"]["helpdesk-agent"]["runtime"]["local_tools"].append("delete_blob")
        cfg["deployment"]["agents"]["helpdesk-agent"]["runtime"]["policy_check"] = False
        r = twin.run_turn(cfg, "bob", "contractor offboarding checklist")
        self.assertEqual(r["executed"], [])
        self.assertTrue(any("403" in x for x in r["refused"]))

    def test_08_scope_rules(self):
        """08 RBAC scope: account scope covers every agent; agent scope covers exactly one"""
        acc = "/subscriptions/x/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/a"
        self.assertTrue(twin.scope_covers(acc, acc + "/projects/p/agents/z"))
        self.assertTrue(twin.scope_covers(acc + "/projects/p/agents/z", acc + "/projects/p/agents/z"))
        self.assertFalse(twin.scope_covers(acc + "/projects/p/agents/z", acc + "/projects/p/agents/z2"))

    def test_09_egress_semantics(self):
        """09 egress: first match wins, defaultAction applies otherwise, Audit never blocks, Enforced returns 403"""
        cfg = twin.setup("fixes")
        log = []
        self.assertTrue(twin.egress(cfg, "https://passwordreset.contoso.com/x", log)[0])
        self.assertFalse(twin.egress(cfg, "https://collect.attacker.example/", log)[0])
        self.assertFalse(twin.egress(cfg, "https://contoso.com.attacker.example/", log)[0])
        cfg["deployment"]["agents"]["helpdesk-agent"]["egressPolicy"]["mode"] = "Audit"
        ok, why = twin.egress(cfg, "https://collect.attacker.example/", log)
        self.assertTrue(ok and "Audit" in why)
        self.assertEqual([e["action"] for e in log], ["Allow", "Deny", "Deny", "WouldDeny"])

    def test_10_guardrail_fails_open(self):
        """10 guardrail: a missing policy name filters nothing; no rai_config filters nothing; a real one blocks"""
        cfg = twin.setup("contoso")
        self.assertIs(twin.rai_policy_exists(cfg), False)
        del cfg["deployment"]["agents"]["helpdesk-agent"]["definition"]["rai_config"]
        self.assertIsNone(twin.rai_policy_exists(cfg))
        self.assertTrue(twin.guardrail_blocks_input(twin.setup("fixes"), twin.PROMPT_ATTACK))

    def test_11_memory_scope(self):
        """11 memory: {{$userId}} gives each user a partition; a fixed scope string is one partition for all"""
        for setup_name, shared in (("contoso", True), ("fixes", False)):
            m = twin.Memory(twin.setup(setup_name))
            self.assertEqual(m.scope_for("alice") == m.scope_for("bob"), shared)

    def test_12_code_interpreter_isolation(self):
        """12 Code Interpreter: via the toolbox every user sees every upload; attached directly only their own"""
        self.assertEqual(len(twin.code_interpreter_files(twin.setup("contoso"), "bob")), 1)
        self.assertEqual(twin.code_interpreter_files(twin.setup("fixes"), "bob"), [])
        self.assertEqual(len(twin.code_interpreter_files(twin.setup("fixes"), "alice")), 1)

    def test_13_shared_session_rule(self):
        """13 AZ14-02 fires when helpdesk-web routes users to one shared session"""
        cfg = twin.setup("fixes")
        orig = twin.setup
        try:
            cfg["app"]["session_per_user"] = False
            twin.setup = lambda name: cfg
            self.assertIn("AZ14-02", {f[0] for f in checker.check("fixes")[0]})
        finally:
            twin.setup = orig

    def test_14_allowed_tools_filter(self):
        """14 allowed_tools: omitted = every server tool reaches the model; set = only the listed ones"""
        self.assertIn("delete_ticket", twin.offered_tools(twin.setup("contoso")))
        self.assertNotIn("delete_ticket", twin.offered_tools(twin.setup("fixes")))

    def test_15_per_user_connection(self):
        """15 oauth2 connection: Bob's email runs as bob, not as the shared admin key"""
        r = twin.run_turn(twin.setup("fixes"), "bob", "email me", actions=[
            {"name": "send_email", "args": {"to": "bob@contoso.com", "subject": "s", "body": "b"}}])
        self.assertTrue(r["executed"] and r["executed"][0].endswith("done as bob"))

    def test_16_policy_runs_before_human(self):
        """16 the deterministic policy refuses an outside address before any human sees an approval request"""
        trace = []
        twin.run_turn(twin.setup("fixes"), "bob", "VPN client certificate renewal", trace=trace)
        self.assertEqual([t["name"] for t in trace], ["policy_deny"])

    def test_17_hunt(self):
        """17 hunt: 1 outside email (the lookalike), 1 would-deny egress, 1 identity mismatch, 1 secret in a trace"""
        ev = hunt.load()
        self.assertEqual(len(ev), 72)
        self.assertEqual([x[2] for x in hunt.h1_outside_email(ev)], ["it-support@contoso.com.attacker.example"])
        self.assertEqual([x[3] for x in hunt.h2_egress(ev)], ["WouldDeny"])
        self.assertEqual(len(hunt.h3_identity_mismatch(ev)), 1)
        self.assertEqual([x[2] for x in hunt.h4_secrets(ev)], ["get_config"])

    def test_18_safety(self):
        """18 safety: injected lines are labelled placeholders, addresses are reserved test domains, no secrets"""
        bad_host = re.compile(r"https?://(?![a-z0-9.-]*(contoso\.com|contoso\.example|attacker\.example|azure\.com|"
                              r"microsoft\.com|azurecr\.io)\b)[a-z0-9.-]+", re.I)
        for folder in ("data", "contoso", "fixes", "logs"):
            for name in os.listdir(os.path.join(HERE, folder)):
                with open(os.path.join(HERE, folder, name), encoding="utf-8") as f:
                    text = f.read()
                self.assertIsNone(bad_host.search(text), f"{folder}/{name}: unexpected host")
                for m in re.finditer(r"\[LAB-PLACEHOLDER [^\]]*\]", text):
                    self.assertTrue(m.group(0).startswith("[LAB-PLACEHOLDER"))
                self.assertNotRegex(text, r"(?i)(sk-[a-z0-9]{20,}|AccountKey=|-----BEGIN)")
        for d in twin.DOCS.values():
            for addr in re.findall(r"[\w.-]+@[\w.-]+", d["text"]):
                self.assertTrue(addr.endswith(".example") or addr.endswith("@contoso.com"), addr)


if __name__ == "__main__":
    unittest.main()
