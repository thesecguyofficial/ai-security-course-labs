"""test_lab.py: 18 tests. They prove version 1 leaks and acts unchecked, that the hardened build holds where it should,
and that the twin follows the Microsoft rules it claims to model. Run: python3 run_tests.py (make test)."""

import json
import os
import re
import shutil
import tempfile
import unittest

import attack
import checker
import hunt
import twin

HERE = os.path.dirname(os.path.abspath(__file__))
CHALLENGE = {"A6", "A7"}           # left open in fixes/ on purpose: challenges 1 and 2


def worked(setup_name):
    return {r["id"] for r in attack.run(setup_name, quiet=True)["results"] if r["kind"] == "attack" and r["worked"]}


def failed(setup_name):
    return {r["id"] for r in attack.run(setup_name, quiet=True)["results"] if r["kind"] == "legit" and r["failed"]}


class Lab(unittest.TestCase):
    longMessage = False

    def test_01_contoso_leaks(self):
        """01 version 1: all 9 attacks work, all 5 legitimate requests still work"""
        self.assertEqual(worked("contoso"), {f"A{i}" for i in range(1, 10)})
        self.assertEqual(failed("contoso"), set())

    def test_02_obvious_fixes(self):
        """02 v1.1 (native ACL on, token forwarded, search tool removed) still leaves A3, A5, A6, A7, A8, A9"""
        self.assertEqual(worked("v1.1"), {"A3", "A5", "A6", "A7", "A8", "A9"})

    def test_03_hardened_holds(self):
        """03 hardened build: A1-A5, A8, A9 blocked; no legitimate request fails"""
        self.assertEqual(worked("fixes") - CHALLENGE, set())
        self.assertEqual(failed("fixes"), set())

    def test_04_checker_contoso(self):
        """04 checker finds 19 issues in version 1, 8 of them HIGH"""
        F, _ = checker.check("contoso")
        self.assertEqual(len(F), 19)
        self.assertEqual(sum(1 for f in F if f[1] == "HIGH"), 8)
        for rule in ("AZ13-01", "AZ13-05", "AZ13-07", "AZ13-11", "AZ13-12", "AZ13-14", "AZ13-15", "AZ13-18"):
            self.assertIn(rule, {f[0] for f in F}, f"{rule} missing")

    def test_05_checker_fixes(self):
        """05 checker: hardened build has 0 findings and 1 note (tool-response guardrail doesn't cover MCP)"""
        F, notes = checker.check("fixes")
        self.assertEqual(F, [])
        self.assertEqual([n[0] for n in notes], ["AZ13-17"])

    def test_06_chunk_projection_rule(self):
        """06 AZ13-06 fires when native permission fields aren't projected to chunk rows"""
        tmp = tempfile.mkdtemp()
        try:
            for f in ("search.json", "agent.json", "app.json", "roles.json"):
                shutil.copy(os.path.join(HERE, "fixes", f), tmp)
            s = json.load(open(os.path.join(tmp, "search.json")))
            s["index"]["projection"]["permission_fields_to_chunks"] = ["group_ids"]
            json.dump(s, open(os.path.join(tmp, "search.json"), "w"))
            self.assertIn("AZ13-06", {f[0] for f in checker.check(tmp)[0]})
        finally:
            shutil.rmtree(tmp)

    def test_07_security_filter_is_a_string(self):
        """07 a GA security filter trusts whatever groups it is given (request body = leak)"""
        cfg = twin.setup("contoso")
        hits = twin.retrieve(cfg, "web", "disciplinary case notes", "bob", groups_claim=["hr"])
        self.assertIn("HR-7003", {h["parent_id"] for h in hits})
        hits = twin.retrieve(cfg, "web", "disciplinary case notes", "bob")
        self.assertNotIn("HR-7003", {h["parent_id"] for h in hits})

    def test_08_kb_without_token_unfiltered(self):
        """08 knowledge base retrieve: no x-ms-query-source-authorization = unfiltered; with it = trimmed"""
        cfg = twin.setup("fixes")
        self.assertNotIn("HR-7003", {h["parent_id"] for h in twin.retrieve(cfg, "kb", "disciplinary case notes", "bob")})
        tool = next(t for t in twin.agent_def(cfg)["definition"]["tools"] if t.get("server_label") == "knowledge-base")
        del tool["headers"]
        self.assertIn("HR-7003", {h["parent_id"] for h in twin.retrieve(cfg, "kb", "disciplinary case notes", "bob")})

    def test_09_direct_query_without_token(self):
        """09 direct query on a permission-enabled index without a user token returns only documents open to all"""
        cfg = twin.setup("v1.1")
        cfg["agent"]["agents"][0]["definition"]["tools"].insert(0, {"type": "azure_ai_search"})
        hits = twin.retrieve(cfg, "search_tool", "VPN password disciplinary case refund", "bob")
        self.assertTrue(hits)
        self.assertTrue(all(h["parent_id"].startswith("KB-1") for h in hits), [h["chunk_id"] for h in hits])

    def test_10_any_field_authorises(self):
        """10 native trimming: a document is authorised if ANY permission field matches ('all' opens it)"""
        idx = {"fields": [{"name": "UserIds"}, {"name": "GroupIds"}]}
        tok = {"oid": "u1", "groups": ["g1"]}
        rows = [{"UserIds": ["none"], "GroupIds": ["g1"]}, {"UserIds": ["u2"], "GroupIds": ["g2"]},
                {"UserIds": ["all"], "GroupIds": []}, {"UserIds": [], "GroupIds": []}]
        self.assertEqual(len(twin.native_trim(rows, idx, tok)), 2)
        self.assertEqual(len(twin.native_trim(rows, idx, None)), 1)

    def test_11_labels(self):
        """11 Purview trimming drops labels the user can't extract, and lets unlabelled chunk rows through"""
        idx = {"purviewEnabled": True}
        tok = {"labels": ["General", "Confidential"]}
        rows = [{"sensitivityLabel": "Highly Confidential"}, {"sensitivityLabel": None}, {"sensitivityLabel": "General"}]
        self.assertEqual(twin.label_trim(rows, idx, tok), rows[1:])

    def test_12_odata(self):
        """12 search.in splits on spaces and commas; a doubled quote keeps input inside its string"""
        row = {"group_ids": ["hr"], "title": "x"}
        self.assertTrue(twin.odata_match("group_ids/any(g: search.in(g, 'staff hr'))", row))
        self.assertTrue(twin.odata_match("group_ids/any(g: search.in(g, 'staff,hr'))", row))
        self.assertFalse(twin.odata_match("group_ids/any(g: search.in(g, 'staff')) and title eq 'x'' or true or title eq ''y'", row))
        self.assertTrue(twin.odata_match("group_ids/any(g: search.in(g, 'staff')) and title eq 'x' or true or title eq 'y'", row))

    def test_13_require_approval(self):
        """13 require_approval: default always; never; {"never": [...]}; {"always": [...]}"""
        n = twin.needs_approval
        self.assertTrue(n({}, "x"))
        self.assertFalse(n({"require_approval": "never"}, "x"))
        self.assertFalse(n({"require_approval": {"never": ["x"]}}, "x"))
        self.assertTrue(n({"require_approval": {"never": ["x"]}}, "y"))
        self.assertTrue(n({"require_approval": {"always": ["x"]}}, "x"))
        self.assertFalse(n({"require_approval": {"always": ["x"]}}, "y"))

    def test_14_allowed_tools(self):
        """14 no allowed_tools = every tool on the server; a list = only those"""
        self.assertIn("delete_ticket", twin.offered_tools(twin.setup("contoso")))
        self.assertNotIn("delete_ticket", twin.offered_tools(twin.setup("fixes")))

    def test_15_guardrail_coverage(self):
        """15 tool-response guardrail runs for azure_ai_search, not for MCP tools"""
        cfg = twin.setup("fixes")
        self.assertFalse(twin.guardrail_scans_response(cfg, {"type": "mcp"}))
        self.assertTrue(twin.guardrail_scans_response(cfg, {"type": "azure_ai_search"}))

    def test_16_identity(self):
        """16 a shared admin credential closes anyone's ticket; the user's own identity can't"""
        for name, expect in (("contoso", True), ("fixes", False)):
            cfg = twin.setup(name)
            tool = twin.offered_tools(cfg)["close_ticket"][0]
            self.assertEqual(twin.actions_server(cfg, "close_ticket", {"ticket": "4480"}, "bob", tool)[0], expect)

    def test_17_hunt(self):
        """17 hunt: 3 token-less retrieves, dana rubber-stamps 14 approvals, 1 email outside contoso.com"""
        ev = hunt.load_events()
        self.assertEqual(len(hunt.h1_no_token(ev)), 3)
        self.assertEqual(hunt.h2_fast_approvers(ev), {"dana": 14})
        self.assertEqual([e["turn_id"] for e in hunt.h3_outside_email(ev)], ["turn-0044"])

    def test_18_safety(self):
        """18 safety: injected lines are labelled placeholders, addresses are reserved test domains, no secrets"""
        src = open(os.path.join(HERE, "data", "source-docs.json"), encoding="utf-8").read()
        for line in re.findall(r"\[[A-Z-]+ TOOL REQUEST[^\]]*\]", src):
            self.assertTrue(line.startswith("[LAB-PLACEHOLDER"), line)
        for root, _, files in os.walk(HERE):
            if "__pycache__" in root:
                continue
            for f in files:
                if f.endswith((".json", ".jsonl", ".py", ".md", ".sh")):
                    text = open(os.path.join(root, f), encoding="utf-8").read()
                    for addr in re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", text):
                        self.assertTrue(addr.endswith((".example", "contoso.com", "example.com", "thesecguy.com")), f"{f}: {addr}")
                    self.assertNotRegex(text, r"AccountKey=[A-Za-z0-9+/]{20}|sk-[A-Za-z0-9]{20}", f)


if __name__ == "__main__":
    unittest.main()
