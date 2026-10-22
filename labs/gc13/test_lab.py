"""
test_lab.py: `make test`. Proves the lab works as described in the README: what today's port lost, that the
hardened port keeps every control from Modules 6 and 7, that the twins behave the way Google's documentation and
ADK 2.12.0 describe, that the cloud files match the hardened twin, and that nothing real is in here.
These tests pass before AND after you finish the challenge.
"""

import copy
import json
import re
import unittest

import attack
import checker
import helpdesk_agent
from adk_twin import ModelArmorPluginTwin, Runner, Tool
from gcp_twin import CANARY, DOCS, HERE, AgentSearchTwin, ModelArmorTwin, RagEngineTwin, load_json

TODAY_RULES = {f"GC13-{n:02d}" for n in range(1, 18)} - {"GC13-14"}


def rows(twin, **kw):
    return {r["id"]: r for r in attack.run(twin, quiet=True, **kw)}


def variant(twin, change):
    dep = copy.deepcopy(helpdesk_agent.load_deployment(twin))
    change(dep)
    return helpdesk_agent.Helpdesk(dep)


class T1_Checker(unittest.TestCase):
    def test_01_today_findings(self):
        """check: 16 findings on today's port, 11 of them HIGH (17 once you've written GC13-18)"""
        f = [x for x in checker.run("today") if x.rule != "GC13-18"]
        self.assertEqual(len(f), 16)
        self.assertEqual(sum(1 for x in f if x.sev == "HIGH"), 11)
        self.assertEqual({x.rule for x in f}, TODAY_RULES)

    def test_02_hardened_only_challenge_left(self):
        """check-hardened: nothing left but the challenge (GC13-15 recipient policy, GC13-16 fail-open)"""
        self.assertLessEqual({x.rule for x in checker.run("hardened")}, {"GC13-15", "GC13-16"})

    def test_03_confirmation_on_agent_runtime_sessions(self):
        """check: GC13-14 fires when ADK tool confirmation is used with VertexAiSessionService"""
        orig = checker.load_json

        def fake(path):
            data = orig(path)
            if str(path).endswith("hardened/deployment.json"):
                data = copy.deepcopy(data)
                data["agent"]["tools"]["close_ticket"]["confirmation"] = "adk_confirmation"
            return data
        checker.load_json = fake
        try:
            self.assertIn("GC13-14", {x.rule for x in checker.run("hardened")})
        finally:
            checker.load_json = orig


class T2_Today(unittest.TestCase):
    def test_04_every_attack_works_today(self):
        """attack: 5 of 5 attacks succeed on today's port; both legitimate requests complete; nothing is paused"""
        r = rows("today")
        self.assertEqual([k for k, v in r.items() if v["kind"] == "attack" and v["ok"]], ["R2", "R3", "R4", "R5", "R7"])
        self.assertTrue(r["R1"]["ok"] and r["R6"]["ok"])
        self.assertFalse(any(e[0] == "paused" for v in r.values() for e in v["res"]["events"]))

    def test_05_filter_was_written_by_the_model(self):
        """attack R2: the metadata filter that 'protects' finance docs came from the model's own argument"""
        r = rows("today", only=["R2"])["R2"]
        self.assertEqual(r["rag_calls"][0]["metadata_filter"], 'team == "finance"')
        self.assertIn(CANARY, r["res"]["answer"])

    def test_06_runs_as_project_service_agent(self):
        """attack: today's tools run as the project's Reasoning Engine Service Agent, and the log names no person"""
        r = rows("today", only=["R5"])["R5"]
        self.assertRegex(r["principal"], r"^serviceAccount:service-\d+@gcp-sa-aiplatform-re\.iam\.gserviceaccount\.com$")
        self.assertTrue(r["audit"] and all("end_user" not in a for a in r["audit"]))


class T3_Hardened(unittest.TestCase):
    def test_07_hardened_rag_engine(self):
        """attack-safe: 0 of 5 attacks with RAG Engine corpora per group; both legitimate requests complete"""
        r = rows("hardened")
        self.assertEqual([k for k, v in r.items() if v["kind"] == "attack" and v["ok"]], [])
        self.assertTrue(r["R1"]["ok"] and r["R6"]["ok"])

    def test_08_hardened_agent_search(self):
        """attack-search: 0 of 5 attacks with Agent Search document ACLs, searched as the end user"""
        r = rows("hardened", backend="agent_search")
        self.assertEqual([k for k, v in r.items() if v["kind"] == "attack" and v["ok"]], [])
        self.assertTrue(r["R1"]["ok"])

    def test_09_model_cannot_widen_scope(self):
        """hardened R2: the model still asks for team=finance, but only alice's corpus is searched"""
        r = rows("hardened", only=["R2"])["R2"]
        self.assertEqual({c["rag_corpus"].rsplit("/", 1)[1] for c in r["rag_calls"]}, {"kb-staff"})

    def test_10_identity_from_token(self):
        """hardened R3: the request says user_id bob, the verified token says alice: the agent acts for alice"""
        self.assertEqual(rows("hardened", only=["R3"])["R3"]["user"], "alice@example.com")

    def test_11_spoof_works_without_token(self):
        """hardened, but user_id taken from the request body: the identity spoof (R3) leaks again"""
        desk = variant("hardened", lambda d: d["agent"].__setitem__("user_id_from", "request_body"))
        _, res = desk.ask(dict(attack.SCENARIOS[2]["who"], message=attack.SCENARIOS[2]["message"]))
        self.assertIn(CANARY, res["answer"])

    def test_12_tool_output_screened(self):
        """hardened R5: Model Armor screens the ticket text (tool output) and the injected email never happens"""
        r = rows("hardened", only=["R5"])["R5"]
        self.assertEqual(r["res"]["events"][0][0], "result_blocked")
        self.assertFalse(r["ok"])

    def test_13_write_waits_for_a_person(self):
        """hardened R6: close_ticket pauses (adk_request_confirmation shape) and runs only after approval"""
        desk = helpdesk_agent.build("hardened")
        _, res = desk.ask({"id_token": "tok-bob-0002", "message": attack.SCENARIOS[5]["message"]}, human=None)
        self.assertEqual(desk.tickets["T-2041"]["status"], "open")
        self.assertEqual(res["paused"]["name"], "adk_request_confirmation")
        self.assertEqual(res["paused"]["args"]["originalFunctionCall"]["args"], {"ticket_id": "T-2041"})
        desk2 = helpdesk_agent.build("hardened")
        desk2.ask({"id_token": "tok-bob-0002", "message": attack.SCENARIOS[5]["message"]}, human=lambda req: False)
        self.assertEqual(desk2.tickets["T-2041"]["status"], "open")

    def test_14_other_teams_ticket(self):
        """hardened R7: before_tool refuses a ticket from a team the user isn't in"""
        r = rows("hardened", only=["R7"])["R7"]
        self.assertEqual(r["res"]["events"][0][0], "blocked")


class T4_Twins(unittest.TestCase):
    def test_15_acl_sees_the_caller(self):
        """twin: an ACL'd Agent Search store searched with the agent's identity returns nothing to anyone"""
        dep = helpdesk_agent.load_deployment("hardened")
        s = AgentSearchTwin(dep)
        self.assertEqual(s.search("serviceAccount:helpdesk-agent@example-chatbot-prod.iam.gserviceaccount.com",
                                  "How do I set up the VPN?")["results"], [])
        self.assertEqual(len(s.search("user:alice@example.com", "How do I set up the VPN?")["results"]), 1)
        self.assertEqual(s.search("user:alice@example.com", "hospital partner discount 2027")["results"], [])
        self.assertEqual(len(s.search("user:bob@example.com", "hospital partner discount 2027")["results"]), 1)

    def test_16_rag_permission_is_project_wide(self):
        """twin: RAG Engine lets the agent identity read ANY corpus in the project; no project role, no access"""
        dep = helpdesk_agent.load_deployment("hardened")
        rag = RagEngineTwin(dep)
        fin = dep["retrieval"]["rag_engine"]["corpora"][1]["name"]
        self.assertIn(CANARY, json.dumps(rag.retrieve_contexts("serviceAccount:helpdesk-agent", fin, "hospital discount")))
        dep["agent"]["project_roles"] = []
        self.assertEqual(RagEngineTwin(dep).retrieve_contexts("x", fin, "hospital")["error"]["code"], 403)

    def test_17_a_forgotten_filter(self):
        """twin: in a mixed corpus, a request with no metadata filter retrieves the finance document"""
        dep = helpdesk_agent.load_deployment("today")
        res = RagEngineTwin(dep).retrieve_contexts("sa", dep["retrieval"]["rag_engine"]["corpora"][0]["name"],
                                                   "hospital partners discount")
        self.assertIn(CANARY, json.dumps(res))

    def test_18_model_armor_plugin_rules(self):
        """twin: Model Armor plugin blocks on MATCH_FOUND; on failure it blocks only if block_on_screening_failure"""
        tool = Tool("get_ticket", lambda a, c: {})
        tpl = "projects/p/locations/europe-west4/templates/t"
        on = ModelArmorPluginTwin(ModelArmorTwin(), tool_output_template_name=tpl)
        self.assertIsNotNone(on.after_tool(tool, {}, None, {"text": "[LAB-INJECTED-DIRECTIVE: x]"}))
        self.assertIsNone(on.after_tool(tool, {}, None, {"text": "VPN keeps disconnecting"}))
        closed = ModelArmorPluginTwin(ModelArmorTwin(available=False), tool_output_template_name=tpl)
        opened = ModelArmorPluginTwin(ModelArmorTwin(available=False), tool_output_template_name=tpl,
                                      block_on_screening_failure=False)
        self.assertIsNotNone(closed.after_tool(tool, {}, None, {"text": "anything"}))
        self.assertIsNone(opened.after_tool(tool, {}, None, {"text": "anything"}))

    def test_19_adk_callback_order(self):
        """twin: plugin before_tool runs before the agent's; both run again after a person confirms"""
        calls = []

        class P:
            def before_tool(self, tool, args, ctx):
                calls.append("plugin")

        runner = Runner(type("M", (), {"next_step": lambda s, u, r: {"call": ("w", {})} if not r else {"text": "ok"}})(),
                        {"w": Tool("w", lambda a, c: {"status": "done"}, writes=True, confirmation="adk_confirmation")},
                        plugins=[P()], before_tool=lambda t, a, c: calls.append("agent"))
        runner.run("go", {"end_user": "x"}, human=lambda req: True)
        self.assertEqual(calls, ["plugin", "agent", "plugin", "agent"])


class T5_FailureModes(unittest.TestCase):
    def test_20_fail_open_and_no_recipient_policy(self):
        """outage: with screening failing open and no recipient policy, one approval sends the injected email"""
        def change(d):
            d["agent"]["plugins"]["model_armor"]["block_on_screening_failure"] = False
            d["agent"]["before_tool_callback"] = None
        dep = copy.deepcopy(helpdesk_agent.load_deployment("hardened"))
        change(dep)
        desk = helpdesk_agent.Helpdesk(dep, armor_available=False)
        desk.ask({"id_token": "tok-alice-0001", "message": "Summarise ticket T-2042 for me."}, human=lambda r: True)
        self.assertEqual([m["to"] for m in desk.outbox], ["collector@example.net"])

    def test_21_poisoned_bucket_matters(self):
        """hardened, but importing from the shared inbox again: only Model Armor stands between the poisoned file and the model"""
        def change(d):
            d["retrieval"]["rag_engine"]["corpora"][0]["documents"].append("inbox-refund-update")
        desk = variant("hardened", change)
        _, res = desk.ask({"id_token": "tok-alice-0001", "message": "How do I get a refund for a customer?"})
        self.assertEqual(res["events"][0][0], "result_blocked")     # Model Armor caught it; nothing else would have


class T6_Files(unittest.TestCase):
    def test_22_terraform_matches_hardened(self):
        """terraform: corpus per audience, optional CMEK, a dedicated agent account, Model Armor template"""
        tf = "".join(p.read_text() for p in (HERE / "terraform").glob("*.tf"))
        self.assertIn('resource "google_vertex_ai_rag_corpus" "kb"', tf)
        self.assertIn('toset(["staff", "finance"])', tf)
        self.assertIn('dynamic "encryption_spec"', tf)
        self.assertIn('account_id   = "helpdesk-agent"', tf)
        self.assertIn('"roles/aiplatform.user"', tf)
        self.assertNotRegex(tf, r'roles/(owner|editor|storage\.admin|aiplatform\.admin)"')
        self.assertIn('pi_and_jailbreak_filter_settings', tf)
        self.assertIn("unprovisioned", (HERE / "Makefile").read_text())

    def test_23_adk_agent_matches_hardened(self):
        """adk_agent: no scope argument for the model, confirmation on both writes, tool output screened"""
        src = (HERE / "adk_agent" / "tsg_helpdesk" / "agent.py").read_text()
        self.assertIn("def search_kb(query: str, tool_context: ToolContext)", src)
        self.assertIn("FunctionTool(send_email, require_confirmation=True)", src)
        self.assertIn("FunctionTool(close_ticket, require_confirmation=True)", src)
        self.assertIn("tool_output_template_name=", src)
        self.assertIn("block_on_screening_failure=True", src)
        self.assertIn("before_tool_callback=policy.before_tool", src)

    def test_24_nothing_real(self):
        """safety: only documentation domains, placeholder project numbers, no keys, labelled attack text"""
        text = "".join(p.read_text(errors="ignore") for p in HERE.rglob("*")
                       if p.is_file() and p.suffix in {".py", ".json", ".tf", ".sh", ".md", ".example", ".txt"})
        for email in set(re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", text)):
            self.assertRegex(email, r"(^|\.)(example\.(com|org|net)|iam\.gserviceaccount\.com|anthropic\.com)$|"
                                    r"^gcp-sa-|^example-chatbot-prod", email)
        self.assertNotRegex(text, r"AIza[0-9A-Za-z_-]{35}")
        for doc in DOCS.values():
            if "DIRECTIVE" in doc["text"]:
                self.assertIn("[LAB-INJECTED-DIRECTIVE:", doc["text"])


if __name__ == "__main__":
    unittest.main()
