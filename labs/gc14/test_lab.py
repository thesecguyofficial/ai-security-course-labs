"""
test_lab.py: `make test`. Proves the lab works as the README says: the decision-table numbers, that every checker
rule fires when its setting is wrong and stays quiet when it's right, that the CEL subset follows Google's attribute
table and refuses anything else, what DRY_RUN does, that the controls fail closed, and that nothing real is in here.
These tests pass before AND after you finish the challenge.
"""

import copy
import json
import re
import unittest

import cel
import checker
import decide
from twin import HERE, load_deployment, load_json, load_registry

TODAY_RULES = {f"GC14-{n:02d}" for n in range(2, 18)} - {"GC14-01", "GC14-08", "GC14-10"}
HIJACKS = {"C1", "C2", "C3", "C4", "C5", "C6"}
ANNOTATION_RULE = ("destination.agent_registry.mcp_server.name == "
                   "'projects/example-agents-prod/locations/europe-west4/mcpServers/tickets' && "
                   "destination.agent_registry.mcp_server.tool.annotations.read_only_hint == true")
NAME_RULE = ("destination.agent_registry.mcp_server.name == "
             "'projects/example-agents-prod/locations/europe-west4/mcpServers/tickets' && "
             "destination.agent_registry.mcp_server.tool.name in ['search_kb', 'get_ticket']")


def hardened():
    return copy.deepcopy(load_deployment("hardened"))


def rule(dep, name):
    return next(r for r in dep["access_policy"]["details"]["rules"] if r["description"].split(":")[0] == name)


def with_reads_rule(expr):
    dep = hardened()
    rule(dep, "allow-ticket-reads")["conditions"]["iap.googleapis.com"]["expression"] = expr
    return dep


def rows(twin="hardened", dep=None, **kw):
    return {r["id"]: r for r in decide.run(twin, dep=dep, **kw)}


def through(rs):
    return {i for i, r in rs.items() if r["kind"] == "hijack" and r["succeeded"]}


def legit_ok(rs):
    return all(r["succeeded"] for r in rs.values() if r["kind"] == "legit")


def stopped_by(r):
    return next((layer for layer, decision, _ in r["steps"]
                 if decision in ("BLOCKED", "DENIED", "SKIPPED") or decision.startswith("retrieve")), None)


class T1_DecisionTable(unittest.TestCase):
    longMessage = False

    def test_01_today(self):
        """decide: today, 6 of 6 hijacked calls go through and 2 of 2 legitimate calls complete"""
        rs = rows("today")
        self.assertEqual(through(rs), HIJACKS)
        self.assertTrue(legit_ok(rs))

    def test_02_hardened(self):
        """decide-fixed: hardened, 0 of 6 go through, 2 of 2 complete, each stopped by the control the README names"""
        rs = rows("hardened")
        self.assertEqual(through(rs), set())
        self.assertTrue(legit_ok(rs))
        expect = {"C1": "Model Armor", "C2": "Agent Gateway", "C3": "IAM (BigQuery)", "C4": "Agent Gateway",
                  "C5": "Model Armor", "C6": "Memory Bank"}
        self.assertEqual({i: stopped_by(rs[i]) for i in expect}, expect)
        self.assertIn("default deny", rs["C2"]["steps"][-1][2])
        self.assertIn("deny-mail", rs["C4"]["steps"][-1][2])

    def test_03_dry_run(self):
        """decide-dry: DRY_RUN lets C2 and C4 through; the gateway still says what it would deny, and logs it"""
        rs = rows("hardened", dry_run=True)
        self.assertEqual(through(rs), {"C2", "C4"})
        self.assertTrue(legit_ok(rs))
        for i in ("C2", "C4"):
            self.assertEqual(rs[i]["steps"][-1][1], "DRY_RUN would deny")
            log = rs[i]["gateway_log"][0]
            self.assertEqual((log["lab"]["policy_says"], log["lab"]["dry_run"]), ("DENIED", True))

    def test_04_rugpull_with_annotation_rule(self):
        """rugpull: with an annotation-based allow rule, a re-registered tool marked readOnlyHint goes through (C4)"""
        rs = rows(dep=with_reads_rule(ANNOTATION_RULE), rugpull=True)
        self.assertEqual(through(rs), {"C4"})
        self.assertEqual(rs["C4"]["call"]["tool"], "export_ticket")
        self.assertIn("allow-ticket-reads", rs["C4"]["steps"][-1][2])
        self.assertTrue(legit_ok(rs))

    def test_05_rugpull_with_name_rule(self):
        """rugpull: the same rule written with tool NAMES stops the new tool at the default deny"""
        rs = rows(dep=with_reads_rule(NAME_RULE), rugpull=True)
        self.assertEqual(through(rs), set())
        self.assertIn("default deny", rs["C4"]["steps"][-1][2])
        self.assertTrue(legit_ok(rs))

    def test_06_outage_fail_closed(self):
        """outage: Model Armor down with failOpen false: 0 of 6, every screened response is blocked, legit still works"""
        rs = rows("hardened", armor_up=False)
        self.assertEqual(through(rs), set())
        self.assertTrue(legit_ok(rs))
        for i in ("C1", "C2", "C3", "C4", "C5"):
            self.assertEqual(rs[i]["steps"][0][:2], ("Model Armor", "BLOCKED"))

    def test_07_outage_fail_open(self):
        """outage with failOpen true: C1 and C5 text reaches the model unscreened; the gateway and topics still stop them"""
        dep = hardened()
        dep["gateway"]["model_armor_authz_extension"]["failOpen"] = True
        rs = rows(dep=dep, armor_up=False)
        for i in ("C1", "C5"):
            self.assertEqual(rs[i]["steps"][0][1], "PASSED_UNSCREENED")
        self.assertEqual(through(rs), set())
        self.assertEqual(stopped_by(rs["C1"]), "Agent Gateway")
        self.assertEqual(stopped_by(rs["C5"]), "Memory Bank")

    def test_08_no_agent_identity_fails_closed(self):
        """fail closed: an agent without Agent Identity behind the gateway is denied, legitimate calls too"""
        dep = hardened()
        dep["agent"]["identity_type"] = "SERVICE_ACCOUNT"
        rs = rows(dep=dep)
        self.assertFalse(legit_ok(rs))
        self.assertTrue(rs["L1"]["principal"].endswith("@gcp-sa-aiplatform-re.iam.gserviceaccount.com"))
        self.assertEqual(rs["L1"]["steps"][-1][1], "DENIED")

    def test_09_policy_typo_fails_loudly(self):
        """fail closed: a typo in a policy condition stops decide.py with CelError instead of allowing traffic"""
        dep = with_reads_rule(NAME_RULE.replace("tool.name", "tool.nmae"))
        with self.assertRaises(cel.CelError):
            decide.run("hardened", dep=dep)

    def test_10_memory_scope(self):
        """C6: today the body's user_id (bob) picks the memory scope; hardened uses the verified token (alice)"""
        today = rows("today")["C6"]
        self.assertTrue(any("CANARY-MEM-4410" in m["fact"] for m in today["memories"]))
        self.assertEqual(rows("hardened")["C6"]["memories"], [])

    def test_11_gateway_allows_iam_decides(self):
        """C3: the gateway allows execute_sql_readonly; IAM on the dataset decides (and a project-wide grant leaks)"""
        r = rows("hardened")["C3"]
        self.assertEqual([s[:2] for s in r["steps"][1:]], [("Agent Gateway", "ALLOWED"), ("IAM (BigQuery)", "DENIED")])
        dep = hardened()
        dep["iam_bindings"].append({"resource": "//cloudresourcemanager.googleapis.com/projects/example-agents-prod",
                                    "role": "roles/bigquery.dataViewer",
                                    "member": "principalSet://agents.global.org-100000000099.system.id.goog/"
                                              "attribute.platformContainer/aiplatform/projects/100000000014"})
        self.assertTrue(rows(dep=dep)["C3"]["succeeded"])

    def test_12_logs(self):
        """logs: Google's gateway log field names; an unregistered host has an empty agentGatewayInfo"""
        rs = rows("hardened", dry_run=True)
        c2 = rs["C2"]["gateway_log"][0]
        self.assertEqual(c2["resource"]["type"], "networkservices.googleapis.com/Gateway")
        self.assertTrue(c2["logName"].endswith("/logs/networkservices.googleapis.com%2Fgateway_requests"))
        self.assertEqual(c2["jsonPayload"]["agentGatewayInfo"], {})
        c3 = rs["C3"]["gateway_log"][0]
        self.assertEqual(c3["jsonPayload"]["agentGatewayInfo"]["agentRegistryResource"],
                         "projects/example-agents-prod/locations/global/mcpServers/bigquery")


def _mutations():
    """For each rule: a change to the HARDENED deployment that should make exactly that rule fire."""
    agent_p = load_deployment("hardened")["agent"]["effective_identity"]
    all_agents = ("principalSet://agents.global.org-100000000099.system.id.goog/"
                  "attribute.platformContainer/aiplatform/projects/100000000014")
    proj = "//cloudresourcemanager.googleapis.com/projects/example-agents-prod"

    def m01(d):
        d["agent"]["identity_type"] = "SERVICE_ACCOUNT"

    def m02(d):
        d["agent"]["env_vars"]["GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES"] = False

    def m03(d):
        d["iam_bindings"].append({"resource": proj, "role": "roles/bigquery.dataViewer", "member": all_agents})

    def m04(d):
        d["iam_bindings"].append({"resource": proj, "role": "roles/bigquery.user",
                                  "member": d["_lab_deleted_agents"][0]})

    def m05(d):
        d["gateway"]["iap_authz_extension"]["metadata"]["iamEnforcementMode"] = "DRY_RUN"

    def m05b(d):
        d["agent"]["agent_gateway_config"] = None

    def m06(d):
        d["access_policy"]["details"]["rules"].append(
            {"description": "allow-all", "effect": "ALLOW", "principals": [agent_p],
             "operation": {"permissions": ["iap.googleapis.com/resources.egressViaIAP"]}})

    def m07(d):
        rules = d["access_policy"]["details"]["rules"]
        rules[:] = [r for r in rules if not r["description"].startswith("deny-mail")]
        rules.append({"description": "allow-mail", "effect": "ALLOW", "principals": [agent_p],
                      "operation": {"permissions": ["iap.googleapis.com/resources.egressViaIAP"]},
                      "conditions": {"iap.googleapis.com": {"expression":
                          "destination.agent_registry.mcp_server.name == "
                          "'projects/example-agents-prod/locations/europe-west4/mcpServers/mail'"}}})

    def m08(d):
        rule(d, "allow-ticket-reads")["conditions"]["iap.googleapis.com"]["expression"] = ANNOTATION_RULE

    def m09(d):
        d["gateway"]["model_armor_authz_extension"] = None

    def m10(d):
        d["gateway"]["model_armor_authz_extension"]["failOpen"] = True

    def m11(d):
        d["agent"]["_lab_memory_scope_from"] = "request_body"

    def m12(d):
        d["memory_bank"]["ttl_config"] = None

    def m13(d):
        d["memory_bank"]["_lab_managed_topics"].append("EXPLICIT_INSTRUCTIONS")

    def m14(d):
        d["sandbox_templates"].append({"display_name": "browser", "config": {
            "egress_control_config": {"internet_access": True}}})

    def m15(d):
        d["agent"]["env_vars"]["TICKETS_API_TOKEN"] = "PLACEHOLDER-NOT-A-REAL-TOKEN"

    def m16(d):
        d["agent"]["env_vars"]["OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"] = "EVENT_ONLY"
        d["iam_bindings"].append({"resource": proj, "role": "roles/cloudtrace.user",
                                  "member": "group:all-engineers@example.com"})

    def m17(d):
        d["agent"]["_lab_end_user_from"] = "request_body"

    return {"GC14-01": m01, "GC14-02": m02, "GC14-03": m03, "GC14-04": m04, "GC14-05": m05, "GC14-05b": m05b,
            "GC14-06": m06, "GC14-07": m07, "GC14-08": m08, "GC14-09": m09, "GC14-10": m10, "GC14-11": m11,
            "GC14-12": m12, "GC14-13": m13, "GC14-14": m14, "GC14-15": m15, "GC14-16": m16, "GC14-17": m17}


def clean_hardened():
    """The hardened deployment with the annotation rule replaced by names, so no rule from 01 to 17 fires."""
    return with_reads_rule(NAME_RULE)


class T2_Checker(unittest.TestCase):
    longMessage = False

    def test_13_today(self):
        """check: 14 findings on today's deployment, 9 of them HIGH (15 once you've written GC14-18)"""
        f = [x for x in checker.run("today") if x.rule != "GC14-18"]
        self.assertEqual(len(f), 14)
        self.assertEqual(sum(1 for x in f if x.sev == "HIGH"), 9)
        self.assertEqual({x.rule for x in f}, TODAY_RULES)

    def test_14_hardened(self):
        """check-fixed: nothing left on the hardened deployment but GC14-08 (your challenge)"""
        self.assertLessEqual({x.rule for x in checker.run("hardened")}, {"GC14-08"})

    def test_15_every_rule_both_ways(self):
        """check: each rule GC14-01..17 fires on one wrong setting and stays quiet when it's right (18 cases)"""
        base = {x.rule for x in checker.run("hardened", dep=clean_hardened())} - {"GC14-18"}
        self.assertEqual(base, set(), f"the clean copy should have no findings, has {base}")
        missed = []
        for name, change in _mutations().items():
            want = name[:7]
            dep = clean_hardened()
            change(dep)
            got = {x.rule for x in checker.run("hardened", dep=dep)} - {"GC14-18"}
            if want not in got:
                missed.append(f"{name} didn't fire")
            extra = got - {want}
            if name == "GC14-05b":   # no gateway at all: the gateway-only rules have nothing to read
                extra -= {"GC14-09"}
            if extra:
                missed.append(f"{name} also fired {sorted(extra)}")
        self.assertEqual(missed, [])

    def test_16_gc14_07_asks_the_twin(self):
        """check: GC14-07 doesn't trust a deny rule's name; it asks the gateway twin what it would decide"""
        dep = clean_hardened()
        rule(dep, "deny-mail")["conditions"]["iap.googleapis.com"]["expression"] = (
            "destination.agent_registry.mcp_server.name == "
            "'projects/example-agents-prod/locations/europe-west4/mcpServers/mial'")
        dep["access_policy"]["details"]["rules"].append(
            {"description": "allow-registered", "effect": "ALLOW", "principals": [dep["agent"]["effective_identity"]],
             "operation": {"permissions": ["iap.googleapis.com/resources.egressViaIAP"]},
             "conditions": {"iap.googleapis.com": {"expression": "destination.is_registered == true"}}})
        self.assertIn("GC14-07", {x.rule for x in checker.run("hardened", dep=dep)})

    def test_17_ci_exit_code(self):
        """check --ci: HIGH findings would fail a pipeline; the notes never count"""
        self.assertTrue(any(x.sev == "HIGH" for x in checker.run("today")))
        self.assertEqual(len(checker.NOTES), 4)


class T3_Cel(unittest.TestCase):
    longMessage = False
    REG = {"destination.is_registered": True, "destination.agent_registry.location": "us-central1",
           "destination.agent_registry.mcp_server.tool.name": "GitHubTool",
           "destination.agent_registry.mcp_server.tool.annotations.read_only_hint": True}
    UNREG = {"destination.is_registered": False, "destination.unregistered.host": "api.example-ocr.com",
             "destination.unregistered.path": "/v2/process/1", "destination.unregistered.method": "POST"}

    def test_18_google_examples(self):
        """CEL: Google's example conditions evaluate as written (registry, tool + annotation, unregistered host/path)"""
        self.assertTrue(cel.evaluate("destination.is_registered == true && "
                                     "destination.agent_registry.location == 'us-central1'", self.REG))
        self.assertTrue(cel.evaluate("destination.agent_registry.mcp_server.tool.name == 'GitHubTool' && destination."
                                     "agent_registry.mcp_server.tool.annotations.read_only_hint == true", self.REG))
        self.assertTrue(cel.evaluate("destination.unregistered.host.endsWith('example-ocr.com') && "
                                     "destination.unregistered.path.startsWith('/v2/process') && "
                                     "destination.unregistered.method == 'POST'", self.UNREG))
        self.assertFalse(cel.evaluate("destination.unregistered.host.contains('example.net')", self.UNREG))
        self.assertTrue(cel.evaluate("", {}), "a rule without a condition matches everything")

    def test_19_operators(self):
        """CEL: in, !=, !, ( ), && before ||, and ! binds tighter than =="""
        a = {"destination.agent_registry.mcp_server.tool.name": "get_ticket", "destination.is_registered": True}
        self.assertTrue(cel.evaluate("destination.agent_registry.mcp_server.tool.name in ['search_kb', 'get_ticket']", a))
        self.assertFalse(cel.evaluate("destination.agent_registry.mcp_server.tool.name != 'get_ticket'", a))
        self.assertTrue(cel.evaluate("false && false || true", a))
        self.assertFalse(cel.evaluate("false && (false || true)", a))
        self.assertTrue(cel.evaluate("!destination.is_registered == false", a), "(!true) == false")
        self.assertFalse(cel.evaluate("destination.agent_registry.mcp_server.tool.name == 'x'", {}),
                         "an attribute the request doesn't have is null")

    def test_20_fails_loudly(self):
        """CEL: unsupported syntax raises CelError (unknown attribute, numbers, >, in on a hint, methods, lists)"""
        bad = ["destination.agent_registry.mcp_server.tool.nmae == 'x'",
               "destination.unregistered.port == 443",
               "size(destination.unregistered.path) > 3",
               "destination.agent_registry.mcp_server.tool.annotations.read_only_hint in [true]",
               "destination.agent_registry.mcp_server.tool.name.startsWith('get_')",
               "destination.agent_registry.mcp_server.tool.name in ['a' 'b']",
               "destination.agent_registry.mcp_server.tool.name in 'a'",
               "(destination.is_registered == true",
               "destination.is_registered == true &&",
               "destination.unregistered.host.matches('.*')",
               "destination.is_registered = true"]
        for expr in bad:
            with self.assertRaises(cel.CelError, msg=expr):
                cel.evaluate(expr, self.UNREG)

    def test_21_every_policy_parses(self):
        """CEL: every condition in today's and the hardened deployment is inside the supported subset"""
        for twin in ("today", "hardened"):
            for r in load_deployment(twin)["access_policy"]["details"]["rules"]:
                cel.check(r.get("conditions", {}).get("iap.googleapis.com", {}).get("expression", ""))


class T4_Files(unittest.TestCase):
    longMessage = False

    def test_22_policy_shape(self):
        """files: access policy rules use Google's v3 field names; the IAP extension uses V2 metadata"""
        for twin in ("today", "hardened"):
            dep = load_deployment(twin)
            for r in dep["access_policy"]["details"]["rules"]:
                self.assertLessEqual(set(r), {"description", "effect", "principals", "excluded_principals",
                                              "operation", "conditions"})
                self.assertIn(r["effect"], ("ALLOW", "DENY"))
                self.assertEqual(r["operation"]["permissions"], ["iap.googleapis.com/resources.egressViaIAP"])
            self.assertEqual(dep["gateway"]["iap_authz_extension"]["metadata"]["iapPolicyVersion"], "V2")
            self.assertEqual(dep["gateway"]["googleManaged"]["governedAccessPath"], "AGENT_TO_ANYWHERE")

    def test_23_cases_are_decision_only(self):
        """safety: every hijack case only says where the proposal came from; no model, no attack text in the lab"""
        allowed = {"proposed after reading untrusted ticket text",
                   "proposed after reading an untrusted knowledge-base article",
                   "the request body names a different user than the verified token",
                   "the user's own question", "the user's own request"}
        for c in load_json(HERE / "data" / "cases.json")["cases"]:
            self.assertIn(c["why"], allowed)
            self.assertIn(c["screen"], ("injection-like", "ordinary"))
        for p in ("cel.py", "twin.py", "decide.py", "checker.py"):
            code = (HERE / p).read_text(encoding="utf-8")
            hit = re.search(r"(?m)^\s*(?:import|from)\s+(openai|anthropic|google|vertexai|urllib|http|socket|"
                            r"subprocess|requests)\b", code)
            self.assertIsNone(hit, f"{p}: the offline lab calls no model and no network ({hit and hit.group(0)})")

    def test_24_safety(self):
        """safety: only documentation domains, placeholder IDs, no keys or tokens"""
        text = "".join(p.read_text(errors="ignore") for p in HERE.rglob("*")
                       if p.is_file() and p.suffix in {".py", ".json", ".tf", ".md", ".txt", ".toml", ".example"})
        for dom in set(re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", text)):
            self.assertRegex(dom, r"(^|\.)(example\.(com|org|net)|iam\.gserviceaccount\.com)$|^gcp-sa-", dom)
        self.assertNotRegex(text, r"AIza[0-9A-Za-z_-]{35}")
        self.assertNotRegex(text, r"ya29\.[0-9A-Za-z_-]{20,}")
        self.assertNotRegex(text, r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
        for twin in ("today", "hardened"):
            dep = load_deployment(twin)
            self.assertEqual((dep["project_number"], dep["org_id"]), ("100000000014", "100000000099"))
        self.assertEqual(json.dumps(load_registry()).count("example.com/mcp"), 2)

    def test_25_cloud_files(self):
        """cloud: Terraform starts in DRY_RUN with one DENY rule, grants go to the agent's own principal, audit logs on"""
        tf = (HERE / "cloud" / "terraform" / "main.tf").read_text(encoding="utf-8")
        tv = (HERE / "cloud" / "terraform" / "variables.tf").read_text(encoding="utf-8")
        self.assertRegex(tv, r'variable "enforcement" \{[^}]*default\s*=\s*"DRY_RUN"')
        self.assertRegex(tv, r'variable "grant_all_agents_project_data" \{[^}]*default\s*=\s*false')
        self.assertIn('iapPolicyVersion = "V2"', tf)
        self.assertRegex(tf, r'service\s*=\s*"iap.googleapis.com"\s*\n\s*timeout\s*=\s*"1s"\s*\n\s*fail_open\s*=\s*false')
        self.assertEqual(tf.count('effect      = "DENY"'), 1)
        self.assertIn('policy_kind       = "ACCESS"', tf)
        self.assertIn('log_type = "DATA_READ"', tf)
        self.assertEqual(re.findall(r"member\s*=\s*(\S+)", tf),
                         ["var.agent_principal", "var.agent_principal", "local.all_ours"])
        tools = "'list_dataset_ids', 'execute_sql'"
        for expr in re.findall(r'expression = "([^"]+)"', tf):
            cel.check(expr.replace("${local.bigquery_tool_list}", tools))
        dep = (HERE / "cloud" / "agent" / "deploy.py").read_text(encoding="utf-8")
        self.assertIn('"identity_type": types.IdentityType.AGENT_IDENTITY', dep)
        self.assertIn('"agent_to_anywhere_config"', dep)
        self.assertNotIn('"GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES":', dep)


if __name__ == "__main__":
    unittest.main()
