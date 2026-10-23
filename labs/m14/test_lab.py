"""
test_lab.py: `make test`. The first draft's problems are real, the hardened setup fixes them without breaking the
Helpdesk, and each AgentCore behaviour the lab relies on works the way AWS documents it.
"""

import copy
import unittest

import cedar
import checker
import evaluate
import helpdesk
import hunt
import twin

GW = twin.COMPANY["gateway_arn"]
SHIPPED_POLICIES = {"caller_must_be_signed_in_user", "never_reset_breakglass", "read_tools", "reset_mfa_it_staff",
                    "reset_own_mfa", "send_email"}


def shipped(name: str) -> twin.Setup:
    """The setup as shipped: make test ignores your challenge work (extra .cedar files, the memory flag)."""
    s = twin.Setup(name).copy()
    if name == "hardened":
        s.policies = [p for p in s.policies if p.name in SHIPPED_POLICIES]
        s.app["validate_memory_writes"] = False
    return s


def findings(setup):
    return checker.run(setup if isinstance(setup, twin.Setup) else shipped(setup))


def worked(res):
    return [r["id"] for r in res["attacks"] if r["worked"]]


class TC_Lab(unittest.TestCase):
    # ---------------------------------------------------------------- the two setups
    def test_01_first_draft_findings(self):
        """first draft: 27 findings, 14 HIGH (sessions, identity, gateway bypass, LOG_ONLY, memory, sandbox)"""
        f = findings("first-draft")
        self.assertEqual((len(f), sum(x.severity == "HIGH" for x in f)), (27, 14))

    def test_02_hardened_findings(self):
        """hardened: 0 HIGH; only the two challenge findings are left (M14-20 send_email, M14-23 memory writes)"""
        self.assertEqual(sorted(x.rule for x in findings("hardened")), ["M14-20", "M14-23"])

    def test_03_first_draft_suite(self):
        """first draft: 12 of 12 attacks work, and 7 of 7 normal requests work (that's why it shipped)"""
        r = evaluate.run_suite("first-draft")
        self.assertEqual(len(worked(r)), 12)
        self.assertTrue(all(n["works"] for n in r["normal"]))

    def test_04_hardened_suite(self):
        """hardened: only A11 and A12 still work (the challenge), and 7 of 7 normal requests still work"""
        r = evaluate.run_suite(shipped("hardened"))
        self.assertEqual(worked(r), ["A11", "A12"])
        self.assertTrue(all(n["works"] for n in r["normal"]), [n["id"] for n in r["normal"] if not n["works"]])

    # ---------------------------------------------------------------- policy engine (14.5)
    def test_05_default_deny(self):
        """policy: no applicable permit = DENY, with the reason text AWS documents for a denied tools/call"""
        d = cedar.authorize(shipped("hardened").policies, cedar.request(twin.principal_from_claims(twin.user_token("bob")),
                            "reset_mfa", {"target_username": "ceo", "caller_username": "bob"}, GW))
        self.assertEqual((d["decision"], d["determining"]), ("DENY", []))
        self.assertIn("No policy applies to the request (denied by default).", twin.denied_text(d["reason"]))

    def test_06_forbid_wins(self):
        """policy: Alice is IT staff (a permit applies) but the break-glass forbid still wins"""
        d = cedar.authorize(shipped("hardened").policies, cedar.request(twin.principal_from_claims(twin.user_token("alice")),
                            "reset_mfa", {"target_username": "breakglass-admin", "caller_username": "alice"}, GW))
        self.assertEqual((d["decision"], d["determining"]), ("DENY", ["never_reset_breakglass"]))

    def test_07_error_means_not_applied(self):
        """policy: a forbid whose condition hits a missing attribute does NOT apply (Cedar errors skip the policy)"""
        pols = [cedar.parse(f'permit (principal, action == AgentCore::Action::"HelpdeskTools___reset_mfa", resource == AgentCore::Gateway::"{GW}");', "p"),
                cedar.parse(f'forbid (principal, action == AgentCore::Action::"HelpdeskTools___reset_mfa", resource == AgentCore::Gateway::"{GW}") '
                            'when { context.input.caller_username != principal.getTag("username") };', "f")]
        d = cedar.authorize(pols, cedar.request(twin.principal_from_claims(twin.user_token("bob")), "reset_mfa", {"target_username": "ceo"}, GW))
        self.assertEqual((d["decision"], d["mismatched"]), ("ALLOW", ["f"]))

    def test_08_wildcards_rejected(self):
        """policy: a permit with wildcard action and resource is flagged (AWS rejects it at deploy)"""
        self.assertTrue(cedar.check_wildcards(cedar.parse("permit (principal, action, resource);", "x")))
        self.assertEqual([p for pol in shipped("hardened").policies for p in cedar.check_wildcards(pol)], [])

    def test_09_log_only_lets_everything_through(self):
        """policy: switch the hardened gateway to LOG_ONLY and A1 works again; the checker reports M14-16 HIGH"""
        s = shipped("hardened").copy()
        s.gateway["policyEngineConfiguration"]["mode"] = "LOG_ONLY"
        a1 = next(c for c in evaluate.CASES["attacks"] if c["id"] == "A1")
        self.assertTrue(evaluate.run_case(a1, s)["worked"])
        self.assertIn(("M14-16", "HIGH"), [(f.rule, f.severity) for f in checker.run(s)])

    def test_10_model_chosen_caller_is_refused(self):
        """policy: the model writes caller_username=alice into Bob's call; the token says bob, so it is refused"""
        s, w = shipped("hardened"), twin.World()
        r = twin.gateway_call(s, w, twin.user_token("bob"), "reset_mfa", {"target_username": "ceo", "caller_username": "alice"}, "bob-day")
        self.assertEqual((r["ok"], r["stage"]), (False, "policy"))

    def test_11_temporal_limit(self):
        """temporal: the 4th reset in one policy session is refused; a missing session ID is a validation error"""
        s, w = shipped("hardened"), twin.World()
        tok, args = twin.user_token("bob"), {"target_username": "bob", "caller_username": "bob"}
        oks = [twin.gateway_call(s, w, tok, "reset_mfa", dict(args), "bob-2027-01-23")["ok"] for _ in range(4)]
        self.assertEqual(oks, [True, True, True, False])
        self.assertIn("ValidationException", twin.gateway_call(s, w, tok, "reset_mfa", dict(args), None)["text"])

    # ---------------------------------------------------------------- identity (14.3)
    def test_12_jwt_authorizer(self):
        """identity: Dana's partner-portal token passes a scopes-only authorizer and fails allowedClients"""
        dana = twin.user_token("dana", "partner-portal")
        self.assertTrue(twin.jwt_authorize(twin.Setup("first-draft").gateway["authorizerConfiguration"], dana)[0])
        self.assertFalse(twin.jwt_authorize(shipped("hardened").gateway["authorizerConfiguration"], dana)[0])

    def test_13_authorizer_needs_a_check(self):
        """identity: a JWT authorizer with only a discovery URL is invalid (at least one check is required)"""
        cfg = {"customJWTAuthorizer": {"discoveryUrl": twin.IDP["discovery_url"]}}
        self.assertFalse(twin.jwt_authorize(cfg, twin.user_token("bob"))[0])

    def test_14_user_from_token(self):
        """identity: on the hardened runtime, a forged user_id changes nothing (the user comes from the validated JWT)"""
        r = helpdesk.ask("hardened", "bob", {"question": "Show my tickets", "user_id": "alice"})
        self.assertNotIn("CANARY-M14-ALICE-TICKET", r["answer"])
        self.assertIn("4702", r["answer"])

    # ---------------------------------------------------------------- runtime (14.2)
    def test_15_session_ids(self):
        """runtime: the backend's session map gives each user their own ID (33+ characters); the browser's ID is ignored"""
        self.assertGreaterEqual(len(twin.server_session_id("bob")), 33)
        w = twin.World()
        helpdesk.ask("hardened", "alice", {"question": "What's the status of ticket 4720?", "session_id": "x" * 40}, w)
        helpdesk.ask("hardened", "bob", {"question": "What did we talk about earlier?", "session_id": "x" * 40}, w)
        self.assertEqual(sorted(v["owner"] for v in w.sessions.values()), ["alice", "bob"])

    def test_16_tooluse_block(self):
        """runtime: with the prompt check off, a toolUse block still meets the gateway policy (defence in depth)"""
        s = shipped("hardened").copy()
        s.app["entrypoint_validates_prompt"] = False
        a10 = next(c for c in evaluate.CASES["attacks"] if c["id"] == "A10")
        r = evaluate.run_case(a10, s)
        self.assertFalse(r["worked"])
        self.assertEqual(r["run"]["denied"][0]["stage"], "policy")

    # ---------------------------------------------------------------- gateway (14.4)
    def test_17_gateway_role_needed(self):
        """gateway: take lambda:InvokeFunction away from the gateway role and the target can't be reached"""
        s = shipped("hardened").copy()
        s.iam["principals"]["tsg-gateway-role"]["policy"]["Statement"] = []
        s.iam["resource_policies"]["tools_lambda"] = None
        r = twin.gateway_call(s, twin.World(), twin.user_token("alice"), "search_kb", {"query": "vpn token"}, "alice-day")
        self.assertEqual((r["ok"], r["stage"]), (False, "target"))

    # ---------------------------------------------------------------- memory and sandboxes (14.6)
    def test_18_memory_namespaces(self):
        """memory: {actorId} gives Alice and Bob different namespaces; the shared namespace gives everyone everything"""
        s, w = shipped("hardened"), twin.World()
        twin.memory_write(s, w, "bob", "LAB-POISON-555-0100", "user")
        self.assertEqual(twin.memory_retrieve(s, w, "alice"), [])
        s2, w2 = twin.Setup("first-draft"), twin.World()
        twin.memory_write(s2, w2, "bob", "LAB-POISON-555-0100", "user")
        self.assertEqual(len(twin.memory_retrieve(s2, w2, "alice")), 1)

    def test_19_unneeded_sandbox(self):
        """sandbox: add a SANDBOX-mode Code Interpreter to the hardened setup and M14-24 is HIGH (the task doesn't need it)"""
        s = shipped("hardened").copy()
        s.tools["codeInterpreter"] = {"name": "x", "networkConfiguration": {"networkMode": "SANDBOX"}}
        self.assertIn(("M14-24", "HIGH"), [(f.rule, f.severity) for f in checker.run(s)])

    # ---------------------------------------------------------------- detection (14.7)
    def test_20_hunt(self):
        """hunt: finds the LOG_ONLY window, the one DENY that ran anyway, and the forged runtimeUserId"""
        trail, spans, app = hunt.load("cloudtrail.jsonl"), hunt.load("spans.jsonl"), hunt.load("app-log.jsonl")
        self.assertEqual([m["mode"] for m in hunt.mode_changes(trail)], ["LOG_ONLY", "ENFORCE"])
        self.assertEqual([(d["tool"], d["input"]["target_username"]) for d in hunt.would_have_been_denied(spans)],
                         [("HelpdeskTools___reset_mfa", "ceo")])
        self.assertEqual([(m["signed_in"], m["runtimeUserId"]) for m in hunt.user_id_mismatch(trail, app)], [("bob", "alice")])


if __name__ == "__main__":
    unittest.main()
