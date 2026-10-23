"""
checker.py: review an AgentCore deployment of the Helpdesk the way you'd review the pull request. Offline,
standard library only.

    python3 checker.py first-draft     # make check
    python3 checker.py hardened        # make check-hardened

28 rules, M14-01 to M14-28, each tagged with the lesson that explains it. Each rule reads only the files in
setups/<name>/: request bodies, IAM and Cedar policies, and the app's notes on how it builds requests. Policy rules
don't pattern-match the Cedar text: they ask the policy engine twin concrete questions ("may Bob reset the CEO's
MFA?"). Exit code 1 if any HIGH finding, so it can fail a pipeline.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

import cedar
import twin

C = twin.COMPANY
RUNTIME_DATA_ACTIONS = ("bedrock-agentcore:InvokeAgentRuntime", "bedrock-agentcore:InvokeAgentRuntimeCommand",
                        "bedrock-agentcore:InvokeAgentRuntimeCommandShell")


@dataclass
class Finding:
    rule: str
    severity: str
    lesson: str
    message: str

    def __str__(self):
        return f"[{self.severity:6}] {self.rule} ({self.lesson}) {self.message}"


def _non_admin(s):
    return [n for n, p in s.iam["principals"].items() if not p.get("admin")]


def _reachable(s):
    return [n for n, p in s.iam["principals"].items() if p.get("end_user_reachable")]


def _ask(s, user, tool, args, client=None):
    principal = twin.principal_from_claims(twin.user_token(user, client))
    return cedar.authorize(s.policies, cedar.request(principal, tool, args, C["gateway_arn"]))["decision"]


# --------------------------------------------------------------------------------------------------------------------
# 14.2 Runtime
# --------------------------------------------------------------------------------------------------------------------
def rule_01(s):
    if s.app["runtime_session_id_from"] == "request":
        return [Finding("M14-01", "HIGH", "14.2", "the runtimeSessionId comes from the browser: AgentCore does not enforce session-to-user mappings, so a replayed ID lands in someone else's microVM")]
    return []


def rule_02(s):
    out = []
    for n in _reachable(s):
        acts = [a.split(":")[1] for a in RUNTIME_DATA_ACTIONS if twin.iam_allowed(s, n, a, C["runtime_arn"])]
        if acts:
            out.append(Finding("M14-02", "HIGH", "14.2", f"{n} (end-user reachable) may call {', '.join(acts)} on the runtime: "
                               "InvokeAgentRuntimeCommand runs shell commands in a session without the model"))
    return out


def rule_03(s):
    if not s.app["entrypoint_validates_prompt"]:
        return [Finding("M14-03", "HIGH", "14.2", "the entrypoint passes the payload's prompt to the framework without checking it is a string: a toolUse block runs a tool with no model in the loop (AgentCore Runtime has no server-side protection for this)")]
    return []


def rule_04(s):
    role = s.iam["principals"]["tsg-agent-runtime-role"]
    wide = []
    for st in twin._statements(role["policy"]):
        if st["Effect"] != "Allow":
            continue
        for r in twin._as_list(st.get("Resource", "*")):
            if r == "*" or r.endswith(":memory/*") or r.endswith(":runtime/*") or r.endswith(":code-interpreter/*"):
                wide += [f"{a} on {r}" for a in twin._as_list(st["Action"])]
    if wide:
        short = sorted({w.split(" on ")[1].split(":")[-1] for w in wide})
        return [Finding("M14-04", "HIGH", "14.2", f"the execution role has {len(wide)} grants on wildcards ({', '.join(short)}): "
                        "one compromised session can read other agents' memory, call other runtimes and sandboxes (Unit 42 'Agent God Mode')")]
    return []


def rule_05(s):
    out = []
    for n in ("tsg-agent-runtime-role", "tsg-gateway-role"):
        trust = s.iam["principals"].get(n, {}).get("trust")
        if not trust:
            continue
        keys = {k.lower() for st in twin._statements(trust) for c in st.get("Condition", {}).values() for k in c}
        if not {"aws:sourceaccount", "aws:sourcearn"} <= keys:
            out.append(Finding("M14-05", "MEDIUM", "14.2", f"{n} trust policy has no aws:SourceAccount + aws:SourceArn: any AgentCore resource could assume it (confused deputy)"))
    return out


# --------------------------------------------------------------------------------------------------------------------
# 14.3 Identity
# --------------------------------------------------------------------------------------------------------------------
def rule_06(s):
    if not s.runtime.get("authorizerConfiguration") and s.app["runtime_user_id_from"] == "request":
        return [Finding("M14-06", "HIGH", "14.3", "SigV4 runtime and the backend copies runtimeUserId from the browser: AgentCore treats it as an opaque string, so anyone can fetch anyone's tokens from the vault")]
    return []


def rule_07(s):
    out = []
    for what, body in (("runtime", s.runtime), ("gateway", s.gateway)):
        cfg = (body.get("authorizerConfiguration") or {}).get("customJWTAuthorizer")
        if cfg and not (cfg.get("allowedClients") or cfg.get("allowedAudience")):
            out.append(Finding("M14-07", "HIGH", "14.3", f"the {what} JWT authorizer checks only {', '.join(k for k in ('allowedScopes', 'customClaims') if cfg.get(k))}: "
                               "a token issued to ANY app of this identity provider (a partner portal in the same user pool) is accepted"))
    return out


def rule_08(s):
    denied = any(st["Effect"] == "Deny" and any(a.lower().endswith(("getworkloadaccesstokenforuserid", "invokeagentruntimeforuser"))
                                              for a in twin._as_list(st["Action"]))
                 for p in s.iam["principals"].values() for st in twin._statements(p.get("policy")))
    if not denied:
        return [Finding("M14-08", "MEDIUM", "14.3", "nothing explicitly denies GetWorkloadAccessTokenForUserId / InvokeAgentRuntimeForUser: the unverified user-id path stays open")]
    return []


def rule_09(s):
    out = []
    users = [c for c in s.identity["credentialProviders"] if c.get("_flow") == "USER_FEDERATION"]
    if users and (not s.identity["workloadIdentity"].get("allowedResourceOauth2ReturnUrls")
                  or not s.identity["session_binding"]["callback_checks_signed_in_user"]):
        out.append(Finding("M14-09", "MEDIUM", "14.3", "3-legged OAuth without session binding: no registered return URL that checks the signed-in user before CompleteResourceTokenAuth, so a forwarded consent link can bind one user's account to another"))
    return out


def rule_10(s):
    role = s.iam["principals"]["tsg-agent-runtime-role"]
    for st in twin._statements(role["policy"]):
        if st["Effect"] == "Allow" and any(a.lower().endswith("getresourceoauth2token") for a in twin._as_list(st["Action"])) \
                and "*" in twin._as_list(st.get("Resource")):
            return [Finding("M14-10", "MEDIUM", "14.3", "GetResourceOauth2Token on '*': the role may use every credential provider in the account; scope it to this workload identity and provider")]
    return []


# --------------------------------------------------------------------------------------------------------------------
# 14.4 Gateway
# --------------------------------------------------------------------------------------------------------------------
def rule_11(s):
    t = s.gateway["authorizerType"]
    mode = (s.gateway.get("policyEngineConfiguration") or {}).get("mode")
    if t == "NONE" or (t == "AUTHENTICATE_ONLY" and mode != "ENFORCE"):
        return [Finding("M14-11", "HIGH", "14.4", f"gateway authorizerType {t} with no enforcing policy engine: the gateway makes no authorization decision")]
    return []


def rule_12(s):
    who = [n for n in _non_admin(s) if n != "tsg-gateway-role" and twin.iam_allowed(s, n, "lambda:InvokeFunction", C["tools_lambda_arn"])]
    if who:
        return [Finding("M14-12", "HIGH", "14.4", f"{', '.join(who)} may invoke the tools Lambda directly: that path skips the gateway's authorizer and policy engine")]
    return []


def rule_13(s):
    if s.app["agent_gateway_token"] != "user_jwt":
        return [Finding("M14-13", "HIGH", "14.4", "the agent calls the gateway with its own client-credentials token: every tool call looks like the agent, so the gateway policy can't tell Bob from Alice")]
    return []


def rule_14(s):
    for st in twin._statements(s.iam["principals"]["tsg-gateway-role"]["policy"]):
        if st["Effect"] == "Allow" and "*" in twin._as_list(st.get("Resource")):
            return [Finding("M14-14", "MEDIUM", "14.4", "the gateway role has lambda:InvokeFunction on '*': its permissions are the upper bound for every caller of every target")]
    return []


def rule_15(s):
    if s.gateway.get("exceptionLevel") == "DEBUG":
        return [Finding("M14-15", "LOW", "14.4", "exceptionLevel DEBUG: detailed error messages go back to callers; turn it off outside development")]
    return []


# --------------------------------------------------------------------------------------------------------------------
# 14.5 Policy
# --------------------------------------------------------------------------------------------------------------------
def rule_16(s):
    cfg = s.gateway.get("policyEngineConfiguration")
    if not cfg:
        return [Finding("M14-16", "HIGH", "14.5", "no policy engine on the gateway: nothing outside the model decides which tool calls run")]
    if cfg["mode"] != "ENFORCE":
        return [Finding("M14-16", "HIGH", "14.5", "the policy engine is attached in LOG_ONLY mode: every tool call succeeds regardless of forbid policies")]
    return []


def rule_17(s):
    probes = [("bob", "reset_mfa", {"target_username": "ceo", "caller_username": "bob"}, "Bob resets the CEO's MFA"),
              ("bob", "reset_mfa", {"target_username": "ceo", "caller_username": "ceo"}, "Bob resets the CEO's MFA naming the CEO as caller"),
              ("bob", "reset_mfa", {"target_username": "bob", "caller_username": "alice"}, "Bob's call claims to come from Alice"),
              ("alice", "reset_mfa", {"target_username": "breakglass-admin", "caller_username": "alice"}, "the break-glass admin is reset through the agent")]
    bad = [why for user, tool, args, why in probes if _ask(s, user, tool, args) == "ALLOW"]
    if bad:
        return [Finding("M14-17", "HIGH", "14.5", "the Cedar policies ALLOW: " + "; ".join(bad))]
    return []


def rule_18(s):
    who = [n for n in _non_admin(s) if twin.iam_allowed(s, n, "bedrock-agentcore:UpdateGateway", C["gateway_arn"])]
    if who:
        return [Finding("M14-18", "HIGH", "14.5", f"{', '.join(who)} may call UpdateGateway: that permission alone can set the mode to LOG_ONLY or remove the policy engine")]
    return []


def rule_19(s):
    if s.temporal.get("rules") and s.app["policy_session_id_from"] == "request":
        return [Finding("M14-19", "MEDIUM", "14.5", "the temporal limit counts per policy session, and the browser chooses the session ID: a new ID is a new count")]
    return []


def rule_20(s):
    if _ask(s, "bob", "send_email", {"to": "someone@example.net", "subject": "x", "body": "x", "caller_username": "bob"}) == "ALLOW":
        return [Finding("M14-20", "MEDIUM", "14.5", "send_email is allowed to addresses outside example.com: an injected instruction can mail data out (challenge 1)")]
    return []


# --------------------------------------------------------------------------------------------------------------------
# 14.6 Memory, Code Interpreter, Browser
# --------------------------------------------------------------------------------------------------------------------
def rule_21(s):
    shared = [ns for ns in twin.strategy_namespaces(s) if "{actorId}" not in ns]
    if shared:
        return [Finding("M14-21", "HIGH", "14.6", f"long-term memory namespace {shared[0]} has no {{actorId}}: what one user teaches the agent, every user gets back")]
    return []


def rule_22(s):
    if s.app["memory_actor_id_from"] == "request":
        return [Finding("M14-22", "HIGH", "14.6", "the agent takes the memory actorId from the request: a user can read or write another user's memories")]
    return []


def rule_23(s):
    if not s.app.get("validate_memory_writes"):
        return [Finding("M14-23", "MEDIUM", "14.6", "memory writes are not validated: text the agent read in a tool result can become a long-term memory (challenge 2)")]
    return []


def rule_24(s):
    ci = s.tools.get("codeInterpreter")
    if not ci:
        return []
    needed = "code" in s.tools.get("_task_needs", [])
    mode = ci["networkConfiguration"]["networkMode"]
    sev = "HIGH" if (mode == "PUBLIC" or not needed) else "MEDIUM"
    return [Finding("M14-24", sev, "14.6", f"a Code Interpreter ({mode} network{', with an execution role' if ci.get('executionRoleArn') else ''}) the task "
                    f"{'does not need' if not needed else 'needs; prefer VPC mode and a role scoped to one bucket'}: even SANDBOX mode can reach Amazon S3 and resolve DNS")]


def rule_25(s):
    if s.tools.get("browser") and "browser" not in s.tools.get("_task_needs", []):
        return [Finding("M14-25", "MEDIUM", "14.6", "a Browser tool the task does not need: every page it opens is untrusted input")]
    return []


# --------------------------------------------------------------------------------------------------------------------
# 14.7 Observability and evaluations
# --------------------------------------------------------------------------------------------------------------------
def rule_26(s):
    want = {"AWS::BedrockAgentCore::Runtime", "AWS::BedrockAgentCore::Gateway", "AWS::BedrockAgentCore::Memory", "AWS::BedrockAgentCore::TokenVault"}
    have = set()
    for sel in s.observability["cloudtrail_advanced_event_selectors"]:
        f = {x["Field"]: x["Equals"] for x in sel["FieldSelectors"]}
        if f.get("eventCategory") == ["Data"]:
            have |= set(f.get("resources.type", []))
    if want - have:
        return [Finding("M14-26", "MEDIUM", "14.7", f"CloudTrail does not log data events for {', '.join(sorted(want - have))}: trails don't log data events by default")]
    return []


def rule_27(s):
    o = s.observability
    if not (o["tracing"].get("gateway") and o.get("transaction_search")):
        return [Finding("M14-27", "MEDIUM", "14.7", "gateway tracing (and CloudWatch Transaction Search) is off: no spans with the policy decision, determining policies and mode")]
    return []


def rule_28(s):
    if not s.observability.get("online_evaluation"):
        return [Finding("M14-28", "LOW", "14.7", "no online evaluation configuration: nobody samples production traces for quality or safety drift")]
    return []


RULES = [globals()[f"rule_{i:02d}"] for i in range(1, 29)]


def run(setup: twin.Setup) -> list[Finding]:
    out = []
    for r in RULES:
        out += r(setup)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(out, key=lambda f: (order[f.severity], f.rule))


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "first-draft"
    s = twin.Setup(name)
    findings = run(s)
    for f in findings:
        print(f)
    n = {k: sum(f.severity == k for f in findings) for k in ("HIGH", "MEDIUM", "LOW")}
    print(f"\n{n['HIGH']} HIGH, {n['MEDIUM']} MEDIUM, {n['LOW']} LOW  ({len(findings)} findings)")
    sys.exit(1 if n["HIGH"] else 0)


if __name__ == "__main__":
    main()
