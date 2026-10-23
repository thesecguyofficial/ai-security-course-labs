"""
twin.py: the OFFLINE stand-in for the Amazon Bedrock AgentCore pieces of the M14 lab. Standard-library Python.

It reads a setup folder (setups/<name>/: the request bodies, IAM policies, Cedar policies and app notes under
review) and copies the DOCUMENTED behaviour of each AgentCore feature the lab needs. The README's "How faithful is
the twin?" table lists the AWS page behind every rule.

  * Inbound JWT authorizer (Runtime and Gateway): issuer from the discovery URL, then allowedClients -> client_id,
    allowedAudience -> aud, allowedScopes -> scope, customClaims; at least one of the four must be set
    (inbound-jwt-authorizer, runtime-oauth)
  * Runtime: one session per runtimeSessionId; "AgentCore does not enforce session-to-user mappings"
    (runtime-sessions); SigV4 callers name the user with runtimeUserId (the X-Amzn-Bedrock-AgentCore-Runtime-User-Id
    header), which needs bedrock-agentcore:InvokeAgentRuntimeForUser and is not verified (runtime-oauth)
  * Identity token vault: tokens stored per workload identity AND user; the user comes from the JWT
    (GetWorkloadAccessTokenForJWT) or from the opaque userId string (GetWorkloadAccessTokenForUserId)
  * Gateway: authorizer, then the policy engine (default deny, forbid wins; LOG_ONLY logs but allows), then the
    session-scoped temporal rule, then the target Lambda invoked with the gateway role
  * Memory: long-term records saved under the strategy namespace with {actorId} filled in from CreateEvent
  * A tiny IAM evaluator: Allow with wildcards, explicit Deny wins (identity policies; no conditions)

What the twin does NOT do: real JWT signatures (tokens here are claim dictionaries), real models, real networking,
Dogwood syntax (the one temporal rule is in temporal.json), resource-policy conditions on the Lambda.

    python3 twin.py token bob                 # the claims in Bob's Helpdesk access token
    python3 twin.py authorize hardened gateway partner-portal dana
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import pathlib
import re
import sys

import cedar

HERE = pathlib.Path(__file__).resolve().parent
COMPANY = json.loads((HERE / "anycompany.json").read_text(encoding="utf-8"))
DATA = json.loads((HERE / "data" / "tickets.json").read_text(encoding="utf-8"))
IDP = COMPANY["idp"]
SETUP_FILES = ("runtime", "gateway", "targets", "temporal", "identity", "memory", "tools", "iam", "observability", "app")
CONSENTED = ("alice", "bob", "priya", "ceo")     # users who completed the ticketing SaaS consent once


# --------------------------------------------------------------------------------------------------------------------
# Loading a setup
# --------------------------------------------------------------------------------------------------------------------
class Setup:
    """One folder under setups/. Each JSON file becomes an attribute; setup.policies holds the Cedar policies."""

    def __init__(self, name: str):
        self.name = name
        folder = HERE / "setups" / name
        if not folder.is_dir():
            raise SystemExit(f"no such setup: {name} (choose from: {', '.join(sorted(p.name for p in (HERE / 'setups').iterdir()))})")
        for stem in SETUP_FILES:
            setattr(self, stem, json.loads((folder / f"{stem}.json").read_text(encoding="utf-8")))
        self.policies = cedar.load_dir(folder / "policies")

    def copy(self) -> "Setup":
        return copy.deepcopy(self)


# --------------------------------------------------------------------------------------------------------------------
# Tokens (claim dictionaries; the real ones are signed JWTs)
# --------------------------------------------------------------------------------------------------------------------
def user_token(username: str, client: str | None = None) -> dict:
    """The access token Cognito issues to a user of one app client. Cognito access tokens carry client_id, not aud."""
    u = COMPANY["users"][username]
    client = client or u["client"]
    return {"iss": IDP["issuer"], "sub": f"sub-{username}", "client_id": IDP["clients"][client], "token_use": "access",
            "scope": "openid profile", "username": username}


def m2m_token() -> dict:
    """The agent's own client-credentials token (first draft): it names the agent, not the person asking."""
    cid = IDP["clients"]["agent-m2m"]
    return {"iss": IDP["issuer"], "sub": cid, "client_id": cid, "token_use": "access", "scope": "helpdesk/tools"}


def principal_from_claims(claims: dict) -> dict:
    """AgentCore::OAuthUser: id from the sub claim; JWT claims become tags (policy-core-concepts, policy-conditions)."""
    return {"type": "AgentCore::OAuthUser", "id": claims["sub"], "tags": {k: v for k, v in claims.items()}}


def jwt_authorize(authorizer: dict | None, claims: dict | None) -> tuple[bool, str]:
    """customJWTAuthorizer. Returns (accepted, reason)."""
    if authorizer is None:
        return True, "no JWT authorizer"
    cfg = authorizer.get("customJWTAuthorizer", {})
    if claims is None:
        return False, "401: no bearer token"
    issuer = cfg["discoveryUrl"].rsplit("/.well-known/openid-configuration", 1)[0]
    if claims.get("iss") != issuer:
        return False, "401: issuer does not match the discovery URL"
    checks = [k for k in ("allowedAudience", "allowedClients", "allowedScopes", "customClaims") if cfg.get(k)]
    if not checks:
        return False, "invalid authorizer: at least one of allowed audiences, clients, scopes or custom claims is required"
    if cfg.get("allowedClients") and claims.get("client_id") not in cfg["allowedClients"]:
        return False, "401: client_id not in allowedClients"
    if cfg.get("allowedAudience"):
        aud = claims.get("aud", [])
        aud = aud if isinstance(aud, list) else [aud]
        if not set(aud) & set(cfg["allowedAudience"]):
            return False, "401: aud not in allowedAudience"
    if cfg.get("allowedScopes") and not set(claims.get("scope", "").split()) & set(cfg["allowedScopes"]):
        return False, "401: no allowed scope"
    for rule in cfg.get("customClaims", []):
        v = claims.get(rule["inboundTokenClaimName"])
        want = rule["authorizingClaimMatchValue"]
        op = want["claimMatchOperator"]
        if op == "EQUALS" and v != want["claimMatchValue"].get("matchValueString"):
            return False, f"401: claim {rule['inboundTokenClaimName']} does not match"
        if op in ("CONTAINS", "CONTAINS_ANY"):
            have = v if isinstance(v, list) else []
            need = want["claimMatchValue"].get("matchValueStringList") or [want["claimMatchValue"].get("matchValueString")]
            if not (set(have) & set(need) if op == "CONTAINS_ANY" else all(n in have for n in need)):
                return False, f"401: claim {rule['inboundTokenClaimName']} does not match"
    return True, "accepted (" + ", ".join(checks) + " checked)"


# --------------------------------------------------------------------------------------------------------------------
# IAM (identity-based policies; explicit Deny wins)
# --------------------------------------------------------------------------------------------------------------------
def _as_list(v):
    return v if isinstance(v, list) else [v]


def _statements(policy: dict | None) -> list[dict]:
    if not policy:
        return []
    return _as_list(policy.get("Statement", []))


def statement_matches(st: dict, action: str, resource: str) -> bool:
    acts = [a.lower() for a in _as_list(st.get("Action", []))]
    res = _as_list(st.get("Resource", "*"))
    return any(fnmatch.fnmatchcase(action.lower(), a) for a in acts) and any(fnmatch.fnmatchcase(resource, r) for r in res)


def iam_allowed(setup: Setup, principal: str, action: str, resource: str) -> bool:
    p = setup.iam["principals"].get(principal)
    if p is None:
        return False
    sts = _statements(p.get("policy"))
    if any(st["Effect"] == "Deny" and statement_matches(st, action, resource) for st in sts):
        return False
    if any(st["Effect"] == "Allow" and statement_matches(st, action, resource) for st in sts):
        return True
    # same account: a resource-based policy that names the role also grants (the tools Lambda here)
    if action.lower() == "lambda:invokefunction" and resource == COMPANY["tools_lambda_arn"]:
        for st in _statements(setup.iam["resource_policies"].get("tools_lambda")):
            if st["Effect"] == "Allow" and p["arn"] in _as_list(st.get("Principal", {}).get("AWS", [])):
                return True
    return False


def principals_allowed(setup: Setup, action: str, resource: str) -> list[str]:
    return [n for n in setup.iam["principals"] if iam_allowed(setup, n, action, resource)]


# --------------------------------------------------------------------------------------------------------------------
# The world one test runs in (sessions, vault, memory, the things tools changed)
# --------------------------------------------------------------------------------------------------------------------
class World:
    def __init__(self):
        self.sessions: dict[str, dict] = {}            # runtimeSessionId -> {"owner": ..., "history": [...]}
        self.memory: list[dict] = []                    # long-term records
        self.resets: list[dict] = []                    # reset_mfa executions
        self.outbox: list[dict] = []                    # send_email executions
        self.code_runs: list[dict] = []
        self.policy_sessions: dict = {}                 # (principal id, policy session id) -> {tool: count}
        self.spans: list[dict] = []                     # what gateway tracing would show
        self.gateway_mode_override: str | None = None  # set when someone calls UpdateGateway


def server_session_id(username: str) -> str:
    """The backend's own map: one conversation per user, at least 33 characters (runtime-sessions)."""
    return "tsg-" + hashlib.sha256(f"helpdesk-session:{username}".encode()).hexdigest()[:40]


# --------------------------------------------------------------------------------------------------------------------
# Identity token vault
# --------------------------------------------------------------------------------------------------------------------
def tickets_token(setup: Setup, workload_user: str) -> dict:
    """GetResourceOauth2Token (USER_FEDERATION) with a workload access token bound to workload_user.
    The vault returns the token stored for (this workload identity, this user)."""
    if workload_user in CONSENTED:
        return {"accessToken": f"tickets-token-for-{workload_user}", "user": workload_user}
    return {"authorizationUrl": "https://tickets.example.com/oauth/authorize?state=lab", "user": workload_user}


def tickets_for(token: dict) -> list[dict]:
    return [t for t in DATA["tickets"] if t["owner"] == token.get("user")] if "accessToken" in token else []


# --------------------------------------------------------------------------------------------------------------------
# Gateway
# --------------------------------------------------------------------------------------------------------------------
def gateway_mode(setup: Setup, world: World) -> str | None:
    if world.gateway_mode_override is not None:
        return world.gateway_mode_override
    cfg = setup.gateway.get("policyEngineConfiguration")
    return cfg["mode"] if cfg else None


def gateway_tools(setup: Setup) -> dict[str, dict]:
    out = {}
    for t in setup.targets["targets"]:
        for tool in t["targetConfiguration"]["mcp"]["lambda"]["toolSchema"]["inlinePayload"]:
            out[tool["name"]] = dict(tool, target=t["name"])
    return out


def denied_text(reason: str) -> str:
    """The text AWS documents for a denied tools/call (use-gateway-with-policy)."""
    return f"AuthorizeActionException - Tool Execution Denied: Tool call not allowed due to policy enforcement [{reason}]"


def gateway_call(setup: Setup, world: World, claims: dict | None, tool: str, args: dict,
                 policy_session_id: str | None) -> dict:
    """One MCP tools/call through the gateway. Returns {"ok": bool, "text": ..., "stage": ...}."""
    ok, why = jwt_authorize(setup.gateway.get("authorizerConfiguration") if setup.gateway["authorizerType"] == "CUSTOM_JWT" else None, claims)
    if setup.gateway["authorizerType"] == "NONE":
        ok, why = True, "authorizerType NONE"
    if not ok:
        return {"ok": False, "stage": "inbound auth", "text": why}
    tools = gateway_tools(setup)
    if tool not in tools:
        return {"ok": False, "stage": "tools/call", "text": f"unknown tool {tool}"}
    target = tools[tool]["target"]
    mode = gateway_mode(setup, world)
    principal = principal_from_claims(claims) if claims else {"type": "AgentCore::OAuthUser", "id": "anonymous", "tags": {}}
    span = {"name": "AuthorizeAction", "tool": f"{target}___{tool}", "principal": principal["id"], "args": args}
    if mode:
        req = cedar.request(principal, tool, args, COMPANY["gateway_arn"], target)
        d = cedar.authorize(setup.policies, req)
        span["attributes"] = {"aws.agentcore.policy.authorization_decision": d["decision"],
                              "aws.agentcore.policy.determining_policies": d["determining"],
                              "aws.agentcore.policy.mismatched_policies": d["mismatched"],
                              "aws.agentcore.gateway.policy.mode": mode}
        if setup.observability["tracing"].get("gateway"):
            world.spans.append(span)
        if d["decision"] == "DENY" and mode == "ENFORCE":
            reason = d.get("reason") or f"denied by {', '.join(d['determining'])}"
            return {"ok": False, "stage": "policy", "text": denied_text(reason), "decision": d}
        # temporal rule (session-scoped; the policy session is keyed by caller + session ID on authenticated gateways)
        for rule in setup.temporal.get("rules", []):
            if rule["tool"] == tool and mode == "ENFORCE":
                if not policy_session_id:
                    return {"ok": False, "stage": "policy", "text": "ValidationException: x-amzn-bedrock-agentcore-policy-session-id is required"}
                key = (principal["id"] if setup.gateway["authorizerType"] != "NONE" else "*", policy_session_id)
                counts = world.policy_sessions.setdefault(key, {})
                counts[tool] = counts.get(tool, 0) + 1          # the current request counts too (policy-temporal)
                if counts[tool] > rule["max_per_policy_session"]:
                    return {"ok": False, "stage": "policy", "text": denied_text(f"temporal limit: {rule['max_per_policy_session']} {tool} per session")}
    if not iam_allowed(setup, "tsg-gateway-role", "lambda:InvokeFunction", COMPANY["tools_lambda_arn"]):
        return {"ok": False, "stage": "target", "text": "the gateway role may not invoke the tools Lambda"}
    result = run_tool(world, tool, args, via="gateway")
    if mode == "LOG_ONLY" and span.get("attributes", {}).get("aws.agentcore.policy.authorization_decision") == "DENY":
        result["log_only"] = "DENY"
    return result


STOP = {"i", "a", "an", "the", "my", "your", "to", "do", "how", "have", "please", "it", "and", "then", "is", "of", "what", "open"}


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOP}


def run_tool(world: World, tool: str, args: dict, via: str) -> dict:
    """What the tools Lambda does. It trusts its arguments: the event holds only the tool input, and the context only
    gateway, target and tool names (gateway-add-target-lambda). Who is asking is the gateway policy's job."""
    if tool == "search_kb":
        words = _words(args.get("query", ""))
        best = max(DATA["kb"], key=lambda a: len(words & _words(a["text"] + " " + a["id"].replace("-", " "))))
        hit = words & _words(best["text"] + " " + best["id"].replace("-", " "))
        return {"ok": True, "stage": "executed", "text": best["text"] if hit else "No article found."}
    if tool == "reset_mfa":
        world.resets.append({"target": args.get("target_username"), "caller": args.get("caller_username"), "via": via})
        return {"ok": True, "stage": "executed", "text": f"MFA reset for {args.get('target_username')}."}
    if tool == "send_email":
        world.outbox.append({"to": args.get("to"), "subject": args.get("subject"), "body": args.get("body"), "via": via})
        return {"ok": True, "stage": "executed", "text": f"Email sent to {args.get('to')}."}
    return {"ok": False, "stage": "target", "text": f"unknown tool {tool}"}


def lambda_direct_invoke(setup: Setup, world: World, principal: str, tool: str, args: dict) -> dict:
    """Someone calls the tools Lambda directly, not through the gateway (so no authorizer, no policy)."""
    if not iam_allowed(setup, principal, "lambda:InvokeFunction", COMPANY["tools_lambda_arn"]):
        return {"ok": False, "stage": "iam", "text": f"AccessDenied: {principal} may not invoke the tools Lambda"}
    return run_tool(world, tool, args, via=f"direct:{principal}")


# --------------------------------------------------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------------------------------------------------
def strategy_namespaces(setup: Setup) -> list[str]:
    out = []
    for s in setup.memory.get("memoryStrategies", []):
        for body in s.values():
            out += body.get("namespaceTemplates", body.get("namespaces", []))   # namespaces is the deprecated name
    return out


def resolve_namespace(template: str, actor_id: str, session_id: str = "") -> str:
    return template.replace("{actorId}", actor_id).replace("{sessionId}", session_id).replace("{memoryStrategyId}", "helpdesk_facts")


def memory_write(setup: Setup, world: World, actor_id: str, text: str, source: str) -> list[str]:
    """CreateEvent + long-term extraction (synchronous here; asynchronous in AWS)."""
    spaces = [resolve_namespace(ns, actor_id) for ns in strategy_namespaces(setup)]
    for ns in spaces:
        world.memory.append({"namespace": ns, "text": text, "actorId": actor_id, "source": source})
    return spaces


def memory_retrieve(setup: Setup, world: World, actor_id: str) -> list[dict]:
    """RetrieveMemoryRecords on the namespace the agent resolves for this actor."""
    spaces = {resolve_namespace(ns, actor_id) for ns in strategy_namespaces(setup)}
    return [r for r in world.memory if r["namespace"] in spaces]


# --------------------------------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "token":
        print(json.dumps(user_token(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None), indent=2))
    elif len(sys.argv) == 6 and sys.argv[1] == "authorize":
        s = Setup(sys.argv[2])
        cfg = (s.runtime if sys.argv[3] == "runtime" else s.gateway).get("authorizerConfiguration")
        print(jwt_authorize(cfg, user_token(sys.argv[5], sys.argv[4]))[1])
    else:
        print(__doc__.strip().splitlines()[-2].strip())
        print(__doc__.strip().splitlines()[-1].strip())
