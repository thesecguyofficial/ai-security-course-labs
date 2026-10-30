"""
explore.py: look at each AgentCore piece of the Helpdesk on its own, before you attack it (M14 lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's JSON and
Cedar files and asks the offline twin (twin.py, cedar.py) what AgentCore would do. Pick a setup: first-draft or hardened.

    python3 explore.py map hardened                    # 1. the nine AgentCore pieces, and what this setup does with each
    python3 explore.py token bob                       # 2. the claims in Bob's access token from Amazon Cognito
    python3 explore.py inbound hardened gateway dana --client partner-portal
                                                       # 3. the JWT authorizer's checks, one by one
    python3 explore.py session first-draft bob --session-id alice-conversation-0001-0001-0001-0001
                                                       # 4. which runtime session (microVM) a request lands in
    python3 explore.py vault first-draft bob --user-id alice
                                                       # 5. whose OAuth token the token vault hands the agent
    python3 explore.py tools hardened                  # 6. the gateway's tools, and what the tools Lambda receives
    python3 explore.py policy hardened bob reset_mfa '{"target_username": "ceo", "caller_username": "bob"}'
                                                       # 7. the Cedar request, every policy, the decision, the mode
    python3 explore.py memory first-draft bob          # 8. the namespace a memory is stored under
    python3 explore.py logs hardened                   # 9. what gets recorded, and one gateway span

Everything is fake: AWS documentation example account IDs and ARNs, example.com users. cedar.py is a small teaching
evaluator, not AWS's Cedar engine; twin.py copies documented behaviour and cites the AWS page for each rule.
"""

from __future__ import annotations

import argparse
import json
import textwrap
import pathlib

import cedar
import twin

HERE = pathlib.Path(__file__).resolve().parent
C = twin.COMPANY


def _short(arn: str) -> str:
    return arn.split(":")[-1] if arn else "none"


# ---------------------------------------------------------------- 1. map

def cmd_map(a) -> None:
    s = twin.Setup(a.setup)
    rt, gw, mem, obs, tools = s.runtime, s.gateway, s.memory, s.observability, s.tools
    rt_auth = "JWT (customJWTAuthorizer)" if rt.get("authorizerConfiguration") else "IAM SigV4 (the default)"
    gw_cfg = gw["authorizerConfiguration"]["customJWTAuthorizer"] if gw["authorizerType"] == "CUSTOM_JWT" else {}
    gw_checks = ", ".join(k for k in ("allowedClients", "allowedAudience", "allowedScopes", "customClaims") if gw_cfg.get(k))
    pe = gw.get("policyEngineConfiguration")
    n_tools = len(twin.gateway_tools(s))
    prov = s.identity["credentialProviders"][0]
    ns = ", ".join(twin.strategy_namespaces(s))
    ci = tools.get("codeInterpreter")
    data_types = [t.split("::")[-1] for sel in obs["cloudtrail_advanced_event_selectors"] for f in sel["FieldSelectors"]
                  if f["Field"] == "resources.type" for t in f["Equals"]]
    traced = [k for k, v in obs["tracing"].items() if v]
    ev = obs.get("online_evaluation")
    rows = [
        ("Runtime", f"{rt['agentRuntimeName']}, {rt['agentRuntimeArtifact']['codeConfiguration']['runtime']}, "
                    f"network {rt['networkConfiguration']['networkMode']}, inbound {rt_auth}",
         "runs the agent code: one microVM per session"),
        ("Identity", f"workload identity {s.identity['workloadIdentity']['name']}; vault provider {prov['name']} "
                     f"({prov['_flow']})", "who may call; whose tokens the agent uses"),
        ("Gateway", f"{gw['name']}, {n_tools} tools, {gw['protocolType']}, inbound {gw['authorizerType']} "
                    f"({gw_checks or 'no checks'})", "one MCP door to the tools"),
        ("Policy", f"{len(s.policies)} Cedar policies, mode {pe['mode'] if pe else 'none'}",
         "a yes or no on every tool call"),
        ("Memory", f"{mem['name']}, namespace {ns}", "what the agent remembers, per user"),
        ("Code Interpreter", f"{ci['networkConfiguration']['networkMode']} network, role {_short(ci['executionRoleArn'])}"
                             if ci else "none", "runs code in a sandbox"),
        ("Browser", "none" if not tools.get("browser") else "yes", "a cloud web browser"),
        ("Observability", f"data events: {', '.join(data_types) or 'none'}; tracing: {', '.join(traced) or 'none'}",
         "the record of what happened"),
        ("Evaluations", f"{ev['onlineEvaluationConfigName']}, {ev['rule']['samplingConfig']['samplingPercentage']:g}% "
                        f"of traces, {len(ev['evaluators'])} evaluators" if ev else "none",
         "scores answers after release"),
    ]
    print(f"The TSG Helpdesk on Amazon Bedrock AgentCore, setup: {a.setup}   (fictional AnyCompany, Region {C['region']})\n")
    print(f"  {'piece':<17} {'its job':<46} what this setup has")
    for piece, has, job in rows:
        lines = textwrap.wrap(has, 62, break_on_hyphens=False) or ["none"]
        print(f"  {piece:<17} {job:<46} {lines[0]}")
        for more in lines[1:]:
            print(f"  {'':<17} {'':<46} {more}")
    print("\nOn Lambda or ECS you would build each of these yourself. Here each one is a separate AWS service with its own")
    print("settings, its own IAM actions and its own logs. Files: setups/" + a.setup + "/*.json and policies/*.cedar")


# ---------------------------------------------------------------- 2. token

CLAIM_NOTES = {
    "iss": "issuer: who signed it (AnyCompany's Cognito user pool)",
    "sub": "subject: the user's fixed ID in that pool",
    "client_id": "which app asked for the token",
    "token_use": "an access token, for calling things",
    "scope": "what the token allows",
    "username": "the user name, also a claim",
}


def cmd_token(a) -> None:
    claims = twin.user_token(a.user, a.client)
    client = a.client or C["users"][a.user]["client"]
    print(f"The access token Amazon Cognito gives {a.user} after sign-in to the {client} app.")
    print("A real one is a signed JWT: three base64 parts (header.claims.signature). These are its claims:\n")
    for k, v in claims.items():
        print(f"  {k:<10} {v:<64} {CLAIM_NOTES.get(k, '')}")
    print("\nThe browser sends it as: Authorization: Bearer <token>. Anyone who checks it reads these claims.")


# ---------------------------------------------------------------- 3. inbound

def cmd_inbound(a) -> None:
    s = twin.Setup(a.setup)
    where = s.runtime if a.where == "runtime" else s.gateway
    claims = twin.user_token(a.user, a.client)
    print(f"{a.user}'s token from the {a.client or C['users'][a.user]['client']} app, sent to the {a.where} ({a.setup})\n")
    auth = where.get("authorizerConfiguration")
    if not auth or (a.where == "gateway" and where.get("authorizerType") != "CUSTOM_JWT"):
        print(f"  no JWT authorizer here: inbound auth is {'IAM SigV4' if a.where == 'runtime' else where.get('authorizerType')}")
        print("  the caller is an AWS role (your backend), so the token's user is never checked at this door")
        return
    cfg = auth["customJWTAuthorizer"]
    issuer = cfg["discoveryUrl"].rsplit("/.well-known/openid-configuration", 1)[0]
    print(f"  discoveryUrl     {cfg['discoveryUrl']}")
    ok = claims["iss"] == issuer
    print(f"  check 1  iss     {'matches' if ok else 'DOES NOT match'} the issuer from the discovery URL")
    for field, claim in (("allowedClients", "client_id"), ("allowedAudience", "aud"), ("allowedScopes", "scope"),
                         ("customClaims", "custom claims")):
        if field in cfg:
            print(f"  check    {field:<15} {json.dumps(cfg[field])}  vs  {claim} = {claims.get(claim, '(none)')}")
        else:
            print(f"  skipped  {field:<15} not set, so nothing compares {claim}")
    print(f"\n=> {twin.jwt_authorize(auth, claims)[1]}")


# ---------------------------------------------------------------- 4. session

def cmd_session(a) -> None:
    s = twin.Setup(a.setup)
    src = s.app["runtime_session_id_from"]
    sid = a.session_id if (src == "request" and a.session_id) else twin.server_session_id(a.user)
    life = s.runtime.get("lifecycleConfiguration", {})
    print(f"{a.user} sends a message ({a.setup}). Which runtime session does it land in?\n")
    print(f"  the browser sent session ID   {a.session_id or '(none)'}")
    print(f"  this backend takes it from    {src}" + ("  (whatever the browser says)" if src == "request" else
                                                     "  (its own table: user -> session)"))
    print(f"  runtimeSessionId used         {sid}   ({len(sid)} characters; AWS asks for at least 33)")
    print("\n  InvokeAgentRuntime(agentRuntimeArn, runtimeSessionId, payload)")
    print("  same runtimeSessionId  -> the same microVM: its memory, its files, the earlier conversation")
    print("  new runtimeSessionId   -> a new microVM; after the session it is stopped and its memory sanitized")
    print(f"  stops after {life.get('idleRuntimeSessionTimeout', 900)} s idle and {life.get('maxLifetime', 28800)} s at most "
          "(AWS defaults: 15 minutes, 8 hours)")
    if src == "request" and a.session_id:
        print("\n=> AgentCore does not check that this session belongs to this user. Your backend must.")


# ---------------------------------------------------------------- 5. vault

def cmd_vault(a) -> None:
    s = twin.Setup(a.setup)
    prov = s.identity["credentialProviders"][0]
    print(f"{a.user} is signed in and asks for their tickets ({a.setup}). The agent needs a token for {prov['name']}.\n")
    if s.runtime.get("authorizerConfiguration"):
        user = a.user
        print("  1. runtime inbound: JWT. AgentCore validated the token, took iss and sub")
        print("  2. GetWorkloadAccessTokenForJWT -> a workload access token for (agent, user) = "
              f"({s.identity['workloadIdentity']['name']}, {user})")
        if a.user_id:
            print(f"     the browser also said user = {a.user_id}: ignored, the user comes from the token")
    else:
        user = a.user_id if (s.app["runtime_user_id_from"] == "request" and a.user_id) else a.user
        print("  1. runtime inbound: IAM SigV4. The caller is the backend role tsg-backend, not the user")
        print(f"  2. runtimeUserId = {user}  (header X-Amzn-Bedrock-AgentCore-Runtime-User-Id), taken from the "
              f"{s.app['runtime_user_id_from']}")
        print("     GetWorkloadAccessTokenForUserId treats it as an opaque string: nothing checks it")
    tok = twin.tickets_token(s, user)
    print(f"  3. GetResourceOauth2Token({prov['name']}, {prov['_flow']}) with that workload access token")
    print(f"  4. the vault returns the token stored for user {tok['user']}: {tok.get('accessToken', tok.get('authorizationUrl'))}")
    print(f"\n=> the agent reads {tok['user']}'s tickets" + ("   <- not the signed-in user" if tok["user"] != a.user else ""))


# ---------------------------------------------------------------- 6. tools

def cmd_tools(a) -> None:
    s = twin.Setup(a.setup)
    tg = s.targets["targets"][0]
    print(f"Gateway {s.gateway['name']} ({a.setup}): MCP endpoint, inbound {s.gateway['authorizerType']}\n")
    print(f"  target {tg['name']} = Lambda function {_short(tg['targetConfiguration']['mcp']['lambda']['lambdaArn'])}, "
          f"outbound credential {tg['credentialProviderConfigurations'][0]['credentialProviderType']}")
    print("  tools/list shows the agent these tools (target___tool):")
    for name, t in twin.gateway_tools(s).items():
        args = ", ".join(t["inputSchema"]["properties"])
        print(f"    {t['target']}___{name:<12} ({args})  {t['description'].split('. ')[0].rstrip('.')}")
    print("\n  tools/call reset_mfa -> the gateway invokes the Lambda with its own role, tsg-gateway-role. The Lambda gets:")
    print('    event   {"target_username": "...", "caller_username": "..."}       the tool input, nothing else')
    print("    context gateway ID, target ID, tool name, request IDs               nothing about the end user")
    print("\n=> the tools Lambda can't tell Bob from Alice. The check has to happen before it: in the gateway's policy.")


# ---------------------------------------------------------------- 7. policy

def cmd_policy(a) -> None:
    s = twin.Setup(a.setup)
    args = json.loads(a.args)
    principal = twin.principal_from_claims(twin.user_token(a.user))
    req = cedar.request(principal, a.tool, args, C["gateway_arn"])
    pe = s.gateway.get("policyEngineConfiguration")
    print(f"One tools/call through the gateway ({a.setup}), as the policy engine sees it:\n")
    print(f"  principal  AgentCore::OAuthUser::\"{principal['id']}\"   tags = the token's claims (username = {a.user})")
    print(f"  action     AgentCore::Action::\"{req['action']}\"")
    print(f"  resource   AgentCore::Gateway::\"...{C['gateway_arn'][-22:]}\"")
    print(f"  context    input = {json.dumps(args)}   (the tool arguments, written by the model)\n")
    for pol in s.policies:
        try:
            hit = cedar.applies(pol, req)
            res = "applies" if hit else "does not apply"
        except cedar.CedarError as e:
            res = f"error ({e}): skipped"
        print(f"  {pol.effect:<6} {pol.name:<30} {res}")
    d = cedar.authorize(s.policies, req)
    why = d.get("reason") or ("forbid wins" if d["decision"] == "DENY" else "a permit applies, no forbid")
    print(f"\n  decision   {d['decision']}   ({why})")
    mode = pe["mode"] if pe else None
    if mode == "ENFORCE":
        print(f"  mode       ENFORCE  -> the call is {'REFUSED' if d['decision'] == 'DENY' else 'run'}")
    elif mode == "LOG_ONLY":
        print("  mode       LOG_ONLY -> the decision is only logged: the call RUNS either way")
    else:
        print("  mode       no policy engine attached -> the call runs")


# ---------------------------------------------------------------- 8. memory

def cmd_memory(a) -> None:
    s = twin.Setup(a.setup)
    src = s.app["memory_actor_id_from"]
    actor = a.actor_id if (src == "request" and a.actor_id) else a.user
    print(f"{a.user} says \"Remember that I prefer updates by email.\" ({a.setup})\n")
    print(f"  short-term: CreateEvent(actorId = {actor}, sessionId = ...)   the raw turn, kept {s.memory['eventExpiryDuration']} days")
    print(f"  actorId comes from the {src}" + (f"; the browser said {a.actor_id}" if a.actor_id else ""))
    for strat in s.memory["memoryStrategies"]:
        for kind, body in strat.items():
            for tpl in body.get("namespaceTemplates", body.get("namespaces", [])):
                print(f"  long-term:  {kind} '{body['name']}' extracts a fact, saved under {tpl}")
                print(f"              for actorId {actor}: {twin.resolve_namespace(tpl, actor)}")
                others = sorted({twin.resolve_namespace(tpl, u) for u in ("alice", "bob", "priya")})
                if len(others) == 1:
                    print(f"              for alice, bob and priya alike: {others[0]}   <- one shared shelf")
                else:
                    print(f"              alice, bob, priya: {', '.join(others)}   <- one shelf each")
    print("\n  Later, RetrieveMemoryRecords on that namespace brings these facts back into the agent's prompt.")


# ---------------------------------------------------------------- 9. logs

def cmd_logs(a) -> None:
    s = twin.Setup(a.setup)
    o = s.observability
    print(f"What this setup records ({a.setup})\n")
    for sel in o["cloudtrail_advanced_event_selectors"]:
        parts = ["/".join(f["Equals"]) if f["Field"] == "eventCategory" else
                 ", ".join(t.split("::")[-1] for t in f["Equals"]) for f in sel["FieldSelectors"]]
        print(f"  CloudTrail selector '{sel['Name']}': {' events on '.join(parts)}")
    print(f"  tracing (spans)         {', '.join(k for k, v in o['tracing'].items() if v) or 'none'}"
          f"   (Transaction Search {'on' if o['transaction_search'] else 'off'})")
    print(f"  log delivery            {', '.join(f'{k} {v}' for k, v in o['log_delivery'].items() if v) or 'none'}")
    ev = o.get("online_evaluation")
    print(f"  online evaluation       {'built-in ' + ', '.join(e['evaluatorId'].split('.')[-1] for e in ev['evaluators']) if ev else 'none'}")
    span = json.loads((HERE / "data" / "incident" / "spans.jsonl").read_text("utf-8").splitlines()[2])
    print("\nOne gateway span from data/incident/spans.jsonl (illustrative values, AWS's attribute names):")
    print(f"  {span['name']}  {span['startTime']}")
    for k, v in span["attributes"].items():
        if k.startswith("aws.agentcore.policy.authorization") or k.endswith(("determining_policies", "policy.mode")):
            print(f"    {k:<48} {json.dumps(v)}")
    print(f"    lab.tool / lab.principal (lab additions)         {span['lab.tool']} / {span['lab.principal']}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Look at each AgentCore piece of the Helpdesk on its own (read-only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("map"); p.add_argument("setup"); p.set_defaults(fn=cmd_map)
    p = sub.add_parser("token"); p.add_argument("user"); p.add_argument("--client"); p.set_defaults(fn=cmd_token)
    p = sub.add_parser("inbound"); p.add_argument("setup"); p.add_argument("where", choices=["runtime", "gateway"])
    p.add_argument("user"); p.add_argument("--client"); p.set_defaults(fn=cmd_inbound)
    p = sub.add_parser("session"); p.add_argument("setup"); p.add_argument("user"); p.add_argument("--session-id")
    p.set_defaults(fn=cmd_session)
    p = sub.add_parser("vault"); p.add_argument("setup"); p.add_argument("user"); p.add_argument("--user-id")
    p.set_defaults(fn=cmd_vault)
    p = sub.add_parser("tools"); p.add_argument("setup"); p.set_defaults(fn=cmd_tools)
    p = sub.add_parser("policy"); p.add_argument("setup"); p.add_argument("user"); p.add_argument("tool")
    p.add_argument("args"); p.set_defaults(fn=cmd_policy)
    p = sub.add_parser("memory"); p.add_argument("setup"); p.add_argument("user"); p.add_argument("--actor-id")
    p.set_defaults(fn=cmd_memory)
    p = sub.add_parser("logs"); p.add_argument("setup"); p.set_defaults(fn=cmd_logs)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
