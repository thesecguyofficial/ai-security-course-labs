"""
explore.py: look at each Agent Platform piece of the Helpdesk agent on its own, before you run the decision table
(GC14 lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's JSON files
and asks the offline twins (twin.py, cel.py) what Google Cloud would decide. Pick a deployment: today or hardened.

    python3 explore.py map hardened                    # 1. the Agent Platform pieces, and what this deployment has
    python3 explore.py identity today                  # 2. who the agent is (its principal) and which IAM lines match it
    python3 explore.py iam today finance_exports       # 3. may the agent read this BigQuery dataset? (IAM on the data)
    python3 explore.py user today tok-alice-0001 --body-user bob@example.com
                                                       # 4. which user the app acts for: the token or the request body
    python3 explore.py registry                        # 5. the MCP servers in Agent Registry, and their tool hints
    python3 explore.py gateway hardened mail send_email
                                                       # 6. one call through Agent Gateway: attributes, rules, decision
    python3 explore.py armor today                     # 7. Model Armor on the gateway: what it screens, failOpen
    python3 explore.py memory today tok-alice-0001 --body-user bob@example.com
                                                       # 8. the Memory Bank scope, topics and TTL for one request
    python3 explore.py sandbox today                   # 9. sandbox templates and their internet switch
    python3 explore.py logs today                      # 10. which audit logs are on, and one gateway log line
    python3 explore.py case today C1                   # 11. one row of the decision table, control by control

Everything is fake: ExampleCo on the documentation domain example.com, placeholder project and organisation numbers.
twin.py and cel.py are teaching stand-ins, not Google's services; the README cites the Google page for each rule.
"""

from __future__ import annotations

import argparse
import json
import sys

sys.dont_write_bytecode = True   # read-only: leave no __pycache__ behind

import cel
import decide
import twin

TWINS = ("today", "hardened")
DATASET = "//bigquery.googleapis.com/projects/{project}/datasets/{dataset}"
# Google's Agent Identity page (30 Oct 2026): "Don't grant project-level roles such as roles/aiplatform.expressUser or
# roles/aiplatform.user to agent identities".
NOT_FOR_AGENTS = {"roles/aiplatform.expressUser", "roles/aiplatform.user"}


def short_member(m: str) -> str:
    """Make a long IAM member readable: what kind of principal, and how many agents it covers."""
    if m.startswith("principalSet://") and "attribute.platformContainer" in m:
        return "principalSet: EVERY agent in project " + m.rsplit("/", 1)[-1]
    if m.startswith("principal://agents."):
        return "principal: one agent, reasoningEngines/" + m.rsplit("/", 1)[-1]
    return m


def short_res(r: str) -> str:
    return r.split("googleapis.com/")[-1]


def wrap_rows(rows: list[tuple[str, str, str]], heads: tuple[str, str, str], width: int = 62) -> None:
    import textwrap
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
    dep = twin.load_deployment(a.twin)
    ag, gw = dep["agent"], dep.get("gateway") or {}
    iap = gw.get("iap_authz_extension") or {}
    mode = iap.get("metadata", {}).get("iamEnforcementMode", "ENFORCE")
    armor = gw.get("model_armor_authz_extension")
    rules = dep["access_policy"]["details"]["rules"]
    mb = dep["memory_bank"]
    ttl = (mb.get("ttl_config") or {}).get("default_ttl")
    sb = dep["sandbox_templates"]
    caa = ag["env_vars"].get("GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES")
    rows = [
        ("Agent Runtime", "hosts the agent code", f"{ag['display_name']}, reasoningEngines/{ag['name'].rsplit('/', 1)[-1]}"
                                                  f", region {dep['region']}"),
        ("Agent Identity", "who the agent is to IAM",
         f"identity_type {ag.get('identity_type') or 'not set (a service account)'}; token protection "
         f"{'switched OFF' if caa is False else 'on (the default)'}"),
        ("IAM", "what that identity may touch", f"{len(dep['iam_bindings'])} bindings; "
         f"{sum('principalSet://' in b['member'] for b in dep['iam_bindings'])} granted to every agent in the project"),
        ("Agent Gateway", "the one way out to tools",
         f"{gw.get('name', 'none').rsplit('/', 1)[-1]}, {gw.get('googleManaged', {}).get('governedAccessPath', '')}"
         f", policy mode {mode}" if gw else "none"),
        ("Access policy", "allow and deny rules on each call",
         ", ".join(f"{r['effect']} {r['description'].split(':')[0]}" for r in rules)),
        ("Model Armor", "screens tool responses at the gateway",
         f"on, failOpen {str(armor['failOpen']).lower()}" if armor else "none"),
        ("Memory Bank", "long-term memories per scope",
         f"topics {', '.join(mb['_lab_managed_topics'])}; TTL {ttl or 'none'}"),
        ("Sandboxes", "code, shell or browser on demand",
         ", ".join(f"{s['display_name']} (internet {str(s['config']['egress_control_config']['internet_access']).lower()})"
                   for s in sb) or "none"),
        ("Audit logs", "the record of who did what",
         "aiplatform: " + ", ".join(dep["audit_logs"].get("aiplatform.googleapis.com", [])) +
         " (Admin Activity is always on)"),
    ]
    print(f"The TSG Helpdesk on Agent Runtime, deployment: {a.twin}   (fictional ExampleCo, project {dep['project']})\n")
    wrap_rows(rows, ("piece", "its job", "what this deployment has"))


# ---------------------------------------------------------------- 2. identity

def cmd_identity(a) -> None:
    dep = twin.load_deployment(a.twin)
    p = twin.agent_principal(dep)
    ag = dep["agent"]
    print(f"  identity_type    {ag.get('identity_type') or 'not set'}")
    if p.startswith("principal://"):
        trust, rest = p[len("principal://"):].split("/", 1)
        print("  the principal    principal://<trust domain>/<the agent>")
        print(f"     trust domain  {trust}   (your organisation)")
        print(f"     the agent     {rest}")
    else:
        print(f"  the principal    {p}   (a service account, not Agent Identity)")
    caa = ag["env_vars"].get("GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES")
    print(f"  token binding    {'OFF: env var set to false (Google strongly discourages this)' if caa is False else 'on (default Context-Aware Access policy)'}")
    print("\n  IAM bindings, and whether each one reaches THIS agent:")
    data_roles = set(twin.load_json(twin.HERE / "twin" / "requirements.json")["data_roles"])
    wide_data = 0
    for b in dep["iam_bindings"]:
        hit = twin.member_matches(b["member"], p)
        stale = b["member"] in dep.get("_lab_deleted_agents", [])
        tag = "applies" if hit else ("names a DELETED agent" if stale else "someone else")
        wide_data += b["role"] in data_roles and b["member"].startswith("principalSet://")
        print(f"    {b['role']:<40} {short_member(b['member']):<58} {tag}")
        if hit and b["role"] in NOT_FOR_AGENTS:
            print("      ^ Google: \"Don't grant project-level roles such as\" this one \"to agent identities\"")
    print("\n=> A principalSet line covers every agent in the project, including ones deployed next year.")
    print(f"   Data roles granted that way here: {wide_data}" + ("  <- every agent can read the data" if wide_data else ""))


# ---------------------------------------------------------------- 3. iam

def cmd_iam(a) -> None:
    dep = twin.load_deployment(a.twin)
    p = twin.agent_principal(dep)
    res = DATASET.format(project=dep["project"], dataset=a.dataset)
    ok, why = twin.IamTwin(dep).allows(p, "bigquery.tables.getData", res)
    print(f"  who       the agent's principal (reasoningEngines/{p.rsplit('/', 1)[-1]})")
    print(f"  wants     bigquery.tables.getData on dataset {a.dataset}")
    print(f"  IAM looks at bindings on the dataset AND on its parent project {dep['project']}")
    print(f"\n=> {'ALLOWED: ' if ok else 'DENIED: '}{why}")


# ---------------------------------------------------------------- 4. user

def cmd_user(a) -> None:
    dep = twin.load_deployment(a.twin)
    ag = dep["agent"]
    tok_user = twin.DIRECTORY["id_tokens"][a.token]
    body = a.body_user or tok_user
    case = {"id_token": a.token, "request_user_id": body}
    print(f"  verified ID token {a.token}   belongs to {tok_user}")
    print(f"  the request body says user_id   {body}")
    for field, label in (("_lab_end_user_from", "end user for tool calls"), ("_lab_memory_scope_from", "memory scope")):
        src = ag.get(field)
        print(f"  {label:<24} from {src.replace('_', ' '):<15} -> {decide.who(ag, case, field)}")
    if decide.who(ag, case, "_lab_memory_scope_from") != tok_user:
        print("\n=> The app acts for whoever the body names. Agent Runtime doesn't check this: your code must.")
    else:
        print("\n=> The app acts for the user in the verified token; the body can't change it.")


# ---------------------------------------------------------------- 5. registry

def cmd_registry(a) -> None:
    reg = twin.load_registry(a.rugpull)
    print(f"Agent Registry entries the gateway checks{' (after the tickets team re-registered its server)' if a.rugpull else ''}:\n")
    for s in reg["mcpServers"]:
        url = s["interfaces"][0]["url"]
        print(f"  {s['displayName']:<9} {short_res(s['name']) if 'googleapis' in s['name'] else s['name']}")
        print(f"            {url}")
        for t in s["toolspec"]["tools"]:
            hints = ", ".join(f"{k}={str(v).lower()}" for k, v in t.get("annotations", {}).items() if k != "title")
            print(f"     tool {t['name']:<22} {hints or 'no hints'}")
    print("\n=> The hints (readOnlyHint, destructiveHint...) are written by whoever registers the server.")
    print("   MCP spec: clients MUST consider tool annotations untrusted unless they come from trusted servers.")


# ---------------------------------------------------------------- 6. gateway

def cmd_gateway(a) -> None:
    dep = twin.load_deployment(a.twin)
    if a.dry_run:
        dep["gateway"]["iap_authz_extension"].setdefault("metadata", {})["iamEnforcementMode"] = "DRY_RUN"
    gw = twin.GatewayTwin(dep, twin.load_registry(a.rugpull), twin.ModelArmorTwin())
    p = twin.agent_principal(dep)
    if a.host:
        attrs = gw.attributes(None, None, a.host, a.path)
        target = f"https://{a.host}{a.path}"
    else:
        attrs = gw.attributes(a.server, a.tool, None)
        target = f"{a.server}.{a.tool}"
    print(f"  call      {target}   from reasoningEngines/{p.rsplit('/', 1)[-1]}")
    print("  what the gateway knows about it (CEL attributes):")
    for k, v in attrs.items():
        if v is not None:
            print(f"    {k.replace('destination.', ''):<58} {json.dumps(v)}")
    print("  the access policy, deny rules first:")
    for r in sorted(gw.rules, key=lambda r: r["effect"] != "DENY"):
        who_ok = any(twin.member_matches(m, p) for m in r["principals"])
        expr = r.get("conditions", {}).get("iap.googleapis.com", {}).get("expression", "")
        hit = who_ok and cel.evaluate(expr, attrs)
        name = r["description"].split(":")[0]
        print(f"    {r['effect']:<5} {name:<24} {'MATCHES' if hit else 'no match'}"
              + ("" if expr else "   (no condition: matches everything)"))
    result, rule = gw.authorize(p, attrs)
    print(f"\n  decision  {result} ({rule})")
    if gw.dry_run:
        print("  mode      DRY_RUN -> logged only: the call goes through either way")
    else:
        print(f"  mode      ENFORCE -> the call is {'sent' if result == 'ALLOWED' else 'BLOCKED'}")


# ---------------------------------------------------------------- 7. armor

def cmd_armor(a) -> None:
    dep = twin.load_deployment(a.twin)
    ext = (dep.get("gateway") or {}).get("model_armor_authz_extension")
    if not ext:
        print("  Model Armor on the gateway: none. Tool responses reach the model unscreened.")
        return
    tpl = ext["metadata"]["model_armor_settings"][0]
    print(f"  extension   {ext['name']}  ({ext['service']})")
    print(f"  templates   request {tpl['request_template_id'].rsplit('/', 1)[-1]}, "
          f"response {tpl['response_template_id'].rsplit('/', 1)[-1]}")
    print(f"  failOpen    {str(ext['failOpen']).lower()}   (what happens when Model Armor can't be reached)")
    print("  screens     MCP tools/call requests and responses;  NOT tools/list")
    for up in (True, False):
        gw = twin.GatewayTwin(dep, twin.load_registry(), twin.ModelArmorTwin(up))
        for cls in ("injection-like", "ordinary"):
            v, why = gw.screen(cls)
            print(f"    Model Armor {'up  ' if up else 'DOWN'}  a tool response that reads {cls:<15} -> {v:<17} {why}")
    print("\n=> An ordinary-looking request ('send a copy to our partner desk') is not what a filter looks for.")


# ---------------------------------------------------------------- 8. memory

def cmd_memory(a) -> None:
    dep = twin.load_deployment(a.twin)
    ag = dep["agent"]
    tok_user = twin.DIRECTORY["id_tokens"][a.token]
    case = {"id_token": a.token, "request_user_id": a.body_user or tok_user}
    scope_user = decide.who(ag, case, "_lab_memory_scope_from")
    bank = twin.MemoryBankTwin(dep)
    scope = {"app_name": "tsg_helpdesk", "user_id": scope_user}
    print(f"  signed in (verified token)   {tok_user}")
    print(f"  scope used for this request  {json.dumps(scope)}   (from {ag['_lab_memory_scope_from'].replace('_', ' ')})")
    got = bank.retrieve(scope)
    print(f"  memories returned            {len(got)}")
    for m in got:
        print(f"      [{m['topic']}] {m['fact']}")
    print(f"  topics it may generate       {', '.join(sorted(bank.topics))}")
    print(f"  new memories expire          {'never (no TTL)' if bank.ttl_days is None else f'after {bank.ttl_days} days'}")
    print("\n=> Memory Bank keeps an isolated collection per scope. Who fills in the scope is your code's choice.")


# ---------------------------------------------------------------- 9. sandbox

def cmd_sandbox(a) -> None:
    dep = twin.load_deployment(a.twin)
    sb = dep["sandbox_templates"]
    if not sb:
        print("  sandbox templates: none. The agent can't start a browser, shell or code sandbox.")
        return
    for s in sb:
        cat = s["config"]["default_container_environment"]["default_container_category"]
        net = s["config"]["egress_control_config"]["internet_access"]
        print(f"  {s['display_name']:<18} {cat}   internet_access {str(net).lower()}")
    print("\n=> A browser with the internet switched on, for an agent whose job needs no browser (checker GC14-14).")


# ---------------------------------------------------------------- 10. logs

def cmd_logs(a) -> None:
    dep = twin.load_deployment(a.twin)
    on = dep["audit_logs"].get("aiplatform.googleapis.com", [])
    print("  Cloud Audit Logs for aiplatform.googleapis.com:")
    print("    ADMIN_ACTIVITY  always on (deploys, memory generation)")
    for t in ("ADMIN_READ", "DATA_READ", "DATA_WRITE"):
        print(f"    {t:<15} {'on' if t in on else 'OFF'}" + ("   (memory and session reads)" if t == "DATA_READ" else ""))
    env = dep["agent"]["env_vars"]
    print(f"  telemetry       GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY={env.get('GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY')}")
    cap = env.get("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT")
    print(f"  prompt capture  {cap if cap else 'not set (prompts and answers stay out of the traces)'}")
    rows = decide.run(a.twin)
    entry = next(e for r in rows for e in r["gateway_log"] if e["lab"]["case"] == "C2")
    print("\n  one gateway log line (case C2, an unregistered host):")
    print("    " + json.dumps({k: entry[k] for k in ("httpRequest", "jsonPayload")}))
    print(f"    the lab's note: policy says {entry['lab']['policy_says']}, dry_run {str(entry['lab']['dry_run']).lower()}")


# ---------------------------------------------------------------- 11. case

def cmd_case(a) -> None:
    dep = twin.load_deployment(a.twin)
    case = next(c for c in twin.CASES if c["id"] == a.case)
    r = decide.evaluate(dep, twin.load_registry(a.rugpull), case, rugpull=a.rugpull)
    call = r["call"]
    what = (f"{call['server']}.{call['tool']}({json.dumps(call.get('args', {}))})" if call["type"] == "mcp" else
            f"GET https://{call['host']}{call.get('path', '/')}" if call["type"] == "url" else call["type"])
    print(f"  case        {case['id']} ({case['kind']}): {case['title']}")
    print(f"  proposed    {what}")
    print(f"  why         {case['why']}" + (f" (from the {case['source_tool']} response)" if case.get("source_tool") else ""))
    print(f"  acting for  {r['end_user']}   (verified token says {twin.DIRECTORY['id_tokens'][case['id_token']]})")
    print("  the controls, in order:")
    for layer, decision, by in r["steps"]:
        print(f"    {layer:<15} {decision:<20} {by}")
    if case["kind"] == "legit":
        print(f"\n=> {'completed' if r['succeeded'] else 'BROKEN: a legitimate call was stopped'}")
    else:
        print(f"\n=> {'WENT THROUGH: no control stopped it' if r['succeeded'] else 'stopped'}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    tokens = sorted(twin.DIRECTORY["id_tokens"])

    def add(name, fn, with_twin=True):
        p = sub.add_parser(name)
        if with_twin:
            p.add_argument("twin", choices=TWINS)
        p.set_defaults(fn=fn)
        return p

    add("map", cmd_map)
    add("identity", cmd_identity)
    add("iam", cmd_iam).add_argument("dataset", choices=["helpdesk", "finance_exports"])
    for name, fn in (("user", cmd_user), ("memory", cmd_memory)):
        p = add(name, fn)
        p.add_argument("token", choices=tokens)
        p.add_argument("--body-user", help="the user_id the request body claims")
    add("registry", cmd_registry, with_twin=False).add_argument("--rugpull", action="store_true")
    p = add("gateway", cmd_gateway)
    p.add_argument("server", nargs="?")
    p.add_argument("tool", nargs="?")
    p.add_argument("--host", help="an unregistered destination, e.g. status.example.net")
    p.add_argument("--path", default="/")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--rugpull", action="store_true")
    add("armor", cmd_armor)
    add("sandbox", cmd_sandbox)
    add("logs", cmd_logs)
    p = add("case", cmd_case)
    p.add_argument("case", choices=[c["id"] for c in twin.CASES])
    p.add_argument("--rugpull", action="store_true")
    a = ap.parse_args()
    if a.cmd == "gateway" and not (a.host or (a.server and a.tool)):
        ap.error("gateway needs SERVER TOOL, or --host HOST")
    a.fn(a)


if __name__ == "__main__":
    main()
