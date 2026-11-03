"""
explore.py: look at each piece of Azure AI Search, a Foundry IQ knowledge base and a Foundry prompt agent on its own,
before you review the port (AZ13 lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's files
(data/, contoso/, fixes/) and asks the same offline teaching model (twin.py) as the rest of the lab. Request shapes and
property names follow Microsoft Learn (Oct 2026); nothing is ever sent to Azure.

    python3 explore.py source                                  # 1. the source documents: who may read each, labels
    python3 explore.py index contoso                           # 2. indexing: one row per chunk, and what each row carries
    python3 explore.py search contoso "disciplinary case notes" --user bob --groups helpdesk-staff,hr
                                                               # 3. a direct query (helpdesk-web): request, $filter, results
    python3 explore.py retrieve fixes "disciplinary case notes" --user bob
                                                               # 4. a knowledge base retrieve (the agent's path)
    python3 explore.py retrieve fixes "disciplinary case notes" --user bob --no-token
                                                               #    the same, with the user's token left out
    python3 explore.py access dana HR-7002 --setup fixes       # 5. would this user get this document? and why
    python3 explore.py agent contoso                           # 6. the prompt agent: model, tools, approval, connections
    python3 explore.py turn fixes bob "VPN client certificate renewal"
                                                               # 7. one chat turn, step by step
    python3 explore.py identity contoso                        # 8. whose identity each connection presents

Setups: contoso (version 1), v1.1 (the obvious fixes only), fixes (the hardened build).
People: alice (HR), bob and dana (helpdesk). All names, IDs and addresses are fictional.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys

import stand_in_model as sim
import twin

SETUPS = ("contoso", "v1.1", "fixes")
HEADER = "x-ms-query-source-authorization"
NAMES = {**twin.DIRECTORY["groups"], **{u["oid"]: name for name, u in twin.DIRECTORY["users"].items()}}


def clip(text: str, n: int) -> str:
    """Cut at a word boundary and say so."""
    text = " ".join(text.split())
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + " ..."


def names(values) -> str:
    """Object IDs -> readable names (the index holds the IDs)."""
    if values is None:
        return "-"
    if not values:
        return "(none)"
    return ", ".join(NAMES.get(v, v) for v in values)


def visible(text: str) -> str:
    return twin.MARKER.sub("[placeholder]", text)


def doc(doc_id: str) -> dict:
    for d in twin.SOURCE["docs"]:
        if d["id"] == doc_id:
            return d
    sys.exit(f"no document {doc_id}: try one of {', '.join(d['id'] for d in twin.SOURCE['docs'])}")


# ---------------------------------------------------------------- 1. source

def cmd_source(a) -> None:
    docs = twin.SOURCE["docs"]
    print(f"The data source: {len(docs)} documents in Contoso's storage, each with the ACL the source system gives it.\n")
    print(f"  {'id':9} {'label':20} {'who may read it (ACL)':24} title")
    for d in docs:
        print(f"  {d['id']:9} {d['label']:20} {names(d['acl']):24} {clip(d['title'], 58)}")
        if any(twin.MARKER.search(c) for c in d["chunks"]):
            print(f"  {'':9} + one line is a labelled lab placeholder: an instruction hidden in a document")
        for ch in d.get("acl_history", []):
            print(f"  {'':9}   ACL changed {ch['at']}: {names(ch['acl'])} ({ch['note']})")
    print("\n\"all\" = everyone. Groups and people are Microsoft Entra object IDs; names are shown here.")
    print("Labels are Microsoft Purview sensitivity labels: General < Confidential < Highly Confidential.")


# ---------------------------------------------------------------- 2. index

def cmd_index(a) -> None:
    cfg = twin.setup(a.setup)
    idx, sync = cfg["search"]["index"], cfg["search"]["permission_sync"]
    native = [f["name"] for f in idx["fields"] if f.get("permissionFilter")]
    print(f"Index {idx['name']} (setup {a.setup})")
    print(f"  permissionFilterOption  {idx['permissionFilterOption']:9} native trimming by the user's token "
          f"{'ON' if idx['permissionFilterOption'] == 'enabled' else 'off'}")
    print(f"  permission fields       {', '.join(native) if native else 'none'}")
    print(f"  purviewEnabled          {str(idx['purviewEnabled']).lower():9} sensitivity labels checked at query time")
    print(f"  last permission sync    {sync['last_run']} ({sync['schedule']})\n")
    print("Indexing splits each document into chunks; one chunk = one row. A field reaches a chunk row only if the")
    print("index projection maps it there:\n")
    cols = ["group_ids"] + (["GroupIds", "UserIds"] if native else [])
    print((f"  {'chunk':11} {'sensitivityLabel':20} " + " ".join(f"{c:22}" for c in cols)).rstrip())
    for r in twin.build_rows(cfg):
        cells = " ".join(f"{clip(names(r.get(c)), 22):22}" for c in cols)
        print(f"  {r['chunk_id']:11} {str(r['sensitivityLabel'] or '-'):20} {cells}".rstrip())
    print("\n- = this chunk row doesn't have the field; (none) = nobody by this field.")
    print("group_ids is a plain string field: only a $filter your app writes checks it. GroupIds and UserIds are")
    print("permission fields: the engine checks them against the user's token.")


# ---------------------------------------------------------------- 3. search (helpdesk-web, direct query)

def show_results(hits, who) -> None:
    print(f"\nThe response: {len(hits)} result{'' if len(hits) == 1 else 's'}")
    for h in hits:
        print(f"  {h['chunk_id']:11} {str(h['sensitivityLabel'] or 'no label'):20} \"{clip(visible(h['chunk']), 70)}\"")


def cmd_search(a) -> None:
    cfg = twin.setup(a.setup)
    app, idx = cfg["app"], cfg["search"]["index"]
    groups = [g.strip() for g in a.groups.split(",")] if a.groups else None
    notes: list = []
    try:
        hits = twin.retrieve(cfg, "web", a.query, a.user, groups_claim=groups, department=a.department, notes=notes)
    except ValueError as e:
        print(f"The query was refused: {e}")
        return
    flt = notes[-1].split("= ", 1)[1]
    auth = "api-key: <query key> (a key carries no user)" if app["auth_to_search"] == "query_api_key" \
        else "Authorization: Bearer <helpdesk-web's managed identity>"
    print(f"helpdesk-web, signed in as {a.user}, queries the index directly (setup {a.setup}):\n")
    print(f"  POST /indexes/{idx['name']}/docs/search")
    print(f"  {auth}")
    fwd = app.get("forward_user_token")
    print(f"  {HEADER + ':':34} {'<' + a.user + chr(39) + 's Entra token>' if fwd else 'not sent'}")
    print(f"  search   \"{a.query}\"")
    print(f"  filter   {flt}")
    src = "the REQUEST BODY (anyone can type them)" if app["groups_from"] == "request_body" and groups \
        else "the validated sign-in token"
    print(f"\n  groups in the filter came from {src}")
    if a.department:
        print(f"  department box \"{a.department}\" was glued into the filter by {app['filter_builder']}")
    if fwd and idx["permissionFilterOption"] == "enabled":
        print("  the engine ALSO trims by the user's token (permission filters are added to yours)")
    show_results(hits, a.user)


# ---------------------------------------------------------------- 4. retrieve (knowledge base, the agent's path)

def cmd_retrieve(a) -> None:
    cfg = copy.deepcopy(twin.setup(a.setup))
    kb = cfg["search"]["knowledge_base"]
    tool = next(t for t in twin.agent_def(cfg)["definition"]["tools"] if t.get("server_label") == "knowledge-base")
    if a.no_token:
        tool.pop("headers", None)
    sent = HEADER in (tool.get("headers") or {})
    notes: list = []
    hits = twin.retrieve(cfg, "kb", a.query, a.user, notes=notes)
    print(f"The agent's knowledge base tool, for {a.user} (setup {a.setup}{', token left out' if a.no_token else ''}):\n")
    print(f"  POST /knowledgebases/{kb['name']}/retrieve   (over MCP: the tool knowledge_base_retrieve)")
    print("  Authorization: Bearer <the project's managed identity>   (the app's right to query)")
    print(f"  {HEADER + ':':34} {'<' + a.user + chr(39) + 's Entra token>  (whose documents)' if sent else 'NOT SENT'}")
    print(f"  knowledge sources  {', '.join(s['name'] for s in kb['knowledgeSources'])} -> index "
          f"{cfg['search']['knowledge_source']['searchIndexParameters']['searchIndexName']}")
    print(f"  outputMode         {kb['outputMode']}: return the chunks; answerSynthesis (preview) has a model write the answer")
    if not sent:
        print("\n  Microsoft: for indexed sources the engine \"returns unfiltered results\" if the user's identity is omitted.")
    show_results(hits, a.user)


# ---------------------------------------------------------------- 5. access

def cmd_access(a) -> None:
    cfg = twin.setup(a.setup)
    d = doc(a.doc)
    u = twin.user(a.user)
    idx, sync = cfg["search"]["index"], cfg["search"]["permission_sync"]
    rows = [r for r in twin.build_rows(cfg) if r["parent_id"] == d["id"]]
    print(f"Would {a.user} get {d['id']} \"{d['title']}\"? (setup {a.setup}, now {twin.NOW})\n")
    w = 30
    print(f"  {'1. ACL in the source now':{w}} {names(twin.acl_at(d, twin.NOW))}")
    held = rows[0].get("GroupIds") or rows[0].get("group_ids") or []
    print(f"  {'2. ACL the index holds':{w}} {names(held)}   (as of the last sync, {sync['last_run']})")
    later = [c for c in d.get("acl_history", []) if c["at"] > sync["last_run"]]
    for c in later:
        print(f"  {'   changed after that sync':{w}} {c['at']}: {c['note']}   -> the index is out of date")
    print(f"  {'3. ' + a.user + chr(39) + 's token':{w}} groups {names(u['groups'])}; may open labels {', '.join(u['labels'])}")
    if idx["permissionFilterOption"] != "enabled":
        print(f"  {'4. native trimming':{w}} OFF: the engine checks nothing; only a $filter your app writes decides")
        print(f"\n  Without a correct filter in your code: returned to {a.user}.")
        return
    for r in rows:
        g, us = r.get("GroupIds") or [], r.get("UserIds") or []
        match = [n for n in g if n == "all" or n in u["groups"]] + [n for n in us if n == "all" or n == u["oid"]]
        label = r["sensitivityLabel"]
        lab_ok = label is None or label in u["labels"] or not idx["purviewEnabled"]
        ok = bool(match) and lab_ok
        why_perm = f"yes ({names(match)})" if match else ("no field on this row" if not (g or us) else "no")
        why_lab = "no label on this row, so it passes" if label is None else f"{label}, {'yes' if lab_ok else 'no'}"
        print(f"  {'4. chunk ' + r['chunk_id']:{w}} a permission field matches? {why_perm}")
        print(f"  {'':{w}} label {a.user} may open? {why_lab}   -> {'RETURNED' if ok else 'dropped'}")
    print("\n  Microsoft: \"a document is considered authorized if any filter succeeds\"; \"all\" opens it to everyone.")


# ---------------------------------------------------------------- 6. agent

def auth_words(conn: dict) -> str:
    owner = conn.get("credential_owner", "")
    kind = conn["authType"]
    if kind == "ApiKey":
        return "ApiKey: one key for every user"
    if kind == "ProjectManagedIdentity":
        return "ProjectManagedIdentity: the project's identity, shared"
    if owner.startswith("per-user"):
        return f"{kind}: each user's own sign-in"
    return f"{kind}: {owner}'s credential for every user"


def cmd_agent(a) -> None:
    cfg = twin.setup(a.setup)
    ag = twin.agent_def(cfg)
    d = ag["definition"]
    conns = cfg["agent"]["connections"]
    print(f"The prompt agent {ag['name']} (setup {a.setup}): kind {d['kind']}, model deployment {d['model']}")
    print(f"  instructions  \"{clip(d['instructions'], 96)}\"\n")
    print("  Tools:")
    for t in d["tools"]:
        if t["type"] == "azure_ai_search":
            ix = t["azure_ai_search"]["indexes"][0]
            print(f"    azure_ai_search   index {ix['index_name']} through {ix['project_connection_id']} "
                  f"({auth_words(conns[ix['project_connection_id']])})")
            continue
        label = t["server_label"]
        server = ["knowledge_base_retrieve"] if label == "knowledge-base" else list(cfg["agent"]["mcp_servers"][label]["tools"])
        allowed = t.get("allowed_tools")
        print(f"    mcp {label:14} connection {t['project_connection_id']} ({auth_words(conns[t['project_connection_id']])})")
        if allowed:
            print(f"      allowed_tools    {', '.join(allowed)}")
        else:
            print(f"      allowed_tools    not set or []: every tool on the server ({', '.join(server)})")
        ra = t.get("require_approval", "always (the default)")
        print(f"      require_approval {json.dumps(ra) if isinstance(ra, dict) else ra}")
        if label == "knowledge-base":
            print(f"      user token       {'forwarded in ' + HEADER if HEADER in (t.get('headers') or {}) else 'not forwarded'}")
    g = cfg["agent"]["guardrails"][ag["guardrail"]]
    print(f"\n  Guardrail {ag['guardrail']}:")
    for c in g["controls"]:
        print(f"    {c['risk']:32} at {c['point']}")
    if any(c["point"] == "tool_response" for c in g["controls"]):
        scanned = [t.get("server_label", t["type"]) for t in d["tools"] if t["type"] in twin.MODERATED_TOOL_TYPES]
        print(f"    tool_response checks run only for tool types with moderation support: here "
              f"{', '.join(scanned) if scanned else 'none (MCP is not on the list)'}")
    rev = cfg["agent"]["approval"]["reviewer"]
    print(f"\n  Approvals answered by: {'nobody (no tool asks)' if rev == 'none' else rev}")
    print(f"  Audit log of tool calls: {'on' if cfg['agent']['audit_log']['tool_calls'] else 'off'}")


# ---------------------------------------------------------------- 7. turn

def cmd_turn(a) -> None:
    cfg = twin.setup(a.setup)
    u = twin.user(a.user)
    actions = []
    if a.action:
        name, *kv = a.action.split()
        actions = [{"name": name, "args": dict(x.split("=", 1) for x in kv)}]
    audit: list = []
    r = twin.run_agent(cfg, a.user, a.question, actions=actions, audit=audit)
    tools = twin.offered_tools(cfg)
    print(f"One turn on Foundry Agent Service (setup {a.setup}). Shapes follow Microsoft's docs; nothing is sent.\n")
    print(f"  1. who        {u['upn']}, from the Entra sign-in")
    step = 2
    print(f"  {step}. ask        the app calls the agent with the question \"{clip(a.question, 60)}\"")
    for e in audit:
        step += 1
        if e["event"] == "retrieve":
            path = {"kb": "knowledge_base_retrieve (Foundry IQ, over MCP)", "search_tool": "azure_ai_search tool",
                    None: "no retrieval tool"}[e["path"]]
            print(f"  {step}. retrieve   {path}")
            if e["path"] == "kb":
                print(f"                {HEADER}: {'the user' + chr(39) + 's token' if e['user_token'] else 'NOT SENT'}")
            elif e["path"] == "search_tool":
                print("                one connection identity and one filter for every user")
            print(f"                found: {', '.join(e['docs']) or '(nothing)'}")
            for n in r["notes"]:
                if n.startswith("guardrail"):
                    step += 1
                    print(f"  {step}. guardrail  {n}")
        elif e["event"] == "approval":
            src = "the user" if e["source"] == "user" else "a retrieved chunk"
            print(f"  {step}. approval   {e['tool']}({fmt(e['args'])})")
            print(f"                asked for by {src} -> mcp_approval_request (server_label, name, arguments)")
            print(f"                the reviewer answers {'approve' if e['approve'] else 'deny'}")
        elif e["event"] == "tool_call":
            src = "the user" if e["source"] == "user" else "a retrieved chunk"
            print(f"  {step}. act        {e['tool']}({fmt(e['args'])})")
            if not any(x["event"] == "approval" and x["tool"] == e["tool"] for x in audit):
                print(f"                asked for by {src}; no approval asked ({tool_rule(tools, e['tool'])})")
            _, msg = twin.actions_server(cfg, e["tool"], e["args"], a.user, tools[e["tool"]][0])
            print(f"                actions server: {'done as ' + msg.rsplit(' done as ', 1)[1] if ' done as ' in msg else msg}")
    for x in r["refused"]:
        if "allowed_tools" in x:
            step += 1
            print(f"  {step}. refused    {x}")
    step += 1
    print(f"  {step}. answer     \"{clip(r['answer'], 100)}\"")


def fmt(args: dict) -> str:
    return ", ".join(f"{k}={clip(str(v), 30)}" for k, v in args.items())


def tool_rule(tools: dict, name: str) -> str:
    ra = tools[name][0].get("require_approval", "always")
    return f"require_approval {json.dumps(ra) if isinstance(ra, dict) else ra}"


# ---------------------------------------------------------------- 8. identity

def cmd_identity(a) -> None:
    cfg = twin.setup(a.setup)
    conns = cfg["agent"]["connections"]
    print(f"Connections in the Foundry project (setup {a.setup}): the credential each tool presents\n")
    for name, c in conns.items():
        print(f"  {name:18} {c['category']:15} {auth_words(c)}")
    roles = cfg["roles"]["assignments"]
    print("\nRole assignments on the search service:")
    for r in roles:
        print(f"  {clip(r['principal'], 46):46} {r['role']:30} on {r['scope']}")
    tool = next(t for t in twin.agent_def(cfg)["definition"]["tools"] if t.get("server_label") == "helpdesk-actions")
    print(f"\nWhat the actions server sees when bob asks to close tickets (connection {tool['project_connection_id']}):")
    for tid in ("4471", "4480"):
        owner = twin.DIRECTORY["tickets"][tid]["owner"]
        ok, msg = twin.actions_server(cfg, "close_ticket", {"ticket": tid}, "bob", tool)
        print(f"  ticket {tid}, owner {owner:19} {'YES' if ok else 'no '}  {msg}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("source", help="the source documents, their ACLs and labels")
    p = sub.add_parser("index", help="one row per chunk, and what each row carries"); p.add_argument("setup", choices=SETUPS)
    p = sub.add_parser("search", help="a direct query from helpdesk-web")
    p.add_argument("setup", choices=SETUPS); p.add_argument("query")
    p.add_argument("--user", default="bob", choices=sorted(twin.DIRECTORY["users"]))
    p.add_argument("--groups", help="groups the browser claims, comma-separated (version 1 believes them)")
    p.add_argument("--department", help="the department box on the search page")
    p = sub.add_parser("retrieve", help="a knowledge base retrieve, the agent's path")
    p.add_argument("setup", choices=SETUPS); p.add_argument("query")
    p.add_argument("--user", default="bob", choices=sorted(twin.DIRECTORY["users"]))
    p.add_argument("--no-token", action="store_true", help=f"leave {HEADER} out")
    p = sub.add_parser("access", help="would this user get this document?")
    p.add_argument("user", choices=sorted(twin.DIRECTORY["users"])); p.add_argument("doc")
    p.add_argument("--setup", default="fixes", choices=SETUPS)
    p = sub.add_parser("agent", help="the prompt agent's model, tools and settings"); p.add_argument("setup", choices=SETUPS)
    p = sub.add_parser("turn", help="one chat turn, step by step")
    p.add_argument("setup", choices=SETUPS); p.add_argument("user", choices=sorted(twin.DIRECTORY["users"]))
    p.add_argument("question"); p.add_argument("--action", help='a tool the user asks for, e.g. "close_ticket ticket=4480"')
    p = sub.add_parser("identity", help="whose identity each connection presents"); p.add_argument("setup", choices=SETUPS)
    a = ap.parse_args(argv)
    {"source": cmd_source, "index": cmd_index, "search": cmd_search, "retrieve": cmd_retrieve, "access": cmd_access,
     "agent": cmd_agent, "turn": cmd_turn, "identity": cmd_identity}[a.cmd](a)


if __name__ == "__main__":
    main(sys.argv[1:])
