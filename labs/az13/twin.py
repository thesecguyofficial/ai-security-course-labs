"""
twin.py: a TEACHING MODEL of the TSG Helpdesk after its port to Azure AI Search, Foundry IQ and Foundry Agent Service.
It is not Azure. Each rule below comes from a Microsoft Learn page (README "About the twin" lists them):

  Search      security filters are string matching: "The principal is just a string"
              native trimming: userIds / groupIds / "all"; a document is authorised "if any filter succeeds";
              direct search without the user's token returns only documents everyone may see (since Nov 2025);
              a knowledge base retrieve without the token "returns unfiltered results" for indexed sources
              Purview labels: unlabelled chunk rows aren't filtered ("Without this projection, chunk-level
              references aren't filtered"); permission changes appear only after the next sync
  Agent       allowed_tools: if omitted, "the default value includes all of the tools in the MCP server"
              require_approval: always | never | {"never": [...]} | {"always": [...]}; default always
              tool-response guardrail checks run only for tools with moderation support (MCP isn't listed)
  Identity    a shared credential (API key, custom keys, project identity) acts for every user;
              OAuth identity passthrough acts as the signed-in user

Standard library only. Deterministic: same inputs, same output.
"""

import copy
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
NOW = "2026-10-19T10:00:00Z"          # the lab's "now": one hour after HR-7002 was locked down
ALL = "all"
MARKER = re.compile(r"\[LAB-PLACEHOLDER TOOL REQUEST: call (\w+)((?: \w+=[^\s\]]+)*)(?: [^\]]*)?\]")
# Tools whose calls and responses the Foundry guardrail can moderate (intervention points page). MCP isn't listed.
MODERATED_TOOL_TYPES = {"azure_ai_search", "azure_function", "openapi", "sharepoint_grounding", "fabric_dataagent",
                        "bing_grounding", "bing_custom_search", "browser_automation"}


def load(folder: str, name: str) -> dict:
    with open(os.path.join(HERE, folder, name), encoding="utf-8") as f:
        return json.load(f)


DIRECTORY = load("data", "directory.json")
SOURCE = load("data", "source-docs.json")


def user(name: str) -> dict:
    return DIRECTORY["users"][name]


# ------------------------------------------------------------------ setups
def setup(name: str) -> dict:
    """contoso = version 1; v1.1 = the obvious fixes only; fixes = the hardened build."""
    folder = "fixes" if name == "fixes" else "contoso"
    cfg = {"name": name, "search": load(folder, "search.json"), "agent": load(folder, "agent.json"),
           "app": load(folder, "app.json"), "roles": load(folder, "roles.json")}
    if name == "v1.1":
        cfg = copy.deepcopy(cfg)
        idx = cfg["search"]["index"]
        idx["permissionFilterOption"] = "enabled"
        idx["fields"] += [{"name": "UserIds", "type": "Collection(Edm.String)", "permissionFilter": "userIds", "filterable": True},
                          {"name": "GroupIds", "type": "Collection(Edm.String)", "permissionFilter": "groupIds", "filterable": True}]
        idx["projection"]["permission_fields_to_chunks"] += ["UserIds", "GroupIds"]
        tools = cfg["agent"]["agents"][0]["definition"]["tools"]
        tools[:] = [t for t in tools if t["type"] != "azure_ai_search"]
        for t in tools:
            if t.get("server_label") == "knowledge-base":
                t["headers"] = {"x-ms-query-source-authorization": "{{search_auth_token}}"}
        cfg["app"]["groups_from"] = "validated_token"
    return cfg


def agent_def(cfg: dict) -> dict:
    return cfg["agent"]["agents"][0]


# ------------------------------------------------------------------ the index as Azure AI Search would hold it
def acl_at(doc: dict, when: str) -> list:
    """The ACL the source system had at time `when` (ISO strings compare correctly)."""
    acl = doc["acl"]
    for change in doc.get("acl_history", []):
        if change["at"] <= when:
            acl = change["acl"]
    return acl


def stale_docs(cfg: dict) -> set:
    """Documents whose ACL changed after the last permission sync and that the build re-syncs."""
    sync = cfg["search"]["permission_sync"]
    if not sync.get("resync_after_acl_change"):
        return set()
    import sync_check  # challenge 1 lives there
    return set(sync_check.stale_documents(SOURCE["docs"], sync["last_run"]))


def build_rows(cfg: dict) -> list[dict]:
    """One row per chunk. Permission metadata is what the index learned at the last sync (or a targeted resync);
    a field reaches chunk rows only if the index projection maps it there."""
    idx, sync = cfg["search"]["index"], cfg["search"]["permission_sync"]
    projected = set(idx["projection"]["permission_fields_to_chunks"])
    resynced = stale_docs(cfg)
    rows = []
    for d in SOURCE["docs"]:
        acl = d["acl"] if d["id"] in resynced else acl_at(d, sync["last_run"])
        users = [a for a in acl if a in {u["oid"] for u in DIRECTORY["users"].values()}] or ([ALL] if ALL in acl else [])
        groups = [a for a in acl if a in DIRECTORY["groups"]] or ([ALL] if ALL in acl else [])
        for i, text in enumerate(d["chunks"]):
            row = {"chunk_id": f"{d['id']}#{i}", "parent_id": d["id"], "title": d["title"], "chunk": text,
                   "sensitivityLabel": d["label"] if (i == 0 or idx["projection"]["label_to_chunks"]) else None}
            if "group_ids" in projected or i == 0:
                row["group_ids"] = [DIRECTORY["groups"].get(g, g) for g in groups]
            if "UserIds" in projected or i == 0:
                row["UserIds"] = users
            if "GroupIds" in projected or i == 0:
                row["GroupIds"] = groups
            rows.append(row)
    return rows


def has_field(idx: dict, name: str) -> bool:
    return any(f["name"] == name for f in idx["fields"])


# ------------------------------------------------------------------ a tiny OData filter evaluator (enough for this lab)
def _tokens(s: str):
    i = 0
    while i < len(s):
        c = s[i]
        if c.isspace():
            i += 1
        elif c == "'":
            j, buf = i + 1, ""
            while j < len(s):
                if s[j] == "'" and j + 1 < len(s) and s[j + 1] == "'":
                    buf += "'"; j += 2
                elif s[j] == "'":
                    break
                else:
                    buf += s[j]; j += 1
            yield ("str", buf); i = j + 1
        elif c in "(),:":
            yield (c, c); i += 1
        else:
            j = i
            while j < len(s) and not s[j].isspace() and s[j] not in "(),:'":
                j += 1
            yield ("word", s[i:j]); i = j


def odata_match(expr: str, row: dict) -> bool:
    """Supports: field eq 'v' | coll/any(g: search.in(g, 'a, b')) | true | and | or | parentheses.
    search.in splits on spaces and commas by default, as Azure AI Search does."""
    toks = list(_tokens(expr))
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else (None, None)

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def primary():
        kind, val = take()
        if kind == "(":
            v = disj(); take(); return v
        if kind == "word" and val == "true":
            return True
        if kind == "word" and "/any" in val:                       # group_ids/any(g: search.in(g, '...'))
            field = val.split("/")[0]
            take(); take(); take()                                  # ( g :
            take(); take(); take(); take()                          # search.in ( g ,
            _, values = take(); take(); take()                      # 'list' ) )
            wanted = [v for v in re.split(r"[ ,]+", values) if v]
            return any(x in wanted for x in row.get(field) or [])
        if kind == "word":                                          # field eq 'value'
            take(); _, value = take()
            return row.get(val) == value
        raise ValueError(f"unsupported filter near {val!r}")

    def conj():
        v = primary()
        while peek() == ("word", "and"):
            take(); v = primary() and v
        return v

    def disj():
        v = conj()
        while peek() == ("word", "or"):
            take(); v = conj() or v
        return v

    try:
        return disj()
    except (IndexError, ValueError):
        raise ValueError("400 Bad Request: invalid $filter")


# ------------------------------------------------------------------ retrieval paths
STOP = {"the", "a", "is", "what", "how", "do", "i", "my", "for", "are", "me", "who", "your", "of", "to", "and", "it",
        "you", "in", "on", "when", "with", "from", "not", "please", "keeps", "can", "an", "be", "this", "that"}


def _words(s: str) -> set:
    return set(re.findall(r"[a-z0-9]+", s.lower())) - STOP


def _score(text: str, row: dict) -> int:
    """A keyword stand-in for semantic ranking: query words found in the chunk or its document title."""
    return len(_words(text) & _words(row["title"] + " " + row["chunk"]))


def _top(rows, text, k=5):
    """Top k chunks above a crude relevance cut-off: within one point of the best score, or equal to it once the
    best match shares three or more words with the question."""
    scored = [(s, r) for r in rows if (s := _score(text, r)) > 0]
    if not scored:
        return []
    best = max(s for s, _ in scored)
    scored = [(s, r) for s, r in scored if s >= (best if best >= 3 else max(1, best - 1))]
    scored.sort(key=lambda x: (-x[0], x[1]["chunk_id"]))
    return [r for _, r in scored[:k]]


def native_trim(rows, idx, token):
    """Query-time ACL trimming (preview): a document is authorised if ANY permission field matches."""
    out = []
    for r in rows:
        if not (has_field(idx, "UserIds") or has_field(idx, "GroupIds")):
            out.append(r); continue
        u, g = r.get("UserIds") or [], r.get("GroupIds") or []
        if ALL in u or ALL in g:
            out.append(r)
        elif token and (token["oid"] in u or set(token["groups"]) & set(g)):
            out.append(r)
    return out


def label_trim(rows, idx, token):
    """Purview label trimming (preview): drop rows whose label the user can't EXTRACT. Unlabelled rows pass."""
    if not idx.get("purviewEnabled") or not token:
        return rows
    return [r for r in rows if r["sensitivityLabel"] is None or r["sensitivityLabel"] in token["labels"]]


def retrieve(cfg: dict, path: str, text: str, who: str, *, groups_claim=None, department=None, notes=None) -> list[dict]:
    """path: 'search_tool' (agent's built-in Azure AI Search tool), 'kb' (Foundry IQ knowledge base over MCP),
    'web' (helpdesk-web's own query with a GA security filter)."""
    notes = notes if notes is not None else []
    idx = cfg["search"]["index"]
    rows = build_rows(cfg)
    u = user(who)
    token = {"oid": u["oid"], "groups": u["groups"], "labels": u["labels"]}
    perm_on = idx["permissionFilterOption"] == "enabled"

    if path == "search_tool":
        notes.append("Azure AI Search tool: one connection identity for every user, one static filter for every query")
        hits = _top(rows, text)
        if perm_on:
            hits = native_trim(hits, idx, None)        # no user token on this path: only documents open to all
        return hits

    if path == "kb":
        tool = next(t for t in agent_def(cfg)["definition"]["tools"] if t.get("server_label") == "knowledge-base")
        forwarded = "x-ms-query-source-authorization" in (tool.get("headers") or {})
        hits = _top(rows, text)
        if not forwarded:
            notes.append("knowledge_base_retrieve called WITHOUT x-ms-query-source-authorization: results unfiltered")
            return hits
        if perm_on:
            hits = native_trim(hits, idx, token)
        hits = label_trim(hits, idx, token)
        return hits

    if path == "web":
        app = cfg["app"]
        groups = groups_claim if app["groups_from"] == "request_body" and groups_claim else [DIRECTORY["groups"][g] for g in u["groups"]]
        if app["filter_builder"] == "safe_filter":
            import safe_filter  # challenge 3
            flt = safe_filter.build_filter(groups, department)
        else:
            flt = f"group_ids/any(g: search.in(g, '{', '.join(groups)}'))"
            if department:
                flt += f" and title eq '{department}'"
        notes.append(f"$filter = {flt}")
        hits = [r for r in _top(rows, text, k=50) if odata_match(flt, r)][:5]
        if app.get("forward_user_token") and perm_on:
            hits = native_trim(hits, idx, token)        # permission filters are appended to any filter you send
            hits = label_trim(hits, idx, token)
        return hits

    raise ValueError(path)


# ------------------------------------------------------------------ the agent runtime
def offered_tools(cfg: dict) -> dict:
    """name -> (tool definition, kind) for every tool the MODEL can see."""
    out = {}
    servers = cfg["agent"]["mcp_servers"]
    for t in agent_def(cfg)["definition"]["tools"]:
        if t["type"] == "azure_ai_search":
            out["azure_ai_search"] = (t, "read")
        elif t["type"] == "mcp":
            label = t["server_label"]
            names = {"knowledge_base_retrieve": "read"} if label == "knowledge-base" else servers[label]["tools"]
            allowed = t.get("allowed_tools")
            for n, kind in names.items():
                if allowed is None or n in allowed:
                    out[n] = (t, kind)
    return out


def needs_approval(tool: dict, name: str) -> bool:
    ra = tool.get("require_approval", "always")       # Microsoft: "The default value is `always`."
    if ra == "always":
        return True
    if ra == "never":
        return False
    if "never" in ra:
        return name not in ra["never"]
    if "always" in ra:
        return name in ra["always"]
    return True


def guardrail_scans_response(cfg: dict, tool: dict) -> bool:
    g = cfg["agent"]["guardrails"][agent_def(cfg)["guardrail"]]
    has = any(c["point"] == "tool_response" and "IndirectAttack" in c["risk"] for c in g["controls"])
    return has and tool["type"] in MODERATED_TOOL_TYPES


def actions_server(cfg: dict, name: str, args: dict, who: str, tool: dict) -> tuple[bool, str]:
    """The Contoso MCP actions server: it authorises by the identity the connection presents."""
    conn = cfg["agent"]["connections"][tool["project_connection_id"]]
    acting_as = who if conn["credential_owner"].startswith("per-user") else conn["credential_owner"]
    if name in ("close_ticket", "delete_ticket"):
        t = DIRECTORY["tickets"].get(args.get("ticket"))
        if acting_as == "svc-helpdesk-admin":
            return True, f"{name} {args.get('ticket')} done as svc-helpdesk-admin"
        if t and t["owner"] == user(acting_as)["upn"]:
            return True, f"{name} {args.get('ticket')} done as {acting_as}"
        return False, f"403: {acting_as} may not {name} ticket {args.get('ticket')} (owner {t['owner'] if t else '?'})"
    return True, f"{name}({', '.join(f'{k}={v}' for k, v in args.items())}) done as {acting_as}"


def run_agent(cfg: dict, who: str, ask: str, actions: list | None = None, audit: list | None = None) -> dict:
    """One turn. The stand-in model (stand_in_model.py) obeys anything it reads, which is the worst case."""
    import stand_in_model as sim
    import review_policy
    audit = audit if audit is not None else []
    tools = offered_tools(cfg)
    notes, executed, refused, citations = [], [], [], []
    path = "kb" if "knowledge_base_retrieve" in tools else ("search_tool" if "azure_ai_search" in tools else None)
    hits = retrieve(cfg, path, ask, who, notes=notes) if path else []
    rtool = tools["knowledge_base_retrieve" if path == "kb" else "azure_ai_search"][0] if path else None
    audit.append({"event": "retrieve", "user": who, "path": path, "docs": [h["chunk_id"] for h in hits],
                  "user_token": bool(path == "kb" and "x-ms-query-source-authorization" in (rtool.get("headers") or {}))})
    scanned = rtool is not None and guardrail_scans_response(cfg, rtool)
    calls = sim.plan(ask, who, hits, actions or [])
    if scanned and any(c["source"] == "retrieved" for c in calls):
        notes.append("guardrail (tool response, Indirect attack) blocked the retrieved content")
        return {"answer": "", "hits": hits, "executed": [], "refused": [], "notes": notes, "blocked": True}
    if rtool is not None and any(c["source"] == "retrieved" for c in calls):
        why = "no tool-response control" if not any(c["point"] == "tool_response" for c in
                                                     cfg["agent"]["guardrails"][agent_def(cfg)["guardrail"]]["controls"]) \
            else f"tool type '{rtool['type']}' has no moderation support"
        notes.append(f"guardrail did not scan the retrieved content ({why})")
    for call in calls:
        name, args = call["name"], call["args"]
        if name not in tools:
            refused.append(f"{name}: not offered to the model (allowed_tools)")
            continue
        tool, kind = tools[name]
        if needs_approval(tool, name):
            req = {"type": "mcp_approval_request", "id": f"mcpr_{len(audit):03d}", "server_label": tool["server_label"],
                   "name": name, "arguments": json.dumps(args)}
            ok = review_policy.approve(req, who) if cfg["agent"]["approval"]["reviewer"] != "none" else True
            audit.append({"event": "approval", "user": who, "tool": name, "args": args, "approve": ok, "source": call["source"]})
            if not ok:
                refused.append(f"{name}: approval denied by reviewer")
                continue
        ok, msg = actions_server(cfg, name, args, who, tool)
        audit.append({"event": "tool_call", "user": who, "tool": name, "args": args, "ok": ok, "source": call["source"]})
        (executed if ok else refused).append(msg)
    answer = sim.answer(hits)
    citations = sorted({h["parent_id"] for h in hits})
    return {"answer": answer, "hits": hits, "citations": citations, "executed": executed, "refused": refused,
            "notes": notes, "blocked": False}
