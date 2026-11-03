"""
explore.py: look at each piece of RAG Engine, Agent Search and an ADK agent on its own, before you review the port
(GC13 lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's files
(data/, twin/) and asks the same offline stand-ins (gcp_twin.py, adk_twin.py, helpdesk_agent.py) as the rest of the
lab. Request and response shapes follow Google's API definitions and ADK 2.12.0; nothing is ever sent to Google.

    python3 explore.py source                                  # 1. the import buckets: who may write each, what's in them
    python3 explore.py corpus today                            # 2. RAG Engine: the corpora and what each one holds
    python3 explore.py retrieve today "hospital partner discount" --filter 'team == "finance"'
                                                               # 3. one retrieveContexts call: the request, then contexts
    python3 explore.py reach hardened                          # 4. which corpora the agent's identity may read
    python3 explore.py search hardened "hospital partner discount" --as alice@example.com
                                                               # 5. Agent Search with document ACLs: results for a caller
    python3 explore.py acl alice@example.com fin-pricing       # 6. would this person get this document? and why
    python3 explore.py agent today                             # 7. the ADK agent: identity, tools, callbacks, plugin, log
    python3 explore.py turn hardened alice@example.com "Summarise ticket T-2042 for me."
                                                               # 8. one turn in ADK order, step by step

Twins: today (the port as shipped), hardened (the fixed port). All names, numbers and addresses are fictional.
"""

from __future__ import annotations

import argparse
import json
import sys

import helpdesk_agent
from gcp_twin import DIRECTORY, DOCS, INJECTION_MARKER, AgentSearchTwin, IdentityTwin

TWINS = ("today", "hardened")
USERS = sorted(DIRECTORY["users"])
TOKENS = {email: tok for tok, email in DIRECTORY["id_tokens"].items()}


def clip(text: str, n: int) -> str:
    """Cut at a word boundary and say so."""
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + " ..."


def short(name: str) -> str:
    """projects/.../ragCorpora/kb-staff -> kb-staff"""
    return name.rsplit("/", 1)[-1]


def acct(principal: str) -> str:
    return principal.split(":", 1)[-1]


def visible(text: str) -> str:
    """What a person sees on a web page: HTML comments hidden."""
    import re
    return re.sub(r"<!--.*?-->", "", text).strip()


# ---------------------------------------------------------------- 1. source

def cmd_source(a) -> None:
    dep = helpdesk_agent.load_deployment("today")
    print("The documents, and the Cloud Storage buckets the import job reads them from:\n")
    for bucket, b in dep["buckets"].items():
        docs = [d for d in DOCS.values() if d["source"].startswith(bucket + "/")]
        print(f"  {bucket}   who may add files: {', '.join(b['objectCreators'])}")
        for d in docs:
            print(f"    {d['source'][len(bucket) + 1:]:30} team {d['team']:8} \"{clip(d['title'], 54)}\"")
            if INJECTION_MARKER in d["text"]:
                print(f"    {'':30} + one HTML comment with a labelled lab placeholder: hidden on a web page,")
                print(f"    {'':30}   plain text to a program")
    print("\nteam = a metadata tag on each file. Anyone who may add files to a bucket the import reads can put words")
    print("in front of the model.")


# ---------------------------------------------------------------- 2. corpus

def cmd_corpus(a) -> None:
    dep = helpdesk_agent.load_deployment(a.twin)
    rag = dep["retrieval"]["rag_engine"]
    print(f"RAG Engine in project {dep['project']}, region {dep['region']} (twin {a.twin})")
    print(f"  RagManagedDb tier   {rag['rag_managed_db_tier']}   (the managed database that holds every corpus here)")
    print(f"  imports from        {', '.join(dep['retrieval']['import_sources'])}\n")
    print("An import reads each file, splits it into chunks (default 1,024 tokens, 256 overlapping), embeds each")
    print("chunk and stores it in a corpus (RAG Engine's name for an index):\n")
    for c in rag["corpora"]:
        cmek = "CMEK " + short(c["encryption_spec"]["kms_key_name"]) if c.get("encryption_spec") else "no CMEK"
        who = f"for group {c['for_group']}" if c.get("for_group") else "no audience set"
        print(f"  corpus {c['display_name']:12} {who:42} {cmek}")
        for doc_id in c["documents"]:
            d = DOCS[doc_id]
            print(f"    {doc_id:20} team {d['team']:8} ~{max(1, round(len(d['text']) / 4)):2} tokens -> 1 chunk")
    scope = rag["scope"]
    rule = {"model_args": "the MODEL's \"team\" argument becomes a metadata filter",
            "verified_groups": "your tool code picks corpora from the user's verified groups"}[scope["chosen_by"]]
    print(f"\nWhich documents a request may reach: {rule}.")
    print("A corpus has no per-document ACL. The twin keeps words, not vectors: its scores are word overlap.")


# ---------------------------------------------------------------- 3. retrieve

def cmd_retrieve(a) -> None:
    desk = helpdesk_agent.build(a.twin)
    rag = desk.dep["retrieval"]["rag_engine"]
    corpus = a.corpus or rag["corpora"][0]["display_name"]
    full = next((c["name"] for c in rag["corpora"] if c["display_name"] == corpus), None)
    if full is None:
        sys.exit(f"no corpus {corpus} in twin {a.twin}: try {', '.join(c['display_name'] for c in rag['corpora'])}")
    cfg = {"top_k": 2}
    if a.filter:
        cfg["filter"] = {"metadata_filter": a.filter}
    body = {"vertex_rag_store": {"rag_resources": [{"rag_corpus": short(full)}]},
            "query": {"text": a.query, "rag_retrieval_config": cfg}}
    print(f"POST /v1/projects/{desk.dep['project']}/locations/{desk.dep['region']}:retrieveContexts")
    print(f"  caller   {acct(desk.principal)}   (the agent's identity)")
    print(f"  vertex_rag_store       {json.dumps(body['vertex_rag_store'])}")
    print(f"  query.text             {json.dumps(a.query)}")
    print(f"  rag_retrieval_config   {json.dumps(cfg)}")
    print("  (no field names the person who asked)")
    res = desk.rag.retrieve_contexts(desk.principal, full, a.query, a.filter)
    if "error" in res:
        print(f"\nThe response: {res['error']['code']} {res['error']['status']}")
        return
    ctx = res["contexts"]["contexts"]
    print(f"\nThe response: {len(ctx)} context{'' if len(ctx) == 1 else 's'}")
    for c in ctx:
        print(f"  score {c['score']:.2f}  {c['sourceUri']}")
        print(f"              \"{clip(visible(c['text']), 92)}\"")
    print("\nA metadata filter only narrows what is searched. It doesn't check who is asking.")


# ---------------------------------------------------------------- 4. reach

def cmd_reach(a) -> None:
    desk = helpdesk_agent.build(a.twin)
    rag = desk.dep["retrieval"]["rag_engine"]
    print(f"The agent runs as {acct(desk.principal)}")
    print(f"Its roles on project {desk.dep['project']}: {', '.join(desk.dep['agent']['project_roles'])}\n")
    print("Could that identity call retrieveContexts on each corpus? (RAG Engine checks permission on the project)")
    for c in rag["corpora"]:
        res = desk.rag.retrieve_contexts(desk.principal, c["name"], "refund pricing VPN discount")
        ok = "error" not in res
        print(f"  {c['display_name']:12} {'YES' if ok else 'no ' + res['error']['status']}")
    print("\nWhich corpora the tool searches for each person:")
    for email in USERS:
        groups = IdentityTwin.groups(email)
        if rag["scope"]["chosen_by"] == "verified_groups":
            picked = [c["display_name"] for c in rag["corpora"] if c.get("for_group") in groups]
            why = "from the verified groups"
        else:
            picked = [rag["corpora"][0]["display_name"]]
            why = "whatever filter the model writes"
        print(f"  {email:18} {', '.join(picked):22} ({why})")


# ---------------------------------------------------------------- 5. search

def cmd_search(a) -> None:
    dep = helpdesk_agent.load_deployment(a.twin)
    s = AgentSearchTwin(dep)
    cfg = dep["retrieval"]["agent_search"]
    principal = helpdesk_agent.agent_principal(dep)
    caller = principal if a.as_ == "agent" else f"user:{a.as_}"
    print(f"Agent Search data store {short(cfg['data_store'])} (twin {a.twin}), location {cfg['location']}")
    print(f"  access control   {'ON (acl_enabled, chosen when the store was created)' if cfg['acl_enabled'] else 'off: every result for every caller'}")
    print(f"  the search runs with the credentials of: {acct(caller)}\n")
    res = s.search(caller, a.query)
    print(f"POST /v1/.../dataStores/{short(cfg['data_store'])}/servingConfigs/default_search:search   query \"{a.query}\"")
    print(f"\nThe response: {len(res['results'])} result{'' if len(res['results']) == 1 else 's'}")
    for r in res["results"]:
        d = r["document"]["derivedStructData"]
        print(f"  {r['id']:20} {d['link']}")
        print(f"  {'':20} \"{clip(visible(d['snippets'][0]['snippet']), 86)}\"")
    if cfg["acl_enabled"] and a.as_ == "agent":
        print("\nThe agent's own account is on no document's reader list, so it gets nothing. Adding it to every group")
        print("would \"fix\" that and give everyone everything again.")


# ---------------------------------------------------------------- 6. acl

def cmd_acl(a) -> None:
    d = DOCS.get(a.doc) or sys.exit(f"no document {a.doc}: try {', '.join(DOCS)}")
    groups = IdentityTwin.groups(a.user)
    print(f"Would {a.user} get {a.doc} (\"{clip(d['title'], 50)}\")")
    print("from an Agent Search data store with access control?\n")
    print(f"  {'1. the readers on the document':32} {', '.join(f'{k} {v}' for r in d['readers'] for k, v in r.items())}")
    print(f"  {'2. ' + a.user.split('@')[0] + chr(39) + 's groups':32} {', '.join(groups)}   (from the identity provider)")
    hit = [f"{k} {v}" for r in d["readers"] for k, v in r.items() if (k == "user_id" and v == a.user)
           or (k == "group_id" and v in groups)]
    print(f"  {'3. on the reader list?':32} {'yes: ' + ', '.join(hit) if hit else 'no'}")
    print(f"\n  -> {'returned' if hit else 'left out of the results'}, if the search carries {a.user}'s identity.")
    print("     Searched with the agent's own account, the caller is the agent, and the agent is on no list.")


# ---------------------------------------------------------------- 7. agent

def cmd_agent(a) -> None:
    dep = helpdesk_agent.load_deployment(a.twin)
    ag = dep["agent"]
    principal = helpdesk_agent.agent_principal(dep)
    default = ag["identity"].get("service_account") is None
    print(f"The Helpdesk agent (twin {a.twin}): {ag['framework']} on {ag['runtime']}\n")
    print(f"  runs as        {acct(principal)}")
    if default:
        print(f"  {'':14} (the default: the project's Reasoning Engine Service Agent, shared by every agent here)")
    print(f"  project roles  {', '.join(ag['project_roles'])}")
    who = {"request_body": "user_id in the request body (any caller can write it)",
           "verified_id_token": "a verified ID token, written into session state by your server"}[ag["user_id_from"]]
    print(f"  the end user   {who}")
    print(f"  sessions       {ag['session_service']}\n")
    print("  Tools (FunctionTool):")
    for name, t in ag["tools"].items():
        kind = "WRITE" if t.get("writes") else "read "
        conf = t.get("confirmation", "none")
        conf = {"none": "runs at once", "approval_queue": "waits for a person (approval queue your app owns)",
                "adk_confirmation": "require_confirmation=True"}.get(conf, conf)
        extra = "  + checks the ticket's team" if t.get("check_ticket_team") else ""
        print(f"    {name:13} {kind} {conf}{extra}")
    print(f"\n  before_tool_callback  {ag['before_tool_callback'] or 'none'}")
    ma = ag["plugins"].get("model_armor", {})
    print("  ModelArmorPlugin")
    for k in ("prompt_template_name", "response_template_name", "tool_output_template_name"):
        v = ma.get(k)
        print(f"    {k:26} {short(v) if v else 'not set: not screened'}")
    print(f"    {'block_on_screening_failure':26} {str(ma.get('block_on_screening_failure')).lower()}")
    obs = ag["observability"]
    print(f"\n  tool-call log fields  {', '.join(obs['tool_log_fields'])}")
    print(f"  message content in trace spans: {obs['ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS']}; "
          f"trace readers {', '.join(obs['trace_readers'])}")


# ---------------------------------------------------------------- 8. turn

def cmd_turn(a) -> None:
    desk = helpdesk_agent.build(a.twin, armor_available=not a.outage)
    asked = []

    def person(request):
        call = request["args"]["originalFunctionCall"]
        asked.append(call)
        return True                      # the lab's busy approver: request 40 of the day, they click Approve

    request = {"id_token": TOKENS[a.user], "user_id": a.claim_user or a.user, "message": a.question}
    user, res = desk.ask(request, human=person)
    print(f"One turn on {desk.dep['agent']['framework']} (twin {a.twin}{', Model Armor down' if a.outage else ''}). "
          "Shapes follow ADK's; nothing is sent.\n")
    src = "the verified ID token" if desk.dep["agent"]["user_id_from"] == "verified_id_token" else "user_id in the request body"
    print(f"  1. who        {user}, from {src}")
    print("                the server writes end_user and groups into session state")
    step = 2
    plog = desk.runner.plugins[0].log if desk.runner.plugins else []
    failed = sorted({line.split(":")[0].replace("model_armor ", "") for line in plog if "FAILED" in line})
    if failed:
        ma = desk.dep["agent"]["plugins"]["model_armor"]
        let = "everything is blocked" if ma["block_on_screening_failure"] else "it all goes through unscreened"
        print(f"  {step}. screen     Model Armor unreachable for: {', '.join(failed)}")
        print(f"                block_on_screening_failure {str(ma['block_on_screening_failure']).lower()}: {let}")
        step += 1
    for kind, name, args, extra in res["events"]:
        shown = json.dumps({k: clip(v, 32) for k, v in (args or {}).items() if k not in ("subject", "body")})
        if kind == "executed":
            print(f"  {step}. tool       {name}({shown}) EXECUTED")
            if name == "search_kb":
                calls = desk.rag.calls or []
                for c in calls:
                    flt = c["metadata_filter"] or "none"
                    print(f"                retrieveContexts on {short(c['rag_corpus'])}, metadata filter: {flt}")
            out = extra if isinstance(extra, dict) else {}
            texts = [c["text"] for c in out.get("contexts", {}).get("contexts", [])] or [out.get("text", "")]
            if any(INJECTION_MARKER in t for t in texts):
                print("                the result carries a hidden instruction for the model")
        elif kind == "paused":
            print(f"  {step}. pause      {name}({shown}) -> adk_request_confirmation via {extra['via']}")
            print("                originalFunctionCall shows the arguments; the person answers: approve")
        elif kind == "approved":
            print(f"  {step}. approved   {name}: before_tool callbacks run again, then the tool")
        elif kind == "blocked":
            print(f"  {step}. blocked    {name}({shown}) by before_tool: {extra.get('error')}")
        elif kind == "result_blocked":
            print(f"  {step}. screened   {name}({shown}) ran; Model Armor (after_tool) replaced its result:")
            print(f"                {extra.get('error')}")
        else:
            print(f"  {step}. {kind:10} {extra}")
        step += 1
    print(f"  {step}. answer     \"{clip(res['answer'], 100)}\"")
    n = len(desk.runner.audit)
    print(f"\n  tool-call log, {n} line{'' if n == 1 else 's'} (service account domains .iam.gserviceaccount.com left off):")
    for e in desk.runner.audit:
        parts = []
        for k, v in e.items():
            if k == "args":
                continue
            v = acct(v).replace(".iam.gserviceaccount.com", "") if k == "agent_principal" else v
            parts.append(f"{k}={clip(v, 44)}")
        print("    " + "  ".join(parts))
    if desk.outbox:
        print(f"\n  outbox: {', '.join(m['to'] for m in desk.outbox)}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("source", help="the import buckets and the documents in them")
    p = sub.add_parser("corpus", help="RAG Engine corpora and what each holds"); p.add_argument("twin", choices=TWINS)
    p = sub.add_parser("retrieve", help="one retrieveContexts call")
    p.add_argument("twin", choices=TWINS); p.add_argument("query")
    p.add_argument("--filter", help='a metadata filter, e.g. team == "finance"')
    p.add_argument("--corpus", help="corpus display name (default: the first)")
    p = sub.add_parser("reach", help="which corpora the agent's identity may read"); p.add_argument("twin", choices=TWINS)
    p = sub.add_parser("search", help="Agent Search with document ACLs")
    p.add_argument("twin", choices=TWINS); p.add_argument("query")
    p.add_argument("--as", dest="as_", default="agent", help="agent, or a person's email (searches with their identity)")
    p = sub.add_parser("acl", help="would this person get this document?")
    p.add_argument("user", choices=USERS); p.add_argument("doc")
    p = sub.add_parser("agent", help="the ADK agent's identity, tools, callbacks and plugin"); p.add_argument("twin", choices=TWINS)
    p = sub.add_parser("turn", help="one turn in ADK order")
    p.add_argument("twin", choices=TWINS); p.add_argument("user", choices=USERS); p.add_argument("question")
    p.add_argument("--claim-user", help="what the request body's user_id says (default: the signed-in user)")
    p.add_argument("--outage", action="store_true", help="Model Armor unreachable")
    a = ap.parse_args(argv)
    {"source": cmd_source, "corpus": cmd_corpus, "retrieve": cmd_retrieve, "reach": cmd_reach, "search": cmd_search,
     "acl": cmd_acl, "agent": cmd_agent, "turn": cmd_turn}[a.cmd](a)


if __name__ == "__main__":
    main(sys.argv[1:])
