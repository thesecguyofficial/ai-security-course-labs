"""
explore.py: look at each piece of a managed knowledge base and a managed agent on its own, before you review the
port (M13 lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's files
(the bucket in data/docs, the setups in setups/) and prints what it finds, using the same offline stand-in (twin.py)
and Helpdesk (helpdesk.py) as the rest of the lab. Request and response shapes follow AWS's documentation; nothing is
ever sent to AWS.

    python3 explore.py source                                  # 1. the data source: the bucket and what is in it
    python3 explore.py sync ported                             # 2. one ingestion job: read, chunk, index, who may see it
    python3 explore.py retrieve ported "reset my VPN token" --user bob@example.com
                                                               # 3. one Retrieve call: the request, then the results
    python3 explore.py retrieve first-draft "salary bands 2027" --department sales
                                                               #    the same on the first draft, with a metadata filter
    python3 explore.py acl bob@example.com hr/salary-bands-2027.md
                                                               # 4. would this user get this document? and why
    python3 explore.py agent ported                            # 5. a managed agent: model, instructions, tools
    python3 explore.py turn ported bob@example.com "I have a new phone. Please reset my MFA."
                                                               # 6. one chat turn, step by step, with AWS's message shapes
    python3 explore.py invoke ported                           # 7. which agents may call the action group's Lambda

All names, emails, account IDs and ARNs are fake (AWS documentation examples, example.com).
"""

from __future__ import annotations

import argparse
import json
import re
import sys

import helpdesk
import twin

PLATFORM = {"bedrock-agents-classic": "Bedrock Agents Classic", "agentcore-harness": "AgentCore harness"}


def short(uri: str) -> str:
    return uri.split(f"{twin.BUCKET}/", 1)[-1]


def first_line(text: str) -> str:
    return text.splitlines()[0].lstrip("# ").strip()


def clip(text: str, n: int) -> str:
    """Cut at a word boundary and say so."""
    text = " ".join(text.split())
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + " ..."


def show_filter(f: dict) -> str:
    """A metadata filter in words: equals -> key = value, orAll -> a OR b."""
    (op, arg), = f.items()
    if op in ("orAll", "andAll"):
        return (" OR " if op == "orAll" else " AND ").join(show_filter(x) for x in arg)
    sym = {"equals": "=", "notEquals": "!=", "in": "in", "notIn": "not in"}[op]
    return f"{arg['key']} {sym} {arg['value']}"


def tokens(text: str) -> int:
    """A rough count: about four characters of English per token."""
    return max(1, round(len(text) / 4))


# ---------------------------------------------------------------- 1. source

def cmd_source(a) -> None:
    docs = twin.all_docs()
    print(f"The data source: one S3 bucket, s3://{twin.BUCKET}/ (fake name). {len(docs)} documents:\n")
    for key, text in docs.items():
        print(f"  {key:34} {len(text):4} characters   \"{clip(first_line(text), 60)}\"")
        if "<!--" in text:
            print(f"  {'':35}+ one HTML comment: invisible on a web page, plain text to a program")
    print("\nThe folders (S3 calls them prefixes) say what each document is:")
    print("  public/     IT articles for every employee")
    print("  inbox/      files staff uploaded (here, a vendor's note)")
    print("  hr/         HR only")
    print("  it-admin/   IT admins only")


# ---------------------------------------------------------------- 2. sync

def cmd_sync(a) -> None:
    s = twin.Setup(a.setup)
    kind = {"VECTOR": "customer-managed (type VECTOR): you run the vector store",
            "MANAGED": "Bedrock Managed (type MANAGED): AWS runs the store"}[s.kb_type]
    ds = s.data_sources["dataSources"][0]
    acl_on = bool(twin._connector_params(ds).get("aclEnabled"))
    print(f"Knowledge base {s.knowledge_base['name']}: {kind}")
    print(f"Data source {ds['name']}: the bucket   ACL awareness: {'ON' if acl_on else 'off'}\n")
    print("One ingestion job (a sync), document by document:")
    print("  read -> chunk (default: about 300 tokens, whole sentences) -> embed -> store, with who may see it\n")
    idx = twin.ingest(s)
    for c in idx.chunks:
        n = tokens(c.text)
        if c.acl is None:
            who = "everyone (no ACL)"
            if c.metadata:
                who += f", metadata {json.dumps(c.metadata)}"
        else:
            who = "only " + ", ".join(e["Name"].split("@")[0] for e in c.acl if e["Access"] == "ALLOW")
        print(f"  {c.key:34} ~{n:2} tokens -> 1 chunk   {who}")
    for key, why in idx.skipped:
        print(f"  {key:34} SKIPPED: {why}")
    print("\nThe twin keeps words, not vectors: its search scores are word overlap, a stand-in for embeddings.")


# ---------------------------------------------------------------- 3. retrieve

def cmd_retrieve(a) -> None:
    s = twin.Setup(a.setup)
    body: dict = {"knowledgeBaseId": s.data_sources["dataSources"][0]["knowledgeBaseId"],
                  "retrievalQuery": {"text": a.query}}
    cfg = None
    if a.department:
        cfg = {"vectorSearchConfiguration": {"filter": {"equals": {"key": "department", "value": a.department}}}}
        body["retrievalConfiguration"] = cfg
    if a.user:
        body["userContext"] = {"userId": a.user}
    print("The request your backend sends (Retrieve, bedrock-agent-runtime):")
    for k, v in body.items():
        print(f"  {k:24} {json.dumps(v)}")
    resp = twin.retrieve(s, a.query, user_context=body.get("userContext"), retrieval_configuration=cfg)
    res = resp["retrievalResults"]
    print(f"\nThe response: {len(res)} result{'' if len(res) == 1 else 's'}" + (", best first" if len(res) > 1 else ""))
    for r in res:
        meta = {k: v for k, v in r["metadata"].items() if not k.startswith(("_", "x-amz"))}
        extra = f"   metadata {json.dumps(meta)}" if meta else ""
        print(f"  score {r['score']:.2f}  {short(r['location']['s3Location']['uri'])}{extra}")
        print(f"              \"{clip(helpdesk.visible(r['content']['text']).splitlines()[-1], 90)}\"")
    print("\nRetrieve returns chunks only. RetrieveAndGenerate would also send them to a model and return its answer.")


# ---------------------------------------------------------------- 4. acl

def cmd_acl(a) -> None:
    s = twin.Setup(a.setup)
    uri = f"s3://{twin.BUCKET}/{a.doc}"
    access = s.kb_access or {}
    print(f"Would {a.user} get {a.doc}? (setup {a.setup}, global ACL file)\n")
    if a.doc in access.get("perDocument", {}):
        acl, where = access["perDocument"][a.doc].get("accessControlList", []), f"{a.doc}.metadata.json"
    else:
        matches = [e for e in access.get("globalAcl", []) if uri.startswith(e["keyPrefix"])]
        if not matches:
            print("  no ACL entry for this document: an ACL-enabled S3 source doesn't ingest it at all")
            return
        best = max(matches, key=lambda e: len(e["keyPrefix"]))
        acl, where = best["aclEntries"], f"keyPrefix {short(best['keyPrefix'])}"
    print(f"  1. the entry that covers it      {where}")
    for e in acl:
        print(f"                                   {e['Access']:5} {e['Name']}")
    allow = any(e["Name"] == a.user and e["Access"] == "ALLOW" for e in acl)
    deny = any(e["Name"] == a.user and e["Access"] == "DENY" for e in acl)
    print(f"  2. {a.user} on an ALLOW line?  {'yes' if allow else 'no'}")
    print(f"  3. {a.user} on a DENY line?    {'yes (deny always wins)' if deny else 'no'}")
    ok = twin.acl_allows(acl, a.user)
    print(f"\n  hasAccess: {str(ok).lower()}   (what CheckIngestedDocumentAcl answers, after the last sync)")


# ---------------------------------------------------------------- 5. agent

def cmd_agent(a) -> None:
    s = twin.Setup(a.setup)
    print(f"The agent in setup {a.setup}: {PLATFORM[s.platform]}\n")
    if s.platform == "bedrock-agents-classic":
        ag = s.agent["createAgent"]
        print(f"  model          {ag['foundationModel']}")
        print(f"  instructions   \"{ag['instruction'][:88]}...\"")
        print(f"  runs as        role {ag['agentResourceRoleArn'].split('/')[-1]} (the agent's own identity)")
        kbs = s.agent.get("knowledgeBaseAssociations", [])
        print(f"  knowledge base {'attached: ' + kbs[0]['knowledgeBaseId'] + ' (the agent searches it itself)' if kbs else 'none attached'}")
        print("\n  Action groups (the tools):")
        for g in s.agent.get("actionGroups", []):
            if g.get("parentActionGroupSignature"):
                print(f"    {g['actionGroupName']:17} built-in {g['parentActionGroupSignature']}: a sandbox that runs code")
                continue
            ex = g["actionGroupExecutor"]
            runs = "Lambda " + ex["lambda"].split(":")[-1] if "lambda" in ex else "RETURN_CONTROL: handed back to your app"
            print(f"    {g['actionGroupName']:17} run by {runs}")
            for f in g["functionSchema"]["functions"]:
                params = ", ".join(f["parameters"])
                print(f"      function {f['name']}({params})   requireConfirmation {f.get('requireConfirmation', 'DISABLED')}")
    else:
        h = s.agent["createHarness"]
        print(f"  model          {h['model']['bedrockModelConfig']['modelId']}")
        print(f"  instructions   \"{h['systemPrompt'][0]['text'][:88]}...\"")
        print(f"  runs as        role {h['executionRoleArn'].split('/')[-1]}, each session in its own microVM")
        print("\n  Tools:")
        for t in h.get("tools", []):
            print(f"    {t['name']:12} {t['type']}: the harness pauses and hands the call to your code")
        print(f"    {'shell, file_operations':12} built in: there unless allowedTools leaves them out")
        print(f"\n  allowedTools   {json.dumps(h.get('allowedTools')) if 'allowedTools' in h else 'not set: every tool allowed'}")
        print(f"  memory         {'off' if 'disabled' in h.get('memory', {}) else 'on'}")


# ---------------------------------------------------------------- 6. turn

def cmd_turn(a) -> None:
    s = twin.Setup(a.setup)
    classic = s.platform == "bedrock-agents-classic"
    prompts = []

    def human(q, caller, prompt):
        d = helpdesk.simulated_human(q, caller, prompt)
        prompts.append((prompt, d))
        return d

    r = helpdesk.ask(s, a.user, {"question": a.question}, human=human)
    print(f"One turn on {PLATFORM[s.platform]} (setup {a.setup}). Shapes follow AWS's docs; nothing is sent.\n")
    print(f"  1. who        the backend takes the user from the sign-in: {r['caller']}")
    if classic:
        sa = {"caller_email": r["caller"]} if s.app.get("session_attributes_from") == "session" else {}
        print(f"  2. ask        InvokeAgent  inputText \"{a.question}\"")
        print(f"                             sessionState.sessionAttributes {json.dumps(sa)}")
    else:
        print(f"  2. ask        InvokeHarness  messages [user: \"{a.question}\"]")
    step = 3
    for t in r["trace"][1:]:
        if t.startswith("agent queried"):
            print(f"  {step}. search     the agent searches its attached knowledge base itself")
            print(f"                metadata filter: {show_filter(json.loads(t.split('= ', 1)[1]))}")
            print(f"                found: {', '.join(r['retrieved']) or '(nothing)'}")
        elif t.startswith("model called search_kb"):
            back = "returnControl (with an invocationId)" if classic else "stopReason tool_use"
            print(f"  {step}. search     model asks for search_kb -> {back} -> your backend")
            print(f"                backend calls Retrieve with userContext.userId {r['caller']}")
            print(f"                found: {', '.join(r['retrieved']) or '(nothing)'}; sends the chunks back")
        elif t.startswith("confirmation asked"):
            prompt, d = prompts.pop(0)
            args = ", ".join(f"{k} = {v}" for k, v in prompt["arguments"].items()) or "(arguments hidden)"
            back = "returnControl (confirmation)" if classic else "stopReason tool_use"
            print(f"  {step}. confirm    model asks for {prompt['tool']} -> {back}")
            print(f"                the user sees: {prompt['tool']}  {args}   and answers {d}")
            if d != "CONFIRM":
                print("                DENY: \"the function or the API in the response is not implemented\"" if classic
                      else "                DENY: your backend doesn't run it")
        elif t.startswith("EXECUTED"):
            m = re.match(r"EXECUTED (\w+)\(([^)]*)\) as (.*)", t)
            tool, target, who = m.groups()
            where = f"Lambda event: function {tool}, parameters target_email = {target}" if classic \
                else f"your backend runs {tool}({target})"
            print(f"  {step}. act        {where}")
            print(f"                acting for: {who}")
        elif t.startswith("model ran code"):
            print(f"  {step}. act        model ran code in the agent's sandbox")
        else:
            print(f"  {step}. note       {t}")
        step += 1
    print(f"  {step}. answer     \"{clip(r['answer'], 104)}\"")


# ---------------------------------------------------------------- 7. invoke

def cmd_invoke(a) -> None:
    s = twin.Setup(a.setup)
    if s.platform != "bedrock-agents-classic":
        print("This setup has no action group Lambda: its tools are inline functions run by your own backend.")
        return
    st = s.lambda_["resourcePolicy"]["Statement"][0]
    print("The Lambda's resource policy (who may invoke tsg-helpdesk-actions):")
    print(f"  Allow  Principal {st['Principal']['Service']}  Action {st['Action']}")
    conds = [f"{k} {v}" for op in st.get("Condition", {}).values() for k, v in op.items()]
    print("  Conditions: " + ("; ".join(conds) if conds else "none"))
    print("\nCould Bedrock, running each of these agents, invoke it?")
    for label, key in (("the Helpdesk agent", "helpdesk_agent_arn"), ("another team's agent", "other_team_agent_arn"),
                       ("an agent in another account", "outside_agent_arn")):
        arn = twin.COMPANY[key]
        ok = helpdesk.lambda_invocable_by(s, arn)
        print(f"  {label:28} {arn:58} {'YES' if ok else 'no'}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("source", help="the data source: the bucket and its documents")
    p = sub.add_parser("sync", help="one ingestion job, document by document"); p.add_argument("setup")
    p = sub.add_parser("retrieve", help="one Retrieve call: request and results")
    p.add_argument("setup"); p.add_argument("query")
    p.add_argument("--user", help="userContext.userId (managed knowledge base)")
    p.add_argument("--department", help="a metadata filter on department (customer-managed knowledge base)")
    p = sub.add_parser("acl", help="would this user get this document?")
    p.add_argument("user"); p.add_argument("doc"); p.add_argument("--setup", default="ported")
    p = sub.add_parser("agent", help="the agent's model, instructions and tools"); p.add_argument("setup")
    p = sub.add_parser("turn", help="one chat turn, step by step")
    p.add_argument("setup"); p.add_argument("user"); p.add_argument("question")
    p = sub.add_parser("invoke", help="which agents may call the action group Lambda"); p.add_argument("setup")
    a = ap.parse_args(argv)
    {"source": cmd_source, "sync": cmd_sync, "retrieve": cmd_retrieve, "acl": cmd_acl, "agent": cmd_agent,
     "turn": cmd_turn, "invoke": cmd_invoke}[a.cmd](a)


if __name__ == "__main__":
    main(sys.argv[1:])
