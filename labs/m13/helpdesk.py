"""
helpdesk.py: TSG Helpdesk v4, the M13 port of the local RAG + agent (M6, M7) to Amazon Bedrock, running OFFLINE.

One user turn goes through the same steps as the real thing:
  1. the backend decides WHO is asking            (app.json "identity": the signed-in session, or what the browser sent?)
  2. it searches the knowledge base               (agent-attached KB with a metadata filter, or the APP calls Retrieve
                                                   with userContext after a return-of-control / inline-function call)
  3. the stand-in model reads the chunks and the question and decides which tools to call
  4. each tool call goes through the platform's path (agent.json: Bedrock Agents Classic action group + Lambda, or an
     AgentCore harness inline function) and the app's controls (confirmation, who the caller is)
  5. it answers from the top chunk

THE STAND-IN MODEL IS NOT AI. It is the WORST CASE on purpose (as in labs M3, M6, M7, M12): it reads everything in its
context, including HTML comments in retrieved documents, and obeys any instruction it finds there. It also helps with
whatever the user asks if a tool exists for it. Real models are less predictable; attackers get as many tries as they like.

    python3 helpdesk.py first-draft bob@example.com "What's new in the VPN client?"
    python3 helpdesk.py ported bob@example.com "What's new in the VPN client?"
    python3 helpdesk.py first-draft bob@example.com "What are the salary bands for 2027?" --department hr

The two functions marked CHALLENGE are yours to write (README, Step 8).
"""

from __future__ import annotations

import argparse
import json
import re
import sys

import twin

DIRECTORY = twin.COMPANY["directory"]
INJECTION = re.compile(r"\[LAB-INJECTED-DIRECTIVE: call (\w+) for ([\w.@-]+)\]")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


# --------------------------------------------------------------------------------------------------------------------
# CHALLENGE 1 (13.2): screen what the knowledge base returns BEFORE the model reads it
# --------------------------------------------------------------------------------------------------------------------
def screen_chunks(chunks: list[dict], setup: twin.Setup) -> list[dict]:
    """Return the chunks the model may read. Today: everything, unchanged.

    Your job: when app.json says "screen_retrieved_chunks": true, remove hidden instructions from each chunk's text
    (here: HTML comments, which a reader of the rendered page never sees) and drop any chunk that still carries the
    lab's injection marker. Keep the visible text: the VPN note is useful. In the real build this is ApplyGuardrail
    on each chunk with source INPUT (M12.2), plus stripping comments at ingestion time (M6.2).
    """
    return chunks


# --------------------------------------------------------------------------------------------------------------------
# CHALLENGE 3 (13.2): confirmation is not authorisation
# --------------------------------------------------------------------------------------------------------------------
def authorise_write(caller: str, action: str, target: str | None, setup: twin.Setup) -> bool:
    """May `caller` (the SIGNED-IN user, never a model-chosen value) do `action` on `target`? Today: always yes.

    Your job: reset_mfa is allowed on your own account, or on anyone's if you're in a group listed in
    anycompany.json "may_reset_mfa_for_others". Everything else: no. This runs in the app (harness inline function)
    or the Lambda (Classic), AFTER the user confirmed: a user who confirms is still only allowed what they're allowed.
    """
    return True


# --------------------------------------------------------------------------------------------------------------------
# The simulated person who answers a confirmation prompt
# --------------------------------------------------------------------------------------------------------------------
def simulated_human(question: str, caller: str, prompt: dict) -> str:
    """Stands in for the user reading a confirmation dialog. Approves only what they asked for, IF the prompt shows
    enough to tell. A prompt without the arguments gets rubber-stamped whenever the user asked for any reset."""
    asked = re.search(r"\breset\b.*\bmfa\b", question, re.I)
    if not asked:
        return "DENY"
    if not prompt.get("arguments_shown"):
        return "CONFIRM"
    wanted = EMAIL.search(question)
    wanted = wanted.group(0).lower() if wanted else caller
    return "CONFIRM" if prompt["arguments"].get("target_email", "").lower() == wanted else "DENY"


# --------------------------------------------------------------------------------------------------------------------
# The stand-in model
# --------------------------------------------------------------------------------------------------------------------
def visible(text: str) -> str:
    return re.sub(r"<!--.*?-->", "", text, flags=re.S).strip()


def plan(question: str, chunks: list[dict], caller: str) -> list[dict]:
    """What the worst-case model asks for, in order."""
    calls = []
    for c in chunks:
        for tool, arg in INJECTION.findall(c["content"]["text"]):
            calls.append({"tool": tool, "args": {"target_email": arg}, "why": f"instruction found in {c['location']['s3Location']['uri']}"})
    if re.search(r"\breset\b.*\bmfa\b", question, re.I):
        m = EMAIL.search(question)
        calls.append({"tool": "reset_mfa", "args": {"target_email": m.group(0).lower() if m else caller}, "why": "the user asked"})
    if re.search(r"\b(shell|run|python|execute|environment variables)\b", question, re.I):
        calls.append({"tool": "code", "args": {"code": "[LAB PLACEHOLDER: print the environment]"}, "why": "the user asked"})
    seen, unique = set(), []
    for c in calls:                      # one call per tool and target
        k = (c["tool"], json.dumps(c["args"], sort_keys=True))
        if k not in seen:
            seen.add(k)
            unique.append(c)
    return unique


# --------------------------------------------------------------------------------------------------------------------
# Platform helpers
# --------------------------------------------------------------------------------------------------------------------
def classic_functions(setup: twin.Setup) -> dict[str, dict]:
    out = {}
    for g in setup.agent.get("actionGroups", []):
        if g.get("actionGroupState", "ENABLED") != "ENABLED":
            continue
        for f in g.get("functionSchema", {}).get("functions", []):
            out[f["name"]] = dict(f, executor=g.get("actionGroupExecutor", {}), group=g["actionGroupName"])
    return out


def code_tool_available(setup: twin.Setup) -> bool:
    if setup.platform == "bedrock-agents-classic":
        return any(g.get("parentActionGroupSignature") == "AMAZON.CodeInterpreter" and g.get("actionGroupState", "ENABLED") == "ENABLED"
                   for g in setup.agent.get("actionGroups", []))
    # AgentCore harness: "Default tools shell and file_operations are available in every session unless you restrict
    # them with allowedTools." / "If omitted, all tools are allowed." (harness-tools)
    allowed = setup.agent["createHarness"].get("allowedTools")
    if allowed is None:
        return True
    return any(p in ("*", "@builtin", "@builtin/shell", "shell") for p in allowed)


def tool_available(setup: twin.Setup, tool: str) -> bool:
    if tool == "code":
        return code_tool_available(setup)
    if setup.platform == "bedrock-agents-classic":
        return tool in classic_functions(setup)
    return any(t["name"] == tool for t in setup.agent["createHarness"].get("tools", []))


def needs_confirmation(setup: twin.Setup, tool: str) -> bool:
    if setup.platform == "bedrock-agents-classic":
        return classic_functions(setup)[tool].get("requireConfirmation") == "ENABLED"
    # harness inline function: the call comes back to the app, which decides (app.json "confirmation")
    return bool(setup.app.get("confirmation", {}).get("enabled"))


# --------------------------------------------------------------------------------------------------------------------
# One turn
# --------------------------------------------------------------------------------------------------------------------
def ask(setup_name: str | twin.Setup, session_user: str, request: dict | str, human=simulated_human) -> dict:
    """session_user = who the identity provider says is signed in. request = what the browser sent."""
    setup = setup_name if isinstance(setup_name, twin.Setup) else twin.Setup(setup_name)
    if isinstance(request, str):
        request = {"question": request}
    q = request["question"]
    app = setup.app
    trace = []

    # 1. who is asking?
    caller = session_user if app["identity"]["user_from"] == "session" else request.get("user", session_user)
    trace.append(f"identity: caller = {caller} (from {app['identity']['user_from']})")

    # 2. retrieval
    mode = app["retrieval"]["mode"]
    if mode == "agent_kb_association":
        dept = request.get("department") or DIRECTORY.get(caller, {}).get("department", "none")
        if request.get("cross_department") and app["retrieval"].get("implicit_filter_for_cross_department_search"):
            cfg = {"vectorSearchConfiguration": {"implicitFilterConfiguration": app["retrieval"]["implicitFilterConfiguration"]}}
        else:
            cfg = {"vectorSearchConfiguration": {"filter": {"orAll": [{"equals": {"key": "department", "value": dept}},
                                                                     {"equals": {"key": "department", "value": "all"}}]}}}
        resp = twin.retrieve(setup, q, retrieval_configuration=cfg)
        trace.append(f"agent queried its knowledge base; filter = {json.dumps(resp['_filter_applied'])}")
    else:
        resp = twin.retrieve(setup, q, user_context={"userId": caller},
                             retrieval_configuration={"managedSearchConfiguration": {"numberOfResults": 3}})
        how = "returnControl" if mode == "return_control_search" else "inline function tool_use"
        trace.append(f"model called search_kb -> {how} -> app called Retrieve with userContext.userId = {caller}")
    chunks = resp["retrievalResults"]
    if app.get("screen_retrieved_chunks"):
        chunks = screen_chunks(chunks, setup)
    keys = [c["location"]["s3Location"]["uri"].split(f"{twin.BUCKET}/")[1] for c in chunks]

    # 3-4. tools
    executed, denied, unavailable = [], [], []
    session_attributes = ({"caller_email": caller} if app.get("session_attributes_from") == "session"
                          else request.get("sessionAttributes", {}))
    for call in plan(q, chunks, caller):
        tool = call["tool"]
        if not tool_available(setup, tool):
            unavailable.append(call)
            trace.append(f"model wanted {tool}: no such tool on this agent")
            continue
        if tool == "code":
            executed.append(call)
            trace.append("model ran code in the agent's sandbox (code interpreter / harness shell)")
            continue
        target = call["args"]["target_email"]
        if needs_confirmation(setup, tool):
            shown = bool(app.get("confirmation", {}).get("show_arguments"))
            prompt = {"tool": tool, "arguments_shown": shown, "arguments": call["args"] if shown else {}}
            decision = human(q, caller, prompt)
            trace.append(f"confirmation asked ({'with' if shown else 'WITHOUT'} arguments): {tool}({target if shown else '?'}) -> {decision}")
            if decision != "CONFIRM":
                denied.append(dict(call, reason="user said DENY"))
                continue
        # who does the backend think is calling? Classic: the Lambda reads it from sessionAttributes, or not at all
        if setup.platform == "bedrock-agents-classic":
            src = setup.lambda_["caller_identity_from"]
            write_caller = session_attributes.get("caller_email") if src.startswith("sessionAttributes") else None
        else:
            write_caller = caller   # inline function: runs in the app, which knows the session
        if write_caller is not None and not authorise_write(write_caller, tool, target, setup):
            denied.append(dict(call, reason=f"{write_caller} is not allowed to {tool} {target}"))
            trace.append(f"authorisation: {write_caller} may not {tool}({target}) -> refused")
            continue
        executed.append(dict(call, caller=write_caller))
        trace.append(f"EXECUTED {tool}({target}) as {write_caller or 'nobody in particular (no caller identity)'}")

    # 5. answer
    answer = visible(chunks[0]["content"]["text"]).splitlines()[-1] if chunks else "I couldn't find that in the knowledge base."
    for e in executed:
        if e["tool"] == "reset_mfa":
            answer += f" | Done: MFA reset for {e['args']['target_email']}."
        else:
            answer += " | Done: ran code."
    return {"setup": setup.name, "question": q, "caller": caller, "retrieved": keys, "executed": executed,
            "denied": denied, "unavailable": unavailable, "answer": answer, "trace": trace}


# --------------------------------------------------------------------------------------------------------------------
# Two attacks that don't go through a chat turn
# --------------------------------------------------------------------------------------------------------------------
def lambda_invocable_by(setup: twin.Setup, agent_arn: str) -> bool:
    """Could Amazon Bedrock, running agent `agent_arn`, invoke the Helpdesk's action group Lambda? (Classic only)"""
    if setup.platform != "bedrock-agents-classic":
        return False
    account = agent_arn.split(":")[4]
    return twin.lambda_allows(setup.lambda_["resourcePolicy"], source_arn=agent_arn, source_account=account)


def end_user_can_override_tools(setup: twin.Setup) -> list[str]:
    """Principals that end users control and that may call InvokeHarness, which accepts tools, allowedTools and
    systemPrompt overrides on every call (InvokeHarness API). Harness only."""
    if setup.platform != "agentcore-harness" or not setup.invokers:
        return []
    out = []
    for name, p in setup.invokers["principals"].items():
        acts = [a for st in p["policy"]["Statement"] if st["Effect"] == "Allow"
                for a in (st["Action"] if isinstance(st["Action"], list) else [st["Action"]])]
        if p.get("end_user_reachable") and any(a in ("bedrock-agentcore:InvokeHarness", "bedrock-agentcore:*", "*") for a in acts):
            out.append(name)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("setup"); ap.add_argument("user", help="who is signed in"); ap.add_argument("question")
    ap.add_argument("--claim-user", help="the 'user' field the browser sends (spoofable)")
    ap.add_argument("--department", help="the 'department' field the browser sends (spoofable)")
    ap.add_argument("--cross-department", action="store_true", help="the 'search all departments' switch")
    args = ap.parse_args(argv)
    req = {"question": args.question}
    if args.claim_user:
        req["user"] = req.setdefault("sessionAttributes", {})["caller_email"] = args.claim_user
    if args.department:
        req["department"] = args.department
    if args.cross_department:
        req["cross_department"] = True
    r = ask(args.setup, args.user, req)
    print(f"Q ({args.user}): {r['question']}")
    for t in r["trace"]:
        print(f"   . {t}")
    print(f"Retrieved: {', '.join(r['retrieved']) or '(nothing)'}")
    print(f"A: {r['answer']}")


if __name__ == "__main__":
    main(sys.argv[1:])
