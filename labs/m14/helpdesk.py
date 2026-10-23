"""
helpdesk.py: one turn of TSG Helpdesk v5, the course agent running on AgentCore Runtime (offline twin).

The web backend signs the user in, calls the Runtime, the agent code reads memory, fetches the user's tickets with
an OAuth token from the AgentCore Identity token vault, and calls tools through the AgentCore Gateway.

The model is a WORST-CASE STAND-IN, not AI: it does what the user asks, and it also obeys any line in a tool result
that starts with LAB-INJECTED-DIRECTIVE (hidden in HTML comments in the ticket data). Real models are less
predictable than this, not safer: the controls in this lab must hold even when the model is fully fooled.

    python3 helpdesk.py first-draft bob "What's the latest on ticket 4711?"
    python3 helpdesk.py hardened bob "What's the latest on ticket 4711?"
    python3 helpdesk.py first-draft bob "Show my tickets" --user-id alice

Two challenge stubs live here: validate_memory_write() (challenge 2). Challenge 1 is a Cedar file, challenge 3 is
in hunt.py.
"""

from __future__ import annotations

import argparse
import json
import re
import uuid

import twin

DIRECTIVE = re.compile(r"LAB-INJECTED-DIRECTIVE:\s*tool=(\w+)\s*(.*?)\s*-->", re.S)
ARG = re.compile(r"(\w+)=(.*?)(?=\s+\w+=|$)", re.S)


def visible(text: str) -> str:
    return re.sub(r"<!--.*?-->", "", text, flags=re.S).strip()


# --------------------------------------------------------------------------------------------------------------------
# Challenge 2 (14.6): memory writes need validation, not just a per-user namespace
# --------------------------------------------------------------------------------------------------------------------
def validate_memory_write(text: str, source: str, setup: twin.Setup) -> bool:
    """Return True if this text may be stored in long-term memory.

    source is "user" (the signed-in user typed it) or "tool_result" (the model read it in a ticket, a web page,
    a tool response). Challenge 2: store only what the user said themselves, and never a line that carries an
    instruction marker. ATLAS AML.M0031 Memory Hardening: "requiring external authentication and validation for
    memory updates". Then set "validate_memory_writes": true in setups/hardened/app.json.
    """
    raise NotImplementedError("challenge 2: write validate_memory_write()")


# --------------------------------------------------------------------------------------------------------------------
# The stand-in model's plan
# --------------------------------------------------------------------------------------------------------------------
def plan_from_question(q: str, user: str) -> list[dict]:
    calls = []
    m = re.search(r"\breset (?:the )?mfa for (\w[\w.-]*)", q, re.I)
    if m:
        calls.append({"tool": "reset_mfa", "args": {"target_username": m.group(1).lower()}, "why": "the user asked"})
    elif re.search(r"\breset my mfa\b", q, re.I):
        calls.append({"tool": "reset_mfa", "args": {"target_username": user}, "why": "the user asked"})
    if re.search(r"\b(vpn token|outlook|new phone|how do i)\b", q, re.I):
        calls.append({"tool": "search_kb", "args": {"query": q}, "why": "the user asked"})
    m = re.search(r"\bremember that (.+)", q, re.I)
    if m:
        calls.append({"tool": "remember", "args": {"text": m.group(1).strip()}, "why": "the user asked", "source": "user"})
    if re.search(r"\b(python|run code|execute)\b", q, re.I):
        calls.append({"tool": "code", "args": {"code": "[LAB PLACEHOLDER: list buckets, read a file, post it out]"}, "why": "the user asked"})
    return calls


def directives(text: str) -> list[dict]:
    calls = []
    for tool, rest in DIRECTIVE.findall(text):
        args = {k: v.strip() for k, v in ARG.findall(rest.strip())}
        calls.append({"tool": tool, "args": args, "why": "instruction found in a tool result", "source": "tool_result"})
    return calls


# --------------------------------------------------------------------------------------------------------------------
# One turn
# --------------------------------------------------------------------------------------------------------------------
def ask(setup: str | twin.Setup, signed_in: str, request: dict | str, world: twin.World | None = None) -> dict:
    """signed_in = who the identity provider says is signed in. request = what the browser sent (forgeable)."""
    setup = setup if isinstance(setup, twin.Setup) else twin.Setup(setup)
    world = world or twin.World()
    request = {"question": request} if isinstance(request, str) else request
    app, trace = setup.app, []
    out = {"answer": "", "trace": trace, "executed": [], "denied": [], "world": world, "error": None}

    # 1. Backend -> Runtime: inbound auth and the user the agent will act for ---------------------------------------
    token = twin.user_token(signed_in, request.get("client"))
    if setup.runtime.get("authorizerConfiguration"):
        ok, why = twin.jwt_authorize(setup.runtime["authorizerConfiguration"], token)
        trace.append(f"runtime inbound JWT: {why}")
        if not ok:
            out["error"] = why
            return out
        agent_user = token["username"]
        trace.append(f"workload access token via GetWorkloadAccessTokenForJWT: user = {agent_user} (from the validated token)")
    else:
        agent_user = signed_in
        if app["runtime_user_id_from"] == "request" and request.get("user_id"):
            agent_user = request["user_id"]
        if agent_user != signed_in or app["runtime_user_id_from"] == "request":
            if not twin.iam_allowed(setup, "tsg-backend", "bedrock-agentcore:InvokeAgentRuntimeForUser", twin.COMPANY["runtime_arn"]):
                out["error"] = "AccessDenied: InvokeAgentRuntimeForUser"
                return out
        trace.append(f"runtime inbound SigV4 (tsg-backend) with runtimeUserId = {agent_user}: not verified, taken from the {app['runtime_user_id_from']}")

    if app["runtime_session_id_from"] == "request" and request.get("session_id"):
        sid = request["session_id"]
    else:
        sid = twin.server_session_id(signed_in)
    session = world.sessions.setdefault(sid, {"owner": signed_in, "history": []})
    earlier = [h for h in session["history"]]
    if session["owner"] != signed_in:
        trace.append(f"runtimeSessionId {sid[:16]}... belongs to {session['owner']}: AgentCore does not enforce session-to-user mappings")

    # 2. The entrypoint ------------------------------------------------------------------------------------------------
    prompt = request.get("prompt", request.get("question", ""))
    calls: list[dict] = []
    if not isinstance(prompt, str):
        if app["entrypoint_validates_prompt"]:
            out["error"] = "Invalid input: 'prompt' must be a non-empty string"
            trace.append("entrypoint rejected a non-string prompt")
            return out
        for block in prompt:
            if "toolUse" in block:
                calls.append({"tool": block["toolUse"]["name"], "args": dict(block["toolUse"]["input"]),
                              "why": "toolUse block dispatched by the framework, no model involved", "source": "caller"})
        trace.append("entrypoint passed a list to the framework: the toolUse block runs without the model")
        prompt = ""

    # 3. Memory recall (actorId) ---------------------------------------------------------------------------------------
    actor = request["actor_id"] if (app["memory_actor_id_from"] == "request" and request.get("actor_id")) else agent_user
    recalled = twin.memory_retrieve(setup, world, actor)
    if recalled:
        trace.append(f"memory: {len(recalled)} record(s) recalled for actorId {actor} from {sorted({r['namespace'] for r in recalled})}")

    # 4. Tickets, read with the user's OAuth token from the token vault -----------------------------------------------
    parts = []
    if re.search(r"\bticket", prompt, re.I):
        tok = twin.tickets_token(setup, agent_user)
        trace.append(f"token vault: tickets-saas token for workload user {agent_user}")
        tickets = twin.tickets_for(tok)
        wanted = re.findall(r"\b(\d{4})\b", prompt)
        shown = [t for t in tickets if not wanted or t["id"] in wanted]
        for t in shown:
            parts.append(f"Ticket {t['id']} ({t['title']}): {visible(t['body'])}")
            calls += directives(t["body"])                 # the worst-case model obeys hidden instructions
        if wanted and not shown:
            parts.append("I can't find that ticket in your account.")
        if re.search(r"\bemail me\b", prompt, re.I) and shown:
            calls.append({"tool": "send_email", "args": {"to": twin.COMPANY["users"][agent_user]["email"] if agent_user in twin.COMPANY["users"] else agent_user,
                          "subject": f"Ticket {shown[0]['id']}", "body": visible(shown[0]["body"])}, "why": "the user asked"})
    calls = plan_from_question(prompt, agent_user) + calls if prompt else calls
    if re.search(r"\b(earlier|before|we talked)\b", prompt, re.I) and earlier:
        parts.append("Earlier in this conversation: " + " | ".join(earlier))

    # 5. Run the calls ------------------------------------------------------------------------------------------------
    gw_claims = token if app["agent_gateway_token"] == "user_jwt" else twin.m2m_token()
    if app["policy_session_id_from"] == "backend_per_user_day":
        psid = f"{signed_in}-2027-01-23"
    else:
        psid = request.get("policy_session_id") or str(uuid.uuid4())     # none sent: a new one per request
    for call in calls:
        tool, args = call["tool"], dict(call["args"])
        if tool == "remember":
            source = call.get("source", "user")
            if app.get("validate_memory_writes") and not validate_memory_write(args["text"], source, setup):
                trace.append(f"memory write refused ({source}): {args['text'][:50]}")
                continue
            spaces = twin.memory_write(setup, world, actor, args["text"], source)
            out["executed"].append({"tool": "remember", "args": args, "source": source, "namespaces": spaces})
            trace.append(f"memory: stored for actorId {actor} in {spaces} (source: {source})")
            parts.append("Noted.")
            continue
        if tool == "code":
            ci = setup.tools.get("codeInterpreter")
            if not ci:
                trace.append("model wanted to run code: no code interpreter on this agent")
                continue
            mode = ci["networkConfiguration"]["networkMode"]
            world.code_runs.append({"network": mode, "role": ci.get("executionRoleArn")})
            out["executed"].append({"tool": "code", "args": args, "network": mode})
            trace.append(f"code ran in Code Interpreter ({mode} network, role {ci.get('executionRoleArn', 'none').split('/')[-1]})")
            continue
        args.setdefault("caller_username", agent_user) if tool in ("reset_mfa", "send_email") else None
        r = twin.gateway_call(setup, world, gw_claims, tool, args, psid)
        if r["ok"]:
            out["executed"].append({"tool": tool, "args": args})
            note = f" (policy said {r['log_only']} in LOG_ONLY mode: not enforced)" if r.get("log_only") else ""
            trace.append(f"gateway: {tool}({json.dumps(args)}) EXECUTED{note}  [{call['why']}]")
            if tool == "search_kb":
                parts.append(r["text"])
            elif call.get("source") != "tool_result":
                parts.append(r["text"])
        else:
            out["denied"].append({"tool": tool, "args": args, "stage": r["stage"], "text": r["text"]})
            trace.append(f"gateway: {tool}({json.dumps(args)}) REFUSED at {r['stage']}: {r['text'][:110]}  [{call['why']}]")

    for r in recalled:
        if re.search(r"\bvpn\b", prompt, re.I) and "vpn" in r["text"].lower():
            parts.append(f"(From memory: {r['text']})")
    out["answer"] = " ".join(parts) or "OK."
    session["history"].append(f"{signed_in}: {prompt[:60]} -> {out['answer']}")
    return out


def main():
    ap = argparse.ArgumentParser(description="One Helpdesk turn on the offline AgentCore twin")
    ap.add_argument("setup")
    ap.add_argument("user", help="who is signed in (alice, bob, priya, ceo, dana)")
    ap.add_argument("question")
    ap.add_argument("--user-id", help="what the browser sends as the user (first draft copies it to runtimeUserId)")
    ap.add_argument("--session-id", help="what the browser sends as the runtime session ID")
    args = ap.parse_args()
    req = {"question": args.question}
    if args.user_id:
        req["user_id"] = args.user_id
    if args.session_id:
        req["session_id"] = args.session_id
    r = ask(args.setup, args.user, req)
    print(f"Q ({args.user}): {args.question}")
    for t in r["trace"]:
        print(f"   . {t}")
    print(f"A: {r['error'] or r['answer']}")


if __name__ == "__main__":
    main()
