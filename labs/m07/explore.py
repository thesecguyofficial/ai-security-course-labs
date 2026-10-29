"""
explore.py: look at how the helpdesk agent works, one idea at a time, before you attack it (M7 lab, part 1).

Nothing here changes the agent. explore.py never sends an email and never writes to the audit log. Commands:

    python3 explore.py tools                       # 1. the tools, written the way tool-calling APIs expect them
    python3 explore.py loop --ticket T-1043        # 2. the loop: observe, decide, act, one turn at a time
    python3 explore.py toolcall                    # 3. one tool call as JSON (stand-in model, not AI)
    python3 explore.py toolcall --ollama           #    the same request to a REAL small model through Ollama
    python3 explore.py toolcall --ollama --turns 4 #    several turns: the model asks, the app runs, the result goes back
    python3 explore.py memory write --ticket T-1043   # 4. what a long-term memory layer would save after a run
    python3 explore.py memory read "<new request>"     #    a new session: what it reads back into the context window

Ticket T-1043 is an ordinary ticket with no hidden instruction. T-1042 is the one you attack in part 2.
Fake data only. --ollama talks only to Ollama on 127.0.0.1 (your own computer). The memory demo writes
plain JSON files under state/memory/ (make clean deletes them); the agent itself has no long-term memory.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import urllib.request

import tools
from agent import TICKET_FROM_RE
from controls import POLICY
from ollama_backend import OllamaModel
from stand_in_model import ATTACHMENT_RE, AMOUNT_RE, DUE_RE, StandInModel

OLLAMA_CHAT = "http://127.0.0.1:11434/api/chat"
MAX_TURNS = 20  # the same hard stop as agent.py

# The three tools, described the way tool-calling APIs expect them (OpenAI, Ollama and others use this shape):
# a name, a description the model reads, and a JSON schema for the arguments.
SCHEMAS = {
    "read_file": {"type": "function", "function": {
        "name": "read_file",
        "description": "Read a text file from the helpdesk workspace, e.g. tickets/T-1043.md",
        "parameters": {"type": "object",
                       "properties": {"path": {"type": "string", "description": "Path inside the workspace"}},
                       "required": ["path"]}}},
    "run_task": {"type": "function", "function": {
        "name": "run_task",
        "description": "Run a shell command in the workspace, e.g. ls kb",
        "parameters": {"type": "object",
                       "properties": {"command": {"type": "string", "description": "The command line to run"}},
                       "required": ["command"]}}},
    "send_email": {"type": "function", "function": {
        "name": "send_email",
        "description": "Send an email",
        "parameters": {"type": "object",
                       "properties": {"to": {"type": "string", "description": "One email address"},
                                      "subject": {"type": "string"},
                                      "body": {"type": "string"}},
                       "required": ["to", "subject", "body"]}}},
}


def one_line(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)


def clip(text: str, n: int = 60) -> str:
    text = str(text).replace("\n", "\\n")
    return text if len(text) <= n else text[:n] + "…"


def requester_of(ticket: str) -> str:
    m = TICKET_FROM_RE.search(tools.read_file(f"tickets/{ticket}.md"))
    return m.group(1) if m else ""


# --------------------------------------------------------------------------- 1. tools

def cmd_tools(a):
    names = list(tools.TOOL_DESCRIPTIONS)
    print("The agent's tools, written the way tool-calling APIs expect them: a name, a description the model")
    print("reads, and a JSON schema (which arguments, of which type, which are required).\n")
    print(json.dumps(SCHEMAS[names[0]], indent=2))
    print("\nThe other two have the same shape:")
    for n in names[1:]:
        f = SCHEMAS[n]["function"]
        args = ", ".join(f"{k}: {v['type']}" for k, v in f["parameters"]["properties"].items())
        print(f"  {n:<11} ({args})   \"{f['description']}\"")
    print("\nThe model never runs these. It can only write a request to call one; agent.py runs it.")


# --------------------------------------------------------------------------- 2. loop

def simulated_result(tool: str, args: dict) -> str:
    """What the loop feeds back. read_file really reads; the others are not run by explore.py."""
    if tool == "read_file":
        return tools.read_file(args["path"])
    if tool == "send_email":
        return f"queued for {args.get('to')} in the local outbox. No network was used."
    return f"(simulated) {args.get('command')!r} was recorded, not executed."


def cmd_loop(a):
    model = StandInModel()
    requester = requester_of(a.ticket)
    offered = list(tools.TOOL_DESCRIPTIONS)
    view = {"task": "answer_ticket", "ticket": a.ticket, "requester": requester, "tools": offered,
            "spotlight": False, "history": []}
    shape = OllamaModel("explore")  # only used to build the messages a real model would get; no network
    print(f"ticket {a.ticket} · requester {requester} · model: stand-in (plain Python, not AI)")
    print(f"tools offered: {', '.join(offered)} · the loop stops when the model says it's done, or after {MAX_TURNS} turns\n")
    for turn in range(1, MAX_TURNS + 1):
        msgs = shape._messages(view)
        chars = sum(len(m["content"]) for m in msgs)
        print(f"TURN {turn}")
        print(f"  OBSERVE  the model is sent {len(msgs)} messages, {chars} characters (its working memory)")
        action = model.next_action(view)
        print(f"  DECIDE   {clip(one_line(action), 110)}")
        if "final" in action:
            print("  STOP     the model says it is done")
            break
        tool, args = action["tool"], action["args"]
        result = simulated_result(tool, args)
        if tool == "read_file":
            first = result.strip().splitlines()[0]
            print(f"  ACT      the app runs read_file -> {len(result)} characters, starting \"{first}\"")
        else:
            print(f"  ACT      the app would run {tool} (explore.py doesn't; agent.py would write it to state/)")
        view["history"].append({"tool": tool, "args": args, "allowed": True, "result": result})
    print("\nEach tool result is added to the history, and the WHOLE history is sent again on the next turn.")


# --------------------------------------------------------------------------- 3. toolcall

def system_and_user(ticket: str) -> list[dict]:
    return [{"role": "system", "content": "You are a helpdesk agent. Use the tools to answer the ticket, then stop."},
            {"role": "user", "content": f"Answer ticket {ticket} (file tickets/{ticket}.md). "
                                        f"The requester is {requester_of(ticket)}."}]


def print_request(req: dict) -> None:
    """The real request, with each tool schema on one line so it fits on a screen."""
    lines = ["{"]
    for k, v in req.items():
        if k == "messages":
            lines.append('  "messages": [')
            lines += [f"    {one_line(m)}," for m in v]
            lines[-1] = lines[-1].rstrip(",")
            lines.append("  ],")
        elif k == "tools":
            lines.append('  "tools": [')
            lines += [f"    {one_line(t)}," for t in v]
            lines[-1] = lines[-1].rstrip(",")
            lines.append("  ]")
        else:
            lines.append(f'  "{k}": {one_line(v)},')
    lines.append("}")
    print("\n".join(lines))


def print_response(resp: dict) -> None:
    """The real response: model, the assistant message (each tool call on one line) and why it stopped."""
    msg = resp.get("message", {})
    lines = ["{", f'  "model": {one_line(resp.get("model"))},', '  "message": {']
    inner = [f'    "{k}": {one_line(v)}' for k, v in msg.items() if k != "tool_calls"]
    if msg.get("tool_calls"):
        inner.append('    "tool_calls": [\n' + ",\n".join(f"      {one_line(c)}" for c in msg["tool_calls"]) + "\n    ]")
    lines.append(",\n".join(inner))
    lines += ["  },", f'  "done_reason": {one_line(resp.get("done_reason"))}', "}"]
    print("\n".join(lines))


def ask_ollama(req: dict) -> dict:
    data = json.dumps(req).encode()
    r = urllib.request.Request(OLLAMA_CHAT, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=600) as resp:
            return json.load(resp)
    except OSError as exc:
        raise SystemExit(f"Could not reach Ollama at {OLLAMA_CHAT}: {exc}. Start Ollama, or drop --ollama.")


def ask_stand_in(req: dict, ticket: str) -> dict:
    """The stand-in's next action, wrapped in the same response shape as Ollama's (labelled, not AI)."""
    hist, pending = [], None
    for m in req["messages"]:
        if m["role"] == "assistant" and m.get("tool_calls"):
            pending = m["tool_calls"][0]["function"]
        elif m["role"] == "tool" and pending:
            hist.append({"tool": pending["name"], "args": pending["arguments"], "allowed": True, "result": m["content"]})
    offered = [t["function"]["name"] for t in req["tools"]]
    action = StandInModel().next_action({"task": "answer_ticket", "ticket": ticket, "requester": requester_of(ticket),
                                         "tools": offered, "spotlight": False, "history": hist})
    if "final" in action:
        msg = {"role": "assistant", "content": action["final"]}
    else:
        msg = {"role": "assistant", "content": "",
               "tool_calls": [{"function": {"name": action["tool"], "arguments": action["args"]}}]}
    return {"model": "stand-in (plain Python, not AI)", "message": msg, "done_reason": "stop"}


def cmd_toolcall(a):
    model = a.model if a.ollama else "stand-in"
    offered = ["read_file", "send_email"]
    req = {"model": model, "stream": False, "options": {"temperature": 0, "seed": 7},
           "messages": system_and_user(a.ticket), "tools": [SCHEMAS[t] for t in offered]}
    for turn in range(1, a.turns + 1):
        resp = ask_ollama(req) if a.ollama else ask_stand_in(req, a.ticket)
        msg = resp.get("message", {})
        calls = msg.get("tool_calls") or []
        if a.turns == 1:
            print(f"REQUEST  POST {OLLAMA_CHAT if a.ollama else '(stand-in, no network)'}   the app -> the model")
            print_request(req)
            print("\nRESPONSE   the model -> the app (timing fields left out)")
            print_response(resp)
            print("\nThe model only wrote a request. Nothing has run yet: the app decides whether to run it.")
            return
        print(f"TURN {turn}  model -> app: " + (one_line([c["function"] for c in calls]) if calls
                                               else f"text, no tool call: {clip(msg.get('content', ''), 90)}"))
        if not calls:
            print("         the model answered in text, so the loop stops")
            return
        req["messages"].append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})
        for c in calls:
            name, args = c["function"]["name"], c["function"].get("arguments") or {}
            if name != "read_file":
                print(f"         app: explore.py stops here and never runs {name}. agent.py would run it")
                print(f"         (after its controls) and write it to state/outbox.jsonl.")
                return
            try:
                result = tools.read_file(str(args.get("path", "")))
            except tools.ToolError as exc:
                result = f"ERROR: {exc}"
            print(f"         app runs read_file, then sends back: "
                  f"{one_line({'role': 'tool', 'tool_name': name, 'content': result[:44] + '…'})}")
            req["messages"].append({"role": "tool", "tool_name": name, "content": result})
    print(f"(stopped after {a.turns} turns)")


# --------------------------------------------------------------------------- 4. memory

MEM_DIR = lambda: tools.state_dir() / "memory"  # noqa: E731


def honest_run(ticket: str) -> list[dict]:
    """Run the stand-in loop quietly (no tools that write), return the steps."""
    model = StandInModel()
    view = {"task": "answer_ticket", "ticket": ticket, "requester": requester_of(ticket),
            "tools": ["read_file", "send_email"], "spotlight": False, "history": []}
    for _ in range(MAX_TURNS):
        action = model.next_action(view)
        if "final" in action:
            break
        view["history"].append({"tool": action["tool"], "args": action["args"], "allowed": True,
                                "result": simulated_result(action["tool"], action["args"])})
    return view["history"]


def cmd_memory_write(a):
    steps = honest_run(a.ticket)
    requester = requester_of(a.ticket)
    t = tools.read_file(f"tickets/{a.ticket}.md")
    att = ATTACHMENT_RE.search(t).group(1)
    note = tools.read_file(att)
    invoice = re.search(r"Invoice:\s*(\S+)", note).group(1)
    amount, due = AMOUNT_RE.search(note).group(1).strip(), DUE_RE.search(note).group(1).strip()
    when = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    entries = {
        "episodic": {"when": when, "ticket": a.ticket, "requester": requester,
                     "what_happened": " -> ".join(f"{s['tool']} {s['args'].get('path') or s['args'].get('to')}"
                                                  for s in steps),
                     "outcome": "answered"},
        "procedural": {"task": "answer_ticket", "learned_from": a.ticket,
                       "steps": ["read_file the ticket", "read_file its attachment",
                                 "send_email to the requester with the amount and due date"]},
        "semantic": {"fact": f"Invoice {invoice}: amount due {amount}, due {due}", "source": att,
                     "saved": when},
    }
    d = MEM_DIR()
    d.mkdir(parents=True, exist_ok=True)
    print(f"The run on {a.ticket} is over. A memory layer now decides what to keep for NEXT time.")
    print("Here it is plain Python (real products ask a model to pick and summarise). Three kinds:\n")
    labels = {"episodic": "what happened, and when", "procedural": "how to do this task",
              "semantic": "facts"}
    for kind, entry in entries.items():
        path = d / f"{kind}.jsonl"
        with path.open("a", encoding="utf-8") as f:
            f.write(one_line(entry) + "\n")
        print(f"{kind.upper():<11}({labels[kind]})  appended to state/memory/{path.name}")
        print(f"  {one_line(entry)}")
    print("\nThese files outlive this session. The model hasn't changed at all: the app saved notes.")


def values(entry: dict) -> str:
    """The text of an entry's values (not its field names), for the word match."""
    return " ".join(" ".join(v) if isinstance(v, list) else str(v) for v in entry.values())


def cmd_memory_read(a):
    d = MEM_DIR()
    words = {w for w in re.findall(r"[a-z0-9-]+", a.request.lower()) if len(w) > 3}
    print(f'New session. Request: "{a.request}"')
    print("Search long-term memory (word match here; real products search by meaning, as in Module 6):")
    notes = []
    for kind in ("semantic", "episodic", "procedural"):
        path = d / f"{kind}.jsonl"
        rows = [json.loads(x) for x in path.read_text("utf-8").splitlines()] if path.exists() else []
        hits = [r for r in rows if words & set(re.findall(r"[a-z0-9-]+", values(r).lower()))]
        print(f"  {kind:<11} {len(rows)} saved, {len(hits)} match")
        if hits:
            r = hits[-1]
            if kind == "semantic":
                notes.append(f"- [semantic] {r['fact']} (from {r['source']})")
            elif kind == "episodic":
                notes.append(f"- [episodic] {r['when'][:10]}: {r['ticket']} from {r['requester']}: {r['what_happened']}")
            else:
                notes.append(f"- [procedural] For {r['task']}: " + "; then ".join(r["steps"]) + ".")
    if not notes:
        print("\nNothing matched, so nothing is added (no notes yet? run `python3 explore.py memory write`).")
        return
    print("\nWhat the app puts into the model's working memory (the context window) for this new run:")
    print("=== system message ===")
    print("You are a helpdesk agent. Use the tools to answer the ticket, then stop.")
    print("Notes from memory (saved by the app in earlier sessions):")
    print("\n".join(notes))
    print("\nThe model reads these notes like anything else in its prompt. Whoever got a note saved is writing part of it.")


def main(argv=None):
    p = argparse.ArgumentParser(description="Look at how the helpdesk agent works, one idea at a time (M7 lab).")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("tools"); s.set_defaults(fn=cmd_tools)
    s = sub.add_parser("loop"); s.add_argument("--ticket", default="T-1043"); s.set_defaults(fn=cmd_loop)
    s = sub.add_parser("toolcall"); s.add_argument("--ticket", default="T-1043")
    s.add_argument("--ollama", action="store_true", help="ask a real model through Ollama on 127.0.0.1")
    s.add_argument("--model", default="llama3.2:3b")
    s.add_argument("--turns", type=int, default=1, help="1 = show the full request and response")
    s.set_defaults(fn=cmd_toolcall)
    s = sub.add_parser("memory"); ms = s.add_subparsers(dest="mcmd", required=True)
    w = ms.add_parser("write"); w.add_argument("--ticket", default="T-1043"); w.set_defaults(fn=cmd_memory_write)
    r = ms.add_parser("read"); r.add_argument("request"); r.set_defaults(fn=cmd_memory_read)
    a = p.parse_args(argv)
    if getattr(a, "ticket", None) and not re.fullmatch(r"T-\d{4}", a.ticket):
        p.error("--ticket looks like T-1043")
    a.fn(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
