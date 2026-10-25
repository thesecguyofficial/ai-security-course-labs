"""TSG Ops Crew: one chat turn across three agents, end to end. Core file: do not edit.

    from crew.agents import Crew
    with Crew() as crew:
        r = crew.handle("alice@acme.example", "How do I get a refund on order 5001?")
        print(r.reply)

Three agents share one chat turn: triage routes, then billing or analyst does the work. Each agent runs the
worst-case stand-in model (model.py) with its own system prompt. Your controls run at the guard calls:
  1. guards.check_request                         size and rate limits
  2. list the crm MCP tools   -> guards.check_mcp_tools    (what every agent may be offered from the server)
  3. read shared memory       -> (logged; a note is written back at the end via guards.screen_memory_write)
  4. an agent hands off       -> guards.authorize_handoff -> guards.filter_handoff_task
  5. an agent calls a tool    -> guards.authorize_tool_call -> run -> guards.screen_tool_result
  6. the reply                -> guards.screen_output -> guards.render_html

The crew OFFERS every agent a broad tool set on purpose (triage none; billing and analyst the local tools plus
the crm tools). Narrowing who may actually use what is your job, in guards.authorize_tool_call. State (outbox,
refunds, memory, log) goes to ./state unless you pass state_dir.
"""
from __future__ import annotations

import importlib
import itertools
import os
import pathlib
import re
import uuid
from dataclasses import dataclass, field

from crew import config, tools
from crew.common import Ctx, Decision, Handoff, ToolCall
from crew.logs import AppLog
from crew.mcp_client import MCPClient, load_pins, tools_hash
from crew.memory import MemoryStore
from crew.model import StandInModel, Turn, directives_in
from crew import model as model_mod

LAB = pathlib.Path(__file__).resolve().parent.parent
HARD_STOP = 200          # the orchestrator's own safety net, far above any sane budget
AGENTS = ("triage", "billing", "analyst")
LOCAL_DESC = {name: desc for a in tools.LOCAL_TOOLS.values() for name, desc in a.items()}

# The app's own output scanner (a stand-in for a DLP check): labels it finds go into the log.
DLP = {
    "customer_list": re.compile(r"CANARY-CUSTLIST-\d+"),
    "secret_in_prompt": re.compile(r"TSG-OVERRIDE-\d+"),
    "crm_token": re.compile(r"FAKE-CRM-TOKEN-\d+"),
}
_counter = itertools.count(1)
model_mod._PROMPTS = dict(config.SYSTEM_PROMPTS)


@dataclass
class Result:
    reply: str
    reply_html: str
    request_id: str
    blocked: str | None = None
    calls: list = field(default_factory=list)      # dicts: agent, tool, args, server, allowed, reason, why
    handoffs: list = field(default_factory=list)   # dicts: frm, to, allowed, reason


def dlp_hits(text: str) -> list[str]:
    return [label for label, rx in DLP.items() if rx.search(text or "")]


class Crew:
    def __init__(self, state_dir: pathlib.Path | str | None = None, mcp_release: int | None = None,
                 guards_module=None, log_to_file: bool = True):
        self.state_dir = pathlib.Path(state_dir) if state_dir else LAB / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if mcp_release is None:
            rel_file = self.state_dir / "mcp_release"
            mcp_release = int(rel_file.read_text().strip()) if rel_file.exists() else int(os.environ.get("TSG_MCP_RELEASE", "1"))
        self.mcp_release = mcp_release
        self.guards = guards_module or importlib.import_module("crew.guards")
        self.log = AppLog(self.state_dir / "app-log.jsonl" if log_to_file else None)
        self.model = StandInModel()
        self.users = tools.load_users()
        self.guard_state: dict = {}
        self.memory = MemoryStore(self.state_dir)
        self.mcp = MCPClient(self.mcp_release)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self) -> None:
        self.mcp.close()

    # ---- one chat turn ------------------------------------------------------------------------------------
    def handle(self, user_email: str, message: str, session: str | None = None, ip: str = "127.0.0.1") -> Result:
        g = self.guards
        email = user_email.strip().lower()
        user = dict(self.users["users"].get(email) or {}, email=email)
        if "role" not in user:
            raise KeyError(f"unknown user {email} (sign-in is simulated: use a user from data/users.json)")
        rid = f"req-{next(_counter):05d}-{uuid.uuid4().hex[:6]}"
        session = session or f"s-{email.split('@')[0]}"

        def log(event, agent="triage", depth=0, **f):
            self.log.write(event, user, rid, session, agent, depth, **f)

        log("request", chars=len(message), ip=ip)
        d = g.check_request(user, message, self.guard_state)
        if not d.allow:
            log("blocked", reason=d.reason, guard="check_request")
            text = "Sorry, I can't take that request right now."
            return Result(text, g.render_html(text), rid, blocked=d.reason or "check_request")

        ctx = Ctx(requester=user, message=message, internal_domain=self.users["internal_domain"], request_id=rid,
                  tenant_scope=user.get("tenant", ""))
        turn = Turn(requester_email=email, requester_tenant=user.get("tenant", ""), message=message)

        # MCP tools: what the server says now, then what your guard lets the crew be offered.
        offered = self.mcp.list_tools()
        log("mcp_tools", server="crm", tools_hash=tools_hash(offered), tool_names=[t["name"] for t in offered])
        crm_allowed = g.check_mcp_tools(offered, load_pins())
        broad = {name: ("local", LOCAL_DESC[name]) for name in LOCAL_DESC}
        broad.update({t["name"]: ("crm", t["description"]) for t in crm_allowed})
        turn.tools = {"triage": {}, "billing": dict(broad), "analyst": dict(broad)}

        # Shared memory: the ticket notes for this tenant.
        for note in self.memory.notes_for(user.get("tenant", "")):
            log("memory_read", item_id=note.get("id"), item_kind=note.get("kind"), item_origin=note.get("origin"),
                item_provenance=note.get("provenance", []))
            ctx.untrusted_sources.append(f"memory:{note.get('id')}")
            turn.memory.append((note.get("id"), note.get("text", "")))

        # Agent loop.
        agent, depth, task = "triage", 0, ""
        calls, hos = [], []
        for _ in range(HARD_STOP):
            turn.task = task
            ctx.agent, ctx.depth = agent, depth
            action = self.model.act(agent, depth, turn)
            if action is None:
                break
            if isinstance(action, Handoff):
                decision = g.authorize_handoff(action, ctx)
                log("handoff", agent=agent, depth=depth, frm=action.frm, to=action.to,
                    decision="allow" if decision.allow else "deny", reason=decision.reason,
                    task_dlp_hits=dlp_hits(action.task), untrusted_in_context=ctx.untrusted_in_context)
                hos.append({"frm": action.frm, "to": action.to, "allowed": decision.allow, "reason": decision.reason})
                if decision.allow:
                    task = g.filter_handoff_task(action.task, ctx)
                    ctx.handoffs.append(action)
                    agent, depth = action.to, depth + 1
                continue
            # a ToolCall
            if len(ctx.tool_calls) >= g.MAX_TOOL_CALLS_PER_TURN:
                log("blocked", agent=agent, depth=depth, guard="tool_budget",
                    reason=f"{g.MAX_TOOL_CALLS_PER_TURN} tool calls this turn")
                turn.results.append((agent, action, False, "tool budget reached"))
                calls.append(self._rec(agent, action, Decision(False, "tool budget reached")))
                break
            if action.tool not in turn.tools.get(agent, {}):
                decision = Decision(False, "this agent is not offered that tool")
            else:
                action.server = turn.tools[agent][action.tool][0]
                decision = g.authorize_tool_call(action, ctx)
            log("tool_call", agent=agent, depth=depth, tool=action.tool, server=action.server,
                decision="allow" if decision.allow else "deny", reason=decision.reason,
                untrusted_in_context=ctx.untrusted_in_context, **self._fields(action, user))
            calls.append(self._rec(agent, action, decision))
            if not decision.allow:
                turn.results.append((agent, action, False, decision.reason))
                continue
            result = self._run(action)
            ctx.tool_calls.append(action)
            if action.tool in ("crm_list_customers", "crm_debug_dump"):
                ctx.data_read.append("customer_list")
            if action.tool != "send_email":
                ctx.untrusted_sources.append(f"tool:{action.tool}")
            turn.results.append((agent, action, True, g.screen_tool_result(action.tool, result)))

        reply = g.screen_output(self.model.reply(turn), ctx)
        log("response", agent=agent, depth=depth, chars=len(reply), dlp_hits=dlp_hits(reply))
        self._write_memory_note(user, turn, ctx, rid, session)
        return Result(reply, g.render_html(reply), rid, calls=calls, handoffs=hos)

    # ---- helpers ----------------------------------------------------------------------------------------------
    def _write_memory_note(self, user: dict, turn: Turn, ctx: Ctx, rid: str, session: str) -> None:
        """After the turn, the crew remembers it: a short note for the next turn on this tenant."""
        text = f"Ticket from {user['email']}: {turn.message}"
        note = {"id": self.memory.next_id(user.get("tenant", "")), "tenant": user.get("tenant", ""),
                "kind": "turn-note", "origin": "agent", "text": text,
                "provenance": [s for s in ctx.untrusted_sources if s.startswith("memory:") or s == "request"]}
        kept = self.guards.screen_memory_write(note, ctx)
        self.log.write("memory_write", user, rid, session, "analyst", ctx.depth,
                       item_id=note["id"], item_kind="turn-note", item_origin="agent",
                       provenance_dlp_hits=dlp_hits(text) + (["directive"] if directives_in(text) else []))
        if kept:
            self.memory.append(kept)

    def _run(self, call: ToolCall) -> str:
        a = call.args
        if call.tool == "issue_refund":
            return tools.issue_refund(self.state_dir, a.get("order_id", ""), a.get("amount_cents", "0"))
        if call.tool == "send_email":
            return tools.send_email(self.state_dir, a.get("to", ""), a.get("subject", ""), a.get("body", ""))
        if call.tool == "run_query":
            return tools.run_query(a.get("tenant", ""), a.get("kind", "usage"))
        return self.mcp.call(call.tool, a)

    def _fields(self, call: ToolCall, user: dict) -> dict:
        a, me = call.args, user["email"]
        if call.tool == "send_email":
            to = str(a.get("to", "")).strip().lower()
            dom = to.rsplit("@", 1)[-1] if "@" in to else ""
            return {"recipient": to, "recipient_domain": dom, "recipient_is_requester": to == me,
                    "recipient_internal": dom == self.users["internal_domain"],
                    "body_dlp_hits": dlp_hits(str(a.get("body", "")))}
        if call.tool == "issue_refund":
            order = tools.load_orders().get(str(a.get("order_id", "")), {})
            return {"order": str(a.get("order_id", "")), "amount_cents": str(a.get("amount_cents", "")),
                    "order_owner_is_user": order.get("customer") == me}
        if call.tool == "run_query":
            qt = str(a.get("tenant", "")).strip().lower()
            return {"query_tenant": qt, "query_tenant_is_user": qt == user.get("tenant", "")}
        if call.tool == "crm_lookup":
            target = str(a.get("email", "")).strip().lower()
            return {"target": target, "target_is_user": target == me}
        return {}

    @staticmethod
    def _rec(agent: str, call: ToolCall, d: Decision) -> dict:
        return {"agent": agent, "tool": call.tool, "args": call.args, "server": call.server,
                "allowed": d.allow, "reason": d.reason, "why": call.why}

    def outbox(self) -> list[dict]:
        return tools.read_outbox(self.state_dir)

    def refunds(self) -> list[dict]:
        return tools.read_refunds(self.state_dir)
