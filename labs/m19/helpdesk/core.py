"""TSG Helpdesk, capstone edition: one chat turn, end to end. Core file: do not edit.

    from helpdesk.core import Helpdesk
    with Helpdesk() as hd:
        r = hd.handle("alice@acme.example", "How do I get a refund?")
        print(r.reply)

What a turn does (the guard calls are where your controls run):
  1. guards.check_request                  rate limits, size limits
  2. list the crm MCP server's tools       -> guards.check_mcp_tools
  3. retrieve documents (rag.py)           -> guards.filter_retrieval -> guards.screen_retrieved
  4. agent loop: the model asks for tools  -> guards.authorize_tool_call -> run -> guards.screen_tool_result
  5. the model writes the reply            -> guards.screen_output -> guards.render_html
Every step is written to the app log (logs.py). State (outbox, log) goes to ./state unless you pass state_dir.
"""
from __future__ import annotations

import importlib
import itertools
import os
import pathlib
import re
import uuid
from dataclasses import dataclass, field

from helpdesk import config, rag, tools
from helpdesk.common import Ctx, Decision, ToolCall
from helpdesk.logs import AppLog
from helpdesk.mcp_client import MCPClient, load_pins, tools_hash
from helpdesk.model import StandInModel, Turn

LAB = pathlib.Path(__file__).resolve().parent.parent
HARD_STOP = 200          # the loop's own safety net, far above any sane budget
# The app's own output scanner (a stand-in for a DLP check): labels it finds in a reply go into the log.
DLP = {
    "customer_list": re.compile(r"CANARY-CUSTLIST-\d+"),
    "confidential_doc": re.compile(r"CANARY-PRICING-\d+"),
    "other_tenant_doc": re.compile(r"CANARY-ACME-ONBOARD-\d+"),
    "secret_in_prompt": re.compile(r"TSG-OVERRIDE-\d+"),
    "crm_token": re.compile(r"FAKE-CRM-TOKEN-\d+"),
}
_counter = itertools.count(1)


@dataclass
class Result:
    reply: str
    reply_html: str
    request_id: str
    blocked: str | None = None
    docs: list = field(default_factory=list)
    calls: list = field(default_factory=list)      # dicts: tool, args, server, allowed, reason, why


def dlp_hits(text: str) -> list[str]:
    return [label for label, rx in DLP.items() if rx.search(text or "")]


class Helpdesk:
    def __init__(self, state_dir: pathlib.Path | str | None = None, mcp_release: int | None = None,
                 guards_module=None, log_to_file: bool = True):
        self.state_dir = pathlib.Path(state_dir) if state_dir else LAB / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if mcp_release is None:
            rel_file = self.state_dir / "mcp_release"
            mcp_release = int(rel_file.read_text().strip()) if rel_file.exists() else int(os.environ.get("TSG_MCP_RELEASE", "1"))
        self.mcp_release = mcp_release
        self.guards = guards_module or importlib.import_module("helpdesk.guards")
        self.log = AppLog(self.state_dir / "app-log.jsonl" if log_to_file else None)
        self.model = StandInModel()
        self.users = tools.load_users()
        self.guard_state: dict = {}
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
            raise KeyError(f"unknown user {email} (the lab's sign-in is simulated: use a user from data/users.json)")
        rid = f"req-{next(_counter):05d}-{uuid.uuid4().hex[:6]}"
        session = session or f"s-{email.split('@')[0]}"
        log = lambda event, **f: self.log.write(event, user, rid, session, **f)  # noqa: E731

        log("request", chars=len(message), ip=ip)
        d = g.check_request(user, message, self.guard_state)
        if not d.allow:
            log("blocked", guard="check_request", reason=d.reason)
            text = "Sorry, I can't take that request right now."
            return Result(text, g.render_html(text), rid, blocked=d.reason or "check_request")

        ctx = Ctx(user=user, message=message, internal_domain=self.users["internal_domain"], request_id=rid)
        turn = Turn(system_prompt=config.SYSTEM_PROMPT, user_email=email, message=message)

        # MCP tools: what the server says now, then what your guard lets the model see.
        offered = self.mcp.list_tools()
        log("mcp_tools_list", server="crm", tools_hash=tools_hash(offered), tool_names=[t["name"] for t in offered])
        allowed_tools = g.check_mcp_tools(offered, load_pins())
        turn.tools = {name: ("local", desc) for name, desc in tools.LOCAL_TOOLS.items()}
        turn.tools.update({t["name"]: ("crm", t["description"]) for t in allowed_tools})

        # Retrieval
        docs = g.filter_retrieval(user, rag.search(message, k=config.TOP_K))
        for doc in docs:
            log("retrieval", doc_id=doc.id, doc_tenant=doc.tenant, doc_audience=doc.audience,
                doc_source=doc.source, doc_flags=doc.flags)
            ctx.untrusted_sources.append(doc.id)
            turn.docs.append((doc.id, doc.title, g.screen_retrieved(doc.text, doc)))

        # Agent loop
        calls = []
        for _ in range(HARD_STOP):
            call = self.model.next_action(turn)
            if call is None:
                break
            if len(ctx.tool_calls) >= g.MAX_TOOL_CALLS_PER_TURN:
                log("blocked", guard="tool_budget", reason=f"{g.MAX_TOOL_CALLS_PER_TURN} tool calls this turn")
                turn.results.append((call, False, "tool budget reached"))
                calls.append(self._call_record(call, Decision(False, "tool budget reached")))
                break
            if call.tool not in turn.tools:
                decision = Decision(False, "the model does not have this tool")
            else:
                call.server = turn.tools[call.tool][0]
                decision = g.authorize_tool_call(call, ctx)
            log("tool_call", tool=call.tool, server=call.server, decision="allow" if decision.allow else "deny",
                reason=decision.reason, untrusted_in_context=ctx.untrusted_in_context,
                **self._call_fields(call, user))
            calls.append(self._call_record(call, decision))
            if not decision.allow:
                turn.results.append((call, False, decision.reason))
                continue
            result = self._run(call)
            ctx.tool_calls.append(call)
            if call.tool in ("crm_list_customers", "crm_debug_dump"):
                ctx.data_read.append("customer_list")
            if call.tool != "send_email":
                ctx.untrusted_sources.append(f"tool:{call.tool}")
            turn.results.append((call, True, g.screen_tool_result(call.tool, result)))

        reply = g.screen_output(self.model.answer(turn), ctx)
        log("response", chars=len(reply), dlp_hits=dlp_hits(reply))
        return Result(reply, g.render_html(reply), rid, docs=[x[0] for x in turn.docs], calls=calls)

    # ---- helpers ----------------------------------------------------------------------------------------------
    def _run(self, call: ToolCall) -> str:
        if call.tool == "lookup_order":
            return tools.lookup_order(call.args.get("order_id", ""))
        if call.tool == "send_email":
            a = call.args
            return tools.send_email(self.state_dir, a.get("to", ""), a.get("subject", ""), a.get("body", ""))
        return self.mcp.call(call.tool, call.args)

    def _call_fields(self, call: ToolCall, user: dict) -> dict:
        a, me = call.args, user["email"]
        if call.tool == "send_email":
            to = str(a.get("to", "")).strip().lower()
            dom = to.rsplit("@", 1)[-1] if "@" in to else ""
            return {"recipient": to, "recipient_domain": dom, "recipient_is_requester": to == me,
                    "recipient_internal": dom == self.users["internal_domain"],
                    "body_dlp_hits": dlp_hits(str(a.get("body", "")))}
        if call.tool == "lookup_order":
            order = tools.load_orders().get(str(a.get("order_id", "")), {})
            return {"order": str(a.get("order_id", "")), "order_owner_is_user": order.get("customer") == me}
        if call.tool == "crm_lookup":
            target = str(a.get("email", "")).strip().lower()
            return {"target": target, "target_is_user": target == me}
        return {}

    @staticmethod
    def _call_record(call: ToolCall, d: Decision) -> dict:
        return {"tool": call.tool, "args": call.args, "server": call.server, "allowed": d.allow,
                "reason": d.reason, "why": call.why}

    def outbox(self) -> list[dict]:
        return tools.read_outbox(self.state_dir)
