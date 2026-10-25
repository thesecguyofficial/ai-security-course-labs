"""guards.py: YOUR controls for the TSG Ops Crew. This is the file you change in the capstone.

agents.py calls every function below at a fixed point of each chat turn. Right now every one of them allows
everything, which is why the crew is vulnerable. Replace the bodies with real checks.

Rules of the capstone (README, "Ground rules"):
  * Put your controls here (and in config.py). You may add helper modules next to this file and import them.
  * Do not edit agents.py, model.py, tools.py, mcp_server.py, mcp_client.py, memory.py, logs.py or common.py.
    The self-check compares them with the originals.
  * Every agent runs a worst-case stand-in model: it obeys every instruction it reads and ignores labels. A
    control that asks the model to behave does nothing here. A control in code that checks the action does.
  * Keep normal use working: tests/test_functional.py must still pass.

The crew offers billing and analyst a BROAD tool set (every local tool plus the crm tools); triage is offered
none. Deciding which agent may actually use which tool, for whom, is your job in authorize_tool_call.

Intended design, for reference (yours to enforce):
  triage   : routes only, no tools
  billing  : issue_refund, send_email (for the requester's own orders)
  analyst  : run_query, crm_lookup, crm_list_customers (never crm_debug_dump), for the requester's own tenant
"""
from __future__ import annotations

from crew.common import ALLOW, Ctx, Decision, Handoff, ToolCall

# The agent loop stops when this many tool calls have been ALLOWED in one turn.
MAX_TOOL_CALLS_PER_TURN = 50
# The loop does NOT read this one: a hand-off depth limit only holds if authorize_handoff checks ctx.depth against it.
MAX_HANDOFF_DEPTH = 10


def check_request(user: dict, message: str, state: dict) -> Decision:
    """First thing in every turn, before any agent runs.

    user  = {"email", "name", "role" ("customer" | "staff"), "tenant"}
    state = a dict that lives as long as this Crew instance: keep counters or timestamps in it.
    Return Decision(False, "why") to refuse the request.
    """
    return ALLOW


def check_mcp_tools(tools: list[dict], pins: dict) -> list[dict]:
    """The crm MCP server's tool list, every turn, before any agent is offered it.

    tools = [{"name", "description", "inputSchema"}, ...] exactly as the server sent them.
    pins  = {tool name: fingerprint} from crew/mcp_pins.json (python3 -m crew.mcp_client --pin), or {}.
            crew.mcp_client.fingerprint(tool) computes a tool's fingerprint.
    Return the tools the crew may be offered. Leaving a tool out means no agent can call it.
    """
    return tools


def authorize_handoff(handoff: Handoff, ctx: Ctx) -> Decision:
    """Every hand-off from one agent to another, before the next agent runs.

    handoff.frm, handoff.to = agent names ("triage" | "billing" | "analyst"); handoff.task = the instruction
    passed along. ctx.depth = how many hand-offs deep we already are; ctx.handoffs = the ones allowed so far.
    Return Decision(False, "why") to refuse the hand-off.
    """
    return ALLOW


def filter_handoff_task(task: str, ctx: Ctx) -> str:
    """The task text crossing a hand-off, before the next agent reads it. Return the text to pass along."""
    return task


def authorize_tool_call(call: ToolCall, ctx: Ctx) -> Decision:
    """Every tool call an agent asks for, before it runs.

    call.tool = "issue_refund" | "send_email" | "run_query" | "crm_lookup" | "crm_list_customers" | ...
    call.agent = "triage" | "billing" | "analyst";  call.args = the arguments the agent chose;
    call.server = "local" or "crm".
    ctx.requester (the signed-in human), ctx.tenant_scope (the tenant this turn may touch), ctx.agent,
    ctx.internal_domain, ctx.tool_calls (allowed so far), ctx.data_read.
    """
    return ALLOW


def screen_memory_write(note: dict, ctx: Ctx) -> dict | None:
    """A note the crew is about to store in shared memory after the turn. Return the note to keep, or None to
    drop it. note = {"id", "tenant", "kind", "origin", "text", "provenance"}."""
    return note


def screen_tool_result(tool: str, text: str) -> str:
    """A tool's result, before it enters an agent's context. Return the text to use."""
    return text


def screen_output(text: str, ctx: Ctx) -> str:
    """The crew's reply, before anyone sees it. Return the text to send."""
    return text


def render_html(text: str) -> str:
    """Turn the reply into HTML for the web page (the page puts it into the chat with innerHTML)."""
    return text.replace("\n", "<br>")


def response_headers() -> dict:
    """Extra HTTP headers for every response from app.py, e.g. {"Content-Security-Policy": "..."}."""
    return {}
