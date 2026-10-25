"""guards.py: YOUR controls for the TSG Helpdesk. This is the file you change in the capstone.

core.py calls every function below at a fixed point of each chat turn. Right now every one of them allows
everything, which is why the Helpdesk is vulnerable. Replace the bodies with real checks.

Rules of the capstone (README, "Ground rules"):
  * Put your controls here (and in config.py). You may add helper modules next to this file and import them.
  * Do not edit core.py, model.py, rag.py, tools.py, mcp_server.py, mcp_client.py, logs.py, common.py or app.py.
    The self-check compares them with the originals.
  * The model is a worst-case stand-in: it ignores labels and follows every instruction it reads. A control that
    asks the model to behave does nothing here. A control in code that checks the action does.
  * Keep normal use working: tests/test_functional.py must still pass.

The order of calls in one turn (core.Helpdesk.handle):
  check_request -> check_mcp_tools -> filter_retrieval -> screen_retrieved (per document)
  -> [model asks for a tool] -> authorize_tool_call -> (tool runs) -> screen_tool_result   (repeats)
  -> screen_output -> render_html
"""
from __future__ import annotations

from helpdesk.common import ALLOW, Ctx, Decision, ToolCall

# The agent loop stops when this many tool calls have been ALLOWED in one turn.
MAX_TOOL_CALLS_PER_TURN = 100


def check_request(user: dict, message: str, state: dict) -> Decision:
    """First thing in every turn, before the model sees anything.

    user  = {"email", "name", "role" ("customer" | "staff"), "tenant"}
    state = a dict that lives as long as this Helpdesk instance: keep counters or timestamps in it.
    Return Decision(False, "why") to refuse the request.
    """
    return ALLOW


def check_mcp_tools(tools: list[dict], pins: dict) -> list[dict]:
    """The crm MCP server's tool list, every turn, before the model sees it.

    tools = [{"name", "description", "inputSchema"}, ...] exactly as the server sent them.
    pins  = {tool name: fingerprint} from helpdesk/mcp_pins.json (python3 -m helpdesk.mcp_client --pin),
            or {} if you have not pinned. helpdesk.mcp_client.fingerprint(tool) computes a tool's fingerprint.
    Return the tools the model may see. Leaving a tool out means the model cannot call it.
    """
    return tools


def filter_retrieval(user: dict, docs: list) -> list:
    """The documents the retriever found, before any of them reaches the model.

    Each doc has .id .title .tenant ("all" or a tenant name) .audience ("public" | "staff")
    .source ("tsg-kb" | "partner-feed") .text .flags. Return only the documents this user may read.
    """
    return docs


def screen_retrieved(text: str, doc) -> str:
    """The text of one document that is about to enter the model's context. Return the text to use."""
    return text


def authorize_tool_call(call: ToolCall, ctx: Ctx) -> Decision:
    """Every tool call the model asks for, before it runs.

    call.tool = "lookup_order" | "send_email" | "crm_lookup" | "crm_list_customers" | ...
    call.args = the arguments the model chose, e.g. {"to": ..., "subject": ..., "body": ...}
    call.server = "local" or "crm";  call.why = what made the model ask
    ctx.user, ctx.message, ctx.internal_domain, ctx.untrusted_sources, ctx.tool_calls (allowed so far this turn),
    ctx.data_read (e.g. ["customer_list"] once the turn has read it)
    """
    return ALLOW


def screen_tool_result(tool: str, text: str) -> str:
    """A tool's result, before it enters the model's context. Return the text to use."""
    return text


def screen_output(text: str, ctx: Ctx) -> str:
    """The model's reply, before anyone sees it. Return the text to send."""
    return text


def render_html(text: str) -> str:
    """Turn the reply into HTML for the web page (the page puts it into the chat with innerHTML)."""
    return text.replace("\n", "<br>")


def response_headers() -> dict:
    """Extra HTTP headers for every response from app.py, e.g. {"Content-Security-Policy": "..."}."""
    return {}
