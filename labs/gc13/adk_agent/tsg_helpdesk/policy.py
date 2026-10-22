"""
policy.py: the agent's before_tool callback (ADK signature). Deterministic rules the model can't talk its way past.

ADK calls it before every tool call, after any plugin's before_tool_callback, and again after a person confirms.
Return None to allow the call, or a dict to block it (the model reads the dict as the tool's result).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from google.adk.tools import BaseTool, ToolContext

from . import backends

AUDIT = logging.getLogger("tsg.audit")      # on Agent Runtime, what the agent logs ends up in Cloud Logging


def ticket_visible(ticket_id: str, groups: list[str]) -> bool:
    t = backends.STATE["tickets"].get(ticket_id)
    if t is None:
        return False
    return ("finance-team@example.com" if t["team"] == "finance" else "helpdesk-staff@example.com") in groups


def _audit(tool_context: ToolContext, tool: BaseTool, args: dict, decision: str) -> None:
    AUDIT.info(json.dumps({"end_user": tool_context.state.get("end_user"), "tool": tool.name,
                           "args": {k: v for k, v in args.items() if k not in ("body",)},
                           "confirmed": bool(tool_context.tool_confirmation and tool_context.tool_confirmation.confirmed),
                           "decision": decision}))


def before_tool(tool: BaseTool, args: dict[str, Any], tool_context: ToolContext) -> Optional[dict]:
    groups = tool_context.state.get("groups", [])       # written by YOUR server from a verified ID token
    if not tool_context.state.get("end_user"):
        _audit(tool_context, tool, args, "blocked: no verified user")
        return {"error": "No verified user in this session."}
    if args.get("ticket_id") and not ticket_visible(args["ticket_id"], groups):
        _audit(tool_context, tool, args, "blocked: ticket not visible")
        return {"error": f"Ticket {args['ticket_id']} is not visible to this user."}
    # Your recipient policy from the offline challenge (controls.recipient_allowed) belongs here too.
    _audit(tool_context, tool, args, "allowed")
    return None
