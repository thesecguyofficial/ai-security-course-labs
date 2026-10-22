"""
controls.py: the Helpdesk agent's own before_tool callback (GC13). YOU EDIT THIS FILE in README Step 7.

In ADK this would be a function with the signature

    def before_tool(tool: BaseTool, args: dict, tool_context: ToolContext) -> Optional[dict]

assigned with LlmAgent(before_tool_callback=before_tool). Return None to let the call go ahead; return a dict to
block it (the dict becomes the tool's result, so the model reads your reason). The twin calls it the same way.

The hardened port already uses it for one rule: a person must never approve an action on a ticket the end user
can't see. The challenge adds a second rule: a recipient policy for send_email.
"""

from __future__ import annotations

from gcp_twin import TICKETS

INTERNAL_DOMAIN = "example.com"


def ticket_visible(ticket_id: str | None, groups: list[str]) -> bool:
    ticket = TICKETS.get(ticket_id or "")
    if ticket is None:
        return False
    needed = "finance-team@example.com" if ticket["team"] == "finance" else "helpdesk-staff@example.com"
    return needed in groups


def recipient_allowed(to: str, ticket_id: str | None) -> bool:
    """CHALLENGE (README Step 7): decide who send_email may write to, in code, before any person is asked.

    Allowed: an address on the internal domain (example.com), or the customer of the ticket the email is about
    (TICKETS[ticket_id]["customer"]). Everything else: False. Today this returns True for everyone.
    """
    return True     # TODO: replace with the policy above


def before_tool(tool, args: dict, tool_context) -> dict | None:
    groups = tool_context.state.get("groups", [])
    if tool.name in ("get_ticket", "close_ticket", "send_email") and args.get("ticket_id"):
        if not ticket_visible(args["ticket_id"], groups):
            return {"error": f"Ticket {args['ticket_id']} is not visible to this user."}
    if tool.name == "send_email" and not recipient_allowed(args.get("to", ""), args.get("ticket_id")):
        return {"error": f"Recipient {args.get('to')} is not allowed for this ticket."}
    return None
