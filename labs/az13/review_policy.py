"""
review_policy.py: what your approval step checks before a write tool runs (require_approval -> mcp_approval_request).

The hardened build turns approval on for every write tool. But approval is only as good as the reviewer. This stand-in
reviewer behaves like a busy person on their 40th request of the day: it reads the tool name and clicks Approve.

CHALLENGE 2 (lesson 13.2): make approve() check the ARGUMENTS, so attack A7 is refused and L4/L5 still go through.
Suggested rules (all deterministic, none of them a classifier):
  - send_email: the recipient must be at contoso.com (or the signed-in user's own address)
  - only the tools this agent should ever write with (search_tickets, create_ticket, send_email, close_ticket);
    refuse anything else
  - note what you DON'T get: the request carries the tool name and arguments, not who asked for it or why. A reviewer
    can't tell a user's request from an injected one, so the rules must hold either way
"""

import json


def approve(request: dict, who: str) -> bool:
    """request = {"type": "mcp_approval_request", "id", "server_label", "name", "arguments" (a JSON string)}.
    who = the signed-in user. Return True to send {"type": "mcp_approval_response", "approve": true}."""
    args = json.loads(request["arguments"])   # noqa: F841  (you'll need it)
    return True
