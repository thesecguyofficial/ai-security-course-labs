"""
refund_tools.py: the guided build's refund tools as ONE Lambda function behind an AgentCore Gateway.

LAB SAFETY: nothing here moves money. issue_refund and request_refund_approval print what they would have done to
CloudWatch Logs and return a message. Orders are fake (reserved .example domains).

What the gateway passes (AWS "Add Lambda targets"): `event` is the tool input; context.client_context.custom carries
bedrockAgentCoreToolName ("<target>___<tool>") and request IDs, not the end user. That is why the Cedar policies on
the gateway check caller_username against the token's username claim BEFORE this function runs.
"""

import json

ORDERS = {
    "O-1001": {"customer": "sam@customer.example", "total_cents": 4500},
    "O-1002": {"customer": "sam@customer.example", "total_cents": 25000},
    "O-3001": {"customer": "mallory@attacker.example", "total_cents": 120000},
}
DELIMITER = "___"


def _tool_name(context) -> str:
    full = context.client_context.custom["bedrockAgentCoreToolName"]
    return full[full.index(DELIMITER) + len(DELIMITER):] if DELIMITER in full else full


def lambda_handler(event, context):
    tool = _tool_name(context)
    print(json.dumps({"tool": tool, "input": event}))          # CloudWatch Logs: what the gateway let through
    if tool == "lookup_order":
        o = ORDERS.get(str(event.get("order_id")))
        return {"order_id": event.get("order_id"), **o} if o else {"error": "no such order"}
    if tool == "issue_refund":
        return {"result": f"LAB: refund of {event.get('amount_cents')} cents on {event.get('order_id')} recorded "
                          f"for {event.get('caller_username')}. No money moved."}
    if tool == "request_refund_approval":
        return {"result": f"LAB: approval request filed for {event.get('amount_cents')} cents on "
                          f"{event.get('order_id')}. A supervisor reviews it in the back office."}
    return {"error": f"unknown tool {tool}"}
