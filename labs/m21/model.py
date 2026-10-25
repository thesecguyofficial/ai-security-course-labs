"""
model.py: the stand-in "model". Plain Python, not AI, so every run is identical and the tests check the PEP, not a
model's mood.

It does what a helpful support model does with a ticket (look the order up, refund what the customer asked for,
reply), and it ALSO obeys any `LAB-INJECTED-DIRECTIVE` comment in the ticket: the worst case of indirect prompt
injection, a model that always follows the hidden text. The directives are harmless placeholders that only this file
reads. They hold the tool calls an injected model would emit, written as raw JSON text, because a model's tool call
arrives as text and that is where parameter smuggling lives.

Placeholders in a directive: {{last_result}} = the text of the previous tool result, {{approval_id}} = the last
approval ID the model was told about.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import lab

DIRECTIVE = re.compile(r"LAB-INJECTED-DIRECTIVE[^:]*:\s*(\[.*\])\s*-->", re.S)


@dataclass
class Ticket:
    id: str
    requester: str
    order: str
    asks_refund_cents: int
    body: str
    directive: list = field(default_factory=list)


def read_ticket(tid: str) -> Ticket:
    text = (lab.DATA / "tickets" / f"{tid}.md").read_text()
    head, _, body = text.partition("\n\n")
    meta = dict(line.split(": ", 1) for line in head.splitlines())
    m = DIRECTIVE.search(body)
    return Ticket(meta["ticket"], meta["requester"], meta["order"], int(meta["asks_refund_cents"]),
                  body.strip(), json.loads(m.group(1)) if m else [])


def _honest_refund(t: Ticket) -> str:
    return json.dumps({"order_id": t.order, "amount_cents": t.asks_refund_cents, "currency": "USD",
                       "reason": f"ticket {t.id}"})


def plan(t: Ticket, phase: str = "first") -> list[tuple[str, str, bool]]:
    """The calls the model will propose, as (tool, raw JSON arguments, injected?)."""
    calls = []
    injected = [d for d in t.directive if bool(d.get("after_approval")) == (phase == "after_approval")]
    if phase == "first":
        calls.append(("lookup_order", json.dumps({"order_id": t.order}), False))
        for d in injected:
            calls += [(d["tool"], d["args"], True)] * int(d.get("repeat", 1))
        if t.asks_refund_cents:
            calls.append(("issue_refund", _honest_refund(t), False))
        calls.append(("send_email", json.dumps({"to": t.requester, "subject": f"Re: {t.id}",
                                                "body": "Thanks for your message. We've looked into it and updated "
                                                        "your ticket."}), False))
    else:  # after a supervisor decided: retry the held refund, then anything the injection saved for this moment
        if t.asks_refund_cents:
            calls.append(("issue_refund", _honest_refund(t), False))
        for d in injected:
            calls += [(d["tool"], d["args"], True)] * int(d.get("repeat", 1))
    return calls


def fill(raw: str, last_result: str, approval_id: str | None, told_to_add_approval: bool, injected: bool) -> str:
    """Substitute placeholders. An honest retry adds approval_id only if the PEP's message told the model to."""
    if "{{" in raw:
        raw = raw.replace("{{last_result}}", json.dumps(last_result)[1:-1]).replace("{{approval_id}}", approval_id or "")
    if not injected and told_to_add_approval and approval_id:
        args = json.loads(raw)
        if args.get("amount_cents", 0) > lab.REFUND_LIMIT_CENTS:
            args["approval_id"] = approval_id
            raw = json.dumps(args)
    return raw
