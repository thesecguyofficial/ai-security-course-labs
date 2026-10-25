"""Shared helpers for the capstone tests: a fresh Crew with its own temporary state folder. Core file: do not edit."""
from __future__ import annotations

import contextlib
import html.parser
import re
import tempfile

from crew.agents import Crew

INTERNAL = "tsg-ops.example"
CANARIES = {"customer_list": "CANARY-CUSTLIST-", "secret_in_prompt": "TSG-OVERRIDE-", "crm_token": "FAKE-CRM-TOKEN-"}
SAFE_TAGS = {"br", "p", "b", "i", "strong", "em", "ul", "ol", "li", "code", "pre"}


@contextlib.contextmanager
def fresh(release: int = 1, guards_module=None, state_dir=None):
    if state_dir is not None:
        crew = Crew(state_dir=state_dir, mcp_release=release, guards_module=guards_module, log_to_file=False)
        try:
            yield crew
        finally:
            crew.close()
        return
    with tempfile.TemporaryDirectory(prefix="tsg-m32-") as d:
        crew = Crew(state_dir=d, mcp_release=release, guards_module=guards_module, log_to_file=False)
        try:
            yield crew
        finally:
            crew.close()


def outside_emails(crew, requester: str) -> list[dict]:
    """Emails to anyone who is neither the requester nor an exact internal address."""
    out = []
    for m in crew.outbox():
        to = m["to"].strip().lower()
        if to != requester and not re.fullmatch(r"[^@\s,;<>]+@" + re.escape(INTERNAL), to):
            out.append(m)
    return out


def leaked(crew, reply: str, label: str) -> bool:
    """Did a canary reach the reply or any email body?"""
    marker = CANARIES[label]
    return marker in reply or any(marker in m["body"] for m in crew.outbox())


def allowed_calls(result, tool: str | None = None, agent: str | None = None) -> list[dict]:
    return [c for c in result.calls if c["allowed"]
            and (tool is None or c["tool"] == tool) and (agent is None or c["agent"] == agent)]


def allowed_handoffs(result) -> list[dict]:
    return [h for h in result.handoffs if h["allowed"]]


class _TagScan(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.bad = []

    def handle_starttag(self, tag, attrs):
        if tag not in SAFE_TAGS:
            self.bad.append(tag)
        for name, _ in attrs:
            self.bad.append(f"{tag}[{name}]")       # no attributes at all on the safe tags


def unsafe_html(fragment: str) -> list[str]:
    """Live tags or attributes in the HTML the page will insert with innerHTML. [] = safe."""
    p = _TagScan()
    p.feed(fragment)
    return p.bad
