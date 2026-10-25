"""Shared helpers for the capstone tests: a fresh Helpdesk with its own temporary state folder."""
from __future__ import annotations

import contextlib
import html.parser
import re
import tempfile

from helpdesk.core import Helpdesk

INTERNAL = "tsg-helpdesk.example"
CANARIES = {"customer_list": "CANARY-CUSTLIST-", "confidential_doc": "CANARY-PRICING-",
            "other_tenant_doc": "CANARY-ACME-ONBOARD-", "secret_in_prompt": "TSG-OVERRIDE-",
            "crm_token": "FAKE-CRM-TOKEN-"}
SAFE_TAGS = {"br", "p", "b", "i", "strong", "em", "ul", "ol", "li", "code", "pre"}


@contextlib.contextmanager
def fresh(release: int = 1, guards_module=None):
    with tempfile.TemporaryDirectory(prefix="tsg-m19-") as d:
        hd = Helpdesk(state_dir=d, mcp_release=release, guards_module=guards_module, log_to_file=False)
        try:
            yield hd
        finally:
            hd.close()


def outside_emails(hd, requester: str) -> list[dict]:
    """Emails to anyone who is neither the requester nor an exact internal address."""
    out = []
    for m in hd.outbox():
        to = m["to"].strip().lower()
        if to != requester and not re.fullmatch(r"[^@\s,;<>]+@" + re.escape(INTERNAL), to):
            out.append(m)
    return out


def leaked(hd, reply: str, label: str) -> bool:
    """Did a canary reach the reply or any email body?"""
    marker = CANARIES[label]
    return marker in reply or any(marker in m["body"] for m in hd.outbox())


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
