"""
guards.py: the four security controls of TSG Helpdesk (M17 build). The hardened profile runs all four.

This is the file a developer changes, and the file the security evals protect. `regress.py` edits it the way a
real pull request might (a new feature, a "harmless" clean-up) so you can watch the eval suite catch the change
in CI, or miss it.

Every control here is ordinary code that runs OUTSIDE the model, so it holds even when the model is fully fooled.
The one exception is G2, a pattern filter: it only knows the patterns it was given (lesson 17.1: a filter is one
layer, never the wall).

    G1  clean_text / clean_tool_result   strip invisible characters (Unicode tags, zero-width) from what the model reads
    G2  quarantine                       drop lines that match known injection patterns from tool results
    G3  authorize_tool                   reset_mfa only for the signed-in user; email only to the internal domain
    G4  filter_output                    no images, links only to our help centre, withhold any reply with the canary
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse

INTERNAL_DOMAIN = "anycompany.example"
ALLOWED_LINK_HOSTS = {"help.anycompany.example"}
CANARY_PREFIX = "CANARY-M17-"

# Patterns the lab's stand-in "injection classifier" knows. Real classifiers know more patterns, and miss more too.
INJECTION_PATTERNS = [
    r"LAB-INJECTED-DIRECTIVE",
    r"ignore (all |your )?(previous|prior|above) instructions",
]


# ---------------------------------------------------------------------------------------------------------------
# G1: invisible characters
# ---------------------------------------------------------------------------------------------------------------
def _is_invisible(ch: str) -> bool:
    cp = ord(ch)
    return 0xE0000 <= cp <= 0xE007F or unicodedata.category(ch) == "Cf"


def clean_text(text: str) -> tuple[str, int]:
    """Remove invisible format characters (Unicode tag block, zero-width spaces and joiners). Returns (text, removed)."""
    kept = [ch for ch in text if not _is_invisible(ch)]
    return "".join(kept), len(text) - len(kept)


def clean_tool_result(text: str) -> tuple[str, int]:
    """Tool results (ticket comments from outside senders) get the same cleaning as user input."""
    return clean_text(text)


# ---------------------------------------------------------------------------------------------------------------
# G2: quarantine known injection patterns in tool results
# ---------------------------------------------------------------------------------------------------------------
def quarantine(text: str) -> tuple[str, list[str]]:
    """Drop every line that matches a known injection pattern. Returns (text, dropped lines)."""
    kept, dropped = [], []
    for line in text.splitlines():
        if any(re.search(p, line, re.IGNORECASE) for p in INJECTION_PATTERNS):
            dropped.append(line.strip())
        else:
            kept.append(line)
    return "\n".join(kept), dropped


# ---------------------------------------------------------------------------------------------------------------
# G3: authorize every tool call in code, whatever the model says
# ---------------------------------------------------------------------------------------------------------------
def email_recipient_allowed(to: str, ticket: dict | None) -> bool:
    """Exactly one plain address, in our own domain."""
    to = to.strip().lower()
    if not re.fullmatch(r"[a-z0-9._+-]+@[a-z0-9.-]+", to):
        return False
    if ticket and to in {c["from"].lower() for c in ticket.get("comments", [])}:
        return True   # reply to whoever commented on the ticket (vendors, customers)
    return to.endswith("@" + INTERNAL_DOMAIN)


def authorize_tool(tool: str, args: dict, user: str, ticket: dict | None) -> tuple[bool, str]:
    """Returns (allowed, reason). `user` is the signed-in user; `ticket` is the ticket in context, if any."""
    if tool == "lookup_ticket":
        return True, "read-only"
    if tool == "reset_mfa":
        if args.get("user") != user:
            return False, f"reset_mfa is only for the signed-in user ({user}), not {args.get('user')}"
        return True, "own account"
    if tool == "send_email":
        if not email_recipient_allowed(str(args.get("to", "")), ticket):
            return False, f"recipient {args.get('to')} is not in {INTERNAL_DOMAIN}"
        return True, "internal recipient"
    return False, f"unknown tool {tool}"


# ---------------------------------------------------------------------------------------------------------------
# G4: filter what goes back to the screen
# ---------------------------------------------------------------------------------------------------------------
ALLOW_IMAGES = False

_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)[^)]*\)")
_LINK = re.compile(r"\[([^\]]*)\]\(([^)\s]+)[^)]*\)")
_BARE_URL = re.compile(r"https?://[^\s)\]>\"']+")


def link_allowed(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return urlparse(url).scheme == "https" and host in ALLOWED_LINK_HOSTS


def image_allowed(url: str) -> bool:
    return ALLOW_IMAGES and link_allowed(url)


def filter_output(text: str) -> tuple[str, list[str]]:
    """Returns (safe text, alerts)."""
    alerts: list[str] = []
    text, removed = clean_text(text)
    if removed:
        alerts.append(f"invisible_in_reply: {removed} invisible characters removed")
    if CANARY_PREFIX in text:
        return "[reply withheld: it contained internal instructions. The security team has been alerted.]", \
            alerts + ["canary_leak: system prompt canary found in the reply"]

    kept: list[str] = []          # images and links that passed, parked so the bare-URL pass leaves them alone

    def park(s: str) -> str:
        kept.append(s)
        return f"\x00{len(kept) - 1}\x00"

    def image(m: re.Match) -> str:
        if image_allowed(m.group(1)):
            return park(m.group(0))
        alerts.append(f"image_removed: {m.group(1)}")
        return "[image removed]"

    def link(m: re.Match) -> str:
        if link_allowed(m.group(2)):
            return park(m.group(0))
        alerts.append(f"link_removed: {m.group(2)}")
        return m.group(1) + " [link removed]"

    def bare(m: re.Match) -> str:
        if link_allowed(m.group(0)):
            return m.group(0)
        alerts.append(f"link_removed: {m.group(0)}")
        return "[link removed]"

    text = _IMAGE.sub(image, text)
    text = _LINK.sub(link, text)
    text = _BARE_URL.sub(bare, text)
    return re.sub("\x00(\\d+)\x00", lambda m: kept[int(m.group(1))], text), alerts
