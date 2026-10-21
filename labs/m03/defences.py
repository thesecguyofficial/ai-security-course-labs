"""
defences.py: the four layered fixes for SupportBot (lessons 3.4 to 3.8). Each one is switched on with --fixes.

    label    Fix 1  Clean and LABEL the untrusted email: strip invisible characters, wrap it in random markers,
                    tell the model it is data. Helps a real model; proves nothing on its own (see the README).
    plan     Fix 2  PLAN-THEN-EXECUTE: your code decides what happens BEFORE the model reads the email.
                    The summariser has no tool; tool calls it types are ignored and logged.
    confirm  Fix 3  HUMAN APPROVAL: any create_ticket waits for a person to approve the exact action.
    output   Fix 4  OUTPUT CHECK: strip invisible characters from the reply, no images, links only to
                    allow-listed hosts, and a canary tripwire for system-prompt leakage, before the reply
                    reaches the screen.

Only fixes 2, 3 and 4 are DETERMINISTIC (ordinary code, same result every time). Fix 1 changes the odds with a
real model; it doesn't guarantee anything. That's the lesson of Module 3 in one file.

What none of them does: make the app injection-proof. They stop THIS attack's three goals (an unrequested tool
call, a link to a host we don't own, a copied canary). A planted note can still make a real model write a
misleading summary that a person then acts on (a "text-to-text" attack), and no code here can check that.
"""

import re
import secrets
import unicodedata
import urllib.parse

# ---------------------------------------------------------------------------------------------------------------
# Fix 1 · label: clean and label untrusted content
# ---------------------------------------------------------------------------------------------------------------

# Characters people can't see but models can read (lesson 3.5). OWASP LLM01:2026 says to strip the tag block,
# variation selectors and zero-width characters "at every ingest and render boundary": fix 1 does the ingest side
# (the email), fix 4 the render side (the reply). We add the bidirectional controls, which can make text display
# in a different order from how it is stored. Stripping removes ONE hiding place: it does nothing against a
# visible note (OWASP: it "does not stop visible-text payloads or future steganographic classes").
INVISIBLE = re.compile(
    "["
    "\U000E0000-\U000E007F"   # Unicode tag block: invisible copies of ASCII letters ("ASCII smuggling")
    "︀-️"           # variation selectors
    "\U000E0100-\U000E01EF"   # variation selectors supplement
    "​-‏"           # zero-width space, joiners, direction marks
    "⁠-⁤"           # word joiner and invisible maths operators
    "﻿"                  # zero-width no-break space (byte-order mark)
    "‪-‮⁦-⁩"  # bidirectional embedding/override/isolate controls
    "]"
)

# Phrases that often appear in injected text. This is a TRIPWIRE for your logs, not a wall:
# attackers rephrase, translate or encode (lesson 3.3), so a match is a clue and a non-match proves nothing.
TRIPWIRE = re.compile(
    r"(?i)\b(ignore (all |any |your )?(previous|prior|above) instructions|ai assistant\s*:|"
    r"system prompt|new instructions|internal reference)\b"
)


def clean_untrusted(text: str) -> tuple[str, int]:
    """Remove invisible characters and normalise look-alike forms. Returns (clean text, how many were removed)."""
    removed = len(INVISIBLE.findall(text))
    text = INVISIBLE.sub("", text)
    # NFKC folds 'compatibility' look-alikes (e.g. full-width letters) into plain ones, so filters and humans
    # see the same letters the model sees.
    return unicodedata.normalize("NFKC", text), removed


def new_boundary() -> str:
    """A random marker per request, so an attacker can't type the closing marker in advance."""
    return secrets.token_hex(4)


def wrap_untrusted(text: str, boundary: str) -> str:
    """Put the email between labelled, random markers, after neutralising anything that looks like a marker.

    This is 'spotlighting' by delimiting (Microsoft's term). It helps the model tell data from instructions,
    but the model learned to respect markers in training; no code makes it obey them (lesson 2.1). OWASP
    LLM01:2026 says labelling "reduces attack success in non-adaptive tests only".
    """
    text = text.replace("<<", "« ").replace(">>", " »")   # the email can't fake an opening or closing marker
    return f"<<EMAIL {boundary}>>\n{text}\n<<END EMAIL {boundary}>>"


def tripwire_hits(text: str) -> list[str]:
    """Instruction-like phrases found in untrusted text (for logging and alerting only)."""
    return sorted({m.group(0).lower() for m in TRIPWIRE.finditer(text)})


# ---------------------------------------------------------------------------------------------------------------
# Fix 2 · plan: the ticket comes from your code, not from the model
# ---------------------------------------------------------------------------------------------------------------

def ticket_from_email(email: str) -> dict:
    """Build the ticket in CODE from the email's headers. The model's words never choose the action.

    The email's subject is still attacker-controlled DATA, so we cut it short and strip links. This is the
    known limit of plan-then-execute: injected text can't change WHICH action runs, but it can still colour the
    action's parameters (the design-patterns paper says so too). Fix 3 shows the person exactly what will run.
    """
    subject, sender = "(no subject)", "(unknown sender)"
    for line in email.splitlines():
        if line.lower().startswith("subject:"):
            subject = line.split(":", 1)[1].strip() or subject
        elif line.lower().startswith("from:"):
            sender = line.split(":", 1)[1].strip() or sender
    subject = re.sub(r"https?://\S+", "[link removed]", subject)[:80]
    return {"tool": "create_ticket", "title": f"Customer email: {subject}", "priority": "normal",
            "requested_by": "code (plan)", "customer": sender[:80]}


# ---------------------------------------------------------------------------------------------------------------
# Fix 3 · confirm: show a person the exact action, run it only after a yes
# ---------------------------------------------------------------------------------------------------------------

def render_action(action: dict) -> str:
    """The exact text a person approves. Show what will RUN, not the model's description of it."""
    return (f"create_ticket(title={action['title']!r}, priority={action['priority']!r})"
            f"  [requested by: {action.get('requested_by', 'model')}]")


# ---------------------------------------------------------------------------------------------------------------
# Fix 4 · output: check the reply before anyone sees it
# ---------------------------------------------------------------------------------------------------------------

# Hosts the bot may link to. Everything else is removed. Keep this list short and specific.
ALLOWED_HOSTS = {"help.example.com"}

MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
MD_LINK = re.compile(r"\[([^\]]*)\]\(([^)\s]+)[^)]*\)")
BARE_URL = re.compile(r"https?://[^\s)\]]+")


def is_allowed_url(url: str) -> bool:
    """Is this URL safe to show? Today: the host must be on ALLOWED_HOSTS and the scheme must be https.

    YOUR TURN (make challenge): an allowed host is not enough. help.example.com has a redirect page,
    /out?to=<any URL>, and an attacker can hide their own URL, with your data in it, inside that parameter.
    That's how a real exploit got data past an allow-list in 2025 (lesson 3.6). Tighten this function so
    that a URL is refused when its query string carries another URL (hint: urllib.parse.parse_qs, then look
    for "://" or the attacker's host in any value). Then run `make challenge` until it passes.
    """
    parts = urllib.parse.urlsplit(url)
    return parts.scheme == "https" and (parts.hostname or "") in ALLOWED_HOSTS


def check_output(reply: str, canary: str) -> tuple[str, list[dict]]:
    """Return (safe reply, alerts). Deterministic: no model involved, so it can't be talked out of it.

    It assumes the reply is shown as plain text or as Markdown with raw HTML switched off. If your UI renders
    HTML, sanitise that too and set a strict Content-Security-Policy (lesson 3.6, Module 5).
    """
    alerts = []

    # 0) The render boundary: a model can WRITE invisible characters too. They can hide data inside a link, or
    #    split the canary (CANARY-7f3a<zero-width space>9c1e) so the check in c) would miss it. Strip them first.
    reply, removed = clean_untrusted(reply)
    if removed:
        alerts.append({"type": "invisible_text_removed", "detail": f"{removed} invisible characters stripped from the reply"})

    # a) Images load automatically when shown, so an image URL can send data with zero clicks. No images at all.
    for img in MD_IMAGE.findall(reply):
        alerts.append({"type": "image_removed", "detail": img[:120]})
    reply = MD_IMAGE.sub("[image removed]", reply)

    # b) Links: keep only links to allow-listed hosts.
    def fix_link(m):
        label, url = m.group(1), m.group(2)
        if is_allowed_url(url):
            return m.group(0)
        alerts.append({"type": "link_removed", "detail": url[:120]})
        return f"{label} [link removed]"
    reply = MD_LINK.sub(fix_link, reply)

    def fix_bare(m):
        url = m.group(0)
        if is_allowed_url(url):
            return url
        alerts.append({"type": "link_removed", "detail": url[:120]})
        return "[link removed]"
    reply = BARE_URL.sub(fix_bare, reply)

    # c) Canary: a unique fake string that lives ONLY in the system prompt. If it shows up in a reply, the
    #    model has been talked into repeating its instructions. Fail closed: withhold the whole reply.
    if canary in reply:
        alerts.append({"type": "canary_leak", "detail": "system-prompt canary found in reply; reply withheld"})
        reply = "[reply withheld: it contained internal instructions. The security team has been alerted.]"

    return reply, alerts
