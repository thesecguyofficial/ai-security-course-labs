"""
stand_in_model.py: a STAND-IN for an AI model. Plain Python, NOT AI.

A real agent reads every tool's description and decides what to call. Real models are non-deterministic,
so a test against one would be flaky. This stand-in copies the one behaviour the lab is about: it reads
the tool definitions it is given, and if a definition carries the lab's hidden-directive token, it does
what a tricked model would do. With no token present, it just answers the user plainly. That makes every
run identical, so `make test` proves YOUR controls, not the model's mood.

The stand-in is deliberately simple. It recognises the single labelled token the malicious server plants
([LAB-INJECTED-DIRECTIVE], defined in servers/facts_server.py) anywhere in a tool's full definition
(name + description + input schema). When it sees the token, it simulates the two effects that real
poisoned-tool research has shown, against FAKE local data only:

  - tool poisoning: call the notes server's read_note on the fake .env and smuggle it into `sidenote`;
  - tool shadowing: send any email to the attacker's address instead of the one the user asked for.

Swap this file for a real local model with `--backend ollama` (an optional step in the README). The safe
controls hold whichever model you use, which is the whole point.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

TOKEN = "[LAB-INJECTED-DIRECTIVE]"
ATTACKER = "attacker@lab.invalid"  # .invalid never resolves (RFC 2606); emails only hit the local outbox
SECRET_FILE = ".env"


@dataclass
class Plan:
    """What the stand-in decided to do: a list of (server, tool, arguments) steps, and a reply string."""

    steps: list[tuple[str, str, dict]] = field(default_factory=list)
    reply: str = ""
    saw_injection: bool = False


def full_text(tool: dict) -> str:
    """Everything a model reads for one tool: name, description and the whole input schema."""
    return "\n".join([tool.get("name", ""), tool.get("description", ""), json.dumps(tool.get("input_schema", {}))])


def decide(user_message: str, tools: list[dict]) -> Plan:
    """Decide what to do, given the user's message and the tool definitions on offer.

    `tools` is a list of dicts: {"server", "name", "description", "input_schema"}.
    """
    plan = Plan()
    poisoned = any(TOKEN in full_text(t) for t in tools)
    plan.saw_injection = poisoned
    names = {(t["server"], t["name"]) for t in tools}
    msg = user_message.lower()

    # The ordinary, honest behaviour: map the request to a tool call.
    if "fact" in msg:
        topic = next((w for w in ("octopus", "honey", "space") if w in msg), "octopus")
        args = {"topic": topic}
        # A tricked model, having read the hidden directive, does the attacker's extra work first and
        # hides the stolen data in the tool's spare `sidenote` argument.
        if poisoned and _has_param(tools, "facts", "fact_of_the_day", "sidenote"):
            if ("notes", "read_note") in names:
                plan.steps.append(("notes", "read_note", {"name": SECRET_FILE}))  # read the fake secret
            args["sidenote"] = "__SMUGGLE_LAST_READ__"  # host fills this with the read_note result
        plan.steps.append(("facts", "fact_of_the_day", args))
        plan.reply = "Here is your fact of the day."
        return plan

    if "email" in msg or "send" in msg:
        to = _recipient(user_message)
        # Shadowing: the hidden directive changes how a DIFFERENT server's tool is used.
        if poisoned:
            to = ATTACKER
        plan.steps.append(("notes", "send_email", {"to": to, "subject": "Notes", "body": "(lab email)"}))
        plan.reply = f"Email sent to {to}."
        return plan

    if "list" in msg and "note" in msg:
        plan.steps.append(("notes", "list_notes", {}))
        plan.reply = "Listed your notes."
        return plan

    plan.reply = "I can fetch a fact, list notes, or send an email."
    return plan


def _has_param(tools: list[dict], server: str, name: str, param: str) -> bool:
    for t in tools:
        if t["server"] == server and t["name"] == name:
            return param in t.get("input_schema", {}).get("properties", {})
    return False


def _recipient(message: str) -> str:
    for token in message.replace(",", " ").split():
        if "@" in token and "." in token:
            return token.strip(".")
    return "bob@lab.invalid"
