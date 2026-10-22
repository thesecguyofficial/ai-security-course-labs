"""
stand_in_model.py: the "model" in this lab. Plain Python, NOT AI, so every run is identical and the tests check your
controls, not a model's mood. It is the worst case on purpose: it obeys any [LAB-PLACEHOLDER TOOL REQUEST ...] line it
reads in a tool result, the way an injected model might. Real models resist some of these; never count on it.
"""

import re

import twin

STOP = {"the", "a", "is", "what", "how", "do", "i", "my", "for", "are", "me", "who", "your", "of", "to", "and", "it",
        "you", "in", "on", "please", "can", "an", "be", "this", "that", "with", "from"}


def _words(s: str) -> set:
    return set(re.findall(r"[a-z0-9]+", s.lower())) - STOP


def retrieve(ask: str) -> list[dict]:
    """KB articles whose TITLE shares two or more words with the question (a crude stand-in for search)."""
    hits = [d for d in twin.DOCS.values() if d["container"] == "kb" and len(_words(ask) & _words(d["title"])) >= 2]
    return sorted(hits, key=lambda d: d["id"])


def plan(ask: str, hits: list[dict], actions: list[dict]) -> list[dict]:
    """The tool calls the model makes this turn: what the user asked for, then whatever the documents said."""
    calls = [{"name": a["name"], "args": dict(a["args"]), "source": "user"} for a in actions]
    for h in hits:
        for m in twin.TOOL_MARK.finditer(h["text"]):
            args = dict(kv.split("=", 1) for kv in m.group(2).split())
            calls.append({"name": m.group(1), "args": args, "source": f"tool_result:{h['id']}"})
    return calls


def answer(hits: list[dict], recalled: list[str]) -> str:
    """Answers from the first article (marker text is never repeated) plus anything memory recalled."""
    parts = [f"{twin.MEMORY_MARK.sub('', twin.TOOL_MARK.sub('', h['text'])).strip()} [{h['id']}]" for h in hits[:1]]
    parts += [f"(I remember: {r})" for r in recalled]
    return " ".join(parts) or "I don't know."
