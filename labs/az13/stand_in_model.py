"""
stand_in_model.py: the "model" in this lab. Plain Python, NOT AI, so every run is identical and the tests check your
controls, not a model's mood. It is the worst case on purpose: it obeys any [LAB-PLACEHOLDER TOOL REQUEST ...] line it
reads in a retrieved document, the way an injected model might. Real models resist some of these; never count on it.
"""

import twin


def plan(ask: str, who: str, hits: list[dict], actions: list[dict]) -> list[dict]:
    """The tool calls the model would make this turn: what the user asked for, then whatever the documents said."""
    calls = [{"name": a["name"], "args": dict(a["args"]), "source": "user"} for a in actions]
    for h in hits:
        m = twin.MARKER.search(h["chunk"])
        if m:
            args = dict(kv.split("=", 1) for kv in m.group(2).split())
            calls.append({"name": m.group(1), "args": args, "source": "retrieved", "from": h["chunk_id"]})
    return calls


def answer(hits: list[dict]) -> str:
    """Answers from the top two chunks, with a citation each (no marker text is ever repeated)."""
    parts = [f"{twin.MARKER.sub('', h['chunk']).strip()} [{h['parent_id']}]" for h in hits[:2]]
    return " ".join(p for p in parts if not p.startswith("[")) or "I don't know."
