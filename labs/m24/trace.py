"""
trace.py: read the recorded, inert multi-agent run in data/recording/. Offline, standard library only.

    python3 trace.py            # make trace

  transcript.jsonl   the crew's recorded run: ingest (an agent reads input), handoff (agent-to-agent message
                     over a channel: memory or task), tool_call (an agent uses a tool). Nothing here runs; it
                     is a recording. The attack run is session a1; n1 and n2 are normal.

The run is illustrative: written as data, with invented events, names and dates. These functions read the path for you so you can see where
the instruction entered, how it crossed the trust boundaries, and where it reached the agent that can act,
before you write the containment in containment.py.

Three questions are answered. One (find_unlabelled_crossings, challenge 1) is left for you to write. All
addresses use reserved .example names (RFC 2606); the injected text is a marked LAB-INJECT placeholder.
"""

from __future__ import annotations

import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
RECORDING = HERE / "data" / "recording"
CONFIG = json.loads((HERE / "config.json").read_text(encoding="utf-8"))

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
SELF_FORWARD = re.compile(r"(?i)\b(pass|forward|relay)\b[^.]*\b(this|these|instruction|instructions|steps?)\b"
                          r"[^.]*\b(along|onward|to the next|to each)\b")
OVERRIDE = re.compile(r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|earlier|above)\s+"
                      r"(instruction|instructions|direction|directions)|you are now\b")


def load(name: str, folder: pathlib.Path = RECORDING) -> list[dict]:
    return [json.loads(line) for line in (folder / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def allowed_send_domains() -> set[str]:
    out: set[str] = set()
    for doms in CONFIG.get("send_email_domains", {}).values():
        out.update(doms)
    return out


def instruction_bearing(text: str) -> bool:
    """A message carries an instruction if it names an external recipient, self-forwards, or overrides."""
    allow = allowed_send_domains()
    if any(dom.lower() not in allow for dom in EMAIL.findall(text or "")):
        return True
    return bool(SELF_FORWARD.search(text or "") or OVERRIDE.search(text or ""))


def events(session: str, txn: list[dict]) -> list[dict]:
    return [e for e in txn if e.get("session") == session]


def entry_point(txn: list[dict]) -> dict:
    """Q1. Where did the instruction enter? An ingest event hiding an instruction in an HTML comment."""
    for e in txn:
        if e.get("kind") == "ingest":
            m = re.search(r"<!--(.*?)-->", e.get("content", ""), re.S)
            if m and (instruction_bearing(m.group(1)) or "LAB-INJECT" in m.group(1)):
                return {"id": e["id"], "agent": e["agent"], "source": e.get("source"), "hidden": m.group(1).strip()}
    return {}


def propagation_path(txn: list[dict]) -> list[dict]:
    """Q2. The hand-offs that carried the instruction from the entry agent toward a sink."""
    return [{"id": e["id"], "from": e["from"], "to": e["to"], "channel": e["channel"], "message": e["message"]}
            for e in txn if e.get("kind") == "handoff" and instruction_bearing(e.get("message", ""))]


def sink_action(txn: list[dict]) -> dict:
    """Q3. The tool call that acts outside the system (a send to a non-allowed domain)."""
    allow = allowed_send_domains()
    for e in txn:
        if e.get("kind") == "tool_call" and e.get("tool") == "send_email":
            doms = EMAIL.findall(e["args"].get("to", ""))
            if doms and any(d.lower() not in allow for d in doms):
                return {"id": e["id"], "agent": e["agent"], "to": e["args"]["to"]}
    return {}


def find_unlabelled_crossings(txn: list[dict]) -> list[str]:
    """Challenge 1 (lesson 24.2): hand-offs that carried the instruction across a trust boundary with NO
    provenance label.

    A hand-off carries a provenance label if it has a truthy "provenance" field (none in this recording do).
    Return the list of hand-off IDs (in order) that are instruction-bearing AND unlabelled: those are the
    crossings a provenance label would have caught. A clean provenance scheme would have marked every one.
    """
    raise NotImplementedError("challenge 1: write find_unlabelled_crossings() in trace.py")


def main():
    txn = load("transcript.jsonl")
    attack = events("a1", txn)
    ep = entry_point(attack)
    print(f"Entry point:   {ep.get('id')} {ep.get('agent')} read {ep.get('source')}; "
          f"hidden instruction in an HTML comment (LAB-INJECT)")
    print("Propagation:")
    for h in propagation_path(attack):
        print(f"               {h['id']} {h['from']} -> {h['to']} ({h['channel']}): "
              f"\"{h['message'][:70]}...\"")
    sa = sink_action(attack)
    print(f"Sink action:   {sa.get('id')} {sa.get('agent')} send_email -> {sa.get('to')} (outside the company)")
    print(f"The same instruction crossed {len(propagation_path(attack))} trust boundaries and reached the agent that can act.")
    try:
        xs = find_unlabelled_crossings(attack)
        print("Unlabelled crossings: " + ", ".join(xs))
    except NotImplementedError as e:
        print(f"Unlabelled crossings: not written yet: {e}")


if __name__ == "__main__":
    main()
