"""Shared memory: the crew's ticket notes. Core file: do not edit.

Seed notes come from data/tickets.json (one per tenant). The crew also appends a short note after each turn to
state/memory.jsonl, so a later turn for the same tenant can see what happened before. That write goes through
guards.screen_memory_write first.

Each note: {id, tenant, kind ("ticket" | "turn-note"), origin ("customer" | "staff" | "agent"), text,
provenance (the ids of the untrusted sources that text came from)}.
"""
from __future__ import annotations

import json
import pathlib

DATA = pathlib.Path(__file__).resolve().parent.parent / "data"


def load_seed() -> list[dict]:
    return json.loads((DATA / "tickets.json").read_text(encoding="utf-8"))["notes"]


class MemoryStore:
    def __init__(self, state_dir: pathlib.Path):
        self.state_dir = state_dir
        self.path = state_dir / "memory.jsonl"
        self._seq = 0

    def notes_for(self, tenant: str) -> list[dict]:
        out = [n for n in load_seed() if n.get("tenant") in (tenant, "all")]
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    n = json.loads(line)
                    if n.get("tenant") in (tenant, "all"):
                        out.append(n)
        return out

    def append(self, note: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(note) + "\n")

    def next_id(self, tenant: str) -> str:
        self._seq += 1
        return f"note-{tenant}-{self._seq:03d}"
