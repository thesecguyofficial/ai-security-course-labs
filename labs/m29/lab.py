"""
lab.py: shared helpers for the M29 lab (paths, JSON files, the simulated clock, setups).

Everything here is local and fake: the "AWS Organization" is a folder of JSON files, every key string is a labelled
lab placeholder (TSGLAB...), every IP address is from the documentation ranges (RFC 5737), and nothing is sent
anywhere.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / "data"
SETUPS = HERE / "setups"
STATE = HERE / "state"

ORG = json.loads((DATA / "org.json").read_text())
ASSUMPTIONS = ORG["assumptions"]


def read_json(path: pathlib.Path):
    return json.loads(pathlib.Path(path).read_text())


def read_jsonl(path: pathlib.Path) -> list[dict]:
    rows = []
    for line in pathlib.Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rows.append(json.loads(line))
    return rows


def write_jsonl(path: pathlib.Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def ts(s: str) -> dt.datetime:
    """'2027-04-10T10:02:10Z' -> aware datetime."""
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mmss(seconds: float) -> str:
    seconds = int(round(seconds))
    return f"{seconds // 60}m{seconds % 60:02d}s"


def load_setup(name: str) -> dict:
    """A setup = setup.json (collection, responder, triage, hunt choices) + its rules/*.json (EventBridge patterns)."""
    folder = SETUPS / name
    if not folder.is_dir():
        raise SystemExit(f"unknown setup '{name}' (try: first-draft, hardened)")
    setup = read_json(folder / "setup.json")
    setup["name"] = name
    setup["rules"] = [read_json(p) | {"file": p.name} for p in sorted((folder / "rules").glob("*.json"))]
    return setup


def all_regions() -> list[str]:
    return list(ORG["regions"])


def all_accounts() -> list[str]:
    return list(ORG["accounts"])
