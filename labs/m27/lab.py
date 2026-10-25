"""lab.py: shared paths and helpers for lab M27 (sandbox and egress review).

Everything in this lab reads JSON files and prints. Nothing opens a network connection, resolves a name or moves
data: the "connections" are pre-recorded request descriptions in data/requests.jsonl, and the logs it writes are
illustrative records in the documented field names, saved under state/.
"""

from __future__ import annotations

import json
import os
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
CONFIGS = HERE / "configs"
DATA = HERE / "data"

# Values used in the illustrative log records (documentation-style placeholders, not a real account).
ACCOUNT = "111122223333"
REGION = "us-east-1"
VPC_ID = "vpc-0lab0000000000000"
SANDBOX_IP = "10.0.1.25"
PROXY_IP = "10.0.2.10"
ENI = "eni-0lab0000000000025"


def state_dir() -> pathlib.Path:
    """Where generated logs go. Tests point M27_STATE at a temporary folder."""
    d = pathlib.Path(os.environ.get("M27_STATE", HERE / "state"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_config(name_or_path: str) -> dict:
    """Load configs/<name>.json, or a path to any config file."""
    p = pathlib.Path(name_or_path)
    if not p.suffix:
        p = CONFIGS / f"{name_or_path}.json"
    return json.loads(p.read_text())


def read_jsonl(path: pathlib.Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_jsonl(path: pathlib.Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r, sort_keys=False) + "\n" for r in rows))


def requests() -> list[dict]:
    """The recorded connection requests from one session of the agent (data/requests.jsonl)."""
    return read_jsonl(DATA / "requests.jsonl")
