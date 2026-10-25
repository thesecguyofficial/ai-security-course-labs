"""
lab.py: shared bits for lab M21 (paths, the lab clock, canonical JSON, the fake data). Standard library only.

State (receipts, approvals, the refund ledger, the outbox) lives in ./state, or in the folder named by M21_STATE.
Nothing leaves this folder: no network, no real payments, no real email.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import pathlib
import time

LAB = pathlib.Path(__file__).resolve().parent
DATA = LAB / "data"
SETUPS = LAB / "setups"
SCHEMA = LAB / "schema" / "tsg.cedarschema"
CATALOGUE = LAB / "catalogue" / "tools.json"
PARTNER = LAB / "catalogue" / "partner-server.json"

REFUND_LIMIT_CENTS = 10000          # $100: above this a refund needs a supervisor's approval
APPROVAL_TTL_S = 15 * 60            # an approval is good for 15 minutes and one use


def state_dir() -> pathlib.Path:
    d = pathlib.Path(os.environ.get("M21_STATE", LAB / "state"))
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------------------------------- the lab clock
class Clock:
    """Real time, unless a test or the suite pins it (M21_NOW=<epoch seconds> or Clock.set)."""

    def __init__(self):
        self._fixed: float | None = None

    def now(self) -> float:
        if self._fixed is not None:
            return self._fixed
        if os.environ.get("M21_NOW"):
            return float(os.environ["M21_NOW"])
        return time.time()

    def set(self, t: float | None) -> None:
        self._fixed = t

    def advance(self, seconds: float) -> None:
        self._fixed = self.now() + seconds


CLOCK = Clock()


def iso(t: float) -> str:
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------------------------------- canonical JSON
def canonical(obj) -> str:
    """One spelling for one value: sorted keys, no spaces. Hash and sign THIS, never the text the model wrote."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------------------------------------------- fake data
def _load(name: str) -> dict:
    d = json.loads((DATA / name).read_text())
    d.pop("_comment", None)
    return d


STAFF = _load("staff.json")
ORDERS = _load("orders.json")


def read_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def append_jsonl(path: pathlib.Path, row: dict) -> None:
    with path.open("a") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
