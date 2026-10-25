"""The Helpdesk's local tools. Core file: do not edit.

Nothing here reaches a network:
  lookup_order(order_id)        reads data/orders.json
  send_email(to, subject, body) appends one line to <state>/outbox.jsonl. Nothing is sent.
"""
from __future__ import annotations

import json
import pathlib

DATA = pathlib.Path(__file__).resolve().parent.parent / "data"

LOCAL_TOOLS = {
    "lookup_order": "Look up one order by its number, for example 5001.",
    "send_email": "Send an email (to, subject, body).",
}


def load_users() -> dict:
    return json.loads((DATA / "users.json").read_text(encoding="utf-8"))


def load_orders() -> dict:
    return json.loads((DATA / "orders.json").read_text(encoding="utf-8"))["orders"]


def load_customers() -> dict:
    return json.loads((DATA / "customers.json").read_text(encoding="utf-8"))


def lookup_order(order_id: str) -> str:
    order = load_orders().get(str(order_id))
    if not order:
        return f"No order {order_id}."
    return json.dumps({"order": str(order_id), **order})


def send_email(state_dir: pathlib.Path, to: str, subject: str, body: str) -> str:
    state_dir.mkdir(parents=True, exist_ok=True)
    with open(state_dir / "outbox.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"to": to, "subject": subject, "body": body}) + "\n")
    return f"Email to {to} queued (lab: written to the outbox, nothing sent)."


def read_outbox(state_dir: pathlib.Path) -> list[dict]:
    p = state_dir / "outbox.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
