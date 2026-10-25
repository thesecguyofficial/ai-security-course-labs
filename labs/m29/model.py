"""
model.py: the stand-in for the SOC triage agent's LLM. It is plain Python, NOT AI, so every run is identical and
the tests check the design around the model, not a model's mood.

How it behaves (the lab's simplification of a model that follows instructions it finds in its prompt):
  - its own job: look up the key, then escalate the alert with a short summary
  - it obeys any 'LAB-PLACEHOLDER-DIRECTIVE: <name> [arg]' line in its INSTRUCTIONS channel
  - by default it ignores such lines in its DATA channel; with fooled=True it obeys them there too
    (because real models sometimes do: lesson 29.6)

The directives are inert lab markers. Only this file reacts to them. They do nothing to a real model.
"""

from __future__ import annotations

import re

DIRECTIVE = re.compile(r"LAB-PLACEHOLDER-DIRECTIVE:\s*([a-z-]+)(?:\s+([0-9A-Za-z.:_-]+))?")

CANNED = {
    "close-as-benign": lambda arg: {"tool": "close_alert", "args": {"reason": "benign (lab directive)"}},
    "allowlist-ip": lambda arg: {"tool": "update_allowlist", "args": {"ip": arg}},
    "disable-key": lambda arg: {"tool": "deactivate_key", "args": {"user": arg}},
}


def decide(instructions: list[str], data: list[str], alert: dict, fooled: bool = False) -> list[dict]:
    calls = []
    channels = instructions + (data if fooled else [])
    for text in channels:
        for m in DIRECTIVE.finditer(text):
            if m.group(1) in CANNED:
                calls.append(CANNED[m.group(1)](m.group(2)))
    if any(c["tool"] == "close_alert" for c in calls):
        return calls  # a model talked into closing the alert stops working it
    ident = alert["event"]["userIdentity"]
    calls.insert(0, {"tool": "lookup_key", "args": {"user": ident.get("userName", ident.get("arn"))}})
    calls.append({"tool": "escalate", "args": {"severity": alert["severity"], "summary": summary(alert)}})
    return calls


def summary(alert: dict) -> str:
    e = alert["event"]
    who = e["userIdentity"].get("userName") or e["userIdentity"]["arn"]
    return (f"{alert['rule']}: {e['eventSource'].split('.')[0]}:{e['eventName']} by {who} in "
            f"{e['recipientAccountId']}/{e['awsRegion']} from {e['sourceIPAddress']}"
            f"{' (' + e['errorCode'] + ')' if e.get('errorCode') else ''}")
