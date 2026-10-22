"""
detect.py: read the agent's audit log and flag suspicious sequences (make detect).

    python3 detect.py                  # reads state/audit.jsonl
    python3 detect.py path/to/audit.jsonl

First it checks the hash chain (an edited, deleted or reordered line breaks it). Then, per run, it looks
for the shape of a hijack: untrusted content enters the context, and then the agent does something the
task didn't need. Exit code 1 if any HIGH alert or a broken chain, so it can gate a pipeline.

Rules (each maps to the frameworks used in lessons 7.3 and 7.8):
  EGRESS-AFTER-UNTRUSTED   high    an email to an address that is neither the requester nor internal was
                                   SENT after untrusted content entered the context
                                   (ATLAS AML.T0051.001 -> AML.T0086; OWASP ASI01:2026 / ASI02:2026)
  SENSITIVE-READ-AFTER-UNTRUSTED
                           medium  a sensitive file (customers/) was read after untrusted content arrived
                                   (ATLAS AML.T0053; ATLAS mitigation AML.M0038 scope drift)
  SHELL-AFTER-UNTRUSTED    medium  run_task ran after untrusted content arrived
  BLOCKED-ATTEMPT          medium  a control refused an action after untrusted content arrived: the attack
                                   failed, but someone tried. Find the source document.
  INSTRUCTION-IN-DATA      low     spotlighting flagged instruction-like text in untrusted content
  HALTED                   low     the budget or kill switch stopped a run
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import controls


def target(e: dict) -> str:
    a = e.get("args", {})
    return next((f"{k}={a[k]!r}" for k in ("to", "path", "command") if k in a), "")


def analyse(entries: list[dict]) -> list[tuple[str, str, str, str]]:
    runs: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        if e.get("run"):
            runs[e["run"]].append(e)
    alerts = []
    for run_id, evs in runs.items():
        start = next((e for e in evs if e.get("event") == "run_start"), {})
        requester = str(start.get("requester", "")).lower()
        last_untrusted = None
        for e in evs:
            if e.get("event") == "untrusted_flag":
                alerts.append(("low", run_id, "INSTRUCTION-IN-DATA",
                               f"#{e['seq']} {e['source']} contains {e['matched']}"))
            if e.get("event") == "run_end" and e.get("halted"):
                alerts.append(("low", run_id, "HALTED", f"#{e['seq']} stopped by {e['halted']}"))
            if e.get("event") != "tool_call":
                continue
            src = e.get("source") or ""
            allowed = e.get("decision") == "allow"
            if allowed and e["tool"] == "read_file" and controls.has_prefix(src, "untrusted_prefixes"):
                last_untrusted = (e["seq"], src)
            if not last_untrusted:
                continue
            after = f"after reading untrusted {last_untrusted[1]} (#{last_untrusted[0]})"
            if not allowed and e.get("control") not in ("budget", "kill_switch"):
                alerts.append(("medium", run_id, "BLOCKED-ATTEMPT",
                               f"#{e['seq']} {e['tool']} {target(e)} refused by {e['control']} {after}"))
                continue
            if not allowed:
                continue
            if e["tool"] == "read_file" and controls.has_prefix(src, "sensitive_prefixes"):
                alerts.append(("medium", run_id, "SENSITIVE-READ-AFTER-UNTRUSTED", f"#{e['seq']} read {src} {after}"))
            if e["tool"] == "run_task":
                alerts.append(("medium", run_id, "SHELL-AFTER-UNTRUSTED",
                               f"#{e['seq']} run_task {e['args'].get('command')!r} {after}"))
            if e["tool"] == "send_email":
                to = str(e["args"].get("to", "")).lower()
                if to != requester and not controls.is_internal(to):
                    alerts.append(("high", run_id, "EGRESS-AFTER-UNTRUSTED",
                                   f"#{e['seq']} email SENT to {to} (not the requester, not internal) {after}"))
    return alerts


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else controls.audit_path()
    ok, msg, entries = controls.verify_chain(path)
    print(f"audit chain: {msg}")
    if not ok:
        print("ALERT [high] TAMPERED: the audit log was changed after it was written. Treat it as evidence of "
              "tampering and use your off-host copy.")
    alerts = analyse(entries)
    order = {"high": 0, "medium": 1, "low": 2}
    for sev, run_id, rule, detail in sorted(alerts, key=lambda a: (a[1], order[a[0]])):
        print(f"ALERT [{sev}] {run_id} {rule}: {detail}")
    runs = {e.get("run") for e in entries if e.get("event") == "run_start"}
    print(f"{len(alerts)} alert(s) across {len(runs)} run(s).")
    return 1 if (not ok or any(a[0] == "high" for a in alerts)) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
