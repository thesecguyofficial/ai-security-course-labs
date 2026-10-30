"""
investigate.py: read the recorded, inert attack trace in data/trace/. Offline, standard library only.

    python3 investigate.py            # make investigate

  app-log.jsonl   the TSG Helpdesk AI app's turn log: user messages, retrieved content, the model's
                  tool calls and output, and sign-in (login) events. Nothing here runs; it is a recording.
  egress.jsonl    the estate's outbound connection log (host -> dest).

The attack was run once, in a sandbox, and frozen. These functions read the trail for you so you can see
where the malicious input entered and what it reached for, before you write the defence in defense.py.

Four questions are answered. One (find_quiet_beacon, challenge 1) is left for you to write.
All addresses use reserved .example names (RFC 2606); the injected text is a clearly marked LAB-INJECT
placeholder, not a working payload.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from collections import defaultdict
from datetime import datetime

HERE = pathlib.Path(__file__).resolve().parent
TRACE = HERE / "data" / "trace"
CONFIG = json.loads((HERE / "config.json").read_text(encoding="utf-8"))


def load(name: str, folder: pathlib.Path = TRACE) -> list[dict]:
    return [json.loads(line) for line in (folder / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def entry_point(app_log: list[dict]) -> dict:
    """Q1. Where did the malicious input enter the model's context?

    A hidden instruction in an HTML comment, carried in retrieved content (not in the user's own message).
    Returns the first content event whose text hides an instruction inside an HTML comment.
    """
    for e in app_log:
        if e.get("kind") in ("retrieval", "user_msg", "tool_result"):
            m = re.search(r"<!--(.*?)-->", e.get("text", ""), re.S)
            if m and re.search(r"(?i)(ignore|disregard|forget)\b|you are now|LAB-INJECT", m.group(1)):
                return {"id": e["id"], "source": e.get("source", e.get("actor")), "hidden": m.group(1).strip()}
    return {}


def reached_for(app_log: list[dict]) -> list[dict]:
    """Q2. What did the model try to do after reading the poisoned content? The 'way out'.

    Tool calls to an outside email recipient, and output or fetches that carry data to an outside host.
    """
    out = []
    email_ok = set(CONFIG["allowed_email_domains"])
    fetch_ok = set(CONFIG["allowed_fetch_hosts"])
    for e in app_log:
        if e.get("kind") == "tool_call" and e.get("tool") == "send_email":
            dom = e["args"].get("to", "").rsplit("@", 1)[-1].lower()
            if dom and dom not in email_ok:
                out.append({"id": e["id"], "how": f"send_email to {e['args']['to']} (outside)"})
        if e.get("kind") in ("model_output", "tool_call"):
            text = e.get("text", "") or json.dumps(e.get("args", {}))
            for url in re.findall(r"https?://[^\s\"'>)]+", text):
                host = re.sub(r"^https?://", "", url).split("/")[0].lower()
                if host not in fetch_ok and re.search(r"[?&](d|x|data|q)=", url):
                    out.append({"id": e["id"], "how": f"data in URL to {host}"})
    return out


def tempo(app_log: list[dict], window_s: int = 60) -> list[dict]:
    """Q3. Accounts making many near-identical attempts in a short window (an automated loop).

    Returns accounts with more than login_fail_per_min failed sign-ins inside any window_s-second window.
    """
    budget = CONFIG["rate"]["login_fail_per_min"]
    fails: dict[str, list[datetime]] = defaultdict(list)
    for e in app_log:
        if e.get("kind") == "login" and e.get("result") == "fail":
            fails[e["actor"]].append(_parse(e["ts"]))
    out = []
    for actor, times in fails.items():
        times.sort()
        for i, t0 in enumerate(times):
            n = sum(0 <= (t - t0).total_seconds() <= window_s for t in times[i:])
            if n > budget:
                span = (times[-1] - times[0]).total_seconds()
                out.append({"account": actor, "attempts": len(times), "window_s": int(span)})
                break
    return out


def find_egress_beacon(egress: list[dict]) -> list[dict]:
    """Q4. Loud egress beacon: many outbound calls to a model API from a host that is not a model caller."""
    callers = set(CONFIG["model_callers"])
    domains = tuple(CONFIG["model_api_domains"])
    hits: dict[str, int] = defaultdict(int)
    for g in egress:
        if g["host"] not in callers and g["dest"].endswith(domains):
            hits[g["host"]] += 1
    return sorted(({"host": h, "calls": n} for h, n in hits.items() if n >= 10), key=lambda r: -r["calls"])


def find_quiet_beacon(egress: list[dict]) -> list[dict]:
    """Challenge 1 (lesson 23.2): low-and-slow egress.

    The loud beacon above is 14 calls from one host. A second host made only a couple of calls to the same
    model API, hours apart, from a service account. Return every host (NOT a model caller) that made at
    least one call to a model-API domain but FEWER than 10 (so the loud one is excluded), as a list of
    {"host": <host>, "calls": <count>}, sorted by host. Only your own grouping can surface this; a
    threshold tuned to the loud beacon would miss it.
    """
    raise NotImplementedError("challenge 1: write find_quiet_beacon() in investigate.py")


def main():
    app_log, egress = load("app-log.jsonl"), load("egress.jsonl")
    ep = entry_point(app_log)
    print("Entry point:   app-log event {} ({}) - hidden instruction: {}".format(
        ep.get("id"), ep.get("source"), (ep.get("hidden", "")[:56] + "...")))
    print("Reached for:   " + "; ".join(f"{r['id']} {r['how']}" for r in reached_for(app_log)))
    for t in tempo(app_log):
        print(f"Tempo:         account {t['account']} made {t['attempts']} failed sign-ins in {t['window_s']}s (automated loop)")
    for b in find_egress_beacon(egress):
        print(f"Egress beacon: host {b['host']} made {b['calls']} outbound calls to a model API (not a model caller)")
    print("\nMalicious findings to catch (data/trace/ground_truth.json):")
    print("  injection e07, tool_abuse e09, exfiltration e10, rate rohan.v, egress ci-runner-07")
    try:
        qb = find_quiet_beacon(egress)
        print("Quiet beacon:  " + ", ".join(f"{r['host']} ({r['calls']})" for r in qb))
    except NotImplementedError as e:
        print(f"Quiet beacon:  not written yet: {e}")


if __name__ == "__main__":
    main()
