#!/usr/bin/env python3
r"""
explore.py: look at each idea of detection on its own, before you investigate the trace and write the defence
(M23 lab, "Understand the lab").

What it does, said plainly: it reads the lab's recorded logs (data/trace/), the adapted variants (data/variants.jsonl)
and the allow-lists (config.json), and prints them one idea at a time. It never runs the attack, never calls your
defence.py, writes no file (not even Python's __pycache__) and uses no network.

    logs                    1. the two logs in this lab: how many lines, and what kinds of event
    line [e14]              2. one log line exactly as it was written, then field by field
    timeline [s2]           3. one session's events in time order (s1 is the attack, s2 a normal one)
    rule signature          4. a signature rule: flag a known pattern
    rule anomaly            5. an anomaly rule: flag what is far above normal (here, a rate budget)
    rule allowlist          6. an allow-list rule: allow what is listed, flag the rest
    variant [injection]     7. a recorded attack next to its adapted variant: what changed, what stayed
    measure                 8. three rules for the same attack: caught on the recording, on the variant, false positives

    e.g. python3 explore.py timeline s1

Windows: `python explore.py ...`. Python 3.11+ standard library only. Fake data only: every address is a reserved
.example name (RFC 2606) and the injected text is a marked LAB-INJECT placeholder, not a working payload.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from collections import Counter, defaultdict

sys.dont_write_bytecode = True  # read-only: importing investigate must not write __pycache__/
import investigate  # noqa: E402  (paths, config and the loader; nothing runs on import)

CONFIG = investigate.CONFIG
TRACE = investigate.TRACE
ZW = "​‌‍⁠﻿"  # zero-width characters: invisible when the text is shown

KINDS = {
    "login": "someone signs in (result ok or fail)",
    "user_msg": "a person types a message",
    "retrieval": "the app looks up a document and gives it to the model",
    "tool_call": "the model asks the app to run a tool",
    "model_output": "the model's reply",
}
FIELDS = {
    "id": "this event's label, unique in the file",
    "ts": "when: date, T, time; Z means UTC",
    "session": "which conversation it belongs to (auth = sign-ins)",
    "actor": "who did it: a person's account, or agent (the app's model)",
    "kind": "what type of event",
    "source": "where the document came from",
    "text": "the words themselves",
    "tool": "which tool the model asked for",
    "args": "what the tool was asked to do: its arguments",
    "result": "how it ended: ok or fail",
    "host": "the computer that connected out",
    "dest": "where it connected to (a domain name)",
    "proto": "the protocol: https is encrypted web traffic",
    "bytes": "how much data went over the connection",
}
CHANGES = {  # one honest line per variant: what an attacker changed, and what the attack still needs
    "injection": ("the words (ignore previous -> disregard all earlier), a zero-width character, a look-alike address",
                  "an instruction hidden in an HTML comment, inside a document the model reads"),
    "tool_abuse": ("the recipient: collector@attacker.example -> collector@attacker.example.co",
                   "an email to an address outside the company"),
    "exfiltration": ("the host (exfil2) and the parameter name (d= -> x=)",
                     "data in a link to a host that is not ours"),
    "egress": ("the computer (ci-runner-08) and a subdomain (eu.api.model-vendor.example)",
               "a computer that is not a model caller, connecting to a model API"),
    "rate": ("the account (deepa.n) and a slower burst: 15 tries, 3 seconds apart",
             "more failed sign-ins in a minute than the budget allows"),
}
RECORDED = {"injection": "e07", "tool_abuse": "e09", "exfiltration": "e10", "egress": "g07", "rate": "L01"}


# ---------------------------------------------------------------------------------------------------- helpers
def _app() -> list[dict]:
    return investigate.load("app-log.jsonl")


def _egress() -> list[dict]:
    return investigate.load("egress.jsonl")


def _variants() -> list[dict]:
    return investigate.load("variants.jsonl", investigate.HERE / "data")


def _show(text: str) -> str:
    """Make invisible characters visible."""
    for ch in ZW:
        text = text.replace(ch, f"[U+{ord(ch):04X}]")
    return text


def _short(text: str, n: int) -> str:
    text = _show(text)
    return text if len(text) <= n else text[: n - 3] + "..."


def _what(e: dict) -> str:
    """One short line for an event, for timelines."""
    k = e.get("kind")
    if k == "tool_call":
        a = e.get("args", {})
        if e.get("tool") == "send_email":
            return f"send_email to {a.get('to')}"
        return f"{e.get('tool')} {json.dumps(a)}"
    if k == "retrieval":
        return f"{e.get('source')}  {e.get('text', '')}"
    if k == "login":
        return f"sign-in {e.get('result')}"
    return e.get("text", "")


def _content(app: list[dict]) -> list[dict]:
    return [e for e in app if e.get("kind") in ("user_msg", "retrieval", "model_output")]


def _hms(ts: str) -> str:
    return ts[11:19]


# ---------------------------------------------------------------------------------------------------- commands
def cmd_logs(a) -> int:
    app, eg = _app(), _egress()
    print("Two logs from the TSG Helpdesk, recorded once and frozen (data/trace/). Nothing here runs.\n")
    print(f"  data/trace/app-log.jsonl   {len(app)} lines   the Helpdesk app writes one line per event")
    for k, n in Counter(e["kind"] for e in app).most_common():
        print(f"      {k:<13} {n:>3}   {KINDS.get(k, '')}")
    print(f"  data/trace/egress.jsonl    {len(eg)} lines   the network writes one line per outbound connection")
    print(f"      {'connection':<13} {len(eg):>3}   a computer (host) connects out to another (dest)")
    times = sorted(e["ts"] for e in app + eg)
    print(f"\n  From {times[0][:10]} {times[0][11:16]} to {times[-1][11:16]} UTC. One line = one event = one JSON object.")
    print("  Logs are one kind of telemetry: data a system sends out about what it is doing.")
    return 0


def cmd_line(a) -> int:
    for name, rows in (("app-log.jsonl", _app()), ("egress.jsonl", _egress())):
        for n, e in enumerate(rows, 1):
            if e["id"] == a.id:
                print(f"data/trace/{name}, line {n}: one event, exactly as it was written (JSON: names and values)\n")
                print(textwrap.fill(_show(json.dumps(e, ensure_ascii=False)), 128, break_on_hyphens=False))
                print("\nField by field:")
                for k, v in e.items():
                    val = json.dumps(v) if isinstance(v, dict) else str(v)
                    print(f"  {k:<8} {_short(val, 58):<60} {FIELDS.get(k, '')}")
                if "<!--" in e.get("text", ""):
                    print("\nThe part inside <!-- ... --> is an HTML comment: a web page or email hides it from the reader,")
                    print("but the model receives the whole text.")
                if e.get("dest", "").endswith(tuple(CONFIG["model_api_domains"])):
                    who = "is" if e["host"] in CONFIG["model_callers"] else "is NOT"
                    print(f"\n{e['dest']} is a model API (config.json). {e['host']} {who} on the list of model callers.")
                return 0
    sys.exit(f"no event {a.id} in data/trace/. Try e14, e07 or g07.")


def cmd_timeline(a) -> int:
    rows = sorted((e for e in _app() if e.get("session") == a.session), key=lambda e: e["ts"])
    if not rows:
        sys.exit(f"no session {a.session}. Sessions: s1, s2, s3 (and auth for sign-ins)")
    print(f"Session {a.session}, in time order (data/trace/app-log.jsonl). Time is UTC.\n")
    print(f"  {'time':<9} {'id':<4} {'actor':<13} {'kind':<13} what")
    for e in rows:
        print(f"  {_hms(e['ts']):<9} {e['id']:<4} {e['actor']:<13} {e['kind']:<13} {_short(_what(e), 86)}")
    span = investigate._parse(rows[-1]["ts"]) - investigate._parse(rows[0]["ts"])
    m, s = divmod(int(span.total_seconds()), 60)
    print(f"\n{len(rows)} events in {m} min {s} s. Read down: what came in, what the model did next, what went out.")
    return 0


def rule_signature() -> None:
    lines = _content(_app())
    print('A signature rule: flag any line whose text contains a known pattern.\n')
    print('  pattern   "LAB-INJECT"   (the marker this lab\'s recorded attack carries)')
    print(f"  checked   {len(lines)} lines with text: messages, documents and replies\n")
    hits = [e for e in lines if "LAB-INJECT" in e.get("text", "")]
    for e in hits:
        print(f"  FLAG  {e['id']}  {e.get('source', e['actor'])}  {_short(e['text'], 92)}")
    print(f"\n{len(hits)} of {len(lines)} lines flagged. Fast and exact, but it only knows what someone wrote down:")
    print("change the words, and it misses.")


def rule_anomaly() -> None:
    budget = CONFIG["rate"]["login_fail_per_min"]
    fails: dict[str, list] = defaultdict(list)
    accounts = []
    for e in _app():
        if e.get("kind") == "login":
            accounts.append(e["actor"]) if e["actor"] not in accounts else None
            if e["result"] == "fail":
                fails[e["actor"]].append(investigate._parse(e["ts"]))
    print("An anomaly rule: flag what is far from normal. The simplest kind is a rate rule: normal is a budget.\n")
    print("  measure   failed sign-ins per account, in its busiest 60 seconds")
    print(f"  normal    at most {budget} a minute (config.json, rate.login_fail_per_min)\n")
    for acct in sorted(accounts):
        t = sorted(fails.get(acct, []))
        most = max((sum(0 <= (x - t0).total_seconds() <= 60 for x in t[i:]) for i, t0 in enumerate(t)), default=0)
        flag = f"FLAG: more than {budget} in 60 s" if most > budget else "normal"
        print(f"  {acct:<10} {most:>3} failed   {flag}")
    print("\nNo pattern needed: it notices the behaviour, even of an attack nobody has seen before.")
    print("It needs a sense of normal, and a busy honest user can trip it.")


def rule_allowlist() -> None:
    ok = CONFIG["allowed_email_domains"]
    print("An allow-list rule: list what is allowed; anything not on the list is flagged (default deny).\n")
    print(f"  allowed email domains (config.json)   {', '.join(ok)}\n")
    for e in _app():
        if e.get("tool") == "send_email":
            to = e["args"]["to"]
            dom = to.rsplit("@", 1)[-1]
            verdict = "on the list: allow" if dom in ok else "NOT on the list: FLAG"
            print(f"  {e['id']}  send_email to {to:<30} domain {dom:<18} {verdict}")
    print("\nNo list of bad addresses needed: anything new is outside the list. Someone has to keep the list up to date.")


def cmd_rule(a) -> int:
    {"signature": rule_signature, "anomaly": rule_anomaly, "allowlist": rule_allowlist}[a.kind]()
    return 0


def cmd_variant(a) -> int:
    rec_id = RECORDED[a.name]
    rec = next(e for e in _app() + _egress() if e["id"] == rec_id)
    var = next(e for e in _variants() if e["_variant_of"] == a.name)
    print(f"A recorded attack ({a.name}) next to its adapted variant (data/variants.jsonl):")
    print("the same intent, changed the way an attacker would.\n")

    def body(e):
        if a.name == "egress":
            return f"{e['host']} -> {e['dest']}"
        if a.name == "rate":
            n = sum(1 for x in (_app() if e["id"].startswith("L") else _variants())
                    if x.get("actor") == e["actor"] and x.get("result") == "fail")
            return f"{e['actor']}: {n} failed sign-ins"
        if a.name == "tool_abuse":
            return f"send_email to {e['args']['to']}"
        m = re.search(r"<!--.*?-->", e.get("text", ""), re.S)
        return m.group(0) if m else e.get("text", "")
    print(f"  recorded  {rec_id:<9} {_short(body(rec), 108)}")
    print(f"  variant   {var['id']:<9} {_short(body(var), 108)}")
    changed, stayed = CHANGES[a.name]
    print(f"\n  what changed   {changed}")
    print(f"  what stayed    {stayed}")
    print("\nA rule that matches what changed misses the variant. A rule on what stayed still catches it.")
    return 0


def cmd_measure(a) -> int:
    app = _app()
    gt = json.loads((TRACE / "ground_truth.json").read_text(encoding="utf-8"))
    ix = {e["id"]: e for e in app}
    rec = ix[gt["findings"]["injection"]["event"]]
    var = next(e for e in _variants() if e["_variant_of"] == "injection")
    normal = [ix[i] for i in gt["normal"]["content_events"]]
    rules = [
        ('A  exact words "ignore previous instructions"', lambda t: "ignore previous instructions" in t.lower()),
        ('B  any "ignore" or "disregard"', lambda t: re.search(r"(?i)\b(ignore|disregard)", t) is not None),
        ("C  text hidden in an HTML comment", lambda t: re.search(r"<!--.*?-->", t, re.S) is not None),
    ]
    print("Three rules for the same attack (prompt injection), each measured three ways:")
    print(f"the recorded attack ({rec['id']}), its adapted variant ({var['id']}), "
          f"and {len(normal)} normal lines (the answer key, data/trace/ground_truth.json)\n")
    print(f"  {'rule':<48} {'recorded':<10} {'variant':<10} false positives")
    for name, hit in rules:
        fps = [e for e in normal if hit(e["text"])]
        note = "   " + "; ".join(f'{e["id"]} "{_short(e["text"], 40)}"' for e in fps) if fps else ""
        print(f"  {name:<48} {'caught' if hit(rec['text']) else 'missed':<10} "
              f"{'caught' if hit(var['text']) else 'missed':<10} {len(fps)} of {len(normal)}{note}")
    print("\nCatch rate: of the attacks, how many were flagged. False positives: of the normal lines, how many were.")
    print("Measure both, on the recording AND on a changed attack. Here only C holds on both with no false positive.")
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="explore.py", description="Look at each idea of detection on its own. Read-only.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("logs", help="the two logs, and what kinds of event they hold")
    s = sub.add_parser("line", help="one log line, field by field")
    s.add_argument("id", nargs="?", default="e14")
    s = sub.add_parser("timeline", help="one session in time order")
    s.add_argument("session", nargs="?", default="s2")
    s = sub.add_parser("rule", help="a signature, anomaly or allow-list rule, run on the trace")
    s.add_argument("kind", choices=["signature", "anomaly", "allowlist"])
    s = sub.add_parser("variant", help="a recorded attack next to its adapted variant")
    s.add_argument("name", nargs="?", default="injection", choices=sorted(RECORDED))
    sub.add_parser("measure", help="three rules, measured on the recording, a variant and normal lines")
    a = p.parse_args(argv)
    return {"logs": cmd_logs, "line": cmd_line, "timeline": cmd_timeline, "rule": cmd_rule,
            "variant": cmd_variant, "measure": cmd_measure}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
