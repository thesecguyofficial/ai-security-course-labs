#!/usr/bin/env python3
"""Run detection rules over an app log and print alerts. A small rule engine, standard library only.

    python3 detections/detect.py                                    # your rules on the attack day (make detect)
    python3 detections/detect.py --log state/app-log.jsonl          # ... on your own Helpdesk's log
    python3 detections/detect.py --rules detections/rules.json --log X --out results/alerts.jsonl

Rules live in detections/rules.json: a list of objects. Every rule needs id, title, severity (low | medium | high),
atlas (a list of MITRE ATLAS IDs, may be empty) and a type:

  match      one event matches "where"
  sequence   an event matching "first", then a later event matching "then", in the same "same" group
             (request_id, session or user), at most "within_events" events apart in that group
  threshold  at least "count" events matching "where" for the same "by" value within "window_s" seconds
             (one alert per burst: the group is quiet again once a full window passes without reaching the count)
  change     the "field" of events matching "where" changes for the same "key" value (first value = baseline)

"where" is {field: condition}. A condition is either a plain value (equals), or an object with one of:
  {"in": [..]}  {"not_in": [..]}  {"contains": x} (x in a list or a string)  {"contains_any": [..]}
  {"gte": n}  {"lte": n}  {"regex": "..."}  {"ne_field": "other_field"}  {"eq_field": "other_field"}
  {"exists": true|false}
Several fields in one "where" must all match (AND). For OR, write two rules.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
from collections import defaultdict, deque

HERE = pathlib.Path(__file__).resolve().parent
TYPES = {"match", "sequence", "threshold", "change"}
SEVERITIES = {"low", "medium", "high"}


def ts(e: dict) -> float:
    return dt.datetime.strptime(e["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc).timestamp()


def cond_ok(event: dict, field: str, cond) -> bool:
    val = event.get(field)
    if not isinstance(cond, dict):
        return val == cond
    (op, arg), = cond.items()
    if op == "exists":
        return (field in event) == bool(arg)
    if op == "in":
        return val in arg
    if op == "not_in":
        return val not in arg
    if op == "contains":
        return val is not None and arg in val
    if op == "contains_any":
        return val is not None and any(a in val for a in arg)
    if op == "gte":
        return isinstance(val, (int, float)) and val >= arg
    if op == "lte":
        return isinstance(val, (int, float)) and val <= arg
    if op == "regex":
        return isinstance(val, str) and re.search(arg, val) is not None
    if op == "ne_field":
        return val != event.get(arg)
    if op == "eq_field":
        return val == event.get(arg)
    raise ValueError(f"unknown condition {op!r} on {field!r}")


def matches(event: dict, where: dict) -> bool:
    return all(cond_ok(event, f, c) for f, c in (where or {}).items())


def validate(rules: list[dict]) -> list[str]:
    problems, ids = [], set()
    for i, r in enumerate(rules):
        where = f"rule #{i + 1} ({r.get('id', '?')})"
        for key in ("id", "title", "severity", "type", "atlas"):
            if key not in r:
                problems.append(f"{where}: missing {key!r}")
        if r.get("id") in ids:
            problems.append(f"{where}: duplicate id")
        ids.add(r.get("id"))
        if r.get("type") not in TYPES:
            problems.append(f"{where}: type must be one of {sorted(TYPES)}")
        if r.get("severity") not in SEVERITIES:
            problems.append(f"{where}: severity must be low, medium or high")
        if not isinstance(r.get("atlas", []), list):
            problems.append(f"{where}: atlas must be a list")
        need = {"match": ["where"], "sequence": ["first", "then", "same"], "threshold": ["where", "by", "count", "window_s"],
                "change": ["where", "key", "field"]}.get(r.get("type"), [])
        for key in need:
            if key not in r:
                problems.append(f"{where}: a {r.get('type')} rule needs {key!r}")
    return problems


def run(rules: list[dict], events: list[dict]) -> list[dict]:
    events = sorted(events, key=lambda e: e["ts"])
    alerts = []

    def alert(rule, event, detail=""):
        alerts.append({"rule": rule["id"], "title": rule["title"], "severity": rule["severity"],
                       "atlas": rule.get("atlas", []), "ts": event["ts"], "request_id": event["request_id"],
                       "user": event.get("user"), "event": event["event"], "detail": detail})

    for rule in rules:
        kind = rule["type"]
        if kind == "match":
            for e in events:
                if matches(e, rule["where"]):
                    alert(rule, e)
        elif kind == "sequence":
            group_key, window = rule["same"], int(rule.get("within_events", 20))
            groups = defaultdict(list)
            for e in events:
                groups[e.get(group_key)].append(e)
            for evs in groups.values():
                for j, e in enumerate(evs):
                    if not matches(e, rule["then"]):
                        continue
                    earlier = evs[max(0, j - window):j]
                    hit = next((x for x in reversed(earlier) if matches(x, rule["first"])), None)
                    if hit is not None:
                        alert(rule, e, f"after {hit['event']} at {hit['ts']} ({hit['request_id']})")
        elif kind == "threshold":
            by, count, win = rule["by"], int(rule["count"]), float(rule["window_s"])
            recent, fired_until = defaultdict(deque), {}
            for e in events:
                if not matches(e, rule["where"]):
                    continue
                k, t = e.get(by), ts(e)
                q = recent[k]
                q.append(t)
                while q and t - q[0] > win:
                    q.popleft()
                if len(q) >= count and t >= fired_until.get(k, 0):
                    alert(rule, e, f"{len(q)} events for {by}={k} within {int(win)} s")
                    fired_until[k] = t + win
        elif kind == "change":
            seen = {}
            for e in events:
                if not matches(e, rule["where"]):
                    continue
                k, v = e.get(rule["key"]), json.dumps(e.get(rule["field"]), sort_keys=True)
                if k in seen and seen[k] != v:
                    alert(rule, e, f"{rule['field']} changed for {rule['key']}={k}")
                seen[k] = v
    alerts.sort(key=lambda a: (a["ts"], a["rule"]))
    return alerts


def load_jsonl(path: pathlib.Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", default=str(HERE / "rules.json"))
    ap.add_argument("--log", default=str(HERE / "logs" / "attack-day.jsonl"))
    ap.add_argument("--out", help="write alerts as JSON lines")
    ap.add_argument("-q", "--quiet", action="store_true", help="only the summary")
    a = ap.parse_args(argv)
    rules = json.loads(pathlib.Path(a.rules).read_text(encoding="utf-8"))["rules"]
    problems = validate(rules)
    if problems:
        print("rules.json has problems:\n  " + "\n  ".join(problems))
        return 2
    events = load_jsonl(pathlib.Path(a.log))
    alerts = run(rules, events)
    if not a.quiet:
        for x in alerts:
            print(f"ALERT [{x['severity']:<6}] {x['ts']} {x['rule']} {x['title']}: {x['user']} {x['request_id']} "
                  f"{x['event']} {x['detail']}".rstrip())
    per_rule = defaultdict(int)
    for x in alerts:
        per_rule[x["rule"]] += 1
    print(f"\n{len(alerts)} alerts from {len(rules)} rules over {len(events)} events: "
          + ", ".join(f"{k} {v}" for k, v in sorted(per_rule.items())))
    if a.out:
        pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.out).write_text("".join(json.dumps(x) + "\n" for x in alerts), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
