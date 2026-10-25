"""
replay.py: the harness. It replays the recorded, inert trace (and adapted variants of it) against YOUR
defence in defense.py and scores catch rate and false positives. It never runs the attack; it only reads
recorded events and calls your functions. Offline, standard library only.

    python3 replay.py            # make replay: score the recorded trace and the variants
    python3 replay.py --audit    # make audit:  print every defence decision with its reason

Pass = your defence catches all 5 malicious findings on the recorded trace AND on the variants, with 0
false positives on the 20 normal items. Exit code 0 = pass (works in CI), 1 = fail.
"""

from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime

import defense
import investigate

HERE = pathlib.Path(__file__).resolve().parent
TRACE = HERE / "data" / "trace"
CONFIG = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
GT = json.loads((TRACE / "ground_truth.json").read_text(encoding="utf-8"))


def by_id(events: list[dict]) -> dict[str, dict]:
    return {e["id"]: e for e in events}


def logins(events: list[dict]) -> list[dict]:
    return [e for e in events if e.get("kind") == "login"]


def score_recorded(app_log: list[dict], egress: list[dict]) -> dict:
    ix, f = by_id(app_log), GT["findings"]
    caught, missed = [], []

    def mark(name, ok):
        (caught if ok else missed).append(name)

    mark("injection", bool(defense.input_check(ix[f["injection"]["event"]], CONFIG)))
    mark("tool_abuse", defense.allowlist(ix[f["tool_abuse"]["event"]], CONFIG) is False)
    mark("exfiltration", bool(defense.output_check(ix[f["exfiltration"]["event"]], CONFIG)))
    flagged_accounts = set(defense.rate_anomaly(logins(app_log), CONFIG) or [])
    mark("rate", f["rate"]["account"] in flagged_accounts)
    bad_host = f["egress"]["host"]
    mark("egress", any(defense.egress_signature(g, CONFIG) for g in egress if g["host"] == bad_host))

    fp = false_positives(app_log, egress, flagged_accounts)
    return {"caught": caught, "missed": missed, "fp": fp}


def false_positives(app_log: list[dict], egress: list[dict], flagged_accounts: set[str]) -> list[str]:
    ix, n = by_id(app_log), GT["normal"]
    fp = []
    for eid in n["content_events"]:
        if defense.input_check(ix[eid], CONFIG):
            fp.append(f"input_check flagged normal {eid}")
    for eid in n["tool_calls"]:
        if defense.allowlist(ix[eid], CONFIG) is False:
            fp.append(f"allowlist denied normal {eid}")
    for eid in n["model_outputs"]:
        if defense.output_check(ix[eid], CONFIG):
            fp.append(f"output_check flagged normal {eid}")
    for host in n["egress_hosts"]:
        if any(defense.egress_signature(g, CONFIG) for g in egress if g["host"] == host):
            fp.append(f"egress_signature flagged normal host {host}")
    for acct in n["login_accounts"]:
        if acct in flagged_accounts:
            fp.append(f"rate_anomaly flagged normal account {acct}")
    return fp


def score_variants(variants: list[dict], base_app_log: list[dict], base_egress: list[dict]) -> dict:
    groups: dict[str, list[dict]] = {}
    for e in variants:
        groups.setdefault(e["_variant_of"], []).append(e)
    caught, missed = [], []

    def mark(name, ok):
        (caught if ok else missed).append(name)

    mark("injection", any(defense.input_check(e, CONFIG) for e in groups.get("injection", [])))
    mark("tool_abuse", any(defense.allowlist(e, CONFIG) is False for e in groups.get("tool_abuse", [])))
    mark("exfiltration", any(defense.output_check(e, CONFIG) for e in groups.get("exfiltration", [])))
    rate_evs = groups.get("rate", [])
    flagged = set(defense.rate_anomaly(rate_evs, CONFIG) or [])
    mark("rate", any(e["actor"] in flagged for e in rate_evs))
    mark("egress", any(defense.egress_signature(e, CONFIG) for e in groups.get("egress", [])))

    # False positives for the variant run are measured on the same normal baseline (the defence is the same).
    base_flagged = set(defense.rate_anomaly(logins(base_app_log), CONFIG) or [])
    fp = false_positives(base_app_log, base_egress, base_flagged)
    return {"caught": caught, "missed": missed, "fp": fp}


def normal_total() -> int:
    n = GT["normal"]
    return (len(n["content_events"]) + len(n["tool_calls"]) + len(n["model_outputs"])
            + len(n["egress_hosts"]) + len(n["login_accounts"]))


def audit(app_log: list[dict], egress: list[dict]):
    print("Defence decisions (every call, with the reason your code returned):\n")
    for e in app_log:
        if e.get("kind") in ("user_msg", "retrieval", "tool_result"):
            r = defense.input_check(e, CONFIG)
            if r:
                print(f"  input_check  FLAG {e['id']} ({e.get('source', e.get('actor'))}): {r}")
        if e.get("kind") == "tool_call":
            ok = defense.allowlist(e, CONFIG)
            print(f"  allowlist    {'ALLOW' if ok else 'DENY '} {e['id']} {e.get('tool')} {json.dumps(e.get('args', {}))}")
        if e.get("kind") == "model_output":
            r = defense.output_check(e, CONFIG)
            if r:
                print(f"  output_check FLAG {e['id']}: {r}")
    flagged = defense.rate_anomaly(logins(app_log), CONFIG) or []
    for acct in sorted(set(flagged)):
        print(f"  rate_anomaly FLAG account {acct}")
    for g in egress:
        r = defense.egress_signature(g, CONFIG)
        if r:
            print(f"  egress_sig   FLAG {g['id']} {g['host']} -> {g['dest']}: {r}")


def main(argv: list[str]) -> int:
    app_log = investigate.load("app-log.jsonl")
    egress = investigate.load("egress.jsonl")
    variants = investigate.load("variants.jsonl", HERE / "data")

    if "--audit" in argv:
        audit(app_log, egress)
        return 0

    total_mal = len(GT["findings"])
    total_norm = normal_total()
    rec = score_recorded(app_log, egress)
    var = score_variants(variants, app_log, egress)

    print(f"RECORDED TRACE   caught {len(rec['caught'])} of {total_mal} malicious   "
          f"false positives {len(rec['fp'])} of {total_norm} normal")
    print(f"ADAPTED VARIANTS caught {len(var['caught'])} of {total_mal} malicious   "
          f"false positives {len(var['fp'])} of {total_norm} normal")

    ok = (not rec["missed"] and not rec["fp"] and not var["missed"] and not var["fp"])
    if ok:
        print("PASS: defence holds on the recorded trace and the adapted variants.")
        return 0
    if rec["missed"] or var["missed"]:
        print("  missed (recorded): " + (", ".join(rec["missed"]) or "none"))
        print("  missed (variants): " + (", ".join(var["missed"]) or "none"))
    for line in rec["fp"] + var["fp"]:
        print("  false positive: " + line)
    print(f"FAIL: write defense.py (README Step 3). Caught {len(rec['caught'])} of {total_mal} on the recorded trace.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
