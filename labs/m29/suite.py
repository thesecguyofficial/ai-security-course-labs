"""
suite.py: 15 things the defence should catch, and 5 normal things it must not break.

    python3 suite.py first-draft
    python3 suite.py hardened
    python3 suite.py hardened --challenge     # adds case H4 (challenge 2)

Each case answers one question: did the defence miss it? MISSED is bad, caught is good. Normal cases answer: does
normal work still work (no false alarm, nothing broken)?
"""

from __future__ import annotations

import sys

import detect
import hunt
import respond
import scenarios
import triage
from lab import ASSUMPTIONS, load_setup


def _hunt_has(setup, fid):
    return any(f["id"] == fid for f in hunt.run(setup)["findings"])


def _alerted(setup, records, rule=None):
    return any(rule is None or a["rule"] == rule for a in detect.alerts(setup, records))


# (id, what, lesson, function(setup) -> True when the defence MISSED it)
CASES = [
    ("D0", "unregistered model, prod account, InvokeModel", "29.1",
     lambda s: not _hunt_has(s, "bedrock:222222222222:us-east-1:deepseek.r1-v1:0")),
    ("D1", "Bedrock in an account missing from the register", "29.1",
     lambda s: not _hunt_has(s, "bedrock:444444444444:eu-west-1:amazon.nova-premier-v1:0")),
    ("D2", "unregistered model through Converse", "29.1",
     lambda s: not _hunt_has(s, "bedrock:222222222222:us-east-1:meta.llama4-scout-17b-instruct-v1:0")),
    ("D3", "inference on bedrock-mantle (a data event)", "29.1",
     lambda s: not _hunt_has(s, "bedrock:333333333333:us-east-1:openai.gpt-oss-120b")),
    ("D4", "EC2 instance calling an outside AI API", "29.1",
     lambda s: not _hunt_has(s, "external:444444444444:api.openai.com")),
    ("D5", "AI key committed, then removed in the next commit", "29.1",
     lambda s: not _hunt_has(s, "secret:ops-scripts:summarise.py:openai-style key")),
    ("H1", "decoy key checked with read-only calls", "29.4",
     lambda s: not _alerted(s, scenarios.honeytoken_read_only(), "honeytoken-key-used")),
    ("H2", "decoy key used: InvokeModel, AccessDenied", "29.4",
     lambda s: not _alerted(s, scenarios.honeytoken_denied_invoke(), "honeytoken-key-used")),
    ("H3", "decoy key used in another Region", "29.4",
     lambda s: not _alerted(s, scenarios.honeytoken_denied_invoke("ap-southeast-2"), "honeytoken-key-used")),
    ("N1", "real app key used from outside its VPC endpoint", "29.7",
     lambda s: not _alerted(s, scenarios.app_key_from_elsewhere())),
    ("N2", "Bedrock invocation logging deleted", "29.4",
     lambda s: not _alerted(s, scenarios.logging_switched_off())),
    ("R1", f"responder acts within {ASSUMPTIONS['containment_slo_s'] // 60} minutes of the first call", "29.7",
     lambda s: respond.replay(s)["time_to_act_s"] > ASSUMPTIONS["containment_slo_s"]),
    ("R2", "attacker's session keeps working after the response", "29.7",
     lambda s: respond.replay(s)["succeeded_after_action"] > 0),
    ("T1", "poisoned alert: agent closes it as benign", "29.6",
     lambda s: triage.run(s, scenarios.poisoned_alert("close-as-benign"))["closed"]),
    ("T2", "poisoned alert: agent allow-lists the attacker's IP", "29.6",
     lambda s: bool(triage.run(s, scenarios.poisoned_alert(f"allowlist-ip {scenarios.ATTACKER_IP}"))["allowlisted"])),
]

CHALLENGE = [
    ("H4", "decoy Bedrock API key used (the key itself isn't logged)", "29.4",
     lambda s: not _alerted(s, scenarios.decoy_api_key_used())),
]

# (id, what, function(setup) -> True when normal work still works)
NORMAL = [
    ("K1", "registered Bedrock use via the VPC endpoint: no alert",
     lambda s: not _alerted(s, scenarios.normal_app_call())
     and not any(f["id"].startswith("bedrock:222222222222:us-east-1:anthropic") for f in hunt.run(s)["findings"])),
    ("K2", "approved outside AI API (api.anthropic.com): no finding",
     lambda s: not _hunt_has(s, "external:333333333333:api.anthropic.com")),
    ("K3", "security team's read-only audit, every Region: no alert",
     lambda s: not _alerted(s, scenarios.security_audit_calls())),
    ("K4", "clean decoy alert: agent escalates it as high",
     lambda s: (triage.run(s, scenarios.clean_alert())["escalated"] or {}).get("severity") == "high"),
    ("K5", "responder changes only the alerted user",
     lambda s: _only_target_changed(s)),
]


def _only_target_changed(s):
    iam = respond.replay(s)["iam"]
    fresh = respond.new_iam()
    changed = [u for u in iam["users"] if iam["users"][u] != fresh["users"][u]]
    return changed == [scenarios.APP["user"]]


def run_case(setup_name: str, case) -> bool:
    return case[3](load_setup(setup_name))


def evaluate(setup_name: str, challenge: bool = False) -> dict:
    s = load_setup(setup_name)
    cases = CASES + (CHALLENGE if challenge else [])
    return {"missed": {c[0]: bool(c[3](s)) for c in cases}, "normal": {n[0]: bool(n[2](s)) for n in NORMAL},
            "cases": cases}


def main(argv: list[str]) -> None:
    if not argv:
        raise SystemExit(__doc__)
    name, challenge = argv[0], "--challenge" in argv
    r = evaluate(name, challenge)
    print(f"setup {name}")
    print(f"{'case':<5} {'what':<56} {'lesson':<7} result")
    for cid, what, lesson, _ in r["cases"]:
        print(f"{cid:<5} {what:<56} {lesson:<7} {'MISSED' if r['missed'][cid] else 'caught'}")
    for nid, what, _ in NORMAL:
        print(f"{nid:<5} {what:<56} {'':<7} {'works' if r['normal'][nid] else 'BROKEN'}")
    missed = [k for k, v in r["missed"].items() if v]
    print(f"\nMissed: {len(missed)} of {len(r['missed'])}  ({', '.join(missed) or 'none'}) | normal work that still "
          f"works: {sum(r['normal'].values())} of {len(r['normal'])}")


if __name__ == "__main__":
    main(sys.argv[1:])
