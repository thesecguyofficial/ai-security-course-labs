"""
detect.py: event-pattern rules over CloudTrail events, the way EventBridge evaluates them (a small subset).

    python3 detect.py <setup> <scenario>     # which rules fire for one scenario, and why the others don't
    python3 detect.py hardened --patterns    # print the setup's rules as EventBridge patterns

What is modelled, because it decides whether an alert ever fires:
  - matching: exact values (OR inside a list, AND across fields), {"prefix"}, {"exists"}, {"anything-but"}, {"cidr"}
  - rule state: a rule in state ENABLED does not see read-only management events; only
    ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS does (EventBridge user guide)
  - Regions: a rule sees only the Regions it is deployed in
  - collection: which accounts and Regions reach the security account at all, and which DATA events the trail
    records (bedrock-mantle inference is a data event and is not logged by default)
"""

from __future__ import annotations

import ipaddress
import json
import sys

import scenarios
from lab import all_accounts, all_regions, load_setup


def _leaf_match(cond, value, present: bool) -> bool:
    if isinstance(cond, dict):
        if "exists" in cond:
            return present is bool(cond["exists"])
        if not present:
            return False
        if "prefix" in cond:
            return isinstance(value, str) and value.startswith(cond["prefix"])
        if "anything-but" in cond:
            bad = cond["anything-but"]
            bad = bad if isinstance(bad, list) else [bad]
            return value not in bad
        if "cidr" in cond:
            try:
                return ipaddress.ip_address(value) in ipaddress.ip_network(cond["cidr"])
            except ValueError:
                return False
        raise ValueError(f"unsupported pattern operator {cond}")
    return present and value == cond


def match(pattern: dict, event: dict) -> bool:
    for key, cond in pattern.items():
        present = isinstance(event, dict) and key in event
        value = event.get(key) if present else None
        if isinstance(cond, dict):
            if not match(cond, value if isinstance(value, dict) else {}):
                return False
        elif isinstance(cond, list):
            if not any(_leaf_match(c, value, present) for c in cond):
                return False
        else:
            raise ValueError(f"pattern values must be lists or objects: {key}")
    return True


def collected(setup: dict, rec: dict) -> tuple[bool, str]:
    c = setup["collect"]
    accounts = all_accounts() if c["accounts"] == "all" else c["accounts"]
    regions = all_regions() if c["regions"] == "all" else c["regions"]
    if rec["recipientAccountId"] not in accounts:
        return False, f"account {rec['recipientAccountId']} is not sent to the security account"
    if rec["awsRegion"] not in regions:
        return False, f"Region {rec['awsRegion']} is not collected"
    if not rec["managementEvent"] and rec["eventSource"] not in c["data_events"]:
        return False, f"data events for {rec['eventSource']} are not recorded"
    return True, "collected"


def rule_sees(rule: dict, rec: dict) -> tuple[bool, str]:
    regions = all_regions() if rule["regions"] == "all" else rule["regions"]
    if rec["awsRegion"] not in regions:
        return False, f"rule not deployed in {rec['awsRegion']}"
    if rec["readOnly"] and rec["managementEvent"] and rule["state"] != "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS":
        return False, "read-only event, rule state ENABLED"
    if not match(rule["pattern"], scenarios.envelope(rec)):
        return False, "pattern does not match"
    return True, "MATCH"


def alerts(setup: dict, records: list[dict]) -> list[dict]:
    out = []
    for rec in records:
        ok, _ = collected(setup, rec)
        if not ok:
            continue
        for rule in setup["rules"]:
            hit, _ = rule_sees(rule, rec)
            if hit:
                out.append({"rule": rule["name"], "severity": rule["severity"], "event": rec})
    return out


def explain(setup: dict, records: list[dict]) -> None:
    for rec in records:
        who = rec["userIdentity"].get("userName") or rec["userIdentity"]["arn"].split("/")[-2]
        err = f" {rec['errorCode']}" if rec.get("errorCode") else ""
        print(f"{rec['eventTime']} {rec['awsRegion']:<14} {rec['eventSource'].split('.')[0]}:{rec['eventName']}"
              f" by {who} from {rec['sourceIPAddress']}{err}")
        ok, why = collected(setup, rec)
        if not ok:
            print(f"   not collected: {why}")
            continue
        for rule in setup["rules"]:
            hit, why = rule_sees(rule, rec)
            print(f"   {'ALERT' if hit else '-    '} {rule['name']:<26} {why}")


SCENARIOS = {
    "honeytoken-read-only": scenarios.honeytoken_read_only,
    "honeytoken-denied": scenarios.honeytoken_denied_invoke,
    "honeytoken-other-region": lambda: scenarios.honeytoken_denied_invoke("ap-southeast-2"),
    "decoy-api-key": scenarios.decoy_api_key_used,
    "app-key-elsewhere": scenarios.app_key_from_elsewhere,
    "logging-off": scenarios.logging_switched_off,
    "normal-app": scenarios.normal_app_call,
    "security-audit": scenarios.security_audit_calls,
}


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        raise SystemExit(__doc__)
    setup = load_setup(argv[0])
    if argv[1] == "--patterns":
        for rule in setup["rules"]:
            print(f"# {rule['name']}  state={rule['state']}  regions={rule['regions']}")
            print(json.dumps(rule["pattern"], indent=2))
        return
    if argv[1] not in SCENARIOS:
        raise SystemExit(f"unknown scenario; choose from: {', '.join(SCENARIOS)}")
    print(f"setup {setup['name']} | scenario {argv[1]}")
    explain(setup, SCENARIOS[argv[1]]())


if __name__ == "__main__":
    main(sys.argv[1:])
