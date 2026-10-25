"""
aws/check.py: review an AgentCore Identity setup for three agents, offline (lesson 20.5).

    python3 aws/check.py first-draft        # make aws-check
    python3 aws/check.py hardened           # make aws-check-hardened

A setup (aws/setups/<name>.json) lists each agent's workload identity and IAM role, the tags on the identities,
each role's trust and permissions policy, how the launcher decides which human a run is for, and the CloudTrail
event selectors. The rules below are the ones lesson 20.5 teaches; each names its source.
"""

from __future__ import annotations

import collections
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REQUIRED_TAGS = ("owner", "purpose", "environment")


def load(name: str) -> dict:
    return json.loads((HERE / "setups" / f"{name}.json").read_text())


def _statements(doc: dict) -> list[dict]:
    st = doc.get("Statement", [])
    return st if isinstance(st, list) else [st]


def _actions(st: dict) -> list[str]:
    a = st.get("Action", [])
    return a if isinstance(a, list) else [a]


def check(setup: dict) -> list[tuple[str, str, str]]:
    findings = []

    def add(sev, rule, text):
        findings.append((sev, rule, text))

    # R1/R2: one identity and one role per agent
    by_wi, by_role = collections.defaultdict(list), collections.defaultdict(list)
    for agent, a in setup["agents"].items():
        by_wi[a["workload_identity"]].append(agent)
        by_role[a["role"]].append(agent)
    for wi, agents in by_wi.items():
        if len(agents) > 1:
            add("HIGH", "R1", f"workload identity {wi} is shared by {', '.join(agents)}: logs can't tell them apart")
    for role, agents in by_role.items():
        if len(agents) > 1:
            add("HIGH", "R2", f"IAM role {role} is shared by {', '.join(agents)}: each gets the other's permissions")

    # R3: accountable owner and purpose on every identity
    for wi, w in setup["workload_identities"].items():
        missing = [t for t in REQUIRED_TAGS if not w.get("tags", {}).get(t)]
        if missing:
            add("MEDIUM", "R3", f"workload identity {wi} has no {', '.join(missing)} tag: nobody to call, nothing to review")

    # R4: the human is taken from a validated token, never from the request
    if setup["launcher"]["user_from"] != "validated-jwt-sub":
        add("HIGH", "R4", f"launcher takes the user from {setup['launcher']['user_from']}: anyone can claim to be anyone")

    for role, r in setup["roles"].items():
        # R5: every role session must carry the human as SourceIdentity
        trust_ok = any("sts:SetSourceIdentity" in _actions(st) and
                       any("sts:SourceIdentity" in cond for cond in st.get("Condition", {}).values())
                       for st in _statements(r["trust"]) if st.get("Effect") == "Allow")
        if not trust_ok:
            add("HIGH", "R5", f"role {role} can be assumed without a SourceIdentity: CloudTrail won't name the human")
        # R6: short sessions
        if r.get("max_session_seconds", 3600) > 3600:
            add("MEDIUM", "R6", f"role {role} allows {r['max_session_seconds'] // 3600} h sessions")
        allows = [st for st in _statements(r["policy"]) if st.get("Effect") == "Allow"]
        denies = [st for st in _statements(r["policy"]) if st.get("Effect") == "Deny"]
        # R7: vault access scoped by ARN
        for st in allows:
            acts = _actions(st)
            if any(a.startswith("bedrock-agentcore:GetResource") or a.endswith("*") for a in acts) and st.get("Resource") == "*":
                add("HIGH", "R7", f"role {role}: {', '.join(acts)} on Resource \"*\" can use every credential provider")
        # R8: the unverified user-ID path is denied
        denied = {a for st in denies for a in _actions(st)}
        if "bedrock-agentcore:GetWorkloadAccessTokenForUserId" not in denied:
            add("HIGH", "R8", f"role {role} doesn't deny GetWorkloadAccessTokenForUserId (an unverified user ID)")

    if setup["launcher"].get("max_session_seconds", 3600) > 3600:
        add("MEDIUM", "R6", f"launcher asks for {setup['launcher']['max_session_seconds'] // 3600} h role sessions")

    # R9: CloudTrail records Identity data events
    types = {v for sel in setup["cloudtrail"]["advanced_event_selectors"] for f in sel["FieldSelectors"]
             if f["Field"] == "resources.type" for v in f["Equals"]}
    for needed in ("AWS::BedrockAgentCore::WorkloadIdentity", "AWS::BedrockAgentCore::TokenVault"):
        if needed not in types:
            add("MEDIUM", "R9", f"CloudTrail doesn't log {needed} data events (off by default)")
    return findings


SOURCES = {
    "R1": "AgentCore: create separate workload identities with separate IAM roles (scope-credential-provider-access)",
    "R2": "same page; OWASP NHI9:2025 NHI Reuse",
    "R3": "OWASP NHI1:2025 Improper Offboarding; Entra Agent ID sponsors; AgentCore: consistent tagging",
    "R4": "AgentCore: prefer GetWorkloadAccessTokenForJWT; derive the userId from the authenticated principal",
    "R5": "IAM: source identity is logged in CloudTrail and persists across role chaining",
    "R6": "OWASP NHI7:2025 Long-Lived Secrets",
    "R7": "AgentCore: the service does not enforce additional binding between workload identities and credential providers",
    "R8": "AgentCore: explicitly deny GetWorkloadAccessTokenForUserId where a JWT is always available",
    "R9": "CloudTrail: data events are not logged by default",
}


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    name = argv[0] if argv else "first-draft"
    setup = load(name)
    findings = check(setup)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for sev, rule, text in sorted(findings, key=lambda f: (order[f[0]], f[1])):
        print(f"{sev:<6} {rule}  {text}\n            why: {SOURCES[rule]}")
    count = collections.Counter(f[0] for f in findings)
    print(f"\n{count['HIGH']} HIGH, {count['MEDIUM']} MEDIUM, {count['LOW']} LOW  ({len(findings)} findings)")
    return 1 if count["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
