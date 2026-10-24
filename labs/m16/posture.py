"""
posture.py: AWS Config-style checks for Bedrock and AgentCore (lesson 16.4), run offline on a setup's resources.

    python3 posture.py first-draft
    python3 posture.py hardened

Two kinds of rule, and the difference is the lesson:
  AWS managed rules   the nine AWS Config managed rules for Bedrock and AgentCore (names exactly as AWS lists them),
                      with the Security Hub CSPM control that runs each one in the AI Security Best Practices standard
  custom rules        checks AWS has no managed rule for (as of Oct 2026): invocation logging, GuardDuty AI Protection,
                      an account-enforced guardrail, data events for mantle and AgentCore, a policy engine left in LOG_ONLY.
                      You write these yourself
                      (a Lambda or Guard custom rule, or a scheduled script)

Input: data/posture/<setup>.json (the Get/List responses, cut to the fields the rules read).
"""

from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent


def managed_rules():
    """(rule name, Security Hub control or '', resource type, check returning None if COMPLIANT else the reason)."""
    return [
        ("bedrockagentcore-runtime-private-network-required", "BedrockAgentCore.1", "AWS::BedrockAgentCore::Runtime",
         lambda r: "NetworkMode PUBLIC" if r["networkConfiguration"]["networkMode"] == "PUBLIC" else None),
        ("bedrockagentcore-gateway-authorizer-enabled", "BedrockAgentCore.2", "AWS::BedrockAgentCore::Gateway",
         lambda r: "AuthorizerType NONE" if r["authorizerType"] == "NONE" else None),
        ("bedrock-agentcore-memory-encryption-enabled", "BedrockAgentCore.3", "AWS::BedrockAgentCore::Memory",
         lambda r: "no EncryptionKeyArn" if not r.get("encryptionKeyArn") else None),
        ("bedrockagentcore-gateway-encryption-enabled", "BedrockAgentCore.4", "AWS::BedrockAgentCore::Gateway",
         lambda r: "no KmsKeyArn" if not r.get("kmsKeyArn") else None),
        ("bedrockagentcore-browsercustom-network-mode-not-public", "BedrockAgentCore.5", "AWS::BedrockAgentCore::BrowserCustom",
         lambda r: "NetworkMode PUBLIC" if r["networkConfiguration"]["networkMode"] == "PUBLIC" else None),
        ("bedrockagentcore-browsercustom-recording-enabled", "BedrockAgentCore.6", "AWS::BedrockAgentCore::BrowserCustom",
         lambda r: "recording disabled" if not (r.get("recording") or {}).get("enabled") else None),
        ("bedrockagentcore-codeinterpreter-networkmode-check", "BedrockAgentCore.7", "AWS::BedrockAgentCore::CodeInterpreterCustom",
         lambda r: f"NetworkMode {r['networkConfiguration']['networkMode']}"
         if r["networkConfiguration"]["networkMode"] in ("PUBLIC", "SANDBOX") else None),
        ("bedrock-agentcore-memory-event-expiry-duration", "", "AWS::BedrockAgentCore::Memory",
         lambda r: f"EventExpiryDuration {r['eventExpiryDuration']} days < 7 (the default minimum)"
         if r["eventExpiryDuration"] < 7 else None),
        ("bedrock-data-source-encryption-enabled", "Bedrock.1", "AWS::Bedrock::DataSource",
         lambda r: "no ServerSideEncryptionConfiguration.KmsKeyArn"
         if not (r.get("serverSideEncryptionConfiguration") or {}).get("kmsKeyArn") else None),
    ]


def custom_rules():
    """(id, what it checks, check over the whole setup file returning None or the reason)."""
    need_types = {"AWS::BedrockMantle::Project", "AWS::BedrockAgentCore::Runtime", "AWS::BedrockAgentCore::Gateway"}

    def logging(a):
        lc = a.get("loggingConfig")
        if not lc:
            return "model invocation logging is off (it is disabled by default)"
        if not lc.get("s3Config"):
            return "CloudWatch only: request and response bodies over 100 KB have nowhere to go"
        return None

    def gd(a):
        st = {f["name"]: f["status"] for f in a.get("guardduty_features", [])}
        return None if st.get("AI_PROTECTION") == "ENABLED" else f"AI_PROTECTION {st.get('AI_PROTECTION', 'missing')}"

    def enforced(a):
        cfgs = a.get("guardrailsConfig", [])
        if not cfgs:
            return "no account-enforced guardrail: GuardDuty's PromptInjection.Direct sees only apps that attach one"
        return None if any(c.get("lab.prompt_attack_filter") for c in cfgs) else "enforced guardrail has no prompt attack filter"

    def data_events(a):
        missing = sorted(need_types - set(a.get("trail_data_resource_types", [])))
        return f"no data event selector for {', '.join(missing)}" if missing else None

    def enforce_mode(data):
        bad = [r["resourceId"] for r in data["resources"] if r["resourceType"] == "AWS::BedrockAgentCore::Gateway"
               and (r.get("policyEngineConfiguration") or {}).get("mode") == "LOG_ONLY"]
        return f"policy engine in LOG_ONLY on {', '.join(bad)}" if bad else None

    acct = lambda f: (lambda data: f(data["account"]))  # noqa: E731
    return [("C01", "Bedrock model invocation logging on, text, with an S3 location for large data", acct(logging)),
            ("C02", "GuardDuty AI Protection enabled", acct(gd)),
            ("C03", "An account-enforced guardrail with a prompt attack filter", acct(enforced)),
            ("C04", "Trail data events for bedrock-mantle and AgentCore Runtime and Gateway", acct(data_events)),
            ("C05", "Every gateway with a policy engine runs it in ENFORCE", enforce_mode)]


def run(setup: str) -> list[dict]:
    data = json.loads((HERE / "data" / "posture" / f"{setup}.json").read_text())
    out = []
    for name, control, rtype, check in managed_rules():
        for r in data["resources"]:
            if r["resourceType"] == rtype:
                why = check(r)
                out.append({"kind": "managed", "rule": name, "control": control, "resource": r["resourceId"],
                            "compliant": why is None, "why": why or ""})
    for rid, what, check in custom_rules():
        why = check(data)
        out.append({"kind": "custom", "rule": rid, "control": "", "resource": what, "compliant": why is None,
                    "why": why or ""})
    return out


def main(argv):
    setup = argv[0] if argv else "first-draft"
    res = run(setup)
    print(f"Posture of the {setup} setup\n\nAWS managed rules (AWS Config; Security Hub CSPM control in brackets)")
    for r in res:
        if r["kind"] == "managed":
            ctl = f"[{r['control']}]" if r["control"] else "[Config only]"
            state = "COMPLIANT    " if r["compliant"] else "NON_COMPLIANT"
            print(f"  {state} {r['rule']:55} {ctl:21} {r['resource']}  {r['why']}")
    print("\nCustom rules (no AWS managed rule: you write these)")
    for r in res:
        if r["kind"] == "custom":
            state = "COMPLIANT    " if r["compliant"] else "NON_COMPLIANT"
            print(f"  {state} {r['rule']} {r['resource']}  {r['why']}")
    bad = sum(not r["compliant"] for r in res)
    print(f"\n{bad} NON_COMPLIANT of {len(res)} evaluations")


if __name__ == "__main__":
    main(sys.argv[1:])
