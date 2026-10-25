"""
posture.py: Azure Policy-style checks for Contoso's AI resources (lesson 16.4), run offline on a setup's resources.

    python3 posture.py first-draft
    python3 posture.py hardened

Two kinds of check, and the difference is the lesson:
  built-in policies   five built-in Azure Policy definitions for Azure AI services, display names exactly as
                      Microsoft lists them. The `if` conditions below copy each definition's policyRule from the
                      Azure/azure-policy repository (versions in brackets), so a resource is NON_COMPLIANT here
                      exactly when the built-in would flag it
  custom checks       settings no built-in policy checks (as of Oct 2026): which log categories reach the workspace,
                      the Defender for AI services plan and its prompt evidence, the gateway's LLM logging, agent
                      tracing, and approval on write tools. You write these yourself (a custom policy, an Azure
                      Resource Graph query on a schedule, or a script like this one)

Input: data/posture/<setup>.json (ARM GET responses, cut to the fields the checks read).
"""

from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
AIS = "Microsoft.CognitiveServices/accounts"
SEARCH = "Microsoft.Search/searchServices"
NEEDED_CATEGORIES = {"Audit", "RequestResponse", "Trace"}


def approved_pe(r) -> int:
    return sum(1 for c in r["properties"].get("privateEndpointConnections", [])
               if c["privateLinkServiceConnectionState"]["status"] == "Approved")


def builtin_policies():
    """(display name, version, resource types it applies to, check returning None if compliant else the reason)."""
    def keys(r):
        return None if r["properties"].get("disableLocalAuth") is True else "disableLocalAuth is not true"

    def network(r):
        p = r["properties"]
        if p.get("publicNetworkAccess") == "Disabled":
            return None
        if r["type"] == AIS:
            return None if (p.get("networkAcls") or {}).get("defaultAction") == "Deny" else \
                "publicNetworkAccess Enabled and networkAcls.defaultAction Allow"
        return None if (p.get("networkRuleSet") or {}).get("ipRules") else "publicNetworkAccess Enabled and no IP rules"

    def private_link(r):
        return None if approved_pe(r) >= 1 else "no approved private endpoint connection"

    def cmk(r):
        ks = r["properties"].get("encryption", {}).get("keySource")
        return None if ks == "Microsoft.KeyVault" else f"encryption.keySource {ks}"

    def diag_exists(r):
        # AuditIfNotExists: compliant when a diagnostic setting with any logs exists. It doesn't look at which ones.
        return None if any(ds.get("logs") for ds in r.get("diagnosticSettings", [])) else "no diagnostic setting with logs"

    return [
        ("Azure AI Services resources should have key access disabled (disable local authentication)", "1.1.0",
         {AIS, SEARCH}, keys),
        ("Azure AI Services resources should restrict network access", "3.3.0", {AIS, SEARCH}, network),
        ("Azure AI Services resources should use Azure Private Link", "1.0.0", {AIS, SEARCH}, private_link),
        ("Azure AI Services resources should encrypt data at rest with a customer-managed key (CMK)", "2.2.0",
         {AIS}, cmk),
        ("Diagnostic logs in Azure AI services resources should be enabled", "1.0.0", {AIS, SEARCH}, diag_exists),
    ]


def custom_checks():
    """(id, what it checks, check over the whole setup file returning None or the reason)."""
    def categories(data):
        bad = []
        for r in data["resources"]:
            if r["type"] != AIS:
                continue
            sent = {lg["category"] for ds in r.get("diagnosticSettings", []) if ds.get("workspaceId")
                    for lg in ds.get("logs", []) if lg.get("enabled") and "category" in lg}
            missing = sorted(NEEDED_CATEGORIES - sent)
            if missing:
                bad.append(f"{r['name']} sends no {', '.join(missing)}")
        return "; ".join(bad) or None

    def defender_ai(data):
        ai = next((p for p in data["subscription"]["defender_pricings"] if p["name"] == "AI"), None)
        if not ai or ai["pricingTier"] != "Standard":
            return "Defender for Cloud plan AI (AI services) is not Standard: no AI threat alerts at all"
        ext = {e["name"]: str(e.get("isEnabled")) for e in ai.get("extensions", [])}
        return None if ext.get("AIPromptEvidence") == "True" else "AI plan on, but AIPromptEvidence is off"

    def gateway_logging(data):
        bad = [f"{a['service']}/{a['api']}" for a in data["subscription"]["apim_llm_apis"]
               if not a["gateway_llm_diagnostic"] or a["log_llm_messages"] != "Enabled"]
        return f"no LLM logging on {', '.join(bad)}" if bad else None

    def tracing(data):
        bad = [p["project"] for p in data["subscription"]["foundry_projects"] if p["has_agents"]
               and not p.get("tracing_app_insights")]
        return f"agents without tracing in {', '.join(bad)}" if bad else None

    def approval(data):
        bad = []
        for tb in data["subscription"]["toolboxes"]:
            for s in tb["servers"]:
                if s["has_write_tools"] and (s["require_approval"] != "always" or not s.get("allowed_tools")):
                    bad.append(f"{tb['toolbox']} v{tb['default_version']} server {s['server_label']}: "
                               f"require_approval {s['require_approval']}, allowed_tools {s.get('allowed_tools')}")
        return "; ".join(bad) or None

    return [("C01", "Foundry diagnostic setting sends Audit, RequestResponse and Trace to a workspace", categories),
            ("C02", "Defender for AI services on, with user prompt evidence", defender_ai),
            ("C03", "API Management LLM logging on for every LLM API", gateway_logging),
            ("C04", "Tracing to Application Insights for every project with agents", tracing),
            ("C05", "Write tools in the toolbox's default version need approval and an allow-list", approval)]


def run(setup: str) -> list[dict]:
    data = json.loads((HERE / "data" / "posture" / f"{setup}.json").read_text())
    out = []
    for name, version, types, check in builtin_policies():
        for r in data["resources"]:
            if r["type"] in types:
                why = check(r)
                out.append({"kind": "builtin", "rule": name, "version": version, "resource": r["name"],
                            "compliant": why is None, "why": why or ""})
    for cid, what, check in custom_checks():
        why = check(data)
        out.append({"kind": "custom", "rule": cid, "version": "", "resource": what, "compliant": why is None,
                    "why": why or ""})
    return out


def main(argv):
    setup = argv[0] if argv else "first-draft"
    res = run(setup)
    print(f"Posture of the {setup} setup\n\nBuilt-in Azure Policy definitions (version in brackets)")
    for r in res:
        if r["kind"] == "builtin":
            state = "Compliant    " if r["compliant"] else "NON_COMPLIANT"
            print(f"  {state} {r['resource']:18} {r['rule']} [{r['version']}]  {r['why']}")
    print("\nCustom checks (no built-in policy: you write these)")
    for r in res:
        if r["kind"] == "custom":
            state = "Compliant    " if r["compliant"] else "NON_COMPLIANT"
            print(f"  {state} {r['rule']} {r['resource']}  {r['why']}")
    bad = sum(not r["compliant"] for r in res)
    print(f"\n{bad} NON_COMPLIANT of {len(res)} evaluations")


if __name__ == "__main__":
    main(sys.argv[1:])
