"""
attack.py: what an attacker (and an auditor) can do against Contoso's Foundry setup, before and after the fixes.

    python3 attack.py --mode vulnerable   # Contoso version 1 (contoso/)
    python3 attack.py --mode safe         # the hardened build (fixes/)

Seven attacker requests (A1-A7) and four legitimate ones (L1-L4) go through the twin in foundry_twin.py: DNS, then
network, then Microsoft Entra ID + RBAC, then Azure Policy. Then three questions every review asks: what does a
developer on the VPN see (G1), can you answer "what did the attacker ask?" (F1), and what happens if you pull the
key (K1). Every "attacker" is a lab placeholder: nothing here sends a request anywhere.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from foundry_twin import Twin

INTERNET = {"kind": "internet", "ip": "203.0.113.50"}
VPN = {"kind": "vpn", "ip": "10.99.0.15"}


def in_vnet(ip: str) -> dict:
    return {"kind": "vnet", "network": "vnet-helpdesk", "ip": ip}


@dataclass
class Step:
    sid: str
    who: str          # "attacker" or "legit"
    what: str
    kind: str         # "chat" | "deploy" | "control"
    app: str = ""     # chat: whose identity (from apps.json) ...
    principal: str = ""   # ... or a named principal
    source: dict | None = None
    host_suffix: str = "openai.azure.com"
    sku: str = ""
    op: str = ""
    fields: dict | None = None


STEPS = [
    Step("A1", "attacker", "Stolen helpdesk token, from the internet: chat via <name>.openai.azure.com", "chat", app="helpdesk-web", source=INTERNET),
    Step("A2", "attacker", "Stolen helpdesk token, from the internet: chat via <name>.services.ai.azure.com", "chat", app="helpdesk-web",
         source=INTERNET, host_suffix="services.ai.azure.com"),
    Step("A3", "attacker", "Compromised HR assistant: call the HELPDESK model with its own identity", "chat", app="hr-assistant",
         source=in_vnet("10.20.1.20")),
    Step("A4", "attacker", "Stolen CI secret: deploy approved gpt-5 as GlobalStandard (any region)", "deploy", principal="ci-deployer", sku="GlobalStandard"),
    Step("A5", "attacker", "Stolen CI secret: deploy approved gpt-5 as GlobalBatch (any region)", "deploy", principal="ci-deployer", sku="GlobalBatch"),
    Step("A6", "attacker", "Stolen CI secret: re-open the resource to the internet", "control", principal="ci-deployer",
         op="Microsoft.CognitiveServices/accounts/write",
         fields={"type": "Microsoft.CognitiveServices/accounts",
                 "Microsoft.CognitiveServices/accounts/publicNetworkAccess": "Enabled",
                 "Microsoft.CognitiveServices/accounts/networkAcls.defaultAction": "Allow"}),
    Step("A7", "attacker", "Stolen CI secret: delete the Foundry resource's diagnostic setting", "control", principal="ci-deployer",
         op="Microsoft.Insights/diagnosticSettings/delete"),
    Step("L1", "legit", "helpdesk-web, in the VNet: chat via <name>.openai.azure.com", "chat", app="helpdesk-web", source=in_vnet("10.20.1.10")),
    Step("L2", "legit", "helpdesk-web, in the VNet: chat via <name>.services.ai.azure.com", "chat", app="helpdesk-web",
         source=in_vnet("10.20.1.10"), host_suffix="services.ai.azure.com"),
    Step("L3", "legit", "helpdesk-web, in the VNet: chat via <name>.cognitiveservices.azure.com", "chat", app="helpdesk-web",
         source=in_vnet("10.20.1.10"), host_suffix="cognitiveservices.azure.com"),
    Step("L4", "legit", "CI pipeline: deploy approved gpt-5 as DataZoneStandard", "deploy", principal="ci-deployer", sku="DataZoneStandard"),
]


def run_step(s: Step, mode: str):
    t = Twin(mode)
    if s.kind == "chat":
        ident = t.apps[s.app]["identity"] if s.app else s.principal
        sub = t.acct.get("custom_subdomain_name") or t.acct["name"]
        return t.call_model(s.source, f"{sub}.{s.host_suffix}", f"entra:{ident}")
    if s.kind == "deploy":
        return t.deploy(s.principal, "gpt-5", "1", s.sku)
    d = t.control(s.principal, s.op, s.fields)
    if s.op.startswith("Microsoft.Insights/diagnosticSettings") and d.allowed:
        has = [x for x in t.plan.of_type("azurerm_monitor_diagnostic_setting") if t.account in t.plan.refs(x, "target_resource_id")]
        if not has:
            d.why.append("NOTE nothing to delete: logging was never on, so the attacker leaves no resource-log trail anyway")
    return d


def review(mode: str) -> list[str]:
    """G1, F1, K1: the questions a reviewer asks after the attack replay."""
    t = Twin(mode)
    sub = t.acct.get("custom_subdomain_name") or t.acct["name"]
    out = []
    g = t.call_model(VPN, f"{sub}.openai.azure.com", "entra:data-science")
    out.append(f"  G1  developer on the office VPN (no DNS forwarding for privatelink zones): {'ALLOWED' if g.allowed else 'REFUSED'} {g.status}")
    out += [f"        {w}" for w in g.why]
    if not g.allowed:
        out.append("        expected: fix DNS (forward the privatelink zones to Azure DNS), never by re-opening public access")
    diag = [x for x in t.plan.of_type("azurerm_monitor_diagnostic_setting") if t.account in t.plan.refs(x, "target_resource_id")]
    cats = sorted({e["category"] for x in diag for e in t.plan.v(x).get("enabled_log") or []})
    if not diag:
        out.append("  F1  'what did 203.0.113.50 ask, and when?'  NO ANSWER: no diagnostic setting, so no resource logs exist")
    else:
        out.append(f"  F1  'what did 203.0.113.50 ask, and when?'  PARTLY: resource logs {', '.join(cats)} -> Log Analytics")
        out.append("        who, when, which operation, status: yes. The prompt text: Microsoft's docs don't say these categories hold it.")
        out.append("        For prompt text you need the API Management AI gateway's LLM logs: run `make hunt`.")
    cmk = t.acct.get("customer_managed_key")
    kvs = [t.plan.v(k) for k in t.plan.of_type("azurerm_key_vault")]
    if not cmk:
        out.append("  K1  'pull the key' drill: NOTHING TO PULL: data at rest uses Microsoft-managed keys")
    else:
        out.append("  K1  'pull the key' drill: disable cmk-foundry -> data encrypted with it is inaccessible until the key is restored")
    for kv in kvs:
        out.append(f"        {kv['name']}: purge protection {'ON' if kv.get('purge_protection_enabled') else 'OFF'}, soft-delete "
                   f"{kv.get('soft_delete_retention_days', 90)} days -> "
                   + ("a deleted key can be recovered; nobody can purge it early" if kv.get("purge_protection_enabled")
                      else "an insider can delete AND purge the key: permanent"))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["vulnerable", "safe"], default="vulnerable")
    mode = ap.parse_args().mode
    title = "Contoso version 1 (contoso/)" if mode == "vulnerable" else "hardened build (fixes/)"
    print(f"--- AZ11 attack replay · {title} ---\n")
    tally = {"attacker": [0, 0], "legit": [0, 0]}
    for s in STEPS:
        d = run_step(s, mode)
        tally[s.who][1] += 1
        tally[s.who][0] += d.allowed
        bad = (s.who == "attacker") == d.allowed
        mark = "!!" if bad else "ok"
        print(f"  {mark} {s.sid}  {'ALLOWED' if d.allowed else 'DENIED '} {d.status}    {s.what}")
        for w in d.why:
            print(f"                     {w}")
    print(f"\nAttacker requests allowed: {tally['attacker'][0]} of {tally['attacker'][1]}   ·   "
          f"legitimate requests allowed: {tally['legit'][0]} of {tally['legit'][1]}\n")
    print("--- review questions ---")
    for line in review(mode):
        print(line)


if __name__ == "__main__":
    main()
