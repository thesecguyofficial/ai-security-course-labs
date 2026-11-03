"""
explore.py: look at each piece of TSG Helpdesk on Microsoft Foundry, one step at a time, before you check and attack
the lab (AZ11 lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's two
Terraform-plan-shaped files (contoso/plan.json and fixes/plan.json), the lab's JSON files and the fake logs in logs/,
and prints what it finds.

    python3 explore.py plan                    # 1. what a Terraform plan is: everything it WOULD create
    python3 explore.py model                   # 2. the model deployments: which model, which version, which type
    python3 explore.py role                    # 3. who may do what: every role assignment, its role and its scope
    python3 explore.py route GlobalStandard    # 4. where a deployment type lets the prompt be processed
    python3 explore.py network                 # 5. the private network: VNet, subnets, private endpoint, public door
    python3 explore.py dns                     # 6. the three names of the resource, and where each one leads
    python3 explore.py keys                    # 7. the Key Vault, the key, and who may use it
    python3 explore.py logging                 # 8. what gets recorded: activity log, resource logs, AI gateway
    python3 explore.py record                  # 9. one Helpdesk call in three logs, side by side

Most commands take a plan name: version-1 (the default, Contoso's pull request, in contoso/) or hardened (fixes/,
the same build as terraform/).
Everything is fake: Microsoft documentation example IDs, Contoso (Microsoft's own placeholder company name).
foundry_twin.py, which route, network and dns use, is a teaching model of Azure's rules, not Azure.
"""

from __future__ import annotations

import argparse
import collections
import json

from foundry_twin import ROLE_FILES, Twin, load, role_name_of

PLANS = {"version-1": "vulnerable", "hardened": "safe"}
FOLDER = {"version-1": "contoso/plan.json", "hardened": "fixes/plan.json"}

# Where each deployment type may process prompts (Microsoft's deployment types page, checked 3 Nov 2026).
PROCESSING = {
    "Global": "any Azure region",
    "DataZone": "the data zone of the resource's region (US, EU or APAC)",
    "Standard": "the Azure geography of the resource's region (may move between its regions)",
    "ProvisionedManaged": "the Azure geography of the resource's region (may move between its regions)",
    "DeveloperTier": "no data residency guarantee",
}


def _twin(name: str) -> Twin:
    return Twin(PLANS[name])


def _area(sku: str) -> str:
    for prefix in ("Global", "DataZone"):
        if sku.startswith(prefix):
            return PROCESSING[prefix]
    return PROCESSING.get(sku, "unknown type: check Microsoft's deployment types page")


# ---------------------------------------------------------------- 1. plan

def cmd_plan(a) -> None:
    raw = load(FOLDER[a.plan])
    t = _twin(a.plan)
    print(f"Terraform plan, {a.plan}: {FOLDER[a.plan]}")
    print(f"  shaped like `terraform show -json` (format {raw.get('format_version')}), written by hand for the lab")
    print(f"  {len(t.plan.res)} resources it WOULD create   (a plan changes nothing; apply would)\n")
    by_type = collections.defaultdict(list)
    for addr, r in t.plan.res.items():
        by_type[r["type"]].append(addr.split(".", 1)[1])
    for typ in sorted(by_type):
        names = ", ".join(by_type[typ])
        print(f"  {len(by_type[typ]):>2} x {typ:<46} {names if len(names) < 70 else names[:67] + '...'}")
    print(f"\n{len(t.plan.res)} resources. Nothing exists yet: this is the plan, read before anything is built.")


# ---------------------------------------------------------------- 2. model

def cmd_model(a) -> None:
    t = _twin(a.plan)
    print(f"The model deployments in the plan, {a.plan} (resource {t.acct['name']}, kind {t.acct.get('kind')}, "
          f"region {t.acct.get('location')}):\n")
    print(f"  {'deployment':<16} {'model':<14} {'version':<12} {'type (sku.name)':<18} capacity")
    for addr in t.plan.of_type("azurerm_cognitive_deployment"):
        v = t.plan.v(addr)
        m, s = v["model"][0], v["sku"][0]
        print(f"  {v['name']:<16} {m['name']:<14} {m['version']:<12} {s['name']:<18} {s.get('capacity')}")
    print("\nYour app calls the DEPLOYMENT by its name, not the model. One resource can hold several deployments.")
    approved = [x for p in t.policies if p["name"] == "allow-only-approved-models"
                for x in p["parameters"]["allowedAssetIds"]["value"]]
    print("Approved models (Azure Policy from lab AZ10, effect Deny):")
    for x in approved:
        print(f"  {x}")
    print("All of these are Models sold by Azure. A partner model (Microsoft's example: Cohere) would also need")
    print("Azure Marketplace, with licence terms and a price set by the model's provider.")


# ---------------------------------------------------------------- 3. role

def _who(t: Twin, addr: str) -> str:
    refs = t.plan.refs(addr, "principal_id")
    if refs:
        return t.name_of(refs[0])
    pid = t.plan.v(addr).get("principal_id")
    for name, p in t.principals.items():
        if p["objectId"] == pid:
            return f"{name} ({p['type']})"
    if t.plan.expr(addr, "principal_id").get("references"):
        return "you (whoever runs terraform apply)"
    return "?"


def _scope(t: Twin, addr: str) -> str:
    for s in t.plan.refs(addr, "scope"):
        typ = t.plan.res[s]["type"].replace("azurerm_", "")
        return f"{typ} {t.name_of(s)}"
    return "?"


def cmd_role(a) -> None:
    t = _twin(a.plan)
    print(f"Role assignments in the plan, {a.plan}. Each one = WHO + WHICH ROLE + WHERE (the scope):\n")
    for addr in t.plan.of_type("azurerm_role_assignment"):
        role = role_name_of(t.plan.v(addr))
        print(f"  {_who(t, addr):<36} {role:<32} @ {_scope(t, addr)}")
    print("\nWhat those roles allow (role definitions copied from Microsoft, in roles/):")
    seen = {role_name_of(t.plan.v(x)) for x in t.plan.of_type("azurerm_role_assignment")}
    for role in sorted(seen & set(ROLE_FILES)):
        r = load(ROLE_FILES[role])
        data = ", ".join(r["dataActions"]) or "none"
        if len(data) > 80:
            data = f"{len(r['dataActions'])} entries, from {r['dataActions'][0]}"
        keys = any("listkeys" in x.lower() or x in ("*", "Microsoft.CognitiveServices/*") for x in r["actions"])
        print(f"  {role:<32} data actions: {data}")
        print(f"  {'':<32} control actions: {len(r['actions'])} entries{', including listkeys' if keys else ''}")
    print("\nData actions = using what is inside (calling a model). Control actions = managing the resource.")


# ---------------------------------------------------------------- 4. route

def cmd_route(a) -> None:
    std = load("contoso/standards.json")
    t = Twin("safe")
    sku = a.sku
    print(f"A deployment of gpt-5 with type {sku}, on {t.acct['name']} in {t.acct.get('location')}\n")
    print(f"  Where prompts may be processed: {_area(sku)}")
    print("  Where data at rest stays:       the resource's Azure geography (every type)")
    ok = sku in std["allowed_deployment_skus"]
    print(f"\nContoso's standard: deployment types {', '.join(std['allowed_deployment_skus'])} only")
    print(f"Verdict: {'fits the standard' if ok else 'BREAKS the standard'}")
    print("\nWould Azure Policy stop the CI pipeline from deploying it?")
    for name in PLANS:
        d = _twin(name).deploy("ci-deployer", "gpt-5", "1", sku)
        pol = [w for w in d.why if w.startswith("POLICY")]
        print(f"  {name:<10} {'DEPLOYED' if d.allowed else 'refused '}  {'; '.join(pol) or d.why[-1]}")


# ---------------------------------------------------------------- 5. network

def cmd_network(a) -> None:
    t = _twin(a.plan)
    print(f"The Helpdesk's network, {a.plan}\n")
    for vn in t.plan.of_type("azurerm_virtual_network"):
        v = t.plan.v(vn)
        print(f"  VNet       {v['name']}  {', '.join(v['address_space'])}   (a private network in Azure)")
    for sn in t.plan.of_type("azurerm_subnet"):
        v = t.plan.v(sn)
        print(f"  subnet     {v['name']:<10} {', '.join(v['address_prefixes'])}")
    for pe in t.private_endpoints():
        v = t.plan.v(pe)
        sub = t.plan.refs(pe, "subnet_id")
        psc = v["private_service_connection"][0]
        print(f"  private endpoint  {v['name']} in {t.name_of(sub[0]) if sub else '?'}: a network card with a private IP"
              f" ({psc['subresource_names'][0]} sub-resource, auto-approved)")
    acct = t.acct
    acl = (acct.get("network_acls") or [None])[0]
    print(f"\n  public network access   {'Enabled' if acct.get('public_network_access_enabled', True) else 'Disabled'}")
    print(f"  network ACL default     {acl['default_action'] if acl else '(none set: no list of allowed IPs)'}")
    print("  endpoint policy         (Azure has none for this: the public setting, the ACL, DNS and RBAC decide)")
    print("\nWho reaches the model's front door? (network only; Microsoft Entra ID and RBAC still decide after this)")
    sub = acct.get("custom_subdomain_name") or acct["name"]
    for label, src in (("from the internet, 203.0.113.50", {"kind": "internet", "ip": "203.0.113.50"}),
                       ("helpdesk-web in the VNet, 10.20.1.10", {"kind": "vnet", "network": "vnet-helpdesk", "ip": "10.20.1.10"})):
        ip, _ = t.resolve(src, f"{sub}.openai.azure.com")
        ok, why = t.network(src, ip)
        print(f"  {'THROUGH' if ok else 'refused':<8} {label:<38} {why}")


# ---------------------------------------------------------------- 6. dns

def cmd_dns(a) -> None:
    t = _twin(a.plan)
    print(f"The Foundry resource's three names, {a.plan}. One private endpoint, three private DNS zones needed:\n")
    zones = [t.name_of(z) for z in t.plan.of_type("azurerm_private_dns_zone")]
    print(f"  private DNS zones in the plan: {len(zones)} of 3")
    for z in zones:
        print(f"      {z}")
    print()
    vnet = {"kind": "vnet", "network": "vnet-helpdesk", "ip": "10.20.1.10"}
    for host in t.hostnames():
        ip, why = t.resolve(vnet, host)
        print(f"  {host}")
        print(f"      from inside the VNet -> {ip}")
        print(f"          {why}")
    print("\nFrom the internet (or a VPN with no DNS forwarding), every name gets the PUBLIC address. Whether that")
    print("public address answers is the public network access setting (`python3 explore.py network`).")


# ---------------------------------------------------------------- 7. keys

def cmd_keys(a) -> None:
    t = _twin(a.plan)
    cmk = t.acct.get("customer_managed_key")
    print(f"Encryption at rest, {a.plan}\n")
    print(f"  {t.acct['name']} ({t.acct.get('location')}): "
          + ("customer-managed key (your key, in your Key Vault)" if cmk else "Microsoft-managed keys (no key of yours)"))
    for kv in t.plan.of_type("azurerm_key_vault"):
        v = t.plan.v(kv)
        same = v.get("location") == t.acct.get("location")
        print(f"\n  Key Vault {v['name']}  region {v.get('location')}{'' if same else '   <- not the Foundry resource region'}")
        print(f"    purge protection {'ON' if v.get('purge_protection_enabled') else 'OFF'}, soft-delete keeps a deleted key "
              f"{v.get('soft_delete_retention_days', 90)} days, access by Azure RBAC {v.get('rbac_authorization_enabled')}")
        for k in t.plan.of_type("azurerm_key_vault_key"):
            kvv = t.plan.v(k)
            print(f"    key {kvv['name']}: {kvv['key_type']} {kvv['key_size']} bits")
        for ra in t.plan.of_type("azurerm_role_assignment"):
            if kv in t.plan.refs(ra, "scope"):
                print(f"    {role_name_of(t.plan.v(ra)):<26} -> {_who(t, ra)}")
    if not cmk:
        print("\n  The key exists, but the Foundry resource doesn't use it: nothing here is encrypted with it.")


# ---------------------------------------------------------------- 8. logging

def cmd_logging(a) -> None:
    t = _twin(a.plan)
    print(f"What gets recorded, {a.plan}\n")
    print("Activity log (who changed what; control plane only, never the prompt):")
    print("  always on, kept 90 days, free; a diagnostic setting can keep it longer\n")
    print("Resource logs (what happened inside a resource): only where a diagnostic setting sends them")
    for ds in t.plan.of_type("azurerm_monitor_diagnostic_setting"):
        v = t.plan.v(ds)
        tgt = t.plan.refs(ds, "target_resource_id")
        dest = t.plan.refs(ds, "log_analytics_workspace_id")
        cats = ", ".join(e["category"] for e in v.get("enabled_log") or [])
        print(f"  {t.name_of(tgt[0]) if tgt else '?':<24} {cats:<32} -> {t.name_of(dest[0]) if dest else '?'}")
    on_foundry = [x for x in t.plan.of_type("azurerm_monitor_diagnostic_setting") if t.account in t.plan.refs(x, "target_resource_id")]
    if not on_foundry:
        print(f"  {t.acct['name']:<24} NONE: no Audit, RequestResponse or Trace logs exist anywhere")
    for w in t.plan.of_type("azurerm_log_analytics_workspace"):
        print(f"  workspace {t.name_of(w)} keeps logs {t.plan.v(w).get('retention_in_days')} days")
    apim = t.plan.of_type("azurerm_api_management")
    print("\nAI gateway (API Management with LLM logging: the prompt and the answer):")
    print(f"  {'in this plan' if apim else 'none in this plan: Contoso piloted one on staging (logs/, Step 5)'}")


# ---------------------------------------------------------------- 9. record

def cmd_record(a) -> None:
    gw = load("logs/apim-gateway-log.json")["rows"][0]
    llm = [r for r in load("logs/apim-llm-log.json")["rows"] if r["CorrelationId"] == gw["CorrelationId"]]
    res = load("logs/foundry-requestresponse.json")["rows"][0]
    ask = next(r for r in llm if r.get("RequestMessages"))
    ans = next(r for r in llm if r.get("ResponseMessages"))
    print("FAKE lab logs with Microsoft's column names (logs/). One Helpdesk call, 19 Oct 2026, in three tables.\n")
    print("1. ApiManagementGatewayLogs (the AI gateway's request log):")
    print(f"   when   TimeGenerated      {gw['TimeGenerated']}")
    print(f"   who    CallerIpAddress    {gw['CallerIpAddress']}   (helpdesk-web, inside the VNet)")
    print(f"   what   Method, ApiId      {gw['Method']} {gw['ApiId']} -> {gw['ResponseCode']}")
    print(f"   join   CorrelationId      {gw['CorrelationId']}")
    print("\n2. ApiManagementGatewayLlmLog (LLM logging on: the conversation):")
    print(f"   said     RequestMessages   \"{ask['RequestMessages'][0]['content']}\"")
    print(f"   answered ResponseMessages  \"{ans['ResponseMessages'][0]['content'][:60]}...\"")
    print(f"   size     tokens            {ask['PromptTokens']} prompt, {ask['CompletionTokens']} completion")
    print(f"   model    DeploymentName    {ask['DeploymentName']} ({ask['ModelName']})")
    print("\n3. AzureDiagnostics, Category RequestResponse (the Foundry resource's own resource log):")
    print(f"   who    CallerIPAddress    {res['CallerIPAddress']}   <- the gateway, not the person")
    print(f"   what   OperationName      {res['OperationName']} -> {res['ResultSignature']}, {res['DurationMs']} ms")
    print("   said   (nothing)          Microsoft's pages don't say this category holds the prompt text")


# ---------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("plan", cmd_plan), ("model", cmd_model), ("role", cmd_role), ("network", cmd_network),
                     ("dns", cmd_dns), ("keys", cmd_keys), ("logging", cmd_logging)):
        s = sub.add_parser(name)
        s.add_argument("plan", nargs="?", choices=list(PLANS), default="version-1")
        s.set_defaults(fn=fn)
    s = sub.add_parser("route")
    s.add_argument("sku", nargs="?", default="DataZoneStandard",
                   help="a deployment type (sku.name), e.g. GlobalStandard, DataZoneStandard, Standard")
    s.set_defaults(fn=cmd_route)
    sub.add_parser("record").set_defaults(fn=cmd_record)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
