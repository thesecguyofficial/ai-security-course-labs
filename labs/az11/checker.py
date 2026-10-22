"""
checker.py: find the risky settings in a Terraform plan for a Microsoft Foundry resource, before anything is deployed.

    python3 checker.py                      # Contoso's version 1 (contoso/plan.json)
    python3 checker.py --with-fixes         # the hardened build (fixes/plan.json)
    python3 checker.py --plan my-plan.json  # YOUR real plan: terraform show -json tfplan > my-plan.json

Rules AZ11-01 to AZ11-14 each come from a Microsoft document; the lesson that explains it is in brackets. Three of
them run Microsoft's own built-in policy rule (copied into policy-definitions/) against the planned values.
Nothing here talks to Azure.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from foundry_twin import PolicyEval, Twin, ZONE_FOR_SUFFIX, deployment_fields, load, role_name_of

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
ALL_SKUS = ["GlobalStandard", "GlobalProvisionedManaged", "GlobalBatch", "DataZoneStandard",
            "DataZoneProvisionedManaged", "DataZoneBatch", "Standard", "ProvisionedManaged", "DeveloperTier"]


@dataclass
class Finding:
    sev: str
    rule: str
    where: str
    what: str
    fix: str

    def show(self) -> str:
        return f"  {self.sev:<7} {self.rule}  {self.where}\n          {self.what}\n          fix: {self.fix}"


def builtin(defn_file: str, fields: dict, effect: str = "Deny") -> bool:
    """True if Microsoft's built-in rule would flag these fields (non-compliant)."""
    return PolicyEval(load(defn_file), {"effect": {"value": effect}}, fields).effect() is not None


def run(twin: Twin, full: bool = True) -> list[Finding]:
    p, out = twin.plan, []
    acct, name = twin.acct, twin.acct["name"]
    std = twin.standards

    # AZ11-01: Microsoft's rule "Azure AI Services resources should restrict network access" (11.2)
    pna = acct.get("public_network_access_enabled", True)
    acl = (acct.get("network_acls") or [{}])[0]
    if builtin("policy-definitions/NetworkAcls_Audit.json", {
            "type": "Microsoft.CognitiveServices/accounts",
            "Microsoft.CognitiveServices/accounts/publicNetworkAccess": "Enabled" if pna else "Disabled",
            "Microsoft.CognitiveServices/accounts/networkAcls.defaultAction": acl.get("default_action", "Allow")}):
        out.append(Finding("HIGH", "AZ11-01", name,
                           "Public network access is on and network_acls doesn't default to Deny: the model answers anyone on the internet who has a valid token "
                           "(the azurerm provider defaults public_network_access_enabled to true).",
                           "public_network_access_enabled = false, plus a private endpoint (lesson 11.2)."))

    # AZ11-02: private endpoint present (Microsoft's "should use Azure Private Link" counts Approved connections)
    pes = twin.private_endpoints()
    if not pes:
        out.append(Finding("HIGH", "AZ11-02", name, "No private endpoint on the 'account' sub-resource: callers in your VNet go over the public endpoint.",
                           "Add azurerm_private_endpoint with subresource_names = [\"account\"] (lesson 11.2)."))
    elif pna:
        out.append(Finding("MEDIUM", "AZ11-02", name,
                           f"A private endpoint exists ({', '.join(twin.name_of(x) for x in pes)}) but public access is still on: a side door was built and the front door left open.",
                           "Set public_network_access_enabled = false once every caller uses the private endpoint (lesson 11.2)."))

    # AZ11-03: all three privatelink zones, linked, in the endpoint's zone group (11.2)
    vnets = {twin.name_of(twin.pe_vnet(pe)) for pe in pes if twin.pe_vnet(pe)}
    for zname in std["foundry_private_dns_zones"]:
        z = twin.zone(zname)
        host = f"{acct.get('custom_subdomain_name', name)}.{next(s for s, zz in ZONE_FOR_SUFFIX.items() if zz == zname)}"
        if pes and not z:
            out.append(Finding("HIGH", "AZ11-03", zname, f"Zone missing: inside the VNet {host} still resolves to the PUBLIC address.",
                               "Create the zone, link it to the VNet and add it to the endpoint's private_dns_zone_group (lesson 11.2)."))
        elif z:
            missing = sorted(vnets - set(twin.zone_linked_to(z)))
            if missing or not any(twin.zone_in_pe_group(pe, z) for pe in pes):
                out.append(Finding("HIGH", "AZ11-03", zname, f"Zone not linked to {', '.join(missing) or 'the VNet'} or not in the endpoint's zone group: {host} resolves publicly.",
                                   "Add an azurerm_private_dns_zone_virtual_network_link and list the zone in private_dns_zone_group (lesson 11.2)."))

    # AZ11-04: key access (lesson 10.4); the provider's default is true
    if acct.get("local_auth_enabled", True) is not False:
        out.append(Finding("HIGH", "AZ11-04", name, "local_auth_enabled is not false: resource keys work and bypass RBAC (the azurerm default is true).",
                           "local_auth_enabled = false (lesson 10.4)."))

    # AZ11-05: one identity per app (11.1)
    if full:
        users: dict[str, list[str]] = {}
        for app, a in twin.apps.items():
            users.setdefault(a["identity"], []).append(app)
        for ident, apps in sorted(users.items()):
            if len(apps) > 1:
                out.append(Finding("MEDIUM", "AZ11-05", ident,
                                   f"Shared by {', '.join(apps)}: compromise one app and you hold the other's access; the logs can't tell them apart.",
                                   "One user-assigned identity per app, with roles only on what that app calls (lesson 11.1)."))

    # AZ11-06: workload roles and scopes (11.1)
    for ra in p.of_type("azurerm_role_assignment"):
        v = p.v(ra)
        role = role_name_of(v)
        scope = p.refs(ra, "scope")
        at_rg = any(p.res[s]["type"] == "azurerm_resource_group" for s in scope)
        who = [twin.name_of(x) for x in p.refs(ra, "principal_id")] or \
              [k for k, pr in twin.principals.items() if pr["objectId"] == v.get("principal_id")] or [ra]
        if role in std["workload_roles_not_allowed"]:
            out.append(Finding("HIGH" if role.startswith("Cognitive Services") and "Contributor" in role else "MEDIUM", "AZ11-06",
                               f"{who[0]}", f"{role} @ {'resource group' if at_rg else 'resource'}: Microsoft says not to use 'Cognitive Services' roles for Foundry, and "
                               + ("this one can change network settings and delete diagnostic settings." if "Contributor" in role
                                  else "its DataActions are Microsoft.CognitiveServices/* and its Actions include listkeys."),
                               "Foundry User on the one Foundry resource for apps; a custom role for pipelines (lessons 10.3, 11.1)."))
        elif role == "Foundry User" and at_rg:
            out.append(Finding("MEDIUM", "AZ11-06", f"{who[0]}", "Foundry User @ resource group: data access to every Foundry resource in it, today and later.",
                               "Assign it on the one Foundry resource (or project) instead (lesson 11.1)."))

    # AZ11-07: customer-managed key (11.3)
    has_cmk = bool(acct.get("customer_managed_key"))
    if std.get("cmk_required") and not has_cmk:
        out.append(Finding("MEDIUM", "AZ11-07", name,
                           "No customer-managed key: data at rest uses Microsoft-managed keys. Contoso's standard requires CMK. Note: the built-in CMK policy "
                           "excludes kind AIServices by default, so it would NOT flag this resource.",
                           "Add customer_managed_key with a user-assigned identity (lesson 11.3)."))

    # AZ11-08: the key store (11.3)
    for kv in p.of_type("azurerm_key_vault"):
        kvv = p.v(kv)
        probs = []
        if not kvv.get("purge_protection_enabled"):
            probs.append("purge protection is off (Azure requires it for CMK)")
        if kvv.get("location") != acct.get("location"):
            probs.append(f"region {kvv.get('location')} differs from the Foundry resource ({acct.get('location')})")
        if not kvv.get("rbac_authorization_enabled"):
            probs.append("uses access policies, not Azure RBAC")
        if probs:
            msg = "; ".join(probs)
            out.append(Finding("HIGH", "AZ11-08", kvv["name"], msg[0].upper() + msg[1:] + ".",
                               "Same region, purge_protection_enabled = true, rbac_authorization_enabled = true (lesson 11.3)."))

    # AZ11-09: the CMK identity can use the key BEFORE CMK is enabled (11.3)
    if has_cmk:
        key_ids = p.refs(twin.account, "customer_managed_key", "key_vault_key_id")
        ident = p.refs(twin.account, "customer_managed_key", "identity_client_id")
        vaults = [v for k in key_ids for v in p.refs(k, "key_vault_id")]
        grant = [ra for ra in p.of_type("azurerm_role_assignment")
                 if role_name_of(p.v(ra)) in ("Key Vault Crypto User", "Key Vault Crypto Service Encryption User")
                 and set(p.refs(ra, "scope")) & set(vaults) and set(p.refs(ra, "principal_id")) & set(ident)]
        waits = set(p.depends_on(twin.account))
        ordered = any(ra in waits for ra in grant) or any(set(p.depends_on(w)) & set(grant) for w in waits)
        if not grant:
            out.append(Finding("HIGH", "AZ11-09", name, "The key's identity has no Key Vault Crypto User role on the vault: enabling CMK fails.",
                               "azurerm_role_assignment Key Vault Crypto User for that identity on the vault (lesson 11.3)."))
        elif not ordered:
            out.append(Finding("MEDIUM", "AZ11-09", name, "The Foundry resource doesn't depend_on the key role assignment: Terraform may enable CMK before access exists.",
                               "depends_on the role assignment (plus a short wait for RBAC propagation) (lesson 11.3)."))

    # AZ11-10 / 11: resource logs (Microsoft's rule "Diagnostic logs in Azure AI services resources should be enabled")
    diag = [d for d in p.of_type("azurerm_monitor_diagnostic_setting") if twin.account in p.refs(d, "target_resource_id")]
    if not diag:
        out.append(Finding("HIGH", "AZ11-10", name, "No diagnostic setting on the Foundry resource: no Audit, RequestResponse or Trace logs exist anywhere.",
                           "azurerm_monitor_diagnostic_setting to a Log Analytics workspace (lesson 11.4)."))
    else:
        cats, groups = set(), set()
        for d in diag:
            for e in p.v(d).get("enabled_log") or []:
                cats.add(e.get("category")); groups.add((e.get("category_group") or "").lower())
        missing = [c for c in std["required_log_categories"] if c not in cats] if "alllogs" not in groups else []
        if missing:
            out.append(Finding("MEDIUM", "AZ11-11", name, f"Diagnostic setting lacks {', '.join(missing)}. (Microsoft's built-in policy only checks that a setting with logs exists.)",
                               "Enable Audit and RequestResponse (and Trace) (lesson 11.4)."))

    # AZ11-12: deployment types (11.5)
    for dep in p.of_type("azurerm_cognitive_deployment"):
        dv = p.v(dep)
        sku = (dv.get("sku") or [{}])[0].get("name")
        if sku and sku not in std["allowed_deployment_skus"]:
            out.append(Finding("MEDIUM", "AZ11-12", dv["name"], f"Deployment type {sku}: "
                               + ("prompts may be processed in any Azure region." if sku.startswith("Global") else "outside Contoso's residency standard."),
                               f"Use {' or '.join(std['allowed_deployment_skus'])} (lesson 11.5)."))

    # AZ11-13: is the residency rule ENFORCED? The approved-models policy reads publisher and asset ID only (11.5)
    if full:
        bad = [s for s in ALL_SKUS if s not in std["allowed_deployment_skus"]]
        slip = []
        for s in bad:
            f = deployment_fields("OpenAI", "azureml://registries/azure-openai/models/gpt-5/versions/1", s)
            if not any(e.lower() == "deny" for _, e in twin.policy_effects(f)):
                slip.append(s)
        if slip:
            out.append(Finding("MEDIUM", "AZ11-13", "policy assignments",
                               f"Nothing denies {', '.join(slip)}. The approved-models policy checks the model, not the deployment type.",
                               "A custom policy on Microsoft.CognitiveServices/accounts/deployments/sku.name with effect deny (lesson 11.5)."))

    # AZ11-14: prompt-level audit (11.4)
    if not any(r["type"].startswith("azurerm_api_management") for r in p.res.values()):
        out.append(Finding("LOW", "AZ11-14", name,
                           "No API Management AI gateway in this plan. Microsoft documents prompt and completion logging there; its pages on the Foundry resource's own log categories don't say they hold prompt text.",
                           "Front the model with API Management, LLM logging on, short retention, restricted workspace access (lesson 11.4). Or accept and record the gap."))

    return sorted(out, key=lambda f: (SEV_ORDER[f.sev], f.rule, f.where))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--with-fixes", action="store_true")
    ap.add_argument("--plan", help="check your own `terraform show -json` output instead")
    a = ap.parse_args()
    if a.plan:
        twin, title, full = Twin("safe", plan_path=a.plan), f"your plan ({a.plan})", False
    else:
        twin = Twin("safe" if a.with_fixes else "vulnerable")
        title, full = ("Contoso, hardened build (fixes/)" if a.with_fixes else "Contoso version 1 (contoso/)"), True
    found = run(twin, full)
    print(f"--- AZ11 checker · {title} ---\n")
    for f in found:
        print(f.show())
    counts = {s: sum(f.sev == s for f in found) for s in SEV_ORDER}
    print(f"\n{counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW  ({len(found)} findings)")
    if not full:
        print("Not checked on a single plan: AZ11-05 (needs your app inventory) and AZ11-13 (needs your policy assignments).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
