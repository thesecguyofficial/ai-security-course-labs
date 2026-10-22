"""
checker.py: find the risky Azure AI settings in Contoso's estate, the way a cloud security engineer would on day one.

    python3 checker.py                # Contoso today (contoso/)
    python3 checker.py --with-fixes   # the same estate with everything in fixes/ applied

It reads exports shaped like Azure CLI output (role assignments, policy assignments, Foundry resources and
deployments, budgets) and Contoso's own standards (contoso/standards.json). Rules AZ10-01 to AZ10-14 each come
from a Microsoft document; the lesson that explains it is in brackets. Nothing here talks to Azure.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from azure_model import (Azure, PolicyEval, Roles, deployment_fields, load, scope_covers, short_scope)

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "WARNING": 3}
APPROVED_MODELS_DEF = "aafe3651-cb78-4f68-9f81-e7e41509110f"
DISABLE_LOCAL_AUTH_DEF = "71ef260a-8f18-47b7-abcb-62d0673d94dc"
COGNITIVE_SERVICES_ROLES_OK = {"Cognitive Services Usages Reader"}


@dataclass
class Finding:
    sev: str
    rule: str
    where: str
    what: str
    fix: str

    def show(self) -> str:
        return f"  {self.sev:<7} {self.rule}  {self.where}\n          {self.what}\n          fix: {self.fix}"


def run(with_fixes: bool = False) -> list[Finding]:
    d = "fixes" if with_fixes else "contoso"
    az = Azure(f"{d}/estate.json", f"{d}/role-assignments.json", f"{d}/policy-assignments.json",
               ["fixes/custom-role-foundry-deployer.json"] if with_fixes else None)
    budgets = load(f"{d}/budgets.json")["budgets"]
    std = load("contoso/standards.json")
    roles: Roles = az.roles
    out: list[Finding] = []
    accounts = az.estate["accounts"]

    for acct in accounts:
        name, keys_on = acct["name"], acct["properties"].get("disableLocalAuth") is not True
        # AZ10-01: key access on
        if keys_on:
            out.append(Finding("HIGH", "AZ10-01", name,
                               "Key access is ON (disableLocalAuth is not true): anyone holding a key gets full access, no role check.",
                               "Move callers to Entra ID, then set disableLocalAuth: true (lesson 10.4)."))
        # AZ10-02: who can read the keys of a keys-enabled resource
        if keys_on:
            for a in az.assignments:
                if not scope_covers(a["scope"], acct["id"]):
                    continue
                ok, _ = roles.grants(a["roleDefinitionName"], "listKeys")
                if ok:
                    human = az.principals[a["principalName"]]["human"]
                    out.append(Finding("MEDIUM" if human else "HIGH", "AZ10-02", f"{a['principalName']} on {name}",
                                       f"{a['roleDefinitionName']} @ {short_scope(a['scope'])} can list the keys, and a key bypasses RBAC.",
                                       "Remove the role or disable key access on the resource (lessons 10.3, 10.4)."))
        # AZ10-10/12/13: deployments
        for dep in acct["deployments"]:
            m = dep["properties"]["model"]
            ok = any(m["name"] == x["name"] and (x["versions"] == "any" or m["version"] in x["versions"])
                     for x in std["approved_models"])
            if not ok:
                out.append(Finding("MEDIUM", "AZ10-10", f"{name}/{dep['name']}",
                                   f"Deployment of {m['name']} v{m['version']} is not on Contoso's approved list. "
                                   "The policy is checked at deployment time, so this one already exists.",
                                   "Delete it or approve it; the policy compliance view lists it as non-compliant (lesson 10.3)."))
            env = acct["environment"]
            if env == "production" and dep["sku"]["name"] not in std["residency"]["production"]:
                out.append(Finding("MEDIUM", "AZ10-12", f"{name}/{dep['name']}",
                                   f"Deployment type {dep['sku']['name']}: prompts may be processed in any Azure region. "
                                   "Contoso's standard says EU data zone or the resource's geography.",
                                   "Redeploy as DataZoneStandard (or Standard) (lesson 10.2)."))
            cap = std["max_capacity_units"].get(env)
            if cap and dep["sku"]["capacity"] > cap:
                out.append(Finding("MEDIUM", "AZ10-13", f"{name}/{dep['name']}",
                                   f"Capacity {dep['sku']['capacity']} units is above Contoso's {env} limit of {cap}. "
                                   "Capacity sets tokens per minute: a speed limit, not a spending cap.",
                                   f"Lower it to {cap} or less, and add a budget alert (lesson 10.5)."))

    # role hygiene for Foundry
    broad: dict[tuple[str, str], list[str]] = {}
    for a in az.assignments:
        p = az.principals[a["principalName"]]
        role, scope = a["roleDefinitionName"], a["scope"]
        on_foundry = any(scope_covers(scope, x["id"]) or scope_covers(x["id"], scope) for x in accounts)
        if not on_foundry:
            continue
        if not p["human"] and (role in ("Owner", "Contributor") or
                               (role.startswith("Cognitive Services") and role not in COGNITIVE_SERVICES_ROLES_OK)):
            broad.setdefault((a["principalName"], role), []).append(short_scope(scope))
        if p["human"] and role.startswith("Cognitive Services") and role not in COGNITIVE_SERVICES_ROLES_OK:
            out.append(Finding("MEDIUM", "AZ10-03", a["principalName"],
                               f"{role} @ {short_scope(scope)}: Microsoft says not to use 'Cognitive Services' roles for Foundry "
                               "(except Usages Reader). This one can read and regenerate keys.",
                               "Use Foundry User / Foundry Project Manager instead (lesson 10.3)."))
        if role == "Foundry User" and scope.count("/") <= 4:
            out.append(Finding("MEDIUM", "AZ10-04", a["principalName"],
                               f"Foundry User @ {short_scope(scope)}: data access to EVERY Foundry resource below it.",
                               "Assign it on the one Foundry resource or project they use (lesson 10.3)."))
        if role == "Foundry Agent Consumer" and "/projects/" not in scope:
            out.append(Finding("LOW", "AZ10-05", a["principalName"],
                               "Foundry Agent Consumer at resource scope: every agent endpoint in every project. "
                               "The portal can only assign it here.",
                               "Assign it at project or agent scope with the Azure CLI (lesson 10.3)."))
        if role == "Azure AI Developer":
            out.append(Finding("MEDIUM", "AZ10-06", a["principalName"],
                               "Azure AI Developer is for Azure Machine Learning workspaces and Foundry hubs, not Foundry projects "
                               "(despite the name), and it carries OpenAI data actions.",
                               "Use Foundry User; remove this role (lesson 10.3)."))

    for (who, role), scopes in broad.items():
        out.append(Finding("MEDIUM", "AZ10-03", who,
                           f"Workload identity has {role} @ {', '.join(scopes)}: it can read keys, change content filters and "
                           "settings, yet has no data actions (so an app given it ends up calling the model with a key).",
                           "Give it only its job: Foundry User on one resource to call models, or a custom role "
                           "that manages deployments only (lesson 10.3)."))

    # policies
    am = [x for x in az.policies if x["policyDefinitionId"].endswith(APPROVED_MODELS_DEF)]
    sub = f"/subscriptions/{az.estate['subscriptionId']}"
    if not am:
        out.append(Finding("HIGH", "AZ10-07", "subscription", "No approved-models policy: any model in the catalog can be deployed.",
                           "Assign 'Foundry model deployments should only use approved models' with Deny (lesson 10.3)."))
    for x in am:
        params = x.get("parameters", {})
        eff = params.get("effect", {}).get("value", "Audit")
        if eff != "Deny":
            out.append(Finding("HIGH", "AZ10-07", x["name"], f"Effect is {eff}: unapproved deployments still succeed (Audit only logs).",
                               "Set the effect to Deny once the list is right (lesson 10.3)."))
        pubs = params.get("allowedPublishers", {}).get("value", [])
        if pubs:
            out.append(Finding("HIGH", "AZ10-08", x["name"],
                               f"allowedPublishers = {pubs}: the rule denies only when the publisher is NOT listed AND no asset ID "
                               "matches, so every model from these publishers is approved, including future ones.",
                               "Empty allowedPublishers; list asset IDs only (lesson 10.3)."))
        for asset in params.get("allowedAssetIds", {}).get("value", []):
            if not asset.endswith("/") and "/versions/" not in asset:
                out.append(Finding("MEDIUM", "AZ10-09", x["name"],
                                   f"Asset ID '{asset.rsplit('/', 1)[-1]}' has no trailing slash or version: it also matches every model "
                                   "whose name starts the same way (gpt-5 also matches gpt-5.2 and gpt-5.4).",
                                   "End it with '/' (all versions of that model) or '/versions/<n>' (one version) (lesson 10.3)."))
    if not any(x["policyDefinitionId"].endswith(DISABLE_LOCAL_AUTH_DEF) for x in az.policies):
        out.append(Finding("MEDIUM", "AZ10-11", "subscription",
                           "No policy for key access: nobody is told when a Foundry resource is created or changed with keys on.",
                           "Assign 'Azure AI Services resources should have key access disabled' (Audit, then Deny) (lesson 10.4)."))

    # budgets
    for rg in std["budgets"]["required_scopes"]:
        mine = [b for b in budgets if b["scope"].lower().endswith(f"/resourcegroups/{rg}")]
        if not mine:
            out.append(Finding("MEDIUM", "AZ10-14", rg,
                               "No budget on this AI resource group: the only alert is the company-wide one.",
                               "Add a budget with an early actual alert and a forecast alert to the team that can act (lesson 10.5)."))
            continue
        lows = [n for b in mine for n in b["notifications"].values()
                if n["thresholdType"] == "Forecasted" or n["threshold"] < std["budgets"]["want_early_warning_below_percent"]]
        if not lows:
            out.append(Finding("MEDIUM", "AZ10-14", rg, "Budget alerts only at or above 80 % of actual cost.",
                               "Add a lower actual threshold and a Forecasted one (lesson 10.5)."))
    return sorted(out, key=lambda f: (SEV_ORDER[f.sev], f.rule, f.where))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--with-fixes", action="store_true")
    a = ap.parse_args()
    findings = run(a.with_fixes)
    print(f"--- AZ10 checker · Contoso {'with fixes/' if a.with_fixes else 'today'} ---\n")
    for f in findings:
        print(f.show())
    counts = {s: sum(f.sev == s for f in findings) for s in SEV_ORDER}
    print(f"\n{counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW  ({len(findings)} findings)")
    print("Remember: a budget alerts, it never stops spending; a TPM quota limits speed, not the monthly bill.")


if __name__ == "__main__":
    main()
