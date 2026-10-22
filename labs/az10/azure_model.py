"""
azure_model.py: a small TEACHING model of how Azure decides "allowed or not" for Foundry. Not the real thing.

It models only what this lab needs, each rule from Microsoft's documentation:

  * Azure RBAC: a role assignment = role + principal + scope. A scope covers itself and everything below it
    (management group > subscription > resource group > resource). Effective permissions are
    Actions - NotActions (management, the "control plane") and DataActions - NotDataActions (data, e.g. calling
    a model). No matching assignment = denied.
  * Foundry roles: Foundry User, Foundry Project Manager, Foundry Account Owner and Foundry Owner are evaluated from
    their real JSON (contoso/roles/, copied from Microsoft's "AI + machine learning" built-in roles page). Note that
    Foundry User's Actions include Microsoft.CognitiveServices/accounts/listkeys/action. Foundry Agent Consumer's JSON
    isn't on that page, so it alone is evaluated from the Foundry RBAC page's capability matrix
    (contoso/roles/foundry-roles-matrix.json); a capability that isn't a column there is treated as NOT granted
    (check the real role with `az role definition list --name "Foundry Agent Consumer"`).
  * Keys ("local authentication"): a request that carries the resource's key is accepted whenever key access is
    on, with NO role check. Microsoft: "the key grants full access without role restrictions."
  * Azure Policy: the two built-in definitions in contoso/policy-definitions/ are evaluated by a tiny interpreter
    of their real policyRule JSON (allOf, anyOf, equals, notEquals, notin, contains, count). String comparisons
    are case-insensitive, as in Azure Policy. Deny refuses the request; Audit lets it through and logs a warning.

Not modelled: deny assignments, conditions (ABAC), PIM, management groups, Conditional Access, network rules,
the propagation delays (minutes to hours) you will meet in real Azure, and every other policy.
"""

from __future__ import annotations

import fnmatch
import json
import pathlib
from dataclasses import dataclass, field

HERE = pathlib.Path(__file__).resolve().parent


def load(rel: str) -> dict:
    return json.loads((HERE / rel).read_text())


# ---------------------------------------------------------------------------------------------- the operations
# kind: "action" (control plane, through Azure Resource Manager) or "data" (the resource's own endpoint)
# perm: the RBAC operation string (Microsoft's "Azure permissions" pages); cap: the Foundry matrix column
OPS = {
    "read":               ("action", "Microsoft.CognitiveServices/accounts/read", "reader"),
    "listKeys":           ("action", "Microsoft.CognitiveServices/accounts/listKeys/action", None),
    "regenerateKey":      ("action", "Microsoft.CognitiveServices/accounts/regenerateKey/action", None),
    "accountWrite":       ("action", "Microsoft.CognitiveServices/accounts/write", None),
    "deploymentWrite":    ("action", "Microsoft.CognitiveServices/accounts/deployments/write", "manage_models"),
    "raiPolicyWrite":     ("action", "Microsoft.CognitiveServices/accounts/raiPolicies/write", None),
    "roleAssignmentWrite": ("action", "Microsoft.Authorization/roleAssignments/write", "assign_roles"),
    "inference":          ("data", "Microsoft.CognitiveServices/accounts/OpenAI/", "data_actions"),
    "agentInvoke":        ("data", "Microsoft.CognitiveServices/accounts/AIServices/", "agent_endpoints"),
}


def _match(pattern: str, op: str) -> bool:
    return fnmatch.fnmatchcase(op.lower(), pattern.lower())


def scope_covers(scope: str, resource_id: str) -> bool:
    """A role or policy assigned at `scope` applies to that scope and every child of it."""
    s, r = scope.rstrip("/").lower(), resource_id.rstrip("/").lower()
    return r == s or r.startswith(s + "/")


class Roles:
    def __init__(self, extra_custom: list[str] | None = None):
        self.defs = {}
        for f in sorted((HERE / "contoso" / "roles").glob("*.json")):
            d = json.loads(f.read_text())
            if "roleName" in d:
                self.defs[d["roleName"]] = d
        for rel in extra_custom or []:
            d = load(rel)
            self.defs[d["roleName"]] = d
        m = load("contoso/roles/foundry-roles-matrix.json")
        self.matrix = {name: dict(zip(m["columns"], row)) for name, row in m["roles"].items()}

    def grants(self, role: str, op: str) -> tuple[bool, str]:
        kind, perm, cap = OPS[op]
        if role in self.matrix and role not in self.defs:   # real JSON wins; the matrix is the fallback
            if cap is None:
                return False, f"{role}: not documented in Microsoft's matrix (treated as not granted)"
            val = self.matrix[role][cap]
            return bool(val), f"{role}: matrix column '{cap}' = {val}"
        d = self.defs.get(role)
        if d is None:
            return False, f"{role}: unknown role"
        if kind == "action":
            ok = any(_match(a, perm) for a in d["actions"]) and not any(_match(n, perm) for n in d["notActions"])
            hit = next((a for a in d["actions"] if _match(a, perm)), None)
            why = f"{role}: Actions {hit!r} covers {perm}" if ok else (
                f"{role}: NotActions removes {perm}" if hit else f"{role}: no Action covers {perm}")
            return ok, why
        # data plane: any DataAction under the service prefix (teaching simplification)
        das = [a for a in d["dataActions"] if a == "*" or perm.lower().startswith(a.lower().rstrip("*"))
               or a.lower().startswith(perm.lower())]
        return (bool(das), f"{role}: DataActions {das}" if das else f"{role}: no DataActions (management only)")


# ------------------------------------------------------------------------------------------------ Azure Policy
class PolicyEval:
    """Evaluate a built-in policyRule against one resource request. Values come from `fields`."""

    def __init__(self, definition: dict, params: dict, fields: dict):
        self.rule = definition["properties"]["policyRule"]
        defaults = {k: v.get("defaultValue") for k, v in definition["properties"]["parameters"].items()}
        self.params = defaults | {k: v["value"] for k, v in params.items()}
        self.fields = {k.lower(): v for k, v in fields.items()}
        self.current: dict = {}

    def value(self, expr):
        if isinstance(expr, str) and expr.startswith("[parameters('"):
            return self.params[expr[len("[parameters('"):-3]]
        if isinstance(expr, str) and expr.startswith("[current('"):
            return self.current[expr[len("[current('"):-3]]
        return expr

    def cond(self, c: dict) -> bool:
        if "allOf" in c:
            return all(self.cond(x) for x in c["allOf"])
        if "anyOf" in c:
            return any(self.cond(x) for x in c["anyOf"])
        if "count" in c:
            spec = c["count"]
            n = 0
            for item in self.value(spec["value"]):
                self.current[spec["name"]] = item
                n += self.cond(spec["where"])
            return self.compare(n, c)
        return self.compare(self.fields.get(c["field"].lower()), c)

    def compare(self, left, c: dict) -> bool:
        low = lambda v: v.lower() if isinstance(v, str) else v
        if "equals" in c:
            return low(left) == low(self.value(c["equals"]))
        if "notEquals" in c:
            return low(left) != low(self.value(c["notEquals"]))
        if "notin" in c or "notIn" in c:
            return low(left) not in [low(v) for v in self.value(c.get("notin", c.get("notIn")))]
        if "in" in c:
            return low(left) in [low(v) for v in self.value(c["in"])]
        if "contains" in c:
            return left is not None and low(self.value(c["contains"])) in low(left)
        raise ValueError(f"operator not modelled: {c}")

    def effect(self) -> str | None:
        """None if the rule doesn't match (compliant), else the effect: Deny / Audit / Disabled."""
        if not self.cond(self.rule["if"]):
            return None
        return self.value(self.rule["then"]["effect"])


DEFINITIONS = {
    "aafe3651-cb78-4f68-9f81-e7e41509110f": "contoso/policy-definitions/approved-models.json",
    "71ef260a-8f18-47b7-abcb-62d0673d94dc": "contoso/policy-definitions/disable-local-auth.json",
}


def policy_effects(assignments: list[dict], resource_id: str, fields: dict) -> list[tuple[str, str]]:
    out = []
    for a in assignments:
        if not scope_covers(a["scope"], resource_id):
            continue
        defn = load(DEFINITIONS[a["policyDefinitionId"].rsplit("/", 1)[-1]])
        eff = PolicyEval(defn, a.get("parameters", {}), fields).effect()
        if eff and eff != "Disabled":
            out.append((a["name"], eff))
    return out


def deployment_fields(model: dict) -> dict:
    return {"type": "Microsoft.CognitiveServices.Data/accounts/deployments",
            "Microsoft.CognitiveServices.Data/accounts/deployments/model.publisher": model.get("publisher"),
            "Microsoft.CognitiveServices.Data/accounts/deployments/model.assetId": model.get("assetId")}


def account_fields(props: dict) -> dict:
    return {"type": "Microsoft.CognitiveServices/accounts",
            "Microsoft.CognitiveServices/accounts/disableLocalAuth": props.get("disableLocalAuth")}


# ------------------------------------------------------------------------------------------------ the decision
@dataclass
class Decision:
    allowed: bool
    status: str                      # what Azure would answer, roughly: 200 / 401 / 403 / Audit
    why: list[str] = field(default_factory=list)


class Azure:
    """One Contoso world: the estate, role assignments and policy assignments for a mode."""

    def __init__(self, estate: str, assignments: str, policies: str, custom_roles: list[str] | None = None):
        self.estate = load(estate)
        self.assignments = load(assignments)["assignments"]
        self.policies = load(policies)["assignments"]
        self.roles = Roles(custom_roles)
        self.principals = load("contoso/principals.json")["principals"]

    def account(self, name: str) -> dict:
        return next(a for a in self.estate["accounts"] if a["name"] == name)

    def rbac(self, principal: str, op: str, resource_id: str) -> tuple[bool, list[str]]:
        why, ok = [], False
        for a in self.assignments:
            if a["principalName"] != principal or not scope_covers(a["scope"], resource_id):
                continue
            g, reason = self.roles.grants(a["roleDefinitionName"], op)
            why.append(("GRANT " if g else "no    ") + reason + f" @ {short_scope(a['scope'])}")
            ok = ok or g
        if not why:
            why.append(f"no role assignment for {principal} covers {short_scope(resource_id)}")
        return ok, why

    def request(self, principal: str, op: str, account: str, *, key_of: str | None = None,
                deployment: str | None = None, model: dict | None = None, set_props: dict | None = None) -> Decision:
        acct = self.account(account)
        target = acct["id"] + (f"/deployments/{deployment}" if deployment else "")
        kind = OPS[op][0]
        if key_of:   # the caller presents a key in the api-key header instead of an Entra ID token
            if kind != "data":
                return Decision(False, "401", ["a key works on the resource's own endpoint, not on Azure Resource Manager"])
            if key_of != account:
                return Decision(False, "401", [f"the key belongs to {key_of}, not {account}"])
            if acct["properties"].get("disableLocalAuth") is True:
                return Decision(False, "401", ["disableLocalAuth = true: keys are refused (after propagation: minutes, up to hours)"])
            return Decision(True, "200", ["key access is ON: the key grants full access, no role is checked"])
        ok, why = self.rbac(principal, op, target)
        if not ok:
            return Decision(False, "403" if kind == "action" else "401", why)
        effects = []
        if op == "deploymentWrite" and model:
            effects = policy_effects(self.policies, target, deployment_fields(model))
        if op == "accountWrite" and set_props is not None:
            effects = policy_effects(self.policies, acct["id"], account_fields(acct["properties"] | set_props))
        for name, eff in effects:
            if eff.lower() == "deny":
                return Decision(False, "403", why + [f"POLICY {name}: Deny"])
        audits = [f"POLICY {n}: Audit (allowed, logged as a warning)" for n, e in effects if e.lower() == "audit"]
        return Decision(True, "Audit" if audits else "200", why + audits)


def short_scope(scope: str) -> str:
    parts = scope.strip("/").split("/")
    if len(parts) <= 2:
        return "subscription"
    if len(parts) <= 4:
        return f"rg:{parts[3]}"
    tail = parts[7:]
    return "/".join(tail) if tail else scope
