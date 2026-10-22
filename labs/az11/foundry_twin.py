"""
foundry_twin.py: a TEACHING MODEL of one Microsoft Foundry resource's front door, built from a Terraform plan.

It is not Azure. It models only what lab AZ11 needs, each rule from a Microsoft document (lesson in brackets):

- DNS (11.2): a caller inside a VNet gets the private endpoint's IP for <name>.openai.azure.com,
  <name>.cognitiveservices.azure.com or <name>.services.ai.azure.com only if the matching privatelink zone exists,
  is linked to that VNet and is in the private endpoint's DNS zone group. Everyone else gets the public IP.
- Network (11.2): the public endpoint answers only if public network access is enabled and, when network_acls has
  default_action Deny, the caller's IP is in ip_rules. The private endpoint answers callers in its own VNet.
- Identity (11.1): a call with a Microsoft Entra token needs a role assignment that covers the Foundry resource and
  whose DataActions match. Roles come from roles/*.json, copied from Microsoft's built-in role pages.
- Policy (11.2, 11.5): Azure Policy rules from policy-definitions/ (copied from Microsoft) and fixes/policies/ are
  evaluated by a small interpreter (case-insensitive, as Azure Policy is, except `match`). Deny refuses.

It does not model peering, custom DNS servers, NSGs, Conditional Access, deny assignments, ABAC conditions,
propagation delays, or what Azure really answers byte for byte. Status codes are "roughly what you'd see".
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
PUBLIC_IP = "198.51.100.20"      # the Foundry resource's public endpoint in this lab (RFC 5737 documentation range)
PE_IP = "10.20.2.4"              # the private endpoint's NIC in snet-pe
ZONE_FOR_SUFFIX = {
    "openai.azure.com": "privatelink.openai.azure.com",
    "cognitiveservices.azure.com": "privatelink.cognitiveservices.azure.com",
    "services.ai.azure.com": "privatelink.services.ai.azure.com",
}
CHAT_ACTION = "Microsoft.CognitiveServices/accounts/OpenAI/deployments/chat/completions/action"


def load(path: str | Path) -> dict:
    p = Path(path)
    return json.loads((p if p.is_absolute() else HERE / p).read_text())


# ------------------------------------------------------------------------------------------ the Terraform plan
class Plan:
    """A Terraform plan in the `terraform show -json` shape: planned_values (what will exist) + configuration
    (how resources reference each other, because IDs are unknown until apply)."""

    def __init__(self, path: str | Path):
        d = load(path)
        self.res = {r["address"]: r for r in d["planned_values"]["root_module"]["resources"]}
        self.cfg = {r["address"]: r for r in d.get("configuration", {}).get("root_module", {}).get("resources", [])}

    def of_type(self, t: str) -> list[str]:
        return [a for a, r in self.res.items() if r["type"] == t]

    def v(self, addr: str) -> dict:
        return self.res[addr]["values"]

    def base(self, addr: str) -> str:
        return addr.split("[", 1)[0]

    def expr(self, addr: str, *path: str):
        e = self.cfg.get(self.base(addr), {}).get("expressions", {})
        for p in path:
            if isinstance(e, list):
                e = e[0] if e else {}
            e = e.get(p, {}) if isinstance(e, dict) else {}
        return e

    def refs(self, addr: str, *path: str) -> list[str]:
        """Resource addresses that attribute `path` of `addr` points at."""
        out: list[str] = []
        raw = self.expr(addr, *path).get("references", []) if isinstance(self.expr(addr, *path), dict) else []
        my_index = self.res.get(addr, {}).get("index")
        for r in raw:
            if r.startswith(("var.", "local.", "each.", "data.", "count.")):
                continue
            parts = r.split(".")
            target = ".".join(parts[:2])
            if target in self.res:
                out.append(target)
                continue
            inst = [a for a in self.res if self.base(a) == target]
            if inst and my_index is not None and "each.value" in raw:
                inst = [a for a in inst if self.res[a].get("index") == my_index]
            out.extend(inst)
        return list(dict.fromkeys(out))

    def depends_on(self, addr: str) -> list[str]:
        return self.cfg.get(self.base(addr), {}).get("depends_on", [])

    def constant(self, addr: str, *path: str):
        e = self.expr(addr, *path)
        return e.get("constant_value") if isinstance(e, dict) else None


# ------------------------------------------------------------------------------------------ roles
ROLE_FILES = {
    "Foundry User": "roles/foundry-user.json",
    "Cognitive Services User": "roles/cognitive-services-user.json",
    "Cognitive Services Contributor": "roles/cognitive-services-contributor.json",
    "Key Vault Crypto User": "roles/key-vault-crypto-user.json",
    "Key Vault Crypto Officer": "roles/key-vault-crypto-officer.json",
    "Contoso Foundry Deployer": "roles/contoso-foundry-deployer.json",
}


def _matches(op: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(op.lower(), p.lower()) for p in patterns)


def role_name_of(values: dict) -> str:
    """A role assignment names its role either by name or by definition ID (Microsoft recommends the ID while the
    Azure AI -> Foundry rename rolls out). Map a known built-in ID back to its name."""
    if values.get("role_definition_name"):
        return values["role_definition_name"]
    guid = (values.get("role_definition_id") or "").rsplit("/", 1)[-1].lower()
    for name, f in ROLE_FILES.items():
        if load(f).get("id", "").lower() == guid:
            return name
    return values.get("role_definition_id") or "?"


def role_allows(role_name: str, op: str, data: bool) -> bool:
    if role_name not in ROLE_FILES:
        return False
    r = load(ROLE_FILES[role_name])
    if data:
        return _matches(op, r["dataActions"]) and not _matches(op, r["notDataActions"])
    return _matches(op, r["actions"]) and not _matches(op, r["notActions"])


# ------------------------------------------------------------------------------------------ Azure Policy
class PolicyEval:
    """Evaluate a policyRule against one request. Field names are matched case-insensitively."""

    def __init__(self, definition: dict, params: dict, fields: dict):
        props = definition.get("properties", definition)
        self.rule = props["policyRule"]
        defaults = {k: v.get("defaultValue") for k, v in props.get("parameters", {}).items()}
        self.params = defaults | {k: v["value"] for k, v in params.items()}
        self.fields = {k.lower(): v for k, v in fields.items()}
        self.current: dict = {}

    def value(self, x):
        if isinstance(x, str) and x.startswith("[parameters('"):
            return self.params[x[len("[parameters('"):-3]]
        if isinstance(x, str) and x.startswith("[current('"):
            return self.current[x[len("[current('"):-3]]
        return x

    def cond(self, c: dict) -> bool:
        if "allOf" in c:
            return all(self.cond(x) for x in c["allOf"])
        if "anyOf" in c:
            return any(self.cond(x) for x in c["anyOf"])
        if "not" in c:
            return not self.cond(c["not"])
        if "count" in c:
            spec, n = c["count"], 0
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
        for k in ("notIn", "notin"):
            if k in c:
                return low(left) not in [low(v) for v in self.value(c[k])]
        if "in" in c:
            return low(left) in [low(v) for v in self.value(c["in"])]
        if "like" in c:
            return isinstance(left, str) and fnmatch.fnmatchcase(left.lower(), low(self.value(c["like"])))
        if "notLike" in c:
            return not (isinstance(left, str) and fnmatch.fnmatchcase(left.lower(), low(self.value(c["notLike"]))))
        if "contains" in c:
            return left is not None and low(self.value(c["contains"])) in low(left)
        if "exists" in c:
            want = str(self.value(c["exists"])).lower() == "true"
            return (left is not None) == want
        if "greater" in c or "less" in c:
            k = "greater" if "greater" in c else "less"
            return left is not None and (left > c[k] if k == "greater" else left < c[k])
        raise ValueError(f"operator not modelled: {c}")

    def effect(self) -> str | None:
        """None if the rule doesn't match (compliant). Raises if the rule has no then block."""
        if "then" not in self.rule:
            raise ValueError("this policy rule has no `then` block, so it names no effect")
        if not self.cond(self.rule["if"]):
            return None
        return self.value(self.rule["then"]["effect"])


# ------------------------------------------------------------------------------------------ decisions
@dataclass
class Decision:
    allowed: bool
    status: str
    why: list[str] = field(default_factory=list)


class Twin:
    """Contoso's Foundry setup for one mode: 'vulnerable' (contoso/) or 'safe' (fixes/)."""

    def __init__(self, mode: str = "vulnerable", plan_path: str | Path | None = None):
        self.mode = mode
        d = "contoso" if mode == "vulnerable" else "fixes"
        self.plan = Plan(plan_path or f"{d}/plan.json")
        self.apps = load(f"{d}/apps.json")["apps"]
        self.policies = load(f"{d}/policy-assignments.json")["assignments"]
        self.principals = load("contoso/principals.json")["principals"]
        self.standards = load("contoso/standards.json")
        accts = self.plan.of_type("azurerm_cognitive_account")
        if len(accts) != 1:
            raise ValueError("this lab expects exactly one azurerm_cognitive_account in the plan")
        self.account = accts[0]

    # ---- facts about the plan
    @property
    def acct(self) -> dict:
        return self.plan.v(self.account)

    def name_of(self, addr: str) -> str:
        return self.plan.v(addr).get("name", addr)

    def rg_name(self) -> str:
        return self.acct.get("resource_group_name", "")

    def private_endpoints(self) -> list[str]:
        """Private endpoints connected to the Foundry resource's 'account' sub-resource, auto-approved."""
        out = []
        for pe in self.plan.of_type("azurerm_private_endpoint"):
            psc = (self.plan.v(pe).get("private_service_connection") or [{}])[0]
            if self.account in self.plan.refs(pe, "private_service_connection", "private_connection_resource_id") \
                    and "account" in (psc.get("subresource_names") or []) and psc.get("is_manual_connection") is False:
                out.append(pe)
        return out

    def vnet_of_subnet(self, subnet: str) -> str | None:
        vname = self.plan.v(subnet).get("virtual_network_name")
        for vn in self.plan.of_type("azurerm_virtual_network"):
            if self.name_of(vn) == vname:
                return vn
        return None

    def pe_vnet(self, pe: str) -> str | None:
        subs = self.plan.refs(pe, "subnet_id")
        return self.vnet_of_subnet(subs[0]) if subs else None

    def zone(self, zone_name: str) -> str | None:
        for z in self.plan.of_type("azurerm_private_dns_zone"):
            if self.name_of(z) == zone_name:
                return z
        return None

    def zone_linked_to(self, zone_addr: str) -> list[str]:
        """VNet names linked to a private DNS zone."""
        out = []
        for link in self.plan.of_type("azurerm_private_dns_zone_virtual_network_link"):
            if zone_addr in self.plan.refs(link, "private_dns_zone_id"):
                out += [self.name_of(v) for v in self.plan.refs(link, "virtual_network_id")]
        return out

    def zone_in_pe_group(self, pe: str, zone_addr: str) -> bool:
        return zone_addr in self.plan.refs(pe, "private_dns_zone_group", "private_dns_zone_ids")

    def hostnames(self) -> list[str]:
        sub = self.acct.get("custom_subdomain_name") or self.acct["name"]
        return [f"{sub}.{s}" for s in ZONE_FOR_SUFFIX]

    # ---- DNS and network (11.2)
    def resolve(self, source: dict, host: str) -> tuple[str, str]:
        suffix = host.split(".", 1)[1]
        zone_name = ZONE_FOR_SUFFIX[suffix]
        if source["kind"] != "vnet":
            return PUBLIC_IP, f"{source['kind']} resolver: public DNS answer"
        z = self.zone(zone_name)
        if not z:
            return PUBLIC_IP, f"no private DNS zone {zone_name}: public answer, even inside the VNet"
        if source["network"] not in self.zone_linked_to(z):
            return PUBLIC_IP, f"{zone_name} is not linked to {source['network']}: public answer"
        for pe in self.private_endpoints():
            if self.zone_in_pe_group(pe, z):
                return PE_IP, f"{zone_name} (linked to {source['network']}) answers with the private endpoint"
        return PUBLIC_IP, f"{zone_name} has no record for this resource (not in a private endpoint's DNS zone group)"

    def network(self, source: dict, ip: str) -> tuple[bool, str]:
        if ip == PE_IP:
            for pe in self.private_endpoints():
                if self.pe_vnet(pe) and self.name_of(self.pe_vnet(pe)) == source.get("network"):
                    return True, "via the PRIVATE endpoint"
            return False, "private IP not reachable from here"
        if self.acct.get("public_network_access_enabled", True) is False:
            return False, "public network access is Disabled"
        acl = (self.acct.get("network_acls") or [None])[0]
        if acl and acl.get("default_action") == "Deny" and source.get("ip") not in (acl.get("ip_rules") or []):
            return False, "network_acls default_action Deny and the caller's IP isn't listed"
        return True, "via the PUBLIC endpoint (internet-reachable)"

    # ---- identity (11.1)
    def identity_addr(self, identity: str) -> str | None:
        for i in self.plan.of_type("azurerm_user_assigned_identity"):
            if self.name_of(i) == identity:
                return i
        return None

    def assignments_for(self, identity: str) -> list[tuple[str, str, str]]:
        """(role name, scope description, role-assignment address) that cover the Foundry resource."""
        out = []
        ident_addr = self.identity_addr(identity)
        obj = self.principals.get(identity, {}).get("objectId")
        for ra in self.plan.of_type("azurerm_role_assignment"):
            v = self.plan.v(ra)
            who = self.plan.refs(ra, "principal_id")
            if not ((ident_addr and ident_addr in who) or (obj and v.get("principal_id") == obj)):
                continue
            scope = self.plan.refs(ra, "scope")
            if self.account in scope:
                out.append((role_name_of(v), f"resource {self.acct['name']}", ra))
            elif any(self.plan.res[s]["type"] == "azurerm_resource_group" for s in scope):
                out.append((role_name_of(v), f"resource group {self.rg_name()}", ra))
        return out

    def can(self, identity: str, op: str, data: bool) -> tuple[bool, str]:
        held = self.assignments_for(identity)
        for role, scope, _ in held:
            if role_allows(role, op, data):
                return True, f"{role} @ {scope}"
        if held:
            return False, "roles held (" + ", ".join(f"{r} @ {s}" for r, s, _ in held) + ") don't include it"
        return False, "no role on this resource"

    # ---- policy (11.2, 11.5)
    def policy_effects(self, fields: dict) -> list[tuple[str, str]]:
        """Every assignment's effect on this request. A request may carry several views of the same resource
        (`_views`): each rule checks `type`, so it only matches the view it was written for."""
        out = []
        for a in self.policies:
            defn = load(a["definition"])
            for view in fields.get("_views", [fields]):
                eff = PolicyEval(defn, a.get("parameters", {}), view).effect()
                if eff and eff.lower() not in ("disabled", "auditifnotexists"):
                    out.append((a["name"], eff))
        return out

    # ---- requests
    def call_model(self, source: dict, host: str, auth: str) -> Decision:
        ip, dns_why = self.resolve(source, host)
        ok, net_why = self.network(source, ip)
        why = [f"DNS {host} -> {ip}: {dns_why}", f"NETWORK {net_why}"]
        if not ok:
            return Decision(False, "403", why)
        if auth == "key":
            if self.acct.get("local_auth_enabled", True) is False:
                return Decision(False, "401", why + ["AUTH key access is disabled"])
            return Decision(True, "200", why + ["AUTH key accepted: no role check"])
        ident = auth.split(":", 1)[1]
        ok, role_why = self.can(ident, CHAT_ACTION, data=True)
        return Decision(ok, "200" if ok else "401", why + [f"RBAC {ident}: {role_why}"])

    def control(self, who: str, op: str, fields: dict | None = None) -> Decision:
        ok, role_why = self.can(who, op, data=False)
        why = [f"RBAC {who}: {role_why}"]
        if not ok:
            return Decision(False, "403", why)
        if fields:
            effs = self.policy_effects(fields)
            why += [f"POLICY {n}: {e}" for n, e in effs] or ["POLICY every assignment: compliant"]
            if any(e.lower() == "deny" for _, e in effs):
                return Decision(False, "403", why)
        return Decision(True, "200", why)

    def deploy(self, who: str, model: str, version: str, sku: str) -> Decision:
        asset = f"azureml://registries/azure-openai/models/{model}/versions/{version}"
        fields = deployment_fields(model_publisher="OpenAI", asset_id=asset, sku=sku)
        return self.control(who, "Microsoft.CognitiveServices/accounts/deployments/write", fields)


def deployment_fields(model_publisher: str, asset_id: str, sku: str) -> dict:
    """The two views Azure Policy has of one deployment: the Data-mode type the approved-models policy reads,
    and the resource type with sku.name that Microsoft's deployment-type snippet reads. The interpreter checks
    `type` per rule, so each rule only sees the view it was written for."""
    return {"_views": [
        {"type": "Microsoft.CognitiveServices.Data/accounts/deployments",
         "Microsoft.CognitiveServices.Data/accounts/deployments/model.publisher": model_publisher,
         "Microsoft.CognitiveServices.Data/accounts/deployments/model.assetId": asset_id},
        {"type": "Microsoft.CognitiveServices/accounts/deployments",
         "Microsoft.CognitiveServices/accounts/deployments/sku.name": sku},
    ]}

