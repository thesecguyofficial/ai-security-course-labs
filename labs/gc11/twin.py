"""
twin.py: a TEACHING MODEL of the controls around Gemini on Agent Platform, run against an offline "twin" of a
deployment (a Terraform-plan-shaped JSON file + an app settings file). Nothing here contacts Google.

It is not Google's authorization, networking or VPC Service Controls engine. It models only the rules this lab
depends on, each taken from Google's documentation (links in the README):

  1. Credentials. A stolen service account key only works if a user-managed key exists. A workload on a VM uses the
     service account attached to the VM (Application Default Credentials find it through the metadata server).
  2. IAM. A request needs a role that contains the permission. Agent Platform User (roles/aiplatform.user) contains
     aiplatform.endpoints.predict AND aiplatform.endpoints.create/deploy. Custom roles contain what you list.
     Token Creator on the project lets a principal mint tokens for the project's service accounts.
  3. Organization Policy vertexai.allowedModels: no policy = every model and action allowed; an allow-list denies
     every value it doesn't list (values look like publishers/P/models/M:ACTION).
  4. Network path from a VM. An external IP or Cloud NAT = a route to the internet. With neither, Google APIs are
     reached through a Private Service Connect (PSC) endpoint (with a private googleapis.com zone) or Private Google
     Access on the subnet. Private Google Access doesn't support endpoints that end in rep.googleapis.com, and the
     PSC bundles for global Google APIs exclude *.rep.googleapis.com. An egress deny-all firewall rule blocks
     everything not explicitly allowed.
  5. VPC Service Controls. For a restricted service on a project in the perimeter: access from outside (the
     internet, an office) needs an ingress rule; a copy to a project outside needs an egress rule. A perimeter in
     DRY RUN only logs the violation (metadata.dryRun = true); the enforced config (status) denies it.
  6. Evidence. Data Access (DATA_READ) audit logs record who called a model only when switched on; request-response
     logging records what was said; the endpoint location decides where ML processing may happen.

The role -> permission map is a SUBSET written for this lab. Group membership comes from twin/groups.json.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
TWIN = HERE / "twin"

ROLE_PERMISSIONS = {
    "roles/owner": {"*"},
    "roles/editor": {"aiplatform.*", "bigquery.*", "compute.*", "storage.*", "iam.serviceAccountKeys.create"},
    "roles/aiplatform.admin": {"aiplatform.*"},
    # Google's IAM reference lists create and deploy in Agent Platform User: it is not a "call models only" role.
    "roles/aiplatform.user": {"aiplatform.endpoints.predict", "aiplatform.endpoints.create",
                              "aiplatform.endpoints.deploy", "aiplatform.endpoints.undeploy"},
    "roles/aiplatform.viewer": {"aiplatform.endpoints.get", "aiplatform.endpoints.list"},
    "roles/bigquery.dataViewer": {"bigquery.tables.getData", "bigquery.tables.get", "bigquery.tables.list"},
    "roles/bigquery.dataEditor": {"bigquery.tables.getData", "bigquery.tables.get", "bigquery.tables.list",
                                  "bigquery.tables.create", "bigquery.tables.updateData"},
    "roles/iam.serviceAccountTokenCreator": {"iam.serviceAccounts.getAccessToken"},
    "roles/iam.serviceAccountUser": {"iam.serviceAccounts.actAs"},
    "roles/cloudkms.cryptoKeyEncrypterDecrypter": {"cloudkms.cryptoKeyVersions.useToEncrypt",
                                                   "cloudkms.cryptoKeyVersions.useToDecrypt"},
}
BROAD_AI_ROLES = {"roles/owner", "roles/editor", "roles/aiplatform.admin", "roles/aiplatform.user"}


def _grants(perms: set[str], permission: str) -> bool:
    for p in perms:
        if p == "*" or p == permission or (p.endswith(".*") and permission.startswith(p[:-1])):
            return True
    return False


def load_json(path: pathlib.Path):
    return json.loads(pathlib.Path(path).read_text())


@dataclasses.dataclass
class Deployment:
    name: str
    plan: dict
    app: dict
    req: dict
    groups: dict

    @classmethod
    def load(cls, twin: str | pathlib.Path = "today", plan: str | None = None, app: str | None = None):
        d = pathlib.Path(twin) if pathlib.Path(twin).is_dir() else TWIN / str(twin)
        plan_path = pathlib.Path(plan) if plan else d / "plan.json"
        app_path = pathlib.Path(app) if app else d / "app.json"
        groups = load_json(TWIN / "groups.json")
        return cls(name=d.name, plan=load_json(plan_path), app=load_json(app_path),
                   req=load_json(TWIN / "requirements.json"), groups=groups)

    # ---- raw access -----------------------------------------------------------------------------------------------
    def resources(self, rtype: str | None = None) -> list[dict]:
        out = []

        def walk(module):
            out.extend(module.get("resources", []))
            for child in module.get("child_modules", []):
                walk(child)

        walk(self.plan.get("planned_values", {}).get("root_module", {}))
        return [r for r in out if rtype is None or r.get("type") == rtype]

    def values(self, rtype: str) -> list[dict]:
        return [r.get("values", {}) for r in self.resources(rtype)]

    def var(self, name, default=None):
        return self.plan.get("variables", {}).get(name, {}).get("value", default)

    @property
    def project(self) -> str:
        return self.var("project_id", "")

    # ---- identity ---------------------------------------------------------------------------------------------------
    def member_ids(self, principal: str) -> set[str]:
        """The principal plus every group it belongs to (from twin/groups.json)."""
        ids = {principal}
        for group, members in self.groups.items():
            if principal in members:
                ids.add(group)
        return ids

    def custom_roles(self) -> dict[str, set[str]]:
        out = {}
        for v in self.values("google_project_iam_custom_role"):
            out[f"projects/{v.get('project', self.project)}/roles/{v['role_id']}"] = set(v.get("permissions", []))
        return out

    def project_roles(self, principal: str) -> list[str]:
        ids = self.member_ids(principal)
        roles = [v["role"] for v in self.values("google_project_iam_member") if v.get("member") in ids]
        for v in self.values("google_project_iam_binding"):
            if ids & set(v.get("members", [])):
                roles.append(v["role"])
        return roles

    def dataset_roles(self, principal: str, dataset: str) -> list[str]:
        ids = self.member_ids(principal)
        return [v["role"] for v in self.values("google_bigquery_dataset_iam_member")
                if v.get("dataset_id") == dataset and v.get("member") in ids]

    def role_perms(self, role: str) -> set[str]:
        return ROLE_PERMISSIONS.get(role) or self.custom_roles().get(role, set())

    def has_permission(self, principal: str, permission: str, dataset: str | None = None) -> tuple[bool, str]:
        roles = [(r, "project") for r in self.project_roles(principal)]
        if dataset:
            roles += [(r, f"dataset {dataset}") for r in self.dataset_roles(principal, dataset)]
        for role, where in roles:
            if _grants(self.role_perms(role), permission):
                return True, f"{permission} via {role} on {where}"
        return False, f"no role grants {permission} to {principal}"

    def sa_emails_with_keys(self) -> set[str]:
        out = set()
        for v in self.values("google_service_account_key"):
            out.add(v.get("service_account_id", "").rsplit("/", 1)[-1])
        return out

    # ---- org policy -------------------------------------------------------------------------------------------------
    def allowed_models_policy(self) -> dict | None:
        for v in self.values("google_org_policy_policy"):
            if v.get("name", "").endswith("/policies/vertexai.allowedModels"):
                return v
        return None

    def model_allowed(self, value: str) -> tuple[bool, str]:
        pol = self.allowed_models_policy()
        if not pol:
            return True, "no vertexai.allowedModels policy: all models and actions allowed"
        allowed = []
        for spec in pol.get("spec", []):
            for rule in spec.get("rules", []):
                for vals in rule.get("values", []):
                    allowed += vals.get("allowed_values", [])
        if value in allowed:
            return True, f"{value} is on the allow-list"
        return False, f"vertexai.allowedModels allow-list doesn't include {value}"

    # ---- network ----------------------------------------------------------------------------------------------------
    def vms(self) -> dict[str, dict]:
        out = {}
        for v in self.values("google_compute_instance"):
            nic = (v.get("network_interface") or [{}])[0]
            sa = (v.get("service_account") or [{}])[0].get("email", "")
            out[v["name"]] = {"name": v["name"], "sa": sa, "external_ip": bool(nic.get("access_config")),
                              "subnetwork": nic.get("subnetwork"), "labels": v.get("labels", {})}
        return out

    def has_nat(self) -> bool:
        return bool(self.resources("google_compute_router_nat"))

    def psc_endpoint(self) -> dict | None:
        for v in self.values("google_compute_global_forwarding_rule"):
            if v.get("target") in ("all-apis", "vpc-sc"):
                return v
        return None

    def psc_ip(self) -> str | None:
        """The endpoint's internal IP. In a real plan the forwarding rule's ip_address is often a reference that
        is only known after apply, so fall back to the reserved global address (purpose PRIVATE_SERVICE_CONNECT)."""
        psc = self.psc_endpoint()
        if not psc:
            return None
        ip = str(psc.get("ip_address", ""))
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            for a in self.values("google_compute_global_address"):
                if a.get("purpose") == "PRIVATE_SERVICE_CONNECT" and a.get("address"):
                    return a["address"]
        return None

    def private_googleapis_zone(self) -> bool:
        psc = self.psc_endpoint()
        zones = [z for z in self.values("google_dns_managed_zone")
                 if z.get("dns_name") == "googleapis.com." and z.get("visibility") == "private"]
        if not psc or not zones:
            return False
        recs = self.values("google_dns_record_set")
        a_ok = any(r.get("type") == "A" and self.psc_ip() in r.get("rrdatas", []) for r in recs)
        cname_ok = any(r.get("type") == "CNAME" and r.get("name") == "*.googleapis.com." for r in recs)
        return a_ok and cname_ok

    def pga_on(self, subnet: str | None) -> bool:
        return any(v.get("private_ip_google_access") for v in self.values("google_compute_subnetwork")
                   if subnet is None or v.get("name") == subnet)

    def egress_denied_except(self) -> list[str] | None:
        """None if no deny-all egress rule; otherwise the destination ranges explicitly allowed."""
        fws = self.values("google_compute_firewall")
        deny_all = any(f.get("direction") == "EGRESS" and f.get("deny") and "0.0.0.0/0" in f.get("destination_ranges", [])
                       for f in fws)
        if not deny_all:
            return None
        return [r for f in fws if f.get("direction") == "EGRESS" and f.get("allow")
                for r in f.get("destination_ranges", [])]

    def route_to(self, vm: dict, host: str) -> tuple[bool, str, str]:
        """(reachable, path, why) from a VM to a hostname."""
        google = host.endswith("googleapis.com")
        allowed_ranges = self.egress_denied_except()
        internet = vm["external_ip"] or self.has_nat()
        if not google:
            if allowed_ranges is not None:
                return False, "none", "egress firewall denies all traffic except the PSC endpoint"
            if internet:
                return True, "internet", "the VM has a route to the internet (external IP or Cloud NAT)"
            return False, "none", "no external IP and no Cloud NAT: no route to the internet"
        rep = host.endswith(".rep.googleapis.com")
        psc = self.psc_endpoint()
        if not rep and psc and self.private_googleapis_zone():
            ip = self.psc_ip()
            if allowed_ranges is not None and not any(
                    ipaddress.ip_address(ip) in ipaddress.ip_network(r) for r in allowed_ranges):
                return False, "none", "egress firewall blocks the PSC endpoint"
            return True, "psc", f"Private Service Connect endpoint {ip} ({psc['target']} bundle)"
        if internet and allowed_ranges is None:
            return True, "internet", f"{host} over the internet (external IP or Cloud NAT)"
        if not rep and self.pga_on(vm["subnetwork"]) and allowed_ranges is None:
            return True, "pga", "Private Google Access on the subnet"
        if rep:
            return False, "none", (f"{host} ends in rep.googleapis.com: Private Google Access doesn't support it and "
                                   "the PSC bundles for global Google APIs exclude *.rep.googleapis.com")
        return False, "none", "no private path to Google APIs and no internet route"

    # ---- VPC Service Controls ---------------------------------------------------------------------------------------
    def perimeter(self) -> dict | None:
        for v in self.values("google_access_context_manager_service_perimeter"):
            def cfg(block):
                b = (v.get(block) or [{}])
                return b[0] if b else {}
            return {"name": v.get("name"), "status": cfg("status"), "spec": cfg("spec"),
                    "dry_run_explicit": bool(v.get("use_explicit_dry_run_spec"))}
        return None

    def access_level_ranges(self, name: str) -> list[str]:
        for v in self.values("google_access_context_manager_access_level"):
            if v.get("name") == name:
                return [r for b in v.get("basic", []) for c in b.get("conditions", [])
                        for r in c.get("ip_subnetworks", [])]
        return []

    @staticmethod
    def _identity_matches(rule_from: dict, principal: str, ids: set[str]) -> bool:
        itype = rule_from.get("identity_type", "")
        if itype == "ANY_IDENTITY":
            return True
        if itype == "ANY_USER_ACCOUNT":
            return principal.startswith("user:")
        if itype == "ANY_SERVICE_ACCOUNT":
            return principal.startswith("serviceAccount:")
        return bool(ids & set(rule_from.get("identities", [])))

    def _ingress_ok(self, cfg: dict, principal: str, ip: str, service: str) -> bool:
        ids = self.member_ids(principal)
        for pol in cfg.get("ingress_policies", []):
            frm = (pol.get("ingress_from") or [{}])[0]
            to = (pol.get("ingress_to") or [{}])[0]
            if not self._identity_matches(frm, principal, ids):
                continue
            src_ok = False
            for s in frm.get("sources", []):
                for rng in self.access_level_ranges(s.get("access_level", "")):
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(rng):
                        src_ok = True
            if not src_ok:
                continue
            if any(op.get("service_name") in (service, "*") for op in to.get("operations", [])):
                return True
        return False

    def _egress_ok(self, cfg: dict, principal: str, dest_project: str, service: str) -> bool:
        ids = self.member_ids(principal)
        for pol in cfg.get("egress_policies", []):
            frm = (pol.get("egress_from") or [{}])[0]
            to = (pol.get("egress_to") or [{}])[0]
            if self._identity_matches(frm, principal, ids) and dest_project in to.get("resources", []) and any(
                    op.get("service_name") in (service, "*") for op in to.get("operations", [])):
                return True
        return False

    def perimeter_check(self, principal: str, service: str, from_inside: bool, ip: str | None,
                        dest_project: str | None) -> tuple[str, str]:
        """('pass'|'dryrun'|'deny'|'none', why)."""
        p = self.perimeter()
        if not p:
            return "none", "no VPC Service Controls perimeter"
        number = f"projects/{self.var('project_number', '100000000001')}"
        results = []
        for mode, cfg in (("enforced", p["status"]), ("dry run", p["spec"] if p["dry_run_explicit"] else {})):
            if not cfg or service not in cfg.get("restricted_services", []) or number not in cfg.get("resources", []):
                continue
            if not from_inside and not self._ingress_ok(cfg, principal, ip or "0.0.0.0", service):
                results.append((mode, f"ingress from {ip} has no matching ingress rule (NO_MATCHING_ACCESS_LEVEL)"))
            elif dest_project and dest_project not in cfg.get("resources", []) and not self._egress_ok(
                    cfg, principal, dest_project, service):
                results.append((mode, f"copy to {dest_project}, outside the perimeter "
                                      "(RESOURCE_NOT_IN_SAME_SERVICE_PERIMETER)"))
        for mode, why in results:
            if mode == "enforced":
                return "deny", f"VPC Service Controls (enforced): {why}"
        for mode, why in results:
            return "dryrun", f"VPC Service Controls DRY RUN would block this, but only logs it: {why}"
        return "pass", "inside the perimeter rules"

    # ---- evidence ---------------------------------------------------------------------------------------------------
    def data_access_logs_on(self, service: str = "aiplatform.googleapis.com") -> bool:
        for v in self.values("google_project_iam_audit_config"):
            if v.get("service") in (service, "allServices") and any(
                    c.get("log_type") == "DATA_READ" for c in v.get("audit_log_config", [])):
                return True
        return False

    def datasets(self) -> dict[str, dict]:
        out = {}
        for v in self.values("google_bigquery_dataset"):
            # A real plan omits values only known after apply (the key ID), so a non-empty block counts as CMEK.
            key = v.get("default_encryption_configuration") or []
            out[v["dataset_id"]] = {"cmek": bool(key),
                                    "labels": v.get("labels", {}), "location": v.get("location")}
        return out


# ---- requests -----------------------------------------------------------------------------------------------------
@dataclasses.dataclass
class Request:
    principal: str                     # "serviceAccount:x", "user:x"
    credential: str                    # "sa_key" (stolen JSON key), "attached" (VM's service account), "user", "impersonate"
    source: str                        # "vm:NAME" or an IP address
    service: str                       # "aiplatform.googleapis.com", "bigquery.googleapis.com", "webhook"
    permission: str = ""
    model_value: str = ""              # publishers/P/models/M:ACTION, for aiplatform
    dataset: str = ""
    dest_project: str = ""             # for a cross-project copy
    host: str = ""                     # overrides the app's endpoint host
    caller: str = ""                   # for "impersonate": who mints the token


@dataclasses.dataclass
class Decision:
    allowed: bool
    why: str
    notes: list[str] = dataclasses.field(default_factory=list)


def evaluate(r: Request, d: Deployment) -> Decision:
    notes: list[str] = []
    principal = r.principal
    email = principal.split(":", 1)[-1]

    # 1. credentials
    if r.credential == "sa_key":
        if email not in d.sa_emails_with_keys():
            return Decision(False, f"no user-managed key exists for {email}: there is nothing to steal")
        notes.append(f"user-managed JSON key for {email} works from anywhere")
    if r.credential == "impersonate":
        ok, why = d.has_permission(r.caller, "iam.serviceAccounts.getAccessToken")
        if not ok:
            return Decision(False, f"can't mint a token for the service account: {why}")
        notes.append(f"impersonation allowed: {why}")

    # 2. where the request comes from
    from_inside, ip = False, None
    if r.source.startswith("vm:"):
        vm = d.vms().get(r.source[3:])
        if not vm:
            return Decision(False, f"no VM called {r.source[3:]}")
        if r.credential == "attached" and f"serviceAccount:{vm['sa']}" != principal:
            return Decision(False, f"{vm['name']} runs as {vm['sa']}, not {email}")
        host = r.host or (d.app.get("endpoint_host") if r.service == "aiplatform.googleapis.com" else
                          ("bigquery.googleapis.com" if r.service == "bigquery.googleapis.com" else "attacker.example"))
        ok, path, why = d.route_to(vm, host)
        if not ok:
            return Decision(False, f"network: {why}")
        notes.append(f"path: {why}")
        from_inside = path in ("psc", "pga") or not vm["external_ip"]
        ip = "10.10.0.5"
        if path == "internet":
            from_inside, ip = False, "203.0.113.200"
    else:
        ip = r.source
        notes.append(f"from {ip} over the internet")

    if r.service == "webhook":
        return Decision(True, "data sent to a non-Google destination: VPC Service Controls covers Google APIs only",
                        notes)

    # 3. IAM
    ok, why = d.has_permission(principal, r.permission, r.dataset or None)
    if not ok:
        return Decision(False, f"IAM: {why}", notes)
    notes.append(f"IAM: {why}")

    # 4. org policy
    if r.model_value:
        ok, why = d.model_allowed(r.model_value)
        if not ok:
            return Decision(False, f"org policy: {why}", notes)
        notes.append(f"org policy: {why}")

    # 5. perimeter
    verdict, why = d.perimeter_check(principal, r.service, from_inside, ip, r.dest_project or None)
    if verdict == "deny":
        return Decision(False, why, notes)
    notes.append(why)
    return Decision(True, "every check passed", notes)
