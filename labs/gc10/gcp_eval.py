"""
gcp_eval.py: a TEACHING MODEL of how Google Cloud decides whether an AI request goes through.

It is not Google's authorization engine. It models only the rules this lab depends on, each taken from Google's
documentation (links in the README):

  1. Credentials. An API key is checked first: deleted keys fail; API restrictions (apiTargets) name the services it
     may call; server (IP) restrictions name the callers' addresses. A standard key carries no identity: requests are
     tied to the key's project for billing and quota. A key bound to a service account (an "authorization key")
     authenticates AS that service account, so IAM applies to the service account.
     The Gemini API (generativelanguage.googleapis.com) rejects requests from unrestricted standard keys.
  2. IAM allow policies. Roles granted on the organization or a folder are inherited by every project below it.
     A request needs one role, anywhere up the hierarchy, that contains the permission. (Deny policies aren't modelled.)
  3. Organization Policy. For the list constraint vertexai.allowedModels, values look like
     publishers/PUBLISHER/models/MODEL:ACTION. No policy anywhere = everything allowed. A policy with
     inheritFromParent merges with its parent's; otherwise it replaces it. An explicit deny beats any allow.
     If an allow-list exists, a value not on it is denied. For boolean/managed constraints the closest policy wins;
     iam.managed.disableServiceAccountApiKeyCreation is enforced by default, iam.managed.disableServiceAccountKeyCreation
     only by default for organizations created on or after 3 May 2024.
  4. The service must be enabled in the project.

The role -> permission map below is a SUBSET written for this lab (real roles have far more permissions).
Simplification: creating an authorization key (CreateKey with bind_to_sa) checks only apikeys.keys.create and the
org constraint. Google also lists Service Account User and Service Account API Key Binding Admin for that; the lab
assumes Editor covers them (Google's docs don't say either way).
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import ipaddress
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
CORP = HERE / "examplecorp"
FIXES = HERE / "fixes"

# --- role -> permissions (subset, for this lab only) -------------------------------------------------------------
# "*" = every permission. A trailing ".*" is a prefix match.
ROLE_PERMISSIONS = {
    "roles/owner": {"*"},
    # Editor: broad write access, but it can't change IAM policies or org policies.
    "roles/editor": {"aiplatform.*", "iam.serviceAccountKeys.create", "apikeys.keys.create", "run.*",
                     "serviceusage.services.enable", "storage.*", "compute.*"},
    "roles/viewer": {"aiplatform.endpoints.get", "aiplatform.endpoints.list"},
    "roles/aiplatform.admin": {"aiplatform.*"},
    # Agent Platform User is broader than "call a model": Google's access-control page lists predict AND
    # aiplatform.endpoints.create/deploy/undeploy in it. So the model allow-list, not this role, stops deployments.
    "roles/aiplatform.user": {"aiplatform.endpoints.predict", "aiplatform.endpoints.create",
                              "aiplatform.endpoints.deploy", "aiplatform.endpoints.undeploy"},
    "roles/aiplatform.viewer": {"aiplatform.endpoints.get", "aiplatform.endpoints.list"},
    "roles/run.developer": {"run.services.create", "run.services.update", "run.services.get"},
    "roles/serviceusage.apiKeysAdmin": {"apikeys.keys.create", "apikeys.keys.update", "apikeys.keys.delete"},
    "roles/serviceusage.serviceUsageAdmin": {"serviceusage.services.enable"},
    "roles/iam.serviceAccountKeyAdmin": {"iam.serviceAccountKeys.create"},
    "roles/iam.serviceAccountApiKeyBindingAdmin": {"iam.serviceAccountApiKeyBindings.create"},
    "roles/iam.serviceAccountUser": {"iam.serviceAccounts.actAs"},
    "roles/consumerprocurement.entitlementManager": {"consumerprocurement.entitlements.manage"},
    "roles/resourcemanager.organizationAdmin": {"resourcemanager.*"},
    "roles/orgpolicy.policyAdmin": {"orgpolicy.*"},
    "roles/logging.privateLogViewer": {"logging.privateLogEntries.list"},
}

MODEL_ACTIONS = {"predict", "deploy", "tune"}
SA_KEY_BLOCK = "iam.managed.disableServiceAccountKeyCreation"
SA_API_KEY_BLOCK = "iam.managed.disableServiceAccountApiKeyCreation"
SECURE_BY_DEFAULT_DATE = dt.datetime(2024, 5, 3, tzinfo=dt.timezone.utc)


def load_json(path):
    return json.loads(pathlib.Path(path).read_text())


def role_grants(role, permission):
    for p in ROLE_PERMISSIONS.get(role, set()):
        if p == "*" or p == permission or (p.endswith(".*") and permission.startswith(p[:-1])):
            return True
    return False


# --- the company ----------------------------------------------------------------------------------------------------
class Corp:
    """ExampleCo's setup, optionally with the files in fixes/ applied."""

    def __init__(self, with_fixes=False, extra_org_policies=(), keys_file=None):
        h = load_json(CORP / "hierarchy.json")
        self.org = h["organization"]
        self.folders = {f["name"]: f for f in h["folders"]}
        self.projects = {p["projectId"]: p for p in h["projects"]}
        self.by_number = {p["projectNumber"]: p["projectId"] for p in h["projects"]}
        self.iam = {}
        for f in sorted((CORP / "iam").glob("*.json")):
            pol = load_json(f)
            self.iam[pol["_resource"]] = pol
        self.org_policies = {}
        for f in sorted((CORP / "org-policies").glob("*.json")):
            pol = load_json(f)
            self.org_policies[pol["name"]] = pol
        self.keys = load_json(keys_file or CORP / "api-keys.json")["keys"]
        self.budgets = load_json(CORP / "budgets.json")["budgets"]
        self.service_accounts = load_json(CORP / "service-accounts.json")["serviceAccounts"]
        self.approved = load_json(CORP / "approved-models.json")
        self.groups = load_json(CORP / "groups.json")["groups"]
        self.applied_fixes = []
        if with_fixes:
            self.apply_fixes()
        for path in extra_org_policies:
            pol = load_json(path)
            self.org_policies[pol["name"]] = pol
            self.applied_fixes.append(pathlib.Path(path).name)

    def apply_fixes(self):
        for f in sorted(FIXES.glob("orgpolicy-*.json")):
            pol = load_json(f)
            self.org_policies[pol["name"]] = pol
            self.applied_fixes.append(f.name)
        for f in sorted(FIXES.glob("iam-*.json")):
            pol = load_json(f)
            self.iam[pol["_resource"]] = pol
            self.applied_fixes.append(f.name)
        if (FIXES / "api-keys.json").exists():
            self.keys = load_json(FIXES / "api-keys.json")["keys"]
            self.applied_fixes.append("api-keys.json")
        for f in sorted(FIXES.glob("budget-*.json")):
            self.budgets = self.budgets + [load_json(f)]
            self.applied_fixes.append(f.name)

    # hierarchy -----------------------------------------------------------------------------------------------------
    def ancestry(self, project_id):
        """[project, folder..., organization] resource names, nearest first."""
        p = self.projects[project_id]
        chain = [f"projects/{project_id}"]
        parent = p["parent"]
        while parent.startswith("folders/"):
            chain.append(parent)
            parent = self.folders[parent]["parent"]
        chain.append(parent)
        return chain

    def env_of(self, project_id):
        return "prod" if "folders/111111111111" in self.ancestry(project_id) else "sandbox"

    # IAM -----------------------------------------------------------------------------------------------------------
    def identities(self, member):
        """The member itself plus every group it belongs to."""
        return {member} | {g for g, members in self.groups.items() if member in members}

    def has_permission(self, member, permission, project_id):
        """Return (True, 'role on resource') or (False, reason)."""
        who = self.identities(member)
        for res in self.ancestry(project_id):
            for b in self.iam.get(res, {}).get("bindings", []):
                hit = who & set(b["members"])
                if hit and role_grants(b["role"], permission):
                    via = "" if member in hit else f" (as {sorted(hit)[0].split(':', 1)[1]})"
                    return True, f"{b['role']} on {res}{via}"
        return False, f"no role on {project_id} or its folders/org gives {member.split(':', 1)[1]} {permission}"

    def bindings_everywhere(self):
        for res, pol in self.iam.items():
            for b in pol.get("bindings", []):
                yield res, b

    def audit_configs(self, project_id):
        return self.iam.get(f"projects/{project_id}", {}).get("auditConfigs", [])

    # Organization Policy -------------------------------------------------------------------------------------------
    def _policy_at(self, res, constraint):
        return self.org_policies.get(f"{res}/policies/{constraint}")

    def effective_list(self, project_id, constraint="vertexai.allowedModels"):
        """Merge list-constraint policies from the org down to the project.
        Returns (allowed_values or None, denied_values, sources). None = no allow-list."""
        allowed, denied, sources = None, set(), []
        for res in reversed(self.ancestry(project_id)):  # org first
            pol = self._policy_at(res, constraint)
            if not pol:
                continue
            spec = pol.get("spec", {})
            if not spec.get("inheritFromParent", False) or spec.get("reset"):
                allowed, denied, sources = None, set(), []
            sources.append(pol["name"])
            for rule in spec.get("rules", []):
                if rule.get("allowAll"):
                    allowed = None
                elif rule.get("denyAll"):
                    allowed = set()
                vals = rule.get("values", {})
                if "allowedValues" in vals:
                    allowed = (allowed or set()) | set(vals["allowedValues"])
                denied |= set(vals.get("deniedValues", []))
        return allowed, denied, sources

    def model_allowed(self, project_id, model_value):
        allowed, denied, sources = self.effective_list(project_id)
        if model_value in denied:
            return False, f"explicit deny in vertexai.allowedModels ({sources[-1]})"
        if allowed is not None and model_value not in allowed:
            return False, f"not on the vertexai.allowedModels allow-list ({sources[-1]})"
        if not sources:
            return True, "no vertexai.allowedModels policy anywhere: all models and actions allowed"
        if allowed is None:
            return True, f"vertexai.allowedModels is only a deny-list here and doesn't name this model ({sources[-1]})"
        return True, f"on the vertexai.allowedModels allow-list ({sources[-1]})"

    def boolean_enforced(self, project_id, constraint):
        for res in self.ancestry(project_id):  # nearest first
            pol = self._policy_at(res, constraint)
            if pol:
                rules = pol.get("spec", {}).get("rules", [])
                if rules and "enforce" in rules[0]:
                    return bool(rules[0]["enforce"]), pol["name"]
        # Google's defaults (see module docstring)
        if constraint == SA_API_KEY_BLOCK:
            return True, "Google default"
        if constraint == SA_KEY_BLOCK:
            created = dt.datetime.fromisoformat(self.org["createTime"].replace("Z", "+00:00"))
            return created >= SECURE_BY_DEFAULT_DATE, "secure-by-default baseline" if created >= SECURE_BY_DEFAULT_DATE else "not set (org created before 3 May 2024)"
        return False, "not set"

    # API keys ------------------------------------------------------------------------------------------------------
    def key(self, display_name):
        for k in self.keys:
            if k["displayName"] == display_name:
                return k
        raise KeyError(display_name)

    def key_project(self, k):
        return self.by_number[k["name"].split("/")[1]]


# --- requests -------------------------------------------------------------------------------------------------------
@dataclasses.dataclass
class Request:
    caller: str                  # "serviceAccount:x@...", "user:x@...", or "apikey:<displayName>"
    project: str                 # target project ID
    service: str                 # e.g. aiplatform.googleapis.com
    method: str                  # e.g. GenerateContent, RawPredict, DeployModel, CreateServiceAccountKey, CreateKey
    permission: str = ""         # IAM permission checked
    model: str = ""              # publishers/P/models/M:ACTION for AI calls
    source_ip: str = "192.0.2.10"
    bind_to_sa: str = ""         # CreateKey: service account to bind (authorization key)


@dataclasses.dataclass
class Decision:
    allowed: bool
    checks: list                 # list of (ok: bool, text)

    @property
    def why(self):
        bad = [t for ok, t in self.checks if not ok]
        if bad:
            return "; ".join(bad)
        return "every check passed: " + "; ".join(t for _, t in self.checks)


def _ip_in(ip, allowed):
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(a, strict=False) for a in allowed)


def evaluate(corp: Corp, req: Request) -> Decision:
    checks = []
    member = req.caller

    # 1. credentials
    if req.caller.startswith("apikey:"):
        k = corp.key(req.caller.split(":", 1)[1])
        r = k.get("restrictions", {})
        if k.get("deleteTime"):
            checks.append((False, f"API key {k['displayName']} was deleted"))
            return Decision(False, checks)
        targets = [t["service"] for t in r.get("apiTargets", [])]
        if targets and req.service not in targets:
            checks.append((False, f"API restriction: key {k['displayName']} may only call {', '.join(targets)}"))
        ips = r.get("serverKeyRestrictions", {}).get("allowedIps")
        if ips and not _ip_in(req.source_ip, ips):
            checks.append((False, f"application restriction: {req.source_ip} is not in {ips}"))
        unrestricted = not r
        sa = k.get("serviceAccountEmail")
        if req.service == "generativelanguage.googleapis.com" and unrestricted and not sa:
            checks.append((False, "the Gemini API rejects requests from unrestricted standard keys"))
        if any(not ok for ok, _ in checks):
            return Decision(False, checks)
        if sa:
            member = f"serviceAccount:{sa}"
            checks.append((True, f"authorization key: authenticates as {sa}"))
        else:
            if corp.key_project(k) != req.project:
                checks.append((False, f"standard key belongs to {corp.key_project(k)}, not {req.project}"))
                return Decision(False, checks)
            what = "UNRESTRICTED standard key" if unrestricted else "standard key, restrictions passed"
            checks.append((True, f"{what} (no identity; billed to {req.project})"))
            member = None

    # 2. service enabled
    if req.service not in corp.projects[req.project]["enabledServices"] and req.service != "iam.googleapis.com" \
            and req.service != "serviceusage.googleapis.com":
        checks.append((False, f"{req.service} is not enabled in {req.project}"))
        return Decision(False, checks)

    # 3. IAM
    if member is not None and req.permission:
        ok, text = corp.has_permission(member, req.permission, req.project)
        checks.append((ok, f"IAM: {req.permission} via {text}" if ok else f"IAM: {text}"))

    # 4. organization policy
    if req.model:
        ok, text = corp.model_allowed(req.project, req.model)
        checks.append((ok, f"org policy: {text}"))
    if req.method == "CreateServiceAccountKey":
        on, src = corp.boolean_enforced(req.project, SA_KEY_BLOCK)
        checks.append((not on, f"org policy {SA_KEY_BLOCK}: {'ENFORCED' if on else 'not enforced'} ({src})"))
    if req.method == "CreateKey" and req.bind_to_sa:
        on, src = corp.boolean_enforced(req.project, SA_API_KEY_BLOCK)
        checks.append((not on, f"org policy {SA_API_KEY_BLOCK}: {'ENFORCED' if on else 'not enforced'} ({src})"))

    return Decision(all(ok for ok, _ in checks), checks)
