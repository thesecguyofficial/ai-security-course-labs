"""
twin.py: the offline stand-in for Azure Machine Learning. Standard library only, no network, no Azure account.

    python3 twin.py decide <setup> <principal> <action> <scope>     # Azure RBAC: allowed or not, and why
    python3 twin.py invoke <setup> <caller> <internet|vnet> <key|aad> [deployment]
    python3 twin.py egress <setup> <workspace> <target>             # can code in this workspace reach <target>?
    python3 twin.py policy <setup> <request.json>                   # Azure Policy decision for one request

What it copies (README, "How faithful is the twin?", has the source for each line):
  * Azure RBAC: role assignments at a scope apply to everything below it; Actions minus NotActions, DataActions
    minus NotDataActions; '*' matches any part of an operation name; no deny assignments, no conditions, no PIM.
  * Azure Policy: if/then rules with field conditions (equals, notEquals, in, notIn, like, notLike, contains,
    exists, count), allOf/anyOf/not, parameters with defaults; effects Deny, Audit, Disabled. String comparisons
    ignore case, as Azure Policy does.
  * The workspace managed VNet: Disabled, AllowInternetOutbound, AllowOnlyApprovedOutbound (private endpoint, FQDN
    and service tag rules; the workspace's own storage, key vault and container registry get required private
    endpoint rules automatically).
  * Inbound: the workspace's and the endpoint's public_network_access, and the workspace private endpoint.
  * Online endpoints: auth modes key and aad_token, keys from listKeys, traffic split, and the
    azureml-model-deployment header that routes to a named deployment whatever its traffic share.
  * Model loading: the endpoint identity downloads the files the deployment names; a pickle-based weights file runs
    code when it is loaded (twin choice: the worst case).
SAFETY: nothing here touches a network or runs a model file. "Code ran" is a simulation decided by model_files.py's
scanner, which only parses files.
"""

from __future__ import annotations

import copy
import fnmatch
import json
import pathlib
import re
import sys

import model_files

HERE = pathlib.Path(__file__).resolve().parent
COMPANY = json.loads((HERE / "contoso.json").read_text())
ENVIRONMENTS = json.loads((HERE / "environments.json").read_text())
SUB = "/subscriptions/" + COMPANY["subscription_id"]
ML = "Microsoft.MachineLearningServices"
STORAGE_RG = {"sttsgml": "rg-tsg-ml", "sttsgmldev": "rg-tsg-ml-dev", "stcontosomlreg": "rg-tsg-ml-registry",
              "sthrexports": "rg-hr", "sttsgtickets": "rg-tsg-ml", "stanalytics": "rg-analytics",
              "sttsgpayloads": "rg-tsg-ml"}

# Operation names used by the lab (Azure RBAC "actions" and "data actions").
A_DEPLOY_WRITE = f"{ML}/workspaces/onlineEndpoints/deployments/write"
A_DEPLOY_READ = f"{ML}/workspaces/onlineEndpoints/deployments/read"
A_ENDPOINT_WRITE = f"{ML}/workspaces/onlineEndpoints/write"
A_LIST_KEYS = f"{ML}/workspaces/onlineEndpoints/listKeys/action"
A_SCORE = f"{ML}/workspaces/onlineEndpoints/score/action"
A_MODEL_WRITE = f"{ML}/workspaces/models/versions/write"
A_DATASTORE_READ = f"{ML}/workspaces/datastores/read"
A_DATASTORE_SECRETS = f"{ML}/workspaces/datastores/listSecrets/action"   # twin's name for "Datastores - List Secrets"
A_REGISTRY_ASSET_WRITE = f"{ML}/registries/assets/write"
A_WORKSPACE_WRITE = f"{ML}/workspaces/write"
D_BLOB_READ = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
D_BLOB_WRITE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"

# Built-in roles the lab uses, cut to the operations that matter here. AzureML Data Scientist and AzureML Registry
# User follow Microsoft's built-in role reference (AI + machine learning); the others are the well-known basics.
BUILTIN_ROLES = {
    "Owner": {"actions": ["*"]},
    "Contributor": {"actions": ["*"], "not_actions": ["Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write",
                                                      "Microsoft.Authorization/elevateAccess/Action"]},
    "Reader": {"actions": ["*/read"]},
    "AzureML Data Scientist": {
        "actions": [f"{ML}/workspaces/*/read", f"{ML}/workspaces/*/action", f"{ML}/workspaces/*/delete", f"{ML}/workspaces/*/write"],
        "not_actions": [f"{ML}/workspaces/delete", f"{ML}/workspaces/write", f"{ML}/workspaces/computes/*/write",
                        f"{ML}/workspaces/computes/*/delete", f"{ML}/workspaces/computes/listKeys/action",
                        f"{ML}/workspaces/listKeys/action"]},
    "AzureML Registry User": {"actions": [f"{ML}/registries/read", f"{ML}/registries/assets/*"]},
    "AzureML Registry User (read only)": {"actions": [f"{ML}/registries/read", f"{ML}/registries/assets/read"]},
    "Storage Blob Data Reader": {"actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
                                 "data_actions": [D_BLOB_READ]},
    "Storage Blob Data Contributor": {"actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/*"],
                                      "data_actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"]},
    "AcrPull": {"actions": ["Microsoft.ContainerRegistry/registries/pull/read"]},
}

FILES = ("workspace", "endpoint", "deployments", "models", "rbac", "datastores", "policy", "policy-challenge",
         "monitoring", "app")


# --------------------------------------------------------------------------------------------------------------------
# Scopes and names
# --------------------------------------------------------------------------------------------------------------------
def ws_id(ws: str) -> str:
    return f"{SUB}/resourceGroups/{COMPANY['workspaces'][ws]['resource_group']}/providers/{ML}/workspaces/{ws}"


def scope_id(token: str) -> str:
    """Expand a lab scope token (sub, rg:, ws:, endpoint:, deployment:, model:, datastore:, registry:, regasset:,
    storage:) into a full Azure resource ID. Full IDs pass through unchanged."""
    if token.startswith("/"):
        return token
    kind, _, rest = token.partition(":")
    if kind == "sub":
        return SUB
    if kind == "rg":
        return f"{SUB}/resourceGroups/{rest}"
    if kind == "ws":
        return ws_id(rest)
    if kind == "endpoint":
        ws, ep = rest.split("/")
        return f"{ws_id(ws)}/onlineEndpoints/{ep}"
    if kind == "deployment":
        ws, ep, dep = rest.split("/")
        return f"{ws_id(ws)}/onlineEndpoints/{ep}/deployments/{dep}"
    if kind == "model":
        ws, name, ver = rest.split("/")
        return f"{ws_id(ws)}/models/{name}/versions/{ver}"
    if kind == "datastore":
        ws, name = rest.split("/")
        return f"{ws_id(ws)}/datastores/{name}"
    if kind in ("registry", "regasset"):
        reg = COMPANY["registry"]
        parts = rest.split("/")
        rid = f"{SUB}/resourceGroups/{reg['resource_group']}/providers/{ML}/registries/{parts[0]}"
        return rid + (f"/models/{parts[1]}/versions/{parts[2]}" if kind == "regasset" else "")
    if kind == "storage":
        acct, _, path = rest.partition("/")
        rid = f"{SUB}/resourceGroups/{STORAGE_RG.get(acct, 'rg-unknown')}/providers/Microsoft.Storage/storageAccounts/{acct}"
        container = path.split("/", 1)[0] if path else ""
        return rid + (f"/blobServices/default/containers/{container}" if container else "")
    raise ValueError(f"unknown scope token: {token}")


def oid(principal: str) -> str:
    return COMPANY["principals"][principal]["oid"]


def name_for_oid(value: str) -> str:
    for n, p in COMPANY["principals"].items():
        if p["oid"] == value:
            return n
    return value


# --------------------------------------------------------------------------------------------------------------------
# The setup (one folder under setups/)
# --------------------------------------------------------------------------------------------------------------------
class Setup:
    def __init__(self, name: str):
        self.name = name
        folder = HERE / "setups" / name
        if not folder.is_dir():
            raise SystemExit(f"no such setup: {name} (try first-draft or hardened)")
        for f in FILES:
            p = folder / f"{f}.json"
            setattr(self, f.replace("-", "_"), json.loads(p.read_text()) if p.exists() else {})
        _fill_hashes(self.models)

    def copy(self) -> "Setup":
        return copy.deepcopy(self)

    def policy_assignments(self) -> list[dict]:
        return list(self.policy.get("assignments", [])) + list(self.policy_challenge.get("assignments", []))


def _fill_hashes(models: dict) -> None:
    """The setups say SET-BY-BUILD where the registration step recorded each file's sha256: fill in the real ones."""
    for versions in models.values():
        if not isinstance(versions, dict):
            continue
        for v in versions.values():
            if not isinstance(v, dict):
                continue
            want = model_files.manifest(model_files.build(v["files"]))
            for k in list(v.get("tags", {})):
                if v["tags"][k] == "SET-BY-BUILD":
                    v["tags"][k] = want.get(k, "missing")


# --------------------------------------------------------------------------------------------------------------------
# Azure RBAC
# --------------------------------------------------------------------------------------------------------------------
def _match(pattern: str, op: str) -> bool:
    return fnmatch.fnmatchcase(op.lower(), pattern.lower())


def role_definition(s: Setup, role: str) -> dict:
    if role in BUILTIN_ROLES:
        return BUILTIN_ROLES[role]
    if role in s.rbac.get("custom_roles", {}):
        return s.rbac["custom_roles"][role]
    raise KeyError(f"unknown role: {role}")


def _covers(assigned_scope: str, target: str) -> bool:
    a, t = assigned_scope.lower().rstrip("/"), target.lower().rstrip("/")
    return t == a or t.startswith(a + "/")


def decide(s: Setup, principal: str, op: str, scope: str, data: bool = False) -> tuple[bool, str]:
    """Is `principal` allowed to perform `op` (an action, or a data action when data=True) on `scope`?"""
    target = scope_id(scope)
    for a in s.rbac.get("assignments", []):
        if a["principal"] != principal or not _covers(scope_id(a["scope"]), target):
            continue
        role = a["role"] + (" (read only)" if a.get("_restricted_to") == "read" else "")
        d = role_definition(s, role)
        allow = d.get("data_actions" if data else "actions", [])
        deny = d.get("not_data_actions" if data else "not_actions", [])
        if any(_match(p, op) for p in allow) and not any(_match(p, op) for p in deny):
            return True, f"{a['role']} at {a['scope']}"
    return False, "no role assignment grants it"


# --------------------------------------------------------------------------------------------------------------------
# Azure Policy (the subset of the policy language the lab's rules use)
# --------------------------------------------------------------------------------------------------------------------
def _split_args(text: str) -> list[str]:
    out, depth, cur, quote = [], 0, "", False
    for ch in text:
        if ch == "'" :
            quote = not quote
        if not quote and ch == "(":
            depth += 1
        if not quote and ch == ")":
            depth -= 1
        if ch == "," and depth == 0 and not quote:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _expr(value, params: dict, current: dict):
    """Resolve "[parameters('x')]", "[current('x')]" and "[concat(...)]"; anything else is a literal."""
    if not (isinstance(value, str) and value.startswith("[") and value.endswith("]")):
        return value
    return _call(value[1:-1].strip(), params, current)


def _call(text: str, params: dict, current: dict):
    if text.startswith("'") and text.endswith("'"):
        return text[1:-1]
    m = re.fullmatch(r"(\w+)\((.*)\)", text, flags=re.S)
    if not m:
        raise ValueError(f"policy expression not supported by the twin: {text}")
    fn, args = m.group(1).lower(), [_call(a, params, current) for a in _split_args(m.group(2))]
    if fn == "parameters":
        return params[args[0]]
    if fn == "current":
        return current[args[0]]
    if fn == "concat":
        return "".join(str(a) for a in args)
    raise ValueError(f"policy function not supported by the twin: {fn}")


def _field(request: dict, name: str):
    if name.lower() == "type":
        return request.get("type")
    for prefix in (f"{ML}.v2.Data/workspaces/deployments/", f"{ML}/workspaces/"):
        if name.lower().startswith(prefix.lower()):
            node = request if ".v2.Data" in prefix else request.get("properties", {})
            for part in name[len(prefix):].split("."):
                if not isinstance(node, dict):
                    return None
                node = {k.lower(): v for k, v in node.items()}.get(part.lower())
            return node
    return None


def _like(value: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(str(value).lower(), str(pattern).lower())


def _test(cond: dict, request: dict, params: dict, current: dict) -> bool:
    if "allOf" in cond:
        return all(_test(c, request, params, current) for c in cond["allOf"])
    if "anyOf" in cond:
        return any(_test(c, request, params, current) for c in cond["anyOf"])
    if "not" in cond:
        return not _test(cond["not"], request, params, current)
    if "count" in cond:
        spec = cond["count"]
        items = _expr(spec["value"], params, current) or []
        n = sum(1 for it in items if _test(spec["where"], request, params, {**current, spec["name"]: it}))
        return _compare(n, cond, params, current)
    value = _field(request, cond["field"])
    return _compare(value, cond, params, current)


def _compare(value, cond: dict, params: dict, current: dict) -> bool:
    low = lambda v: v.lower() if isinstance(v, str) else v
    for op in ("equals", "notEquals", "in", "notIn", "notin", "like", "notLike", "contains", "notContains", "exists"):
        if op not in cond:
            continue
        want = _expr(cond[op], params, current)
        if op == "exists":
            return (value is not None) == (str(want).lower() == "true")
        if op == "equals":
            return value is not None and low(value) == low(want)
        if op == "notEquals":
            return value is None or low(value) != low(want)
        if op == "in":
            return value is not None and low(value) in [low(w) for w in want]
        if op in ("notIn", "notin"):
            return value is None or low(value) not in [low(w) for w in want]
        if op == "like":
            return value is not None and _like(value, want)
        if op == "notLike":
            return value is None or not _like(value, want)
        if op == "contains":
            return value is not None and str(want).lower() in str(value).lower()
        if op == "notContains":
            return value is None or str(want).lower() not in str(value).lower()
    raise ValueError(f"condition not supported by the twin: {cond}")


def policy_check(s: Setup, request: dict) -> dict:
    """Every assignment's verdict on one create or update request. Returns {"denied": [...], "audited": [...]}."""
    out = {"denied": [], "audited": []}
    for a in s.policy_assignments():
        params = {k: v.get("defaultValue") for k, v in a.get("parameter_definitions", {}).items()}
        params.update(a.get("parameters", {}))
        params["effect"] = a.get("effect", params.get("effect", "Audit"))
        try:
            hit = _test(a["rule"]["if"], request, params, {})
        except (KeyError, TypeError):
            hit = False
        effect = str(_expr(a["rule"]["then"]["effect"], params, {})).lower()
        if hit and effect == "deny":
            out["denied"].append(a["name"])
        elif hit and effect == "audit":
            out["audited"].append(a["name"])
    return out


def workspace_request(name: str, ws: dict) -> dict:
    return {"type": f"{ML}/workspaces", "name": name, "properties": {
        "publicNetworkAccess": ws.get("publicNetworkAccess"),
        "managedNetwork": {"isolationMode": ws.get("managedNetwork", {}).get("isolationMode", "Disabled")}}}


def deployment_request(model_ref: str) -> dict:
    """The data-plane view the registry-model policies read (mode Microsoft.MachineLearningServices.v2.Data)."""
    req = {"type": f"{ML}.v2.Data/workspaces/deployments", "model": {"assetId": model_ref}}
    m = re.match(r"azureml://registries/([^/]+)/", model_ref)
    if m:
        req["model"]["registryName"] = m.group(1)
    return req


# --------------------------------------------------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------------------------------------------------
def isolation_mode(s: Setup, ws: str) -> str:
    return s.workspace[ws].get("managedNetwork", {}).get("isolationMode", "Disabled")


def _own(s: Setup, ws: str) -> set[str]:
    w = COMPANY["workspaces"][ws]
    return {f"storage:{w['storage']}", f"kv:{w['key_vault']}", f"acr:{w['registry_acr']}", f"ws:{ws}"}


def egress(s: Setup, ws: str, target: str) -> tuple[bool, str]:
    """Can code on compute in workspace `ws` (a deployment or a compute instance) reach `target`?
    target: internet:<host>, storage:<account>, registry:<name>, acr:<name>, kv:<name>, mcr (Microsoft's
    container registry, a required service tag rule)."""
    mode = isolation_mode(s, ws)
    if mode == "Disabled":
        return True, "no managed VNet: outbound traffic isn't restricted"
    if mode == "AllowInternetOutbound":
        return True, "managed VNet in allow internet outbound mode"
    if target == "mcr" or target in _own(s, ws):
        return True, "required rule created automatically in approved-outbound mode"
    rules = s.workspace[ws].get("managedNetwork", {}).get("outboundRules", {})
    host = target.split(":", 1)[1] if target.startswith("internet:") else (
        f"{target.split(':', 1)[1]}.blob.core.windows.net" if target.startswith("storage:") else "")
    for name, r in rules.items():
        if r["type"] == "PrivateEndpoint" and r["destination"] == target:
            return True, f"private endpoint outbound rule '{name}'"
        if r["type"] == "FQDN" and host and _like(host.split("/", 1)[0], r["destination"]):
            return True, f"FQDN outbound rule '{name}' ({r['destination']}), through the workspace's Azure Firewall"
    return False, "approved-outbound mode: no outbound rule allows it"


def inbound(s: Setup, what: str, network: str) -> tuple[bool, str]:
    """what = 'endpoint' or a workspace name. network = 'internet' or 'vnet' (Contoso's network, which has the
    workspace private endpoint when the setup has one)."""
    ws = s.endpoint["workspace"] if what == "endpoint" else what
    flag = s.endpoint.get("public_network_access", "enabled") if what == "endpoint" else \
        s.workspace[ws].get("publicNetworkAccess", "Enabled")
    if str(flag).lower() == "enabled":
        return True, "public network access is enabled"
    if network == "vnet" and s.workspace[ws].get("privateEndpoint"):
        return True, "through the workspace private endpoint"
    return False, "public network access is disabled" + ("" if network == "internet" else " and there's no private endpoint")


# --------------------------------------------------------------------------------------------------------------------
# The endpoint
# --------------------------------------------------------------------------------------------------------------------
def endpoint_scope(s: Setup) -> str:
    return f"endpoint:{s.endpoint['workspace']}/{s.endpoint['name']}"


def list_keys(s: Setup, principal: str) -> tuple[str | None, str]:
    """listKeys is a control-plane action: it goes to Azure Resource Manager over the public network, so only RBAC
    decides. With aad_token auth the twin hands out no usable key."""
    ok, why = decide(s, principal, A_LIST_KEYS, endpoint_scope(s))
    if not ok:
        return None, f"listKeys DENIED ({why})"
    if s.endpoint.get("auth_mode", "key") != "key":
        return None, f"listKeys allowed ({why}), but the endpoint uses {s.endpoint['auth_mode']}: no key to use"
    return s.endpoint.get("_keys", {}).get("primary"), f"listKeys allowed ({why})"


def invoke(s: Setup, caller: str, network: str, credential: str, header: str | None = None) -> dict:
    """One scoring request. credential 'key' = the caller holds a key; 'aad' = an Entra token for `caller`."""
    ok, why = inbound(s, "endpoint", network)
    if not ok:
        return {"ok": False, "why": f"refused at the network: {why}"}
    mode = s.endpoint.get("auth_mode", "key")
    if mode == "key":
        if credential != "key":
            return {"ok": False, "why": "the endpoint expects a key"}
        auth = "key auth: no role needed, the key is enough"
    else:
        if credential != "aad":
            return {"ok": False, "why": f"401: the endpoint uses {mode}, a key isn't accepted"}
        allowed, rwhy = decide(s, caller, A_SCORE, endpoint_scope(s))
        if not allowed:
            return {"ok": False, "why": f"403: {caller} has no score/action ({rwhy})"}
        auth = f"Entra token for {caller} ({rwhy})"
    traffic = s.endpoint.get("traffic", {})
    if header:
        if header not in s.deployments or header.startswith("_"):
            return {"ok": False, "why": f"no deployment named {header}"}
        dep, route = header, f"azureml-model-deployment: {header} (traffic share {traffic.get(header, 0)}%)"
    else:
        live = [d for d, pct in traffic.items() if pct > 0]
        if not live:
            return {"ok": False, "why": "no deployment has traffic"}
        dep, route = max(live, key=lambda d: traffic[d]), "traffic split"
    return {"ok": True, "deployment": dep, "why": f"{auth}; routed by {route} to '{dep}'"}


# --------------------------------------------------------------------------------------------------------------------
# Models and their files
# --------------------------------------------------------------------------------------------------------------------
def resolve_model(s: Setup, ref: str) -> tuple[str, str, dict]:
    """azureml:<name>:<version> (a workspace model) or azureml://registries/<r>/models/<name>/versions/<v>.
    Returns (where, 'name:version', record)."""
    m = re.match(r"azureml://registries/([^/]+)/models/([^/]+)/versions/([^/]+)$", ref)
    if m:
        where, key = f"registry:{m.group(1)}", f"{m.group(2)}:{m.group(3)}"
    else:
        name, ver = ref.split(":")[1:3]
        where, key = f"workspace:{s.endpoint['workspace']}", f"{name}:{ver}"
    rec = s.models.get(where, {}).get(key)
    if rec is None:
        raise KeyError(f"model not found: {ref}")
    return where, key, rec


class World:
    """The bytes in storage: every model version's files, by the path they are stored under."""
    def __init__(self, s: Setup):
        self.store: dict[str, dict[str, bytes]] = {}
        self.events: list[str] = []
        for versions in s.models.values():
            if not isinstance(versions, dict):
                continue
            for v in versions.values():
                if isinstance(v, dict):
                    self.store[v["stored_in"]] = model_files.build(v["files"])

    def files(self, path: str) -> dict[str, bytes]:
        return self.store[path]


def endpoint_identity(s: Setup) -> str:
    return s.endpoint.get("identity", {}).get("principal", "tsg-summariser-sai")


def _identity_can_read(s: Setup, principal: str, account: str) -> tuple[bool, str]:
    if s.endpoint.get("identity", {}).get("type") == "system_assigned":
        if account == COMPANY["workspaces"][s.endpoint["workspace"]]["storage"]:
            return True, "system-assigned endpoint identity: Storage Blob Data Reader on the workspace storage is granted automatically"
    return decide(s, principal, D_BLOB_READ, f"storage:{account}", data=True)


def load_model(s: Setup, world: World, deployment: str = "blue") -> dict:
    """A new instance of a deployment starts: pull the image, download the model files, load them."""
    dep = s.deployments[deployment]
    ws = s.endpoint["workspace"]
    env = dep["environment"]
    image = env.get("image") if isinstance(env, dict) else env
    if str(image).startswith("docker.io/"):
        ok, why = egress(s, ws, "internet:docker.io")
        if not ok:
            return {"ok": False, "code_ran": False, "why": f"image pull from docker.io failed: {why}"}
    hub = dep.get("environment_variables", {}).get("HF_MODEL_ID")
    if hub:
        ok, why = egress(s, ws, "internet:huggingface.co")
        if not ok:
            return {"ok": False, "code_ran": False, "why": f"the container downloads {hub} from the Hub at start: {why}"}
        files = model_files.build("hub-pull")
        where = f"the Hugging Face Hub ({hub})"
        rec = {"tags": {}}
    else:
        src, key, rec = resolve_model(s, dep["model"])
        path = rec["stored_in"]
        account = path.split(":", 1)[1].split("/", 1)[0]
        target = src if src.startswith("registry:") else f"storage:{account}"
        ok, why = egress(s, ws, target)
        if not ok:
            return {"ok": False, "code_ran": False, "why": f"model download from {target} failed: {why}"}
        ident = endpoint_identity(s)
        ok, rwhy = _identity_can_read(s, ident, account)
        if not ok:
            return {"ok": False, "code_ran": False, "why": f"{ident} can't read {account}: {rwhy}"}
        world.events.append(f"the endpoint identity ({ident}) downloads {key} from {path}")
        files = world.files(path)
        where = path
    if s.app.get("deploy_verifies_hashes"):
        bad = model_files.hash_mismatches(files, rec.get("tags", {}))
        if bad:
            return {"ok": False, "code_ran": False, "why": f"the deploy step refused: hash check failed for {', '.join(bad)}"}
    scan = model_files.scan_files(files)
    risky = [r for r in scan["files"] if r["unsafe_globals"]]
    if risky:
        r = risky[0]
        world.events.append(f"container: loading {r['name']} ran {', '.join(r['unsafe_globals'])} (LAB-PLACEHOLDER: a real payload runs here)")
        return {"ok": True, "code_ran": True, "why": f"loaded the files from {where}"}
    return {"ok": True, "code_ran": False, "why": f"loaded the files from {where}"}


def newest_curated(env_ref: str) -> tuple[str | None, str | None, str | None]:
    """(this version's date, newest version, newest date) for a curated environment reference."""
    m = re.match(r"(azureml://registries/azureml/environments/[^/]+)/versions/(\w+)$", str(env_ref))
    if not m or m.group(1) not in ENVIRONMENTS["curated"]:
        return None, None, None
    versions = ENVIRONMENTS["curated"][m.group(1)]["versions"]
    newest = max(versions, key=lambda v: versions[v])
    return versions.get(m.group(2)), newest, versions[newest]


# --------------------------------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------------------------------
def _main(argv: list[str]) -> int:
    if len(argv) == 5 and argv[0] == "decide":
        s = Setup(argv[1])
        data = argv[3].startswith("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/")
        ok, why = decide(s, argv[2], argv[3], argv[4], data=data)
        print(f"{'ALLOW' if ok else 'DENY'}: {why}  [{scope_id(argv[4])}]")
        return 0
    if len(argv) in (5, 6) and argv[0] == "invoke":
        s = Setup(argv[1])
        r = invoke(s, argv[2], argv[3], argv[4], argv[5] if len(argv) == 6 else None)
        print(f"{'200 OK' if r['ok'] else 'REFUSED'}: {r['why']}")
        return 0
    if len(argv) == 4 and argv[0] == "egress":
        ok, why = egress(Setup(argv[1]), argv[2], argv[3])
        print(f"{'REACHABLE' if ok else 'BLOCKED'}: {why}")
        return 0
    if len(argv) == 3 and argv[0] == "policy":
        r = policy_check(Setup(argv[1]), json.loads(pathlib.Path(argv[2]).read_text()))
        print(json.dumps(r))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
