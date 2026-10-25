"""
twin.py: an offline stand-in for the parts of Agent Platform (formerly Vertex AI) and Google Cloud this lab needs.
Standard library only.

    python3 twin.py container first-draft                       # what code inside the model container can reach
    python3 twin.py decide hardened tsg-helpdesk-app aiplatform.endpoints.predict --from vpc   # one access question

It reads the files in setups/<name>/ (API-shaped bodies plus lab notes in keys that start with "_") and answers:
  * what the deployed model's container can reach and which identity it holds          lesson 15.2
  * whether a principal may use a permission on a resource (IAM allow policies on the
    project, bucket, endpoint and service account; VPC Service Controls)                lessons 15.2, 15.3
  * what a Workbench instance can reach and whether org policies let it be created       lesson 15.2
  * which files a deployed model loads (the copy made at upload) and what loading does   lesson 15.3
  * whether vertexai.allowedModels lets a Model Garden model be deployed                  lesson 15.3

It is NOT Google's IAM, networking or VPC Service Controls engine. What is modelled on Google's documentation and
what is a lab choice is listed in README "How faithful is the twin?".
"""

from __future__ import annotations

import copy
import fnmatch
import json
import pathlib
import sys

import model_files

HERE = pathlib.Path(__file__).resolve().parent
COMPANY = json.loads((HERE / "exampleco.json").read_text())
ROLES = json.loads((HERE / "roles.json").read_text())
IMAGES = json.loads((HERE / "images.json").read_text())
PROD = COMPANY["prod_project"]
EP = COMPANY["endpoint"]
MODEL = COMPANY["model"]


def member(name: str) -> str:
    return COMPANY["members"].get(name, name)


def sa_email(name: str) -> str:
    return member(name).split(":", 1)[1]


def name_of(member_or_email: str) -> str:
    """serviceAccount:x@... or x@... -> the lab's short name, if it has one."""
    for n, m in COMPANY["members"].items():
        if m == member_or_email or m.split(":", 1)[1] == member_or_email:
            return n
    return member_or_email


# --------------------------------------------------------------------------------------------------------------------
# A setup: the files of one deployment
# --------------------------------------------------------------------------------------------------------------------
class Setup:
    FILES = ("registry", "endpoint", "workbench", "iam", "network", "orgpolicy", "app")

    def __init__(self, name: str):
        self.name = name
        base = HERE / "setups" / name
        if not base.is_dir():
            raise SystemExit(f"no such setup: {name} (choose first-draft or hardened)")
        for f in self.FILES:
            setattr(self, f, json.loads((base / f"{f}.json").read_text()))

    def copy(self) -> "Setup":
        c = copy.copy(self)
        for f in self.FILES:
            setattr(c, f, copy.deepcopy(getattr(self, f)))
        return c


# --------------------------------------------------------------------------------------------------------------------
# IAM: allow policies on a small resource hierarchy
# --------------------------------------------------------------------------------------------------------------------
def role_has(role: str, permission: str) -> bool:
    return any(fnmatch.fnmatchcase(permission, p) for p in ROLES.get(role, []))


def _is_member(who: str, m: str) -> bool:
    if m == member(who):
        return True
    return who in COMPANY.get("groups", {}).get(m, [])


def project_of(resource: str) -> str:
    """endpoint:projects/P/..., model:projects/P/..., bucket:B/obj, sa:email, project:P -> P"""
    kind, _, rest = resource.partition(":")
    if kind in ("endpoint", "model"):
        return rest.split("/")[1]
    if kind == "project":
        return rest
    if kind == "sa":
        domain = rest.split("@", 1)[1]
        return PROD if domain == "developer.gserviceaccount.com" else domain.split(".", 1)[0]
    if kind == "bucket":
        return _BUCKET_PROJECT_CACHE.get(rest.split("/", 1)[0], PROD)
    raise ValueError(resource)


_BUCKET_PROJECT_CACHE: dict[str, str] = {}


def _bindings(setup: Setup, resource: str) -> list[tuple[str, dict]]:
    """Every binding that applies to the resource: its own, then its project's (IAM is inherited downwards)."""
    iam = setup.iam
    _BUCKET_PROJECT_CACHE.update(iam.get("_bucket_project", {}))
    kind, _, rest = resource.partition(":")
    out = []
    if kind == "bucket":
        out += [("bucket " + rest.split("/", 1)[0], b) for b in iam.get("buckets", {}).get(rest.split("/", 1)[0], [])]
    elif kind == "endpoint":
        out += [("endpoint", b) for b in iam.get("endpoints", {}).get(rest, [])]
    elif kind == "sa":
        out += [("service account", b) for b in iam.get("serviceAccounts", {}).get(rest, [])]
    out += [("project " + project_of(resource), b) for b in iam.get("projects", {}).get(project_of(resource), [])]
    return out


SERVICE_OF = {"aiplatform": "aiplatform.googleapis.com", "storage": "storage.googleapis.com",
              "notebooks": "notebooks.googleapis.com", "iam": "iam.googleapis.com"}


def perimeter_blocks(setup: Setup, permission: str, resource: str, origin: str) -> tuple[bool, str]:
    """VPC Service Controls (simplified): an enforced perimeter that restricts the service denies requests from
    outside the perimeter (origin 'internet' or 'outside-project') unless an ingress rule allows them. Google: once
    a project is inside, 'all public internet access to your Agent Platform instance is automatically blocked'."""
    per = setup.network.get("perimeter")
    service = SERVICE_OF.get(permission.split(".", 1)[0])
    if not per or service not in per.get("restricted_services", []) or project_of(resource) not in per.get("projects", []):
        return False, ""
    if origin in ("internet", "outside-project") and not per.get("ingress_rules"):
        if per.get("mode") == "enforced":
            return True, f"VPC Service Controls: request from outside the perimeter {per['name'].rsplit('/', 1)[-1]}"
        return False, "VPC Service Controls dry run: this request would be denied (logged, not blocked)"
    return False, ""


def decide(setup: Setup, who: str, permission: str, resource: str, origin: str = "vpc") -> tuple[bool, str]:
    """May principal `who` use `permission` on `resource`, calling from `origin` ('vpc' = inside ExampleCo's network,
    'internet', 'outside-project')? Returns (allowed, reason)."""
    blocked, note = perimeter_blocks(setup, permission, resource, origin)
    if blocked:
        return False, note
    for where, b in _bindings(setup, resource):
        if role_has(b["role"], permission) and any(_is_member(who, m) for m in b["members"]):
            why = f"{b['role'].rsplit('/', 1)[-1]} on the {where}"
            return True, why + (f"; {note}" if note else "")
    return False, f"no role with {permission} on the {resource.split(':', 1)[0]} or its project"


def who_can(setup: Setup, permission: str, resource: str, among=None) -> list[str]:
    among = among or [n for n in COMPANY["members"] if not n.startswith("all-")]
    return [n for n in among if decide(setup, n, permission, resource)[0]]


# --------------------------------------------------------------------------------------------------------------------
# Org policy
# --------------------------------------------------------------------------------------------------------------------
def allowed_models_ok(setup: Setup, value: str) -> tuple[bool, str]:
    """vertexai.allowedModels. Google: 'By default, if no policy is set or inherited, all models and actions are
    allowed'; 'Any explicit deny value takes precedence'; it 'only applies to models in Model Garden'."""
    pol = setup.orgpolicy.get("constraints/vertexai.allowedModels")
    if not pol:
        return True, "no vertexai.allowedModels policy: all models and actions are allowed"
    if value in pol.get("deniedValues", []):
        return False, "vertexai.allowedModels denies it"
    if "allowedValues" in pol:
        return (value in pol["allowedValues"],
                "on the vertexai.allowedModels list" if value in pol["allowedValues"] else "not on the vertexai.allowedModels list")
    return True, "not denied by vertexai.allowedModels"


def _enforced(setup: Setup, constraint: str) -> bool:
    pol = setup.orgpolicy.get(f"constraints/{constraint}")
    return bool(pol and pol.get("enforce"))


def workbench_violations(setup: Setup, inst: dict) -> list[str]:
    """Which enforced ainotebooks.* constraints would refuse to create this instance."""
    g, md = inst["gceSetup"], inst["gceSetup"].get("metadata", {})
    out = []
    if _enforced(setup, "ainotebooks.restrictPublicIp") and not g.get("disablePublicIp", False):
        out.append("ainotebooks.restrictPublicIp (the instance has a public IP)")
    if _enforced(setup, "ainotebooks.disableRootAccess") and md.get("notebook-disable-root", "false") != "true":
        out.append("ainotebooks.disableRootAccess (root access enabled)")
    if _enforced(setup, "ainotebooks.disableTerminal") and md.get("notebook-disable-terminal", "false") != "true":
        out.append("ainotebooks.disableTerminal (terminal enabled)")
    if _enforced(setup, "ainotebooks.disableFileDownloads") and md.get("notebook-disable-downloads", "false") != "true":
        out.append("ainotebooks.disableFileDownloads (file downloads enabled)")
    modes = (setup.orgpolicy.get("constraints/ainotebooks.accessMode") or {}).get("allowedValues")
    if modes and inst.get("_access_mode") not in modes:
        out.append(f"ainotebooks.accessMode (access mode {inst.get('_access_mode')} is not allowed)")
    return out


# --------------------------------------------------------------------------------------------------------------------
# The registry and the deployed model
# --------------------------------------------------------------------------------------------------------------------
def version(setup: Setup, ref) -> dict | None:
    """By versionId, by alias, or by the lab's _story tag."""
    ref = str(ref)
    for v in setup.registry["versions"]:
        if v["versionId"] == ref or ref in v.get("versionAliases", []) or v.get("_story") == ref:
            return v
    return None


def deployed_version(setup: Setup) -> dict:
    """DeployedModel.model can name a version ID or an alias; the deployment records the version it resolved to."""
    ref = setup.endpoint["deployModel"]["deployedModel"]["model"].rsplit("@", 1)
    v = version(setup, ref[1]) if len(ref) == 2 else version(setup, "default")
    if v is None:
        raise SystemExit(f"model version not in registry.json: {ref}")
    return v


def env_of(v: dict) -> dict:
    return {e["name"]: e.get("value", "") for e in v.get("containerSpec", {}).get("env", [])}


def runtime_identity(setup: Setup) -> str | None:
    """DeployedModel.serviceAccount: 'The service account that the DeployedModel's container runs as.' Unset: a
    service account managed by Agent Platform 'without access to the resource project' (it can read the model copy)."""
    sa = setup.endpoint["deployModel"]["deployedModel"].get("serviceAccount")
    return name_of(sa) if sa else None


def endpoint_kind(setup: Setup) -> str:
    e = setup.endpoint["endpoint"]
    if e.get("privateServiceConnectConfig", {}).get("enablePrivateServiceConnect"):
        return "psc"
    if e.get("network"):
        return "psa"
    return "dedicated-public" if e.get("dedicatedEndpointEnabled") else "shared-public"


def perimeter_on(setup: Setup) -> bool:
    per = setup.network.get("perimeter")
    return bool(per and per.get("mode") == "enforced" and PROD in per.get("projects", [])
                and "aiplatform.googleapis.com" in per.get("restricted_services", []))


def container_reach(setup: Setup) -> dict:
    """What code inside the deployed model's container can reach.

    Google (VPC Service Controls page): inside a perimeter 'the Google-managed environment hosting Agent Platform has
    its default internet access blocked' and the perimeter 'blocks access from Agent Platform to third-party APIs and
    services on the internet'. Outside a perimeter the twin gives the container internet access (twin choice,
    inferred from 'default internet access'). The identity is DeployedModel.serviceAccount."""
    ident = runtime_identity(setup)
    if perimeter_on(setup):
        return {"internet": False, "identity": ident,
                "why": "inside an enforced VPC Service Controls perimeter: the managed environment's default internet access is blocked"}
    return {"internet": True, "identity": ident,
            "why": "no enforced perimeter: the managed environment keeps its default internet access"}


def deploy_blocked_by_perimeter_timing(setup: Setup) -> str:
    """Google: 'endpoints must be created after the project is added to the service perimeter'; deploying to an
    endpoint created before fails."""
    per = setup.network.get("perimeter")
    created = setup.endpoint["endpoint"].get("_created")
    if per and per.get("mode") == "enforced" and created and per.get("_enforced_since") and created < per["_enforced_since"]:
        return f"the endpoint was created on {created}, before the project joined the perimeter on {per['_enforced_since']}: deploying to it fails"
    return ""


class World:
    """Cloud Storage folders today, and the copy each registry version got at upload."""

    def __init__(self, setup: Setup):
        self.setup = setup
        self.store = {prefix: model_files.build(kind) for prefix, kind in setup.app.get("_gcs_objects", {}).items()}
        self.snapshots = {v["versionId"]: model_files.build(v["_snapshot"]) for v in setup.registry["versions"]}
        self.events: list[str] = []

    def files(self, prefix: str) -> dict[str, bytes]:
        return self.store.get(prefix, {})


def load_model(setup: Setup, world: World) -> dict:
    """Start the deployment: Agent Platform serves the files it copied at upload (AIP_STORAGE_URI points at 'a copy
    of your model artifact directory'). A worst-case loader opens any pickle-based weights file it finds."""
    timing = deploy_blocked_by_perimeter_timing(setup)
    if timing:
        return {"ok": False, "why": timing, "code_ran": False}
    v = deployed_version(setup)
    env = env_of(v)
    if not v.get("artifactUri") and env.get("HF_MODEL_ID"):
        if not container_reach(setup)["internet"]:
            return {"ok": False, "why": f"the container must download {env['HF_MODEL_ID']} from the Hugging Face Hub at start, and it can't reach the internet", "code_ran": False}
        files, why = model_files.build("hub-pull"), f"downloaded {env['HF_MODEL_ID']} from the Hugging Face Hub at start (whatever is there today)"
    else:
        files, why = world.snapshots[v["versionId"]], f"serves version {v['versionId']} from the copy made at upload"
    code_ran = False
    for name, data in files.items():
        if model_files.is_pickle_weights(name, data):
            found = model_files.scan_bytes(name, data)["unsafe_globals"]
            if found:
                code_ran = True
                world.events.append(f"container: loading {name} ran {', '.join(found)} (LAB-PLACEHOLDER: a real payload runs here)")
    return {"ok": True, "why": why, "code_ran": code_ran}


def pipeline_upload(setup: Setup, world: World, source: str, swap_after_scan: bool = False) -> dict:
    """The pipeline's release step: scan the source folder, (time passes), then models.upload copies whatever is in
    the folder at that moment. Returns {"ok", "why", "files"}."""
    scanned = world.files(source)
    recorded = model_files.manifest(scanned)
    if swap_after_scan:
        world.store[source] = model_files.swapped(scanned)
    uploaded = world.files(source)
    if setup.app.get("upload_verifies_hashes"):
        bad = model_files.hash_mismatches(uploaded, recorded)
        if bad:
            return {"ok": False, "why": "pipeline refused the upload: files changed since the scan: " + ", ".join(bad), "files": uploaded}
    return {"ok": True, "why": "models.upload copied the folder as it was at upload time", "files": uploaded}


# --------------------------------------------------------------------------------------------------------------------
# Workbench
# --------------------------------------------------------------------------------------------------------------------
def workbench_reach(setup: Setup, inst: dict) -> dict:
    """A VM with an external IP reaches the internet; without one it needs Cloud NAT. (VPC Service Controls protects
    Google APIs; it doesn't stop a VM from reaching an ordinary website.)"""
    if not inst["gceSetup"].get("disablePublicIp", False):
        return {"internet": True, "why": "the instance has a public IP address"}
    if setup.network.get("cloud_nat") and inst.get("_project") == PROD:
        return {"internet": True, "why": "no public IP, but Cloud NAT gives the subnet a way out"}
    return {"internet": False, "why": "no public IP and no Cloud NAT: no route to the internet"}


def workbench_identity(inst: dict) -> str:
    """Workbench: 'After you create the instance, you can't change the specified service account.' In 'Service
    account' access mode every user's code runs as that account; in 'Single user' mode it is one person's instance."""
    return name_of(inst["gceSetup"]["serviceAccounts"][0]["email"])


def can_open(inst: dict, who: str) -> bool:
    """Who may open JupyterLab on the instance (the lab's _users note; Google: 'Group access is not supported')."""
    return who in inst.get("_users", [])


def user_keys(setup: Setup, sa_name: str) -> list[str]:
    """User-managed service account keys that exist for a service account (iam.json keys)."""
    return setup.iam.get("keys", {}).get(sa_name, [])


# --------------------------------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------------------------------
def _main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "container":
        s = Setup(argv[1])
        print(json.dumps({"endpoint_kind": endpoint_kind(s), "container": container_reach(s),
                          "workbench": {n: workbench_reach(s, i) for n, i in s.workbench["instances"].items()}}, indent=2))
        return 0
    if len(argv) >= 4 and argv[0] == "decide":
        s = Setup(argv[1])
        origin = argv[argv.index("--from") + 1] if "--from" in argv else "vpc"
        rest = [a for a in argv[4:] if not a.startswith("--") and a != origin]
        resource = rest[0] if rest else "endpoint:" + EP
        ok, why = decide(s, argv[2], argv[3], resource, origin)
        print(f"{'ALLOW' if ok else 'DENY'}: {why}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
