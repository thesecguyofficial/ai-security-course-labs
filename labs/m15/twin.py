"""
twin.py: an offline stand-in for the parts of Amazon SageMaker AI this lab needs. Standard library only.

    python3 twin.py container first-draft     # what code inside the model container can reach
    python3 twin.py decide hardened tsg-helpdesk-app sagemaker:InvokeEndpoint --vpce   # one IAM question

It reads the files in setups/<name>/ (real request bodies plus lab notes in keys that start with "_") and answers:
  * what a model container can reach (network isolation, VPC, NAT, credentials)        lesson 15.2
  * whether a principal may call an action on a resource (identity policy, SCPs,
    the sagemaker.runtime VPC endpoint policy, bucket policies)                          lessons 15.2, 15.3
  * which model files an endpoint loads and what happens when it loads them             lesson 15.3
  * what the Studio domain lets a notebook reach                                         lesson 15.2

What is modelled on AWS documentation and what is a lab choice is listed in README "How faithful is the twin?".
"""

from __future__ import annotations

import copy
import fnmatch
import json
import pathlib
import sys

import model_files

HERE = pathlib.Path(__file__).resolve().parent
COMPANY = json.loads((HERE / "anycompany.json").read_text())
IMAGES = json.loads((HERE / "images.json").read_text())
ACCOUNT = COMPANY["account"]
REGION = COMPANY["region"]


def arn_role(name: str, account: str = ACCOUNT) -> str:
    return f"arn:aws:iam::{account}:role/{name}"


def arn_sm(kind: str, name: str, account: str = ACCOUNT) -> str:
    return f"arn:aws:sagemaker:{REGION}:{account}:{kind}/{name}"


def arn_s3(bucket: str, key: str = "") -> str:
    return f"arn:aws:s3:::{bucket}" + (f"/{key}" if key else "")


# --------------------------------------------------------------------------------------------------------------------
# A setup: the files of one deployment
# --------------------------------------------------------------------------------------------------------------------
class Setup:
    FILES = ("model", "endpoint-config", "domain", "registry", "iam", "network", "app")

    def __init__(self, name: str):
        self.name = name
        base = HERE / "setups" / name
        if not base.is_dir():
            raise SystemExit(f"no such setup: {name} (choose first-draft or hardened)")
        for f in self.FILES:
            setattr(self, f.replace("-", "_"), json.loads((base / f"{f}.json").read_text()))
        scp_file = base / "scp.json"
        self.scps = json.loads(scp_file.read_text()) if scp_file.exists() else {"Statement": []}

    def copy(self) -> "Setup":
        c = copy.copy(self)
        for f in self.FILES:
            attr = f.replace("-", "_")
            setattr(c, attr, copy.deepcopy(getattr(self, attr)))
        c.scps = copy.deepcopy(self.scps)
        return c


# --------------------------------------------------------------------------------------------------------------------
# IAM: a small evaluator for the policy features this lab uses
# --------------------------------------------------------------------------------------------------------------------
def _as_list(v):
    return v if isinstance(v, list) else [v]


def _statements(policy: dict | None) -> list[dict]:
    if not policy:
        return []
    return _as_list(policy.get("Statement", []))


def _match_action(patterns, action: str) -> bool:
    return any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in _as_list(patterns))


def _match_resource(patterns, resource: str) -> bool:
    return any(fnmatch.fnmatchcase(resource, p) for p in _as_list(patterns))


def _cond_one(op: str, key: str, want, ctx: dict) -> bool:
    """One condition key. IfExists: true when the key is missing. Null: tests presence. Missing key otherwise: the
    positive operators fail; the negated ones (StringNotEquals, ArnNotLike, ...) succeed, as IAM documents."""
    have = ctx.get(key)
    base = op[:-8] if op.endswith("IfExists") else op
    if op == "Null":
        return (have is None) == (str(want).lower() == "true")
    if have is None:
        return op.endswith("IfExists") or "Not" in base
    haves = [str(h) for h in _as_list(have)]
    wants = [str(w) for w in _as_list(want)]
    if base in ("StringEquals", "ArnEquals"):
        return any(h == w for h in haves for w in wants)
    if base in ("StringNotEquals", "ArnNotEquals"):
        return not any(h == w for h in haves for w in wants)
    if base in ("StringLike", "ArnLike"):
        return any(fnmatch.fnmatchcase(h, w) for h in haves for w in wants)
    if base in ("StringNotLike", "ArnNotLike"):
        return not any(fnmatch.fnmatchcase(h, w) for h in haves for w in wants)
    if base == "Bool":
        return any(h.lower() == w.lower() for h in haves for w in wants)
    if base == "ForAllValues:StringEquals":
        return all(h in wants for h in haves)
    raise ValueError(f"condition operator not in the lab evaluator: {op}")


def _conditions_hold(cond: dict | None, ctx: dict) -> bool:
    for op, pairs in (cond or {}).items():
        for key, want in pairs.items():
            if not _cond_one(op, key, want, ctx):
                return False
    return True


def statement_applies(st: dict, action: str, resource: str, ctx: dict, principal_arn: str | None = None) -> bool:
    if "Action" in st and not _match_action(st["Action"], action):
        return False
    if "NotAction" in st and _match_action(st["NotAction"], action):
        return False
    if "Resource" in st and not _match_resource(st["Resource"], resource):
        return False
    if "NotResource" in st and _match_resource(st["NotResource"], resource):
        return False
    if "Principal" in st and principal_arn is not None:
        p = st["Principal"]
        if p != "*" and not (isinstance(p, dict) and (p.get("AWS") == "*" or principal_arn in _as_list(p.get("AWS", [])))):
            return False
    return _conditions_hold(st.get("Condition"), ctx)


def policy_effect(policy: dict | None, action: str, resource: str, ctx: dict, principal_arn: str | None = None) -> str:
    """'deny' (explicit deny), 'allow', or 'none'."""
    sts = [s for s in _statements(policy) if statement_applies(s, action, resource, ctx, principal_arn)]
    if any(s["Effect"] == "Deny" for s in sts):
        return "deny"
    return "allow" if any(s["Effect"] == "Allow" for s in sts) else "none"


DEFAULT_ENDPOINT_POLICY = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}


def principal(setup: Setup, name: str) -> dict:
    p = setup.iam["principals"].get(name)
    if p is None:
        raise KeyError(f"unknown principal {name}")
    return p


def decide(setup: Setup, who: str, action: str, resource: str, extra: dict | None = None,
           via_vpce: bool = False) -> tuple[bool, str]:
    """May principal `who` call `action` on `resource`? Returns (allowed, reason).

    Order (simplified from IAM policy evaluation): an explicit Deny anywhere wins; SCPs apply to principals in
    AnyCompany's organization; a request through the sagemaker.runtime interface endpoint must also be allowed by
    the endpoint policy; S3 requests are checked against the bucket policy; then the identity policy must allow."""
    p = principal(setup, who)
    acct = p.get("account", ACCOUNT)
    ctx = {"aws:PrincipalArn": p["arn"], "aws:PrincipalAccount": acct}
    if via_vpce:
        ctx["aws:SourceVpce"] = COMPANY["runtime_vpce"]
        ctx["aws:SourceVpc"] = COMPANY["vpc_id"]
    ctx.update(extra or {})

    identity = policy_effect(p.get("policy"), action, resource, ctx)
    if identity == "deny":
        return False, "explicit Deny in the identity policy"
    if acct == ACCOUNT and policy_effect(setup.scps, action, resource, ctx) == "deny":
        return False, "denied by an SCP"
    if via_vpce and action.lower().startswith("sagemaker:invokeendpoint"):
        epol = setup.iam.get("runtime_endpoint_policy") or DEFAULT_ENDPOINT_POLICY
        eff = policy_effect(epol, action, resource, ctx, p["arn"])
        if eff != "allow":
            return False, "the sagemaker.runtime VPC endpoint policy does not allow it"
    if action.lower().startswith("s3:"):
        bucket = resource.split(":::", 1)[1].split("/", 1)[0]
        bpol = setup.iam.get("bucket_policies", {}).get(bucket)
        if policy_effect(bpol, action, resource, ctx, p["arn"]) == "deny":
            return False, f"explicit Deny in the bucket policy of {bucket}"
    if identity == "allow":
        return True, "allowed by the identity policy" + (" (through the VPC endpoint)" if via_vpce else "")
    return False, "no identity policy allows it (implicit deny)"


def principals_allowed(setup: Setup, action: str, resource: str, extra: dict | None = None,
                       same_account_only: bool = True) -> list[str]:
    out = []
    for n, p in setup.iam["principals"].items():
        if same_account_only and p.get("account", ACCOUNT) != ACCOUNT:
            continue
        if decide(setup, n, action, resource, extra)[0]:
            out.append(n)
    return out


# --------------------------------------------------------------------------------------------------------------------
# The model: which container, which files, which network
# --------------------------------------------------------------------------------------------------------------------
def package(setup: Setup, arn_or_version) -> dict | None:
    v = str(arn_or_version).rsplit("/", 1)[-1]
    for p in setup.registry["packages"]:
        if str(p["_version"]) == v:
            return p
    return None


def effective_container(setup: Setup, model: dict | None = None) -> dict:
    """The container definition SageMaker AI would run: the model's own, or the registry package's when the model
    names a ModelPackageName (CreateModel ContainerDefinition)."""
    model = model or setup.model
    c = model["PrimaryContainer"]
    if "ModelPackageName" in c:
        pkg = package(setup, c["ModelPackageName"])
        if pkg is None:
            raise SystemExit(f"model package not in registry.json: {c['ModelPackageName']}")
        out = dict(pkg["InferenceSpecification"]["Containers"][0])
        out["_from_package"] = pkg["_version"]
        return out
    return dict(c)


def model_source(container: dict) -> tuple[str, str]:
    """('s3', uri) for ModelDataSource/ModelDataUrl, ('hub', id) when the container downloads from the Hugging Face
    Hub at start (HF_MODEL_ID that is not an s3:// URI)."""
    ds = container.get("ModelDataSource", {}).get("S3DataSource")
    if ds:
        return "s3", ds["S3Uri"]
    if container.get("ModelDataUrl"):
        return "s3", container["ModelDataUrl"]
    hf = container.get("Environment", {}).get("HF_MODEL_ID", "")
    if hf.startswith("s3://"):
        return "s3", hf
    if hf:
        return "hub", hf
    return "none", ""


def _subnets_have_nat(setup: Setup, subnet_ids: list[str]) -> bool:
    subs = setup.network["subnets"]
    return any("nat" in subs.get(s, {}).get("routes", []) or "igw" in subs.get(s, {}).get("routes", []) for s in subnet_ids)


def container_reach(setup: Setup, model: dict | None = None) -> dict:
    """What code running inside the model container can reach.

    AWS: with network isolation "your training and inference containers can't make any outbound network calls to
    any service, including Amazon S3. No AWS credentials are made available to the container runtime environment."
    Without it, SageMaker AI provides external network access unless the model is in your VPC (then your routes
    decide). The container can then use the execution role (twin choice, see README)."""
    model = model or setup.model
    if model.get("EnableNetworkIsolation"):
        return {"internet": False, "vpc": False, "credentials": False,
                "why": "network isolation: no outbound calls, no AWS credentials in the container"}
    vpc = model.get("VpcConfig")
    if not vpc:
        return {"internet": True, "vpc": False, "credentials": True,
                "why": "no network isolation and no VpcConfig: SageMaker AI provides external network access"}
    nat = _subnets_have_nat(setup, vpc["Subnets"])
    return {"internet": nat, "vpc": True, "credentials": True,
            "why": "in your VPC without network isolation: " + ("a route to a NAT gateway reaches the internet" if nat else "no route to the internet")}


def artifacts_fetch_ok(setup: Setup, model: dict | None = None) -> tuple[bool, str]:
    """Can SageMaker AI download the model files at endpoint start?"""
    model = model or setup.model
    kind, where = model_source(effective_container(setup, model))
    if kind == "hub":
        reach = container_reach(setup, model)
        if not reach["internet"]:
            return False, f"the container must download {where} from the Hugging Face Hub, and it can't reach the internet"
        return True, f"downloaded {where} from the Hugging Face Hub at start (whatever is there today)"
    if kind != "s3":
        return False, "no model files configured"
    vpc = model.get("VpcConfig")
    if vpc:
        # AWS (host-vpc): models in a VPC without internet access need an S3 VPC endpoint; with network isolation
        # "the download and upload of customer data and model artifacts are routed through your VPC subnet".
        if not setup.network.get("s3_gateway_endpoint") and not _subnets_have_nat(setup, vpc["Subnets"]):
            return False, "model is in the VPC and the subnets have neither an S3 gateway endpoint nor a NAT route"
        gw = setup.network.get("s3_gateway_endpoint")
        if gw and gw.get("policy"):
            bucket, key = where[5:].split("/", 1)
            exec_arn = model["ExecutionRoleArn"]
            if policy_effect(gw["policy"], "s3:GetObject", arn_s3(bucket, key + "x"), {"aws:PrincipalArn": exec_arn},
                             exec_arn) != "allow":
                return False, "the S3 gateway endpoint policy does not allow reading the model bucket"
    role = model["ExecutionRoleArn"].rsplit("/", 1)[-1]
    bucket, key = where[5:].split("/", 1)
    ok, why = decide(setup, role, "s3:GetObject", arn_s3(bucket, key + "model-file"))
    return (ok, "SageMaker AI downloads the files with the execution role" if ok else f"execution role can't read the model files: {why}")


# --------------------------------------------------------------------------------------------------------------------
# World: S3 objects and what happened (one test or attack at a time)
# --------------------------------------------------------------------------------------------------------------------
class World:
    def __init__(self, setup: Setup):
        self.setup = setup
        self.store: dict[str, dict[str, bytes]] = {}
        for prefix, kind in setup.app.get("_s3_model_prefixes", {}).items():
            self.store[prefix] = model_files.build(kind)
        self.events: list[str] = []
        self.outbound: list[str] = []

    def files(self, uri: str) -> dict[str, bytes]:
        return self.store.get(uri, {})


def load_model(setup: Setup, world: World, model: dict | None = None) -> dict:
    """Start the endpoint: fetch the files, then load them the way a worst-case framework loader would (it opens
    any pickle-based weights file it finds). Returns {"ok", "why", "code_ran", "files"}."""
    model = model or setup.model
    ok, why = artifacts_fetch_ok(setup, model)
    if not ok:
        return {"ok": False, "why": why, "code_ran": False, "files": {}}
    kind, where = model_source(effective_container(setup, model))
    files = world.files(where) if kind == "s3" else model_files.build("hub-pull")
    if setup.app.get("deploy_verifies_hashes"):
        pkg_v = effective_container(setup, model).get("_from_package")
        pkg = package(setup, pkg_v) if pkg_v else None
        bad = model_files.hash_mismatches(files, (pkg or {}).get("CustomerMetadataProperties", {}))
        if bad:
            return {"ok": False, "why": "deploy step refused: file hashes differ from the registry: " + ", ".join(bad),
                    "code_ran": False, "files": files}
    code_ran = False
    for name, data in files.items():
        if model_files.is_pickle_weights(name, data):
            found = model_files.scan_bytes(name, data)["unsafe_globals"]
            if found:
                code_ran = True
                world.events.append(f"container: loading {name} ran {', '.join(found)} (LAB-PLACEHOLDER: a real payload runs here)")
    return {"ok": True, "why": why, "code_ran": code_ran, "files": files}


# --------------------------------------------------------------------------------------------------------------------
# Studio domain
# --------------------------------------------------------------------------------------------------------------------
def studio_reach(setup: Setup) -> dict:
    """What a notebook in the domain can reach. AWS (CreateDomain AppNetworkAccessType): PublicInternetOnly = "Non-EFS
    traffic is through a VPC managed by Amazon SageMaker AI, which allows direct internet access"; VpcOnly = "All
    traffic is through the specified VPC and subnets"."""
    d = setup.domain
    if d.get("AppNetworkAccessType", "PublicInternetOnly") == "PublicInternetOnly":
        return {"internet": True, "why": "PublicInternetOnly (the default): direct internet access through a SageMaker-managed VPC"}
    nat = _subnets_have_nat(setup, d["SubnetIds"])
    return {"internet": nat, "why": "VpcOnly: " + ("the subnets route to a NAT gateway" if nat else "no route to the internet")}


def instance_has_local_storage(instance_type: str) -> bool:
    return IMAGES["_instance_local_storage"].get(instance_type, False)


# --------------------------------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------------------------------
def _main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "container":
        s = Setup(argv[1])
        print(json.dumps({"container": container_reach(s), "model_files": artifacts_fetch_ok(s)[1],
                          "studio": studio_reach(s)}, indent=2))
        return 0
    if len(argv) >= 4 and argv[0] == "decide":
        s = Setup(argv[1])
        resource = argv[4] if len(argv) > 4 and not argv[4].startswith("--") else COMPANY["endpoint_arn"]
        ok, why = decide(s, argv[2], argv[3], resource, via_vpce="--vpce" in argv)
        print(f"{'ALLOW' if ok else 'DENY'}: {why}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
