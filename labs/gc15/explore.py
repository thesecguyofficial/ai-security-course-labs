"""
explore.py: look at ExampleCo's self-deployed model on Agent Platform one piece at a time, before you attack it (GC15
lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's JSON
files and prints what it finds; `reach`, `call` and `identity` ask twin.py, the lab's offline stand-in for Agent
Platform (formerly Vertex AI) and Google Cloud IAM.

    python3 explore.py pieces first-draft      # 1. every piece ExampleCo uses, in one list
    python3 explore.py endpoint first-draft    # 2. a self-deployed model is three objects: Model, Endpoint, DeployedModel
    python3 explore.py patch first-draft       # 3. who patches what, and how old the serving image is
    python3 explore.py reach first-draft       # 4. what code in the serving container and in a notebook can reach
    python3 explore.py call first-draft tsg-helpdesk-app
                                               # 5. one predict call: the request, the path, the checks
    python3 explore.py identity first-draft    # 6. the service account the container runs as, and who can act as it
    python3 explore.py record Predict          # 7. one Cloud Audit Logs entry, field by field

Use `hardened` instead of `first-draft` to see the fixed version. Everything is fictional: ExampleCo, its projects,
numbers, emails and IDs are placeholders on the documentation domain example.com. twin.py is a teaching model of the
documented behaviour (README "How faithful is the twin?"), not Google Cloud.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

import twin

HERE = pathlib.Path(__file__).resolve().parent
C = twin.COMPANY
LOGS = HERE / "data" / "incident" / "audit-logs.json"
SETUPS = ("first-draft", "hardened")
KIND = {"shared-public": "shared public endpoint", "dedicated-public": "dedicated public endpoint",
        "psc": "dedicated private endpoint (Private Service Connect)", "psa": "private endpoint (private services access, VPC peering)"}


def _setup(a: list[str], i: int = 0) -> twin.Setup:
    name = a[i] if len(a) > i else "first-draft"
    if name not in SETUPS:
        raise SystemExit(f"choose first-draft or hardened (got {name})")
    return twin.Setup(name)


def _short_image(uri: str) -> str:
    tail = uri.split("/serving/", 1)[-1]
    return tail[:40] + "..." if "@sha256:" in tail else tail


def _ep_id() -> str:
    return C["endpoint"].rsplit("/", 1)[1]


# ---------------------------------------------------------------- 1. pieces

def cmd_pieces(a) -> None:
    s = _setup(a)
    print(f"ExampleCo's pieces, setup {s.name} (fictional; example.com placeholders)\n")
    print(f"  Projects         {C['prod_project']} (production), {C['dev_project']} (data science)")
    print(f"  Model Registry   model tsg-summariser in {C['prod_project']}: one entry per version")
    for v in s.registry["versions"]:
        aliases = ", ".join(v.get("versionAliases", [])) or "no alias"
        print(f"                   version {v['versionId']}  aliases: {aliases:<14} uploaded by {v['_uploaded_by']}")
    e = s.endpoint
    dm = e["deployModel"]["deployedModel"]
    print(f"  Endpoint         {_ep_id()} ({e['endpoint']['displayName']}): {KIND[twin.endpoint_kind(s)]}")
    print(f"  DeployedModel    {dm['model'].rsplit('/', 1)[1]} on {dm['dedicatedResources']['machineSpec']['machineType']} "
          f"+ {dm['dedicatedResources']['machineSpec'].get('acceleratorType', 'no GPU')}, "
          f"{dm['dedicatedResources']['minReplicaCount']} to {dm['dedicatedResources']['maxReplicaCount']} replicas")
    print(f"                   runs as {twin.runtime_identity(s) or 'the service account Agent Platform manages'}")
    for name, inst in s.workbench["instances"].items():
        print(f"  Workbench        {name} in {inst['_project']}: a notebook VM for {', '.join(inst['_users'])}")
    print(f"  Buckets          {', '.join(C['buckets'].values())}")
    per = s.network.get("perimeter")
    print(f"  Perimeter        {per['name'].rsplit('/', 1)[1] + ' (VPC Service Controls, ' + per['mode'] + ')' if per else 'none'}")
    set_pols = [k.split('/', 1)[1] for k, v in s.orgpolicy.items() if not k.startswith("_") and v]
    print(f"  Org policies     {', '.join(set_pols) or 'none set'}")
    print("  Where models come from   ExampleCo fine-tunes an open model; Model Garden is Google's catalog")


# ---------------------------------------------------------------- 2. endpoint

def cmd_endpoint(a) -> None:
    s = _setup(a)
    v = twin.deployed_version(s)
    cs = v["containerSpec"]
    e = s.endpoint["endpoint"]
    dm = s.endpoint["deployModel"]["deployedModel"]
    print(f"A self-deployed model is three objects (setup {s.name}). The bodies are in setups/{s.name}/.\n")
    print(f"1. Model (Model Registry)   registry.json, version {v['versionId']} (the one the alias in step 3 points at)")
    print(f"   containerSpec.imageUri   {_short_image(cs['imageUri'])}")
    print(f"   artifactUri              {v.get('artifactUri') or 'none'}")
    env = twin.env_of(v)
    print(f"   containerSpec.env        {', '.join(env) if env else 'none'}")
    print(f"   port, routes             {cs['ports'][0]['containerPort']}, predict {cs['predictRoute']}, health {cs['healthRoute']}")
    print(f"\n2. Endpoint                 endpoint.json  (endpoints.create)")
    print(f"   type                     {KIND[twin.endpoint_kind(s)]}")
    psc = e.get("privateServiceConnectConfig")
    if psc:
        print(f"   projectAllowlist         {', '.join(psc.get('projectAllowlist', []))}")
    print(f"   encryptionSpec           {e['encryptionSpec']['kmsKeyName'].rsplit('/', 1)[1] + ' (your key)' if e.get('encryptionSpec') else 'none (Google-managed key)'}")
    lg = e.get("predictRequestResponseLoggingConfig", {})
    print(f"   request-response logging {'on, sampling ' + str(lg.get('samplingRate')) + ' to ' + lg['bigqueryDestination']['outputUri'] if lg.get('enabled') else 'off'}")
    print(f"\n3. DeployedModel            endpoint.json  (endpoints.deployModel)")
    print(f"   model                    {dm['model'].rsplit('/', 1)[1]}")
    print(f"   serviceAccount           {dm.get('serviceAccount') or 'not set'}")
    ms = dm["dedicatedResources"]["machineSpec"]
    print(f"   machine                  {ms['machineType']} + {ms.get('acceleratorCount', 0)} x {ms.get('acceleratorType', 'none')}")
    print(f"   enableAccessLogging      {str(dm.get('enableAccessLogging', False)).lower()}")
    print("\nWhen it starts (Google's documented contract for serving containers):")
    print("   the container reads its files from AIP_STORAGE_URI: a copy made at upload, not the bucket itself")
    print("   Agent Platform sends prediction requests to the first port in containerSpec.ports (8080 if not set)")
    print("   the container runs as DeployedModel.serviceAccount; if it's not set, as an account with no access to the project")


# ---------------------------------------------------------------- 3. patch

def cmd_patch(a) -> None:
    s = _setup(a)
    image = twin.deployed_version(s)["containerSpec"]["imageUri"]
    info = twin.IMAGES["images"].get(image, {})
    today = dt.date.fromisoformat(C["lab_today"])
    print(f"Who patches what for ExampleCo's deployed model (setup {s.name})\n")
    print("  Google   the serving infrastructure; new versions of its prebuilt images (you still redeploy to use them)")
    print("  You      the image you build, the model files, the network path, the service account, keys, logs\n")
    print(f"  image          {_short_image(image)}")
    print(f"  kind           ExampleCo's own image in Artifact Registry: patching it is ExampleCo's job")
    print(f"  pinned by      {'digest (the same bytes every time)' if '@sha256:' in image else 'tag (a tag can move to other bytes)'}")
    if info:
        built = dt.date.fromisoformat(info["built"])
        pulled = dt.date.fromisoformat(info["last_pulled"])
        rule, window = twin.IMAGES["rebuild_days"], twin.IMAGES["monitoring_window_days"]
        print(f"  built          {built}   (a lab value)   {(today - built).days} days before lab today {today}")
        print(f"  company rule   rebuild and redeploy every {rule} days -> {'OVERDUE' if (today - built).days > rule else 'ok'}")
        print(f"  last pulled    {pulled}   -> {'scans are STALE (not pulled in ' + str(window) + ' days)' if (today - pulled).days > window else 'still scanned continuously'}")
        print(f"  open critical  {info['open_critical_findings']}   (a lab value)")
    print("\n  A rebuilt image reaches the endpoint only when you upload a model version that names it and deploy it.")


# ---------------------------------------------------------------- 4. reach

def cmd_reach(a) -> None:
    s = _setup(a)
    r = twin.container_reach(s)
    per = s.network.get("perimeter")
    print(f"What code can reach (setup {s.name}), from twin.py\n")
    print(f"  Serving container   perimeter {per['name'].rsplit('/', 1)[1] + ' (' + per['mode'] + ')' if per else 'none'}")
    print(f"     internet         {'yes' if r['internet'] else 'no'}")
    print(f"     runs as          {r['identity'] or 'the service account Agent Platform manages (no access to the project)'}")
    print(f"     why              {r['why']}")
    blocked = twin.deploy_blocked_by_perimeter_timing(s)
    print(f"     endpoint order   {blocked or 'fine (created after the project joined the perimeter, or no perimeter)'}")
    for name, inst in s.workbench["instances"].items():
        w = twin.workbench_reach(s, inst)
        print(f"\n  Workbench {name}   ({inst['_project']}, access mode {inst['_access_mode']})")
        print(f"     internet         {'yes' if w['internet'] else 'no'}")
        print(f"     runs as          {twin.workbench_identity(inst)}")
        print(f"     why              {w['why']}")
    print(f"\n  Network             Cloud NAT {'yes' if s.network.get('cloud_nat') else 'no'}, "
          f"PSC forwarding rule {s.network['psc_forwarding_rule']['address'] if s.network.get('psc_forwarding_rule') else 'none'}")
    if per:
        print(f"  Perimeter protects  {', '.join(per['restricted_services'])}")


# ---------------------------------------------------------------- 5. call

def cmd_call(a) -> None:
    s = _setup(a)
    rest = [x for x in a[1:] if not x.startswith("--")]
    who = rest[0] if rest else "tsg-helpdesk-app"
    origin = "internet" if "--internet" in a else "vpc"
    kind = twin.endpoint_kind(s)
    print(f"One predict call (setup {s.name}). Nothing is sent: twin.py answers.\n")
    if kind == "psc":
        print(f"  POST to {s.network['psc_forwarding_rule']['address']}, the PSC forwarding rule in ExampleCo's VPC (a private IP address)")
    else:
        print(f"  POST https://{C['region']}-aiplatform.googleapis.com/v1/{C['endpoint']}:predict")
    print("  body     the ticket text in an instances list; an OAuth access token for the caller")
    print(f"  caller   {twin.member(who)}")
    inside = "inside ExampleCo's network"
    print(f"  from     {'the internet (a laptop outside ExampleCo)' if origin == 'internet' else inside}")
    if kind == "psc" and origin == "internet":
        print("\n  A private IP address isn't reachable from the internet: the request never arrives.")
        print("  (Through the public API name instead, the checks below apply.)")
    print("\n  Checks, in order:")
    blocked, note = twin.perimeter_blocks(s, "aiplatform.endpoints.predict", "endpoint:" + C["endpoint"], origin)
    print(f"   1. VPC Service Controls   {'STOP: ' + note if blocked else (note or 'no perimeter on this path') if not twin.perimeter_on(s) else 'pass: inside the perimeter'}")
    ok, why = twin.decide(s, who, "aiplatform.endpoints.predict", "endpoint:" + C["endpoint"], origin)
    if not blocked:
        print(f"   2. IAM (endpoint, then project)   {'ALLOW: ' + why if ok else 'DENY: ' + why}")
    keys = twin.user_keys(s, who)
    if keys:
        print(f"\n  note     {who} has a user-managed key file: {keys[0]}. It works from any laptop that holds it.")
    print(f"\n  result   {'ALLOW' if ok else 'DENY'}: {why}")


# ---------------------------------------------------------------- 6. identity

def cmd_identity(a) -> None:
    s = _setup(a)
    sa = twin.runtime_identity(s)
    print(f"The deployed model's identity (setup {s.name})\n")
    if not sa:
        print("  serviceAccount   not set: a service account Agent Platform manages, with no access to the project")
        return
    email = twin.sa_email(sa)
    print(f"  serviceAccount   {email}")
    print("  who uses it      code in the serving container: the server, and anything a model file runs")
    roles = [b["role"].rsplit("/", 1)[1] for b in s.iam["projects"].get(twin.PROD, []) if twin.member(sa) in b["members"]]
    print(f"  its roles        on {twin.PROD}: {', '.join(roles) or 'none'}")
    print(f"  user-managed keys  {', '.join(twin.user_keys(s, sa)) or 'none'}")
    people = [n for n in C["members"] if not n.startswith("all-") and n != sa]
    act = [n for n in people if twin.decide(s, n, "iam.serviceAccounts.actAs", "sa:" + email)[0]]
    deploy = [n for n in people if twin.decide(s, n, "aiplatform.endpoints.deploy", "endpoint:" + C["endpoint"])[0]]
    alias = [n for n in people if twin.decide(s, n, "aiplatform.models.update", "model:" + C["model"])[0]]
    print("\n  Who else matters")
    print(f"     iam.serviceAccounts.actAs (attach it to a deployment)   {', '.join(act) or 'nobody'}")
    print(f"     aiplatform.endpoints.deploy (deploy a model)            {', '.join(deploy) or 'nobody'}")
    print(f"     aiplatform.models.update (move the prod alias)          {', '.join(alias) or 'nobody'}")


# ---------------------------------------------------------------- 7. record

def cmd_record(a) -> None:
    name = a[0] if a else "Predict"
    entries = json.loads(LOGS.read_text(encoding="utf-8"))["entries"]
    e = next((x for x in entries if x["protoPayload"]["methodName"].endswith("." + name)), None)
    if e is None:
        raise SystemExit(f"no {name} entry in {LOGS.name}; try Predict, UploadModel, DeployModel, MergeVersionAliases, CreateServiceAccountKey")
    p = e["protoPayload"]
    rm = p.get("requestMetadata", {})
    log = e["logName"].rsplit("%2F", 1)[1]
    print(f"One Cloud Audit Logs entry from data/incident/audit-logs.json (fake values, Google's field names)\n")
    print(f"  log      {log}   ({'a Data Access log: written only if you turn them on' if log == 'data_access' else 'an Admin Activity log: always written'})")
    print(f"  who      {p['authenticationInfo']['principalEmail']}")
    print(f"  what     {p['serviceName']}  {p['methodName']}")
    print(f"  on       {p['resourceName']}")
    print(f"  from     {rm.get('callerIp')}  network {rm.get('callerNetwork', 'none (not from a VPC)').rsplit('/', 1)[-1]}")
    print(f"  agent    {rm.get('callerSuppliedUserAgent')}")
    print(f"  when     {e['timestamp']}")
    req = {k: v for k, v in p.get("request", {}).items() if k != "@type"}
    print(f"  request  {json.dumps(req) if req else 'none'}" + ("   (no instances: audit logs don't hold the prompt, lesson 15.4)" if name == "Predict" else ""))


COMMANDS = {"pieces": cmd_pieces, "endpoint": cmd_endpoint, "patch": cmd_patch, "reach": cmd_reach,
            "call": cmd_call, "identity": cmd_identity, "record": cmd_record}


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in COMMANDS:
        print(__doc__)
        return 2
    COMMANDS[argv[0]](argv[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
