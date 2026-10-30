"""
explore.py: look at AnyCompany's SageMaker AI setup one piece at a time, before you attack it (M15 lab, README
Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's JSON
files and prints what it finds; `reach`, `call` and `role` ask twin.py, the lab's offline stand-in for SageMaker AI.

    python3 explore.py pieces first-draft      # 1. every SageMaker AI piece AnyCompany uses, in one list
    python3 explore.py endpoint first-draft    # 2. an endpoint is three objects: model, endpoint config, endpoint
    python3 explore.py patch first-draft       # 3. who patches what, and when the image stops getting fixes
    python3 explore.py reach first-draft       # 4. what code in the model container and in a notebook can reach
    python3 explore.py call first-draft tsg-helpdesk-app --vpce
                                               # 5. one InvokeEndpoint call: the request, the path, the IAM checks
    python3 explore.py role first-draft tsg-summariser-exec
                                               # 6. an execution role: who may wear it, what it may do, who may pass it
    python3 explore.py record InvokeEndpoint   # 7. one CloudTrail record, field by field

Use `hardened` instead of `first-draft` to see the fixed version. Everything is fictional: AWS documentation example
account IDs and ARNs, reserved amzn-s3-demo- bucket names, invented resource IDs. twin.py is a teaching model of
the documented behaviour (README "How faithful is the twin?"), not AWS.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

import twin

HERE = pathlib.Path(__file__).resolve().parent
C = twin.COMPANY
TRAIL = HERE / "data" / "incident" / "cloudtrail.json"
SETUPS = ("first-draft", "hardened")


def _short_image(image: str) -> str:
    return image.split("/", 1)[1] if "/" in image else image


def _yes(v) -> str:
    return "yes" if v else "no"


def _setup(a: list[str], i: int = 0) -> twin.Setup:
    name = a[i] if len(a) > i else "first-draft"
    if name not in SETUPS:
        raise SystemExit(f"choose first-draft or hardened (got {name})")
    return twin.Setup(name)


def _container(s: twin.Setup) -> dict:
    return twin.effective_container(s)


def _files_where(s: twin.Setup) -> str:
    kind, where = twin.model_source(_container(s))
    return where if kind == "s3" else f"{kind}: {where}"


# ---------------------------------------------------------------- 1. pieces

def cmd_pieces(a) -> None:
    s = _setup(a)
    d, m, ec, reg = s.domain, s.model, s.endpoint_config, s.registry
    c = _container(s)
    print(f"AnyCompany's SageMaker AI pieces, setup {s.name} (fictional; AWS documentation example IDs)\n")
    print(f"  Studio domain    {d['DomainName']}: where the data scientists work in notebooks")
    print(f"                   user profiles: {', '.join(C['user_profiles'].values())}   network: {d.get('AppNetworkAccessType', 'PublicInternetOnly')}")
    print("  Training job     none in this lab: the team fine-tunes in a notebook and exports the files")
    print(f"  Model files      in S3: {_files_where(s)}")
    print(f"  Model Registry   group {reg['ModelPackageGroupName']}: one entry per version, each with an approval status")
    for p in reg["packages"]:
        print(f"                   version {p['_version']}  {p['ModelApprovalStatus']:<22} registered by {p['_registered_by']}")
    print(f"  Model            {m['ModelName']}: image + files + execution role + network settings")
    print(f"                   image {_short_image(c['Image'])}")
    v = ec["ProductionVariants"][0]
    print(f"  Endpoint config  {ec['EndpointConfigName']}: {v['InitialInstanceCount']} x {v['InstanceType']}, "
          f"data capture {'on' if ec.get('DataCaptureConfig', {}).get('EnableCapture') else 'off'}")
    print(f"  Endpoint         {C['endpoint_name']}: the address the Helpdesk app calls")
    print(f"  Execution roles  {m['ExecutionRoleArn'].rsplit('/', 1)[1]} (the endpoint), "
          f"{d['DefaultUserSettings']['ExecutionRole'].rsplit('/', 1)[1]} (notebooks and jobs)")
    src = next((p.get("CustomerMetadataProperties", {}).get("source") for p in reg["packages"]
                if "huggingface.co" in p.get("CustomerMetadataProperties", {}).get("source", "")), "")
    print(f"  Where models come from   {src or 'notebook exports'} (an open model; JumpStart is AWS's catalog, not used here)")


# ---------------------------------------------------------------- 2. endpoint

def cmd_endpoint(a) -> None:
    s = _setup(a)
    m, ec = s.model, s.endpoint_config
    c = _container(s)
    print(f"One real-time endpoint is three objects (setup {s.name}). The request bodies are in setups/{s.name}/.\n")
    print(f"1. CreateModel           model.json")
    if c.get("_from_package"):
        print(f"   ModelPackageName        Model Registry version {c['_from_package']} (its image and files are used)")
    print(f"   Image                   {_short_image(c['Image'])}")
    print(f"   model files             {_files_where(s)}")
    print(f"   ExecutionRoleArn        {m['ExecutionRoleArn']}")
    print(f"   EnableNetworkIsolation  {str(m.get('EnableNetworkIsolation', False)).lower()}")
    vpc = m.get("VpcConfig")
    print(f"   VpcConfig               {'subnets ' + ', '.join(vpc['Subnets']) if vpc else 'none'}")
    env = c.get("Environment", {})
    print(f"   Environment             {', '.join(env) if env else 'none'}")
    v = ec["ProductionVariants"][0]
    print(f"\n2. CreateEndpointConfig  endpoint-config.json")
    print(f"   InstanceType x count    {v['InstanceType']} x {v['InitialInstanceCount']}")
    dc = ec.get("DataCaptureConfig", {})
    print(f"   DataCaptureConfig       {'prompts and answers to ' + dc['DestinationS3Uri'] if dc.get('EnableCapture') else 'off'}")
    print(f"\n3. CreateEndpoint        name {C['endpoint_name']}, config {ec['EndpointConfigName']}")
    print("\nWhen it starts, SageMaker AI (AWS's documented contract for inference containers):")
    print("   copies the model files from S3 to /opt/ml/model (read-only for the container)")
    print("   runs the image as: docker run <image> serve")
    print("   sends requests to a web server in the container on port 8080: POST /invocations, GET /ping")


# ---------------------------------------------------------------- 3. patch

def cmd_patch(a) -> None:
    s = _setup(a)
    image = _container(s)["Image"]
    info = twin.IMAGES["images"].get(image)
    print(f"Who patches what for AnyCompany's endpoint (setup {s.name})\n")
    print("  AWS   the hosts, and the endpoint instances (\"automatically patches endpoints\")")
    print("  You   the image your model names, the model files, the network settings, the execution role, keys, buckets\n")
    print(f"  image          {_short_image(image)}")
    print(f"  pinned by      {'digest (the same bytes every time)' if '@sha256:' in image else 'tag (a tag can move to other bytes)'}")
    if info:
        days = twin.IMAGES["end_of_patch_days"][info["family"]]
        rel = dt.date.fromisoformat(info["released"])
        end = rel + dt.timedelta(days=days)
        today = dt.date.fromisoformat(C["lab_today"])
        print(f"  released       {rel}   (a lab value; read real dates in the image's GitHub release)")
        print(f"  support rule   {info['family'].upper()}: end of patch {days} days after release")
        print(f"  end of patch   {end}")
        print(f"  lab today      {today}   -> {'PAST end of patch: no more security fixes' if end < today else f'{(end - today).days} days of fixes left'}")
    print("\n  A newer image reaches the endpoint only when you deploy a model that names it.")


# ---------------------------------------------------------------- 4. reach

def cmd_reach(a) -> None:
    s = _setup(a)
    r = twin.container_reach(s)
    st = twin.studio_reach(s)
    ok, why = twin.artifacts_fetch_ok(s)
    m = s.model
    print(f"What code can reach (setup {s.name}), from twin.py\n")
    print(f"  Model container   EnableNetworkIsolation {str(m.get('EnableNetworkIsolation', False)).lower()}, "
          f"VpcConfig {'yes' if m.get('VpcConfig') else 'none'}")
    print(f"     internet       {_yes(r['internet'])}")
    print(f"     AWS credentials (the execution role)  {_yes(r['credentials'])}")
    print(f"     why            {r['why']}")
    print(f"     model files    {why if ok else 'FAILS: ' + why}")
    gw = s.network.get("s3_gateway_endpoint")
    print(f"     S3 gateway endpoint   {gw['id'] + (' with a policy' if gw.get('policy') else ' (default policy: full access)') if gw else 'none'}")
    print(f"\n  Studio notebook   AppNetworkAccessType {s.domain.get('AppNetworkAccessType', 'PublicInternetOnly')}")
    print(f"     internet       {_yes(st['internet'])}")
    print(f"     why            {st['why']}")
    eps = s.network.get("interface_endpoints", {})
    print(f"\n  VPC endpoints (private doors to AWS services): {', '.join(eps) or 'none'}")


# ---------------------------------------------------------------- 5. call

def cmd_call(a) -> None:
    s = _setup(a)
    who = a[1] if len(a) > 1 and not a[1].startswith("--") else "tsg-helpdesk-app"
    via = "--vpce" in a
    p = twin.principal(s, who)
    outsider = p.get("account", twin.ACCOUNT) != twin.ACCOUNT
    ep = C["outsider_endpoint_arn"] if outsider else C["endpoint_arn"]   # an outsider calls ITS OWN endpoint
    name = ep.rsplit("/", 1)[1]
    print(f"One InvokeEndpoint call (setup {s.name}). Nothing is sent: twin.py answers.\n")
    print(f"  POST https://runtime.sagemaker.{C['region']}.amazonaws.com/endpoints/{name}/invocations")
    print("  body: the ticket text; signed with SigV4 by the caller's credentials")
    print(f"  caller   {p['arn']}")
    print(f"  target   {ep}" + ("   (the caller's OWN endpoint, in another account)" if outsider else ""))
    if via:
        print(f"  path     through the sagemaker.runtime VPC endpoint {C['runtime_vpce']} (aws:SourceVpce is set)")
    else:
        print("  path     over the internet (no VPC endpoint: aws:SourceVpce is missing)")
    print("\n  IAM checks, in order:")
    acct = p.get("account", twin.ACCOUNT)
    ctx = {"aws:PrincipalArn": p["arn"], "aws:PrincipalAccount": acct}
    if via:
        ctx.update({"aws:SourceVpce": C["runtime_vpce"], "aws:SourceVpc": C["vpc_id"]})
    ident = twin.policy_effect(p.get("policy"), "sagemaker:InvokeEndpoint", ep, ctx)
    print(f"   1. caller's identity policy        {ident.upper() if ident != 'none' else 'no Allow'}")
    if via:
        pol = s.iam.get("runtime_endpoint_policy")
        eff = twin.policy_effect(pol or twin.DEFAULT_ENDPOINT_POLICY, "sagemaker:InvokeEndpoint", ep, ctx, p["arn"])
        print(f"   2. VPC endpoint policy             {eff.upper() if eff != 'none' else 'no Allow'}"
              f"{' (the default policy: full access)' if not pol else ''}")
    else:
        print("   2. VPC endpoint policy             not on the path")
    ok, why = twin.decide(s, who, "sagemaker:InvokeEndpoint", ep, via_vpce=via)
    print(f"\n  result   {'ALLOW' if ok else 'DENY'}: {why}")


# ---------------------------------------------------------------- 6. role

def cmd_role(a) -> None:
    s = _setup(a)
    name = a[1] if len(a) > 1 else "tsg-summariser-exec"
    p = twin.principal(s, name)
    print(f"Execution role {name} (setup {s.name})\n")
    for st in p.get("trust", {}).get("Statement", []):
        print(f"  who may wear it    {st['Principal'].get('Service')} ({st['Action']}): SageMaker AI, on your behalf")
    if p.get("managed_policies"):
        print(f"  managed policies   {', '.join(p['managed_policies'])}")
    print("  what it may do")
    for st in p.get("policy", {}).get("Statement", []):
        res = st["Resource"] if isinstance(st["Resource"], str) else ", ".join(st["Resource"])
        acts = [st["Action"]] if isinstance(st["Action"], str) else st["Action"]
        act = ", ".join(acts) if len(acts) <= 2 else f"{acts[0]} and {len(acts) - 1} more"
        print(f"     {st['Effect']:<6} {act:<34} on {res}")
    passers = twin.principals_allowed(s, "iam:PassRole", p["arn"], {"iam:PassedToService": "sagemaker.amazonaws.com"})
    print(f"  who may pass it    {', '.join(passers) or 'nobody'}")
    print("                     (iam:PassRole: hand this role to a model, job or notebook)")


# ---------------------------------------------------------------- 7. record

def cmd_record(a) -> None:
    name = a[0] if a else "InvokeEndpoint"
    recs = json.loads(TRAIL.read_text())["Records"]
    r = next((x for x in recs if x["eventName"] == name), None)
    if r is None:
        raise SystemExit(f"no {name} record in {TRAIL.name}; try InvokeEndpoint, CreateModel, CreatePresignedDomainUrl")
    ui = r["userIdentity"]
    print(f"One CloudTrail record from data/incident/cloudtrail.json (fake values in CloudTrail's field names)\n")
    print(f"  who      {ui['type']}  {ui['arn'].split('/')[1]}  in account {ui['accountId']}")
    print(f"  what     {r['eventSource']}  {r['eventName']}")
    for res in r.get("resources", []):
        print(f"           on {res['ARN']}")
    print(f"  kind     eventCategory {r['eventCategory']}"
          + ("  (a data event: logged only if the trail selects AWS::SageMaker::Endpoint)" if r["eventCategory"] == "Data" else "  (a management event)"))
    print(f"  where    {r['awsRegion']}, from {r['sourceIPAddress']}" +
          (f", through {r['vpcEndpointId']}" if r.get("vpcEndpointId") else ""))
    print(f"  when     {r['eventTime']}")
    print(f"  error    {r.get('errorCode', 'none')}")
    req = r.get("requestParameters") or {}
    print(f"  request  {json.dumps(req) if req else '{} (AWS: InvokeEndpoint does not log its request parameters: no prompt)'}")


COMMANDS = {"pieces": cmd_pieces, "endpoint": cmd_endpoint, "patch": cmd_patch, "reach": cmd_reach,
            "call": cmd_call, "role": cmd_role, "record": cmd_record}


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in COMMANDS:
        print(__doc__)
        return 2
    COMMANDS[argv[0]](argv[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
