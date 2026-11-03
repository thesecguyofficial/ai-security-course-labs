"""
explore.py: look at Contoso's Azure Machine Learning setup one piece at a time, before you attack it (AZ15 lab,
README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's JSON
files and prints what it finds; `reach`, `call` and `identity` ask twin.py, the lab's offline stand-in for Azure
Machine Learning.

    python3 explore.py pieces first-draft      # 1. every Azure Machine Learning piece Contoso uses, in one list
    python3 explore.py endpoint first-draft    # 2. an online endpoint and the deployments behind it
    python3 explore.py patch first-draft       # 3. who patches what: the host OS, and the environment image
    python3 explore.py reach first-draft       # 4. what code in a deployment can reach, and who can reach in
    python3 explore.py call first-draft tsg-helpdesk-app
                                               # 5. one scoring request: network, auth mode, routing
    python3 explore.py identity first-draft    # 6. the endpoint's identity: its roles, and who holds the keys
    python3 explore.py record listKeys         # 7. one Activity Log row, field by field (or: record traffic)

Use `hardened` instead of `first-draft` to see the fixed version. Everything is fictional: Contoso is Microsoft's
documentation placeholder company, the subscription ID is all zeros, object IDs and keys are invented. twin.py is a
teaching model of the documented behaviour (README "How faithful is the twin?"), not Azure.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

import twin

HERE = pathlib.Path(__file__).resolve().parent
C = twin.COMPANY
DATA = HERE / "data" / "incident"
SETUPS = ("first-draft", "hardened")
WS, EP = C["endpoint_workspace"], C["endpoint"]
REG = C["registry"]["name"]


def _setup(a: list[str], i: int = 0) -> twin.Setup:
    name = a[i] if len(a) > i else "first-draft"
    if name not in SETUPS:
        raise SystemExit(f"choose first-draft or hardened (got {name})")
    return twin.Setup(name)


def _image(dep: dict) -> str:
    env = dep["environment"]
    return env.get("image", "?") if isinstance(env, dict) else env


def _short(ref: str) -> str:
    return ref.replace("azureml://registries/", "registry ").replace("/environments/", " environment ") \
              .replace("/models/", " model ").replace("/versions/", " version ")


def _mode(s: twin.Setup, ws: str) -> str:
    return twin.isolation_mode(s, ws)


# ---------------------------------------------------------------- 1. pieces

def cmd_pieces(a) -> None:
    s = _setup(a)
    print(f"Contoso's Azure Machine Learning pieces, setup {s.name} (fictional; all-zero subscription ID)\n")
    for ws, info in C["workspaces"].items():
        w = s.workspace[ws]
        print(f"  Workspace        {ws}: {info['purpose']}")
        print(f"                   managed network {_mode(s, ws)}, public network access {w.get('publicNetworkAccess')}")
        print(f"                   its own storage {info['storage']}, key vault {info['key_vault']}, container registry {info['registry_acr']}")
        computes = w.get("computes", [])
        if computes:
            print(f"                   compute instances (notebooks): {', '.join(c['name'] for c in computes)}")
    print(f"  Registry         {REG}: shares models across workspaces (storage {C['registry']['storage']})")
    for where, versions in s.models.items():
        if not isinstance(versions, dict):
            continue
        for key, v in versions.items():
            src = where.replace("workspace:", "workspace ").replace("registry:", "registry ")
            extra = f", promoted by {v['promoted_by']}" if v.get("promoted_by") else ""
            print(f"  Model            {key:<20} in {src:<30} registered by {v['registered_by']}{extra}")
    e = s.endpoint
    print(f"  Online endpoint  {e['name']} in {e['workspace']}: one address for the Helpdesk app")
    for dep, pct in e.get("traffic", {}).items():
        d = s.deployments[dep]
        print(f"  Deployment       {dep:<6} {pct:>3}% of traffic, {d['instance_count']} x {d['instance_type']}")
    print(f"  Endpoint identity  {e['identity']['principal']} ({e['identity']['type'].replace('_', '-')})")
    print("  Where models come from   notebooks in tsg-ml-dev (an open model, fine-tuned); the model catalog is Microsoft's, not used here")


# ---------------------------------------------------------------- 2. endpoint

def cmd_endpoint(a) -> None:
    s = _setup(a)
    e = s.endpoint
    print(f"One online endpoint and the deployments behind it (setup {s.name}). The files are in setups/{s.name}/.\n")
    print(f"1. Endpoint              endpoint.json  (az ml online-endpoint show)")
    print(f"   name                    {e['name']}, in workspace {e['workspace']}")
    print(f"   auth_mode               {e.get('auth_mode', 'key')}")
    print(f"   public_network_access   {e.get('public_network_access', 'enabled')}")
    print(f"   identity                {e['identity']['type']} ({e['identity']['principal']})")
    print(f"   traffic                 {', '.join(f'{k} {v}%' for k, v in e.get('traffic', {}).items())}")
    for i, (dep, d) in enumerate(((k, v) for k, v in s.deployments.items() if not k.startswith("_")), start=2):
        print(f"\n{i}. Deployment {dep:<12} deployments.json  (az ml online-deployment show)")
        print(f"   model                   {_short(d['model']) if d['model'].startswith('azureml://') else d['model']}")
        print(f"   environment             {_short(_image(d))}")
        print(f"   instance_type x count   {d['instance_type']} x {d['instance_count']}")
        env = d.get("environment_variables", {})
        print(f"   environment_variables   {', '.join(env) if env else 'none'}")
        dc = d.get("data_collector")
        print(f"   data_collector          {'request and response, sampling ' + str(dc.get('sampling_rate')) if dc else 'off'}")
    print("\nWhen a deployment starts (Microsoft's documented behaviour for managed online endpoints):")
    print("   the model is mounted in the container, by default at /var/azureml-app/azureml-models/<name>/<version>")
    print("   a container you bring must answer three routes: liveness, readiness and scoring")
    print("   the endpoint routes each request by the traffic split, or to the deployment named in the")
    print("   azureml-model-deployment header, whatever its share")


# ---------------------------------------------------------------- 3. patch

def cmd_patch(a) -> None:
    s = _setup(a)
    today = dt.date.fromisoformat(C["today"])
    print(f"Who patches what for Contoso's endpoint (setup {s.name})\n")
    print("  Microsoft  the host OS image of the endpoint's VMs (\"at least once a month\"), and new versions")
    print("             of its curated environments")
    print("  You        which environment version each deployment uses, anything you add to it or bring")
    print("             yourself, the model files, the network settings, the identity, the keys\n")
    for dep, d in s.deployments.items():
        if dep.startswith("_"):
            continue
        ref = _image(d)
        print(f"  deployment {dep}")
        print(f"     environment    {_short(ref)}")
        mine, newest, newest_date = twin.newest_curated(ref)
        if mine:
            age = (today - dt.date.fromisoformat(mine)).days
            print(f"     kind           curated (Microsoft builds it; you pick the version)")
            print(f"     this version   released {mine}   (a lab value)   {age} days before lab today {today}")
            print(f"     newest         version {newest}, released {newest_date}"
                  + ("   -> you are on the newest" if newest_date == mine else "   -> a newer version exists: update the deployment"))
        else:
            info = twin.ENVIRONMENTS["custom"].get(ref, {})
            print(f"     kind           your own image (from {info.get('registry', 'your registry')}): its patching is yours")
            pinned = "digest (the same bytes every time)" if "@sha256:" in ref else "tag (a tag can move to other bytes)"
            print(f"     pinned by      {pinned}")
    print("\n  A newer environment reaches a deployment only when you update the deployment to name it.")


# ---------------------------------------------------------------- 4. reach

def cmd_reach(a) -> None:
    s = _setup(a)
    print(f"What code can reach, and who can reach in (setup {s.name}), from twin.py\n")
    for ws in C["workspaces"]:
        rules = s.workspace[ws].get("managedNetwork", {}).get("outboundRules", {})
        print(f"  Workspace {ws}   managed network {_mode(s, ws)}")
        if rules:
            print(f"     outbound rules  " + ", ".join(f"{n} ({r['type']})" for n, r in rules.items()))
        for label, target in ((f"internet ({C['collector_host']})", f"internet:{C['collector_host']}"),
                              ("huggingface.co", "internet:huggingface.co"),
                              (f"its own storage {C['workspaces'][ws]['storage']}", f"storage:{C['workspaces'][ws]['storage']}"),
                              (f"registry {REG}", f"registry:{REG}")):
            ok, why = twin.egress(s, ws, target)
            print(f"     {label:<36} {'yes' if ok else 'no ':<4} {why}")
    print("\n  Who can reach in (inbound)")
    for ws in C["workspaces"]:
        ok, why = twin.inbound(s, ws, "internet")
        print(f"     workspace {ws:<15} from the internet        {'yes' if ok else 'no ':<4} {why}")
    for net in ("internet", "vnet"):
        ok, why = twin.inbound(s, "endpoint", net)
        where = "the internet" if net == "internet" else "Contoso's network"
        print(f"     endpoint  {EP:<15} from {where:<19} {'yes' if ok else 'no ':<4} {why}")


# ---------------------------------------------------------------- 5. call

def cmd_call(a) -> None:
    s = _setup(a)
    rest = [x for x in a[1:] if not x.startswith("--")]
    who = rest[0] if rest else "tsg-helpdesk-app"
    net = "internet" if "--internet" in a else "vnet"
    cred = "key" if "--key" in a else ("aad" if s.endpoint.get("auth_mode", "key") != "key" else "key")
    header = a[a.index("--deployment") + 1] if "--deployment" in a else None
    print(f"One scoring request (setup {s.name}). Nothing is sent: twin.py answers.\n")
    print(f"  POST <scoring_uri>   (the endpoint's address: az ml online-endpoint show -n {EP} --query scoring_uri)")
    print(f"  body       the ticket text, as JSON")
    print(f"  caller     {who}")
    print(f"  from       {'the internet' if net == 'internet' else "inside Contoso's network (through the workspace private endpoint, if there is one)"}")
    print(f"  credential {'an endpoint key in the Authorization header' if cred == 'key' else 'a Microsoft Entra token for ' + who}")
    if header:
        print(f"  header     azureml-model-deployment: {header}")
    print("\n  Checks, in order:")
    ok, why = twin.inbound(s, "endpoint", net)
    print(f"   1. network   (public_network_access {s.endpoint.get('public_network_access', 'enabled')})   {'pass' if ok else 'STOP'}: {why}")
    mode = s.endpoint.get("auth_mode", "key")
    if mode == "key":
        print(f"   2. auth      (auth_mode key)   a key needs no role: whoever holds it is in")
    else:
        allowed, rwhy = twin.decide(s, who, twin.A_SCORE, twin.endpoint_scope(s))
        print(f"   2. auth      (auth_mode {mode})   {'pass' if allowed else 'STOP'}: score/action {'granted by ' + rwhy if allowed else 'missing'}")
    print(f"   3. routing   {'the header picks the deployment' if header else 'the traffic split picks the deployment'}")
    r = twin.invoke(s, who, net, cred, header)
    print(f"\n  result     {'200 OK' if r['ok'] else 'REFUSED'}: {r['why']}")


# ---------------------------------------------------------------- 6. identity

def cmd_identity(a) -> None:
    s = _setup(a)
    ident = s.endpoint["identity"]
    p = ident["principal"]
    print(f"The endpoint's identity (setup {s.name})\n")
    print(f"  identity         {p} ({ident['type'].replace('_', '-')}), object ID {C['principals'][p]['oid']}")
    print("  who uses it      the deployment's containers, to pull the image and download the model files")
    if ident["type"] == "system_assigned":
        print("  given by Azure   AcrPull, Storage Blob Data Reader (the workspace's default datastore) and")
        print("                   AzureML Metrics Writer: assigned automatically for a system-assigned identity")
    else:
        print("  given by Azure   nothing: for a user-assigned identity, you assign every role")
    print("  role assignments (rbac.json)")
    for x in s.rbac.get("assignments", []):
        if x["principal"] == p:
            print(f"     {x['role']:<28} at {x['scope']}")
    print("\n  Who else can act on the endpoint")
    people = [n for n in C["principals"] if not n.startswith(("tsg-summariser", "id-tsg"))]
    keys = [n for n in people if twin.decide(s, n, twin.A_LIST_KEYS, twin.endpoint_scope(s))[0]]
    deploy = [n for n in people if twin.decide(s, n, twin.A_DEPLOY_WRITE, f"deployment:{WS}/{EP}/blue")[0]]
    score = [n for n in people if twin.decide(s, n, twin.A_SCORE, twin.endpoint_scope(s))[0]]
    print(f"     listKeys (read the keys)          {', '.join(keys) or 'nobody'}")
    print(f"     deployments/write (change it)     {', '.join(deploy) or 'nobody'}")
    print(f"     score/action (call it with Entra) {', '.join(score) or 'nobody'}")


# ---------------------------------------------------------------- 7. record

def cmd_record(a) -> None:
    what = a[0] if a else "listKeys"
    if what == "traffic":
        rows = json.loads((DATA / "endpoint-traffic.json").read_text())["rows"]
        r = rows[0]
        print("One AmlOnlineEndpointTrafficLog row from data/incident/endpoint-traffic.json (fake values, real column names)\n")
        for col in ("TimeGenerated", "EndpointName", "DeploymentName", "Method", "Path", "AuthType", "IdentityData",
                    "ResponseCode", "UserAgent", "RequestPayloadSize", "TotalDurationMs"):
            note = f"   ({twin.name_for_oid(r[col])})" if col == "IdentityData" else ""
            print(f"  {col:<20} {r[col]}{note}")
        print("\n  No client IP column and no prompt: only sizes. Rows exist only if a diagnostic setting sends them to Log Analytics.")
        return
    rows = json.loads((DATA / "azure-activity.json").read_text())["rows"]
    r = next((x for x in rows if x["OperationNameValue"].lower().endswith(what.lower() + "/action")
              or x["OperationNameValue"].lower().endswith("/" + what.lower())), None)
    if r is None:
        raise SystemExit(f"no {what} row in azure-activity.json; try listKeys, write, regenerateKeys or traffic")
    print("One AzureActivity row from data/incident/azure-activity.json (fake values, real column names)\n")
    print(f"  who      Caller {r['Caller']}   ({twin.name_for_oid(r['Caller'])})")
    print(f"  what     {r['OperationNameValue']}")
    rid = r["_ResourceId"]
    print(f"  on       .../workspaces/{rid.split('/workspaces/')[1]}")
    print(f"  kind     CategoryValue {r['CategoryValue']}  (a control-plane operation, through Azure Resource Manager)")
    print(f"  from     {r['CallerIpAddress']}")
    print(f"  when     {r['TimeGenerated']}")
    print(f"  status   {r['ActivityStatusValue']}")
    print("  result   the row says the keys were read, not what anyone did with them: key calls show up only in the traffic log")


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
