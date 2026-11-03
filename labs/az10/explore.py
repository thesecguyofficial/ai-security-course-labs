"""
explore.py: look at how Azure decides and records one request, one step at a time, before you run the lab
(AZ10 lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's JSON
files and prints what it finds; `token` also builds a fake access token in memory and sends nothing.

    python3 explore.py tenant                  # 1. Contoso's tenant, subscription, resource groups, resources, people
    python3 explore.py token                   # 2. how a call proves who it is: an Entra ID token, or a key
    python3 explore.py role contoso/roles/foundry-user.json
                                               # 3. one role definition, read field by field
    python3 explore.py decide data-science inference contoso-sandbox-ai --deployment sandbox-gpt52
                                               # 4. allowed or denied? the checks, in order
    python3 explore.py call helpdesk-app helpdesk-gpt5
                                               # 5. one chat call: the request, and what Azure checks
    python3 explore.py event listKeys          # 6. one Activity Log record, field by field
    python3 explore.py event ChatCompletions   #    and one request-log row, for comparison

Everything is fake: Microsoft documentation example GUIDs, RFC 5737 IP addresses, keys that say EXAMPLE.
azure_model.py, which `decide` and `call` use, is a teaching model of Azure RBAC, keys and Azure Policy, not Azure.
"""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import sys

sys.dont_write_bytecode = True

import attack
from azure_model import OPS, Azure, deployment_fields, account_fields, policy_effects, scope_covers, short_scope

HERE = pathlib.Path(__file__).resolve().parent
ACTIVITY = HERE / "logs" / "activity-log.json"
REQUESTS = HERE / "logs" / "azurediagnostics-requestresponse.json"

MODELS = {"gpt-5": attack.GPT5_V1, "gpt-5.2v2": attack.GPT52_V2, "gpt-5.4": attack.GPT54,
          "fabrikam": attack.FABRIKAM_MODEL}


def world(fixes: bool) -> Azure:
    return attack.world("safe" if fixes else "vulnerable")


# ---------------------------------------------------------------- 1. tenant

def cmd_tenant(a) -> None:
    az = world(a.fixes)
    e = az.estate
    print("Contoso's Azure (fictional; the IDs are Microsoft documentation examples)\n")
    print(f"  tenant          {e['tenantId']}   the directory (Microsoft Entra ID): who exists, how they sign in")
    print(f"  subscription    {e['subscriptionId']}   trusts that tenant; gets the bill")
    groups: dict[str, list] = {}
    for acct in e["accounts"]:
        groups.setdefault(acct["id"].split("/")[4], []).append(acct)
    for rg, accts in groups.items():
        print(f"    resource group  {rg}")
        for acct in accts:
            p = acct["properties"]
            print(f"      resource      {acct['name']}  ({acct['kind']}, {acct['location']})  "
                  f"keys {'OFF' if p.get('disableLocalAuth') else 'ON'}  public network {p.get('publicNetworkAccess')}")
            for d in acct["deployments"]:
                m = d["properties"]["model"]
                print(f"        deployment  {d['name']:<14} model {m['name']} version {m['version']}  ({d['sku']['name']})")
    print("\nIdentities (security principals) and their role assignments (role @ scope; a scope covers everything below it):\n")
    for name, p in az.principals.items():
        print(f"  {p['type']:<16} {name:<15} {p['displayName']}")
        for asg in az.assignments:
            if asg["principalName"] == name:
                print(f"{'':<19}{asg['roleDefinitionName']} @ {short_scope(asg['scope'])}")
    print("\nAzure Policy assignments:")
    for pa in az.policies:
        eff = pa.get("parameters", {}).get("effect", {}).get("value", "default")
        print(f"  {pa['name']} @ {short_scope(pa['scope'])}  effect {eff}")


# ---------------------------------------------------------------- 2. token

def _b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def cmd_token(a) -> None:
    az = world(False)
    tid = az.estate["tenantId"]
    oid = az.principals["helpdesk-app"]["objectId"]
    iat = 1791968400                                    # 2026-10-14T09:00:00Z
    header = {"typ": "JWT", "alg": "RS256", "kid": "EXAMPLE-KEY-ID"}
    payload = {"aud": "https://cognitiveservices.azure.com", "iss": f"https://sts.windows.net/{tid}/",
               "iat": iat, "nbf": iat, "exp": iat + 24 * 3600, "oid": oid, "sub": oid, "tid": tid}
    print("How a call to a Foundry resource proves who is calling. Nothing is sent; this token is fake.\n")
    print("Way 1: a Microsoft Entra ID access token (what the helpdesk app's managed identity gets)")
    print("  the app asks Entra ID for a token for the scope https://cognitiveservices.azure.com/.default")
    print("  and sends it in every request:\n")
    print(f"  Authorization: Bearer {_b64url(header)}.{_b64url(payload)[:24]}...<signature>\n")
    print("  A token is three base64url parts: header . payload . signature. The payload, decoded:")
    notes = {"aud": "audience: the service this token is for (Foundry's data plane)",
             "iss": "issuer: the Entra ID tenant that signed it",
             "iat": "issued at (seconds since 1970: 2026-10-14 09:00 UTC)",
             "nbf": "not valid before",
             "exp": "expires: about a day later (managed identity tokens are cached for around 24 hours)",
             "oid": "object ID: WHO is calling (the helpdesk-app managed identity)",
             "sub": "subject: the principal the token is about",
             "tid": "tenant ID: which directory the caller belongs to"}
    for k, v in payload.items():
        if len(str(v)) > 40:
            print(f"    {k:<4} {v}\n{'':<46}{notes[k]}")
        else:
            print(f"    {k:<4} {str(v):<40} {notes[k]}")
    print("\n  Azure checks the signature, then runs Azure RBAC for that oid at the resource's scope (see decide).")
    print("  Anyone who copies the token can use it until exp: it is a bearer token, not tied to one request.")
    print("  (A user's token gets a random lifetime of 60 to 90 minutes; a managed identity's lasts far longer.)\n")
    print("Way 2: the resource's key (accepted while key access is on, as on both Contoso resources)")
    print("  api-key: <one of the resource's two keys>")
    print("  No name, no expiry, no role check. Whoever holds the key is let in (lesson 10.4).")


# ---------------------------------------------------------------- 3. role

def _show(values) -> str:
    vals = list(values)
    if not vals:
        return "(none)"
    return ", ".join(vals) if len(vals) < 4 else f"{len(vals)} entries: " + ", ".join(vals[:2]) + ", ..."


def cmd_role(a) -> None:
    path = pathlib.Path(a.file)
    doc = json.loads((path if path.is_absolute() or path.exists() else HERE / path).read_text())
    print(f"{a.file}\n")
    print(json.dumps({k: v for k, v in doc.items() if k != "source"}, indent=2))
    print("\nRead it field by field:\n")
    print(f"  roleName        {doc['roleName']}: the name people see")
    print(f"  id              {doc['id']}: the role's ID, the same in every tenant for built-in roles")
    print(f"  actions         {_show(doc['actions'])}")
    print("                  = what it may do to MANAGE resources (control plane, through Azure Resource Manager)")
    print(f"  notActions      {_show(doc['notActions'])}")
    print("                  = taken away from actions")
    print(f"  dataActions     {_show(doc['dataActions'])}")
    print("                  = what it may do INSIDE a resource (data plane: for Foundry, calling a model)")
    print(f"  notDataActions  {_show(doc['notDataActions'])}")
    print("                  = taken away from dataActions")
    keys = [x for x in doc["actions"] if "listkeys" in x.lower()]
    if keys or "*" in doc["actions"]:
        print(f"\n  note: {'*' if '*' in doc['actions'] else keys[0]} lets it read the resource's keys (listKeys).")


# ---------------------------------------------------------------- 4. decide

def _target(az: Azure, account: str, deployment: str | None) -> str:
    return az.account(account)["id"] + (f"/deployments/{deployment}" if deployment else "")


def cmd_decide(a) -> None:
    az = world(a.fixes)
    kind, perm, _ = OPS[a.op]
    target = _target(az, a.account, a.deployment)
    model = MODELS.get(a.model) if a.model else None
    print(f"request   {a.principal} wants {a.op} = {perm}{'...' if kind == 'data' else ''}")
    print(f"          {'data plane (using the resource)' if kind == 'data' else 'control plane (managing it, via Azure Resource Manager)'}")
    print(f"resource  {short_scope(target)}  ({a.account})")
    print(f"world     {'fixes/' if a.fixes else 'contoso/ (today)'}\n")
    d = az.request(a.principal, a.op, a.account, key_of=a.account if a.key else None,
                   deployment=a.deployment, model=model,
                   set_props={"disableLocalAuth": False} if a.op == "accountWrite" else None)
    print(f"step 1  how does it prove who it is?  {'the resource KEY (api-key header)' if a.key else 'an Entra ID token (who: ' + a.principal + ')'}")
    if a.key:
        print(f"        {d.why[0]}")
        return print(f"\n=> {'ALLOWED' if d.allowed else 'DENIED'} ({d.status}): steps 2 to 4 never run for a key")
    mine = [x for x in az.assignments if x["principalName"] == a.principal]
    print(f"step 2  its role assignments ({len(mine)}): which ones cover this resource?")
    for x in mine:
        cov = scope_covers(x["scope"], target)
        print(f"          {'covers  ' if cov else 'no      '}{x['roleDefinitionName']} @ {short_scope(x['scope'])}")
    if not any(scope_covers(x["scope"], target) for x in mine):
        print("          none covers it")
    print(f"step 3  does a covering role include {perm}{'...' if kind == 'data' else ''}?")
    for line in d.why:
        if line.startswith(("GRANT", "no ")):
            print(f"          {line}")
    rbac_ok = any(x.startswith("GRANT") for x in d.why)
    if not rbac_ok:
        return print(f"\n=> DENIED ({d.status}): no role gives it this permission here (Azure RBAC only adds; nothing allows it)")
    pol = [x for x in d.why if x.startswith("POLICY")]
    if a.op in ("deploymentWrite", "accountWrite"):
        fields = deployment_fields(model or {}) if a.op == "deploymentWrite" else account_fields({"disableLocalAuth": False})
        n = len([p for p in az.policies if scope_covers(p["scope"], target)])
        print(f"step 4  Azure Policy: {n} assignment(s) cover it; rules matched: {', '.join(pol) if pol else 'none'}")
    else:
        print("step 4  Azure Policy: not checked for this request (the lab's two policies look at deployments and settings)")
    if d.allowed:
        print(f"\n=> ALLOWED ({d.status}): a role covers it{' (Audit only logs a warning)' if d.status == 'Audit' else ''}")
    else:
        print(f"\n=> DENIED ({d.status}): a policy with effect Deny refused it, whatever the role allows")


# ---------------------------------------------------------------- 5. call

def cmd_call(a) -> None:
    az = world(a.fixes)
    acct = next((x for x in az.estate["accounts"] if any(d["name"] == a.deployment for d in x["deployments"])), None)
    if acct is None:
        sys.exit(f"no deployment called {a.deployment}")
    host = f"{acct['properties']['customSubDomainName']}.openai.azure.com"
    body = {"model": a.deployment, "messages": [{"role": "user", "content": "Summarise ticket 4521 in one line."}]}
    print("One chat call, as the app would send it (illustrative; nothing is sent):\n")
    print(f"  POST https://{host}/openai/v1/chat/completions")
    print(f"  {'api-key: <the resource key>' if a.key else 'Authorization: Bearer <Entra ID token for https://cognitiveservices.azure.com>'}")
    print(f"  {json.dumps(body)}\n")
    print("  The request goes straight to the resource's own endpoint (the data plane), not to Azure Resource Manager.")
    print(f"  \"model\" names the DEPLOYMENT ({a.deployment}), which points at one model version.\n")
    d = az.request(a.principal, "inference", acct["name"], key_of=acct["name"] if a.key else None,
                   deployment=a.deployment)
    print("What Azure checks:")
    for line in d.why:
        print(f"  {line}")
    print(f"\n=> {'ALLOWED' if d.allowed else 'DENIED'} ({d.status}). If it goes through, the bill counts input and output tokens.")


# ---------------------------------------------------------------- 6. event

def cmd_event(a) -> None:
    name = a.name.lower()
    acts = json.loads(ACTIVITY.read_text())["value"]
    hits = [(i, r) for i, r in enumerate(acts, 1) if name in r["operationName"]["value"].lower()
            and (not a.source_ip or r["httpRequest"]["clientIpAddress"] == a.source_ip)]
    if hits:
        i, r = hits[min(a.nth, len(hits)) - 1]
        print(f"Activity Log record {i} of {len(acts)} (fake, trimmed to the fields of Microsoft's schema)\n")
        who = r["caller"]
        for pname, pr in world(False).principals.items():
            if who in (pr.get("appId"), pr["displayName"]):
                who += f"  (= {pname}, a {pr['type']}{': its app ID' if who.startswith(pr.get('appId') or '-') else ''})"
        rows = [("who", "caller", who),
                ("what", "operationName", r["operationName"]["value"]),
                ("", "resourceId", short_scope(r["resourceId"]) + "  (shortened here)"),
                ("where", "clientIpAddress", r["httpRequest"]["clientIpAddress"]),
                ("", "method", r["httpRequest"]["method"]),
                ("when", "eventTimestamp", r["eventTimestamp"]),
                ("kind", "category", r["category"]["value"]),
                ("result", "status", f"{r['status']['value']}  ({r['subStatus']['value'] or '-'})")]
        for g, k, v in rows:
            print(f"  {g:<7}{k:<17}{v}")
        print("\n  not here: any model call. The Activity Log covers the control plane (managing), not the data plane.")
        return
    reqs = json.loads(REQUESTS.read_text())["rows"]
    hits = [(i, r) for i, r in enumerate(reqs, 1) if r["OperationName"].lower() == name
            and (not a.source_ip or r["CallerIPAddress"] == a.source_ip)]
    if not hits:
        sys.exit(f"no {a.name} record" + (f" from {a.source_ip}" if a.source_ip else ""))
    i, r = hits[min(a.nth, len(hits)) - 1]
    print(f"Request-log row {i} of {len(reqs)} (fake AzureDiagnostics, category {r['Category']}: a resource log)\n")
    rows = [("what", "OperationName", r["OperationName"]), ("", "properties_s", r["properties_s"]),
            ("", "_ResourceId", short_scope(r["_ResourceId"]) + "  (shortened here)"),
            ("where", "CallerIPAddress", r["CallerIPAddress"]), ("when", "TimeGenerated", r["TimeGenerated"]),
            ("result", "ResultSignature", r["ResultSignature"]), ("", "DurationMs", r["DurationMs"])]
    for g, k, v in rows:
        print(f"  {g:<7}{k:<17}{v}")
    print("\n  This row exists only because a diagnostic setting sends the resource's logs somewhere.")
    print("  not here: the prompt and the answer.")


# ---------------------------------------------------------------- main

def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="Look at how Azure decides and records one request (AZ10 lab, read-only).")
    sub = p.add_subparsers(dest="cmd", required=True)
    principals = sorted(world(False).principals)
    accounts = ["contoso-helpdesk-ai", "contoso-sandbox-ai"]
    s = sub.add_parser("tenant"); s.add_argument("--fixes", action="store_true", help="show fixes/ instead")
    s.set_defaults(fn=cmd_tenant)
    s = sub.add_parser("token"); s.set_defaults(fn=cmd_token)
    s = sub.add_parser("role"); s.add_argument("file", help="a role JSON, e.g. contoso/roles/owner.json")
    s.set_defaults(fn=cmd_role)
    s = sub.add_parser("decide"); s.add_argument("principal", choices=principals)
    s.add_argument("op", choices=sorted(OPS)); s.add_argument("account", choices=accounts)
    s.add_argument("--deployment"); s.add_argument("--model", choices=sorted(MODELS), help="for deploymentWrite")
    s.add_argument("--key", action="store_true", help="the caller presents the resource's key")
    s.add_argument("--fixes", action="store_true", help="use fixes/"); s.set_defaults(fn=cmd_decide)
    s = sub.add_parser("call"); s.add_argument("principal", choices=principals); s.add_argument("deployment")
    s.add_argument("--key", action="store_true", help="the call uses the resource's key")
    s.add_argument("--fixes", action="store_true", help="use fixes/"); s.set_defaults(fn=cmd_call)
    s = sub.add_parser("event"); s.add_argument("name", help="e.g. listKeys, deployments/write, ChatCompletions")
    s.add_argument("--from", dest="source_ip", help="only records from this IP address")
    s.add_argument("--nth", type=int, default=1, help="which matching record (1 = the earliest)")
    s.set_defaults(fn=cmd_event)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
