"""
explore.py: look at how Google Cloud decides and records one request, one step at a time, before you attack the lab
(GC10 lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's JSON
files and prints what it finds.

    python3 explore.py org                     # 1. ExampleCo's organization, folders, projects, robots and API keys
    python3 explore.py auth                    # 2. how a call proves who it is: an access token, or an API key
    python3 explore.py policy examplecorp/iam/folders-111111111111.json
                                               # 3. one allow policy, read binding by binding
    python3 explore.py decide alice aiplatform.endpoints.predict example-ds-sandbox
                                               # 4. allowed or denied? walk up the tree, then the org policy
    python3 explore.py call chatbot-runtime gemini-3.1-flash-lite example-chatbot-prod
                                               # 5. one generateContent call: the request, and every check it needs
    python3 explore.py event GenerateContent   # 6. one Cloud Audit Logs entry, field by field

Everything is fake: example.com identities, placeholder numbers, RFC 5737 IP addresses.
gcp_eval.py, which `decide` and `call` use, is a teaching model of Google Cloud's rules, not the real engine.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.dont_write_bytecode = True

from gcp_eval import Corp, Request, evaluate, role_grants

HERE = pathlib.Path(__file__).resolve().parent
AUDIT = HERE / "auditlogs" / "examplecorp-2026-10-12_16.jsonl"
AI = "aiplatform.googleapis.com"
MODELS = {"gemini-3.1-flash-lite": "google", "gemini-3.5-flash": "google",
          "claude-opus-4-7": "anthropic", "claude-haiku-4-5": "anthropic"}


def member(corp: Corp, who: str) -> str:
    """'alice' -> user:alice@example.com, 'legacy-etl' -> serviceAccount:legacy-etl@..., or a full member string."""
    if ":" in who:
        return who
    for sa in corp.service_accounts:
        if sa["email"].split("@")[0] == who:
            return f"serviceAccount:{sa['email']}"
    for m in {m for ms in corp.groups.values() for m in ms} | {m for _, b in corp.bindings_everywhere() for m in b["members"]}:
        if m.split(":", 1)[1].split("@")[0] == who:
            return m
    sys.exit(f"unknown principal {who!r}: try alice, bob, legacy-etl, ci-deployer, chatbot-runtime")


def _short(m: str) -> str:
    """Drop the 'serviceAccount:'-style prefix only where the column already says what it is."""
    return m


# ---------------------------------------------------------------- 1. org

def cmd_org(a) -> None:
    corp = Corp(with_fixes=a.fixes)
    print("ExampleCo's Google Cloud (fictional; numbers are placeholders)\n")
    print(f"  organization  {corp.org['name']}  ({corp.org['displayName']}, created {corp.org['createTime'][:10]})")
    for fname, f in corp.folders.items():
        print(f"    folder      {fname}  ({f['displayName']})")
        for pid, p in corp.projects.items():
            if p["parent"] == fname:
                ai = [s.split(".")[0] for s in p["enabledServices"] if s in (AI, "generativelanguage.googleapis.com")]
                print(f"      project   {pid:<20} number {p['projectNumber']}   AI APIs on: {', '.join(ai) or 'none'}")
    print("\nService accounts (identities for software) and their user-managed keys:\n")
    for sa in corp.service_accounts:
        keys = sa["userManagedKeys"]
        k = f"{len(keys)} key, valid until {keys[0]['validBeforeTime'][:10]} (never expires)" if keys else "no keys"
        print(f"  {sa['email']:<62} {k}")
        print(f"    attached to: {sa['attachedTo']}")
    print("\nAPI keys (no identity; billed to their project):\n")
    for k in corp.keys:
        r = k.get("restrictions", {})
        what = ", ".join(t["service"].split(".")[0] for t in r.get("apiTargets", [])) or "ANY API"
        where = "IPs " + ",".join(r["serverKeyRestrictions"]["allowedIps"]) if "serverKeyRestrictions" in r else \
            ("websites" if "browserKeyRestrictions" in r else "anywhere")
        bound = f"   bound to {_short(k['serviceAccountEmail'])}" if k.get("serviceAccountEmail") else ""
        print(f"  {k['displayName']:<22} project {corp.key_project(k):<20} may call {what}; from {where}{bound}")


# ---------------------------------------------------------------- 2. auth

def cmd_auth(a) -> None:
    corp = Corp()
    etl = next(s for s in corp.service_accounts if s["email"].startswith("legacy-etl@"))
    print("How a call to Google Cloud proves who is calling. Nothing is sent.\n")
    print("Way 1: an OAuth 2.0 access token (what the chatbot on Cloud Run uses)")
    print("  The code asks Application Default Credentials (ADC) for a token. On Cloud Run, ADC gets it from the")
    print("  metadata server, for the service account ATTACHED to the service: chatbot-runtime.")
    print("  Authorization: Bearer <access token>")
    print("  The token is opaque (not meant to be read) and lasts 1 hour by default. Whoever holds it can use it.\n")
    print("Way 2: a downloaded service account key (what legacy-etl's laptop job used)")
    print("  A JSON file with a private key. The code signs a short token (a JWT) with it and uses that,")
    print("  or trades it for an access token. The key itself does not expire:")
    k = etl["userManagedKeys"][0]
    print(f"    client_email    {etl['email']}")
    print(f"    private_key_id  {k['keyId']}")
    print(f"    valid after     {k['validAfterTime']}")
    print(f"    valid before    {k['validBeforeTime']}   (= never)")
    print("  Copy the file and you ARE legacy-etl, from anywhere, until someone deletes the key.\n")
    print("Way 3: an API key (what the chatbot's web tier and the notebook use)")
    print("  x-goog-api-key: <the key string>")
    print("  A standard key names no one: Google ties the call to the key's project. Its only limits are its")
    print("  restrictions (which APIs, from which IPs or websites). A key bound to a service account")
    print("  authenticates AS that service account (ops-eval-key, lesson 10.4).\n")
    print("Then, for Ways 1 and 2 (and a bound key), IAM checks the identity's roles: see decide.")


# ---------------------------------------------------------------- 3. policy

def cmd_policy(a) -> None:
    path = pathlib.Path(a.file)
    doc = json.loads((path if path.is_absolute() or path.exists() else HERE / path).read_text())
    shown = {k: v for k, v in doc.items() if not k.startswith("_")}
    print(f"{a.file}  (the allow policy on {doc.get('_resource', '?')})\n")
    print(json.dumps(shown, indent=2))
    print("\nRead it binding by binding:")
    for i, b in enumerate(doc.get("bindings", []), 1):
        print(f"\n  binding {i}  role {b['role']}: a bundle of permissions")
        for m in b["members"]:
            kind = m.split(":", 1)[0]
            what = {"serviceAccount": "a service account: software", "group": "a group of people",
                    "user": "one person"}.get(kind, kind)
            print(f"             member {_short(m)}  ({what})")
        if "condition" in b:
            print(f"             condition {b['condition'].get('expression')}")
    for c in doc.get("auditConfigs", []):
        types = ", ".join(x["logType"] for x in c["auditLogConfigs"])
        print(f"\n  auditConfigs  {c['service']}: {types}  (Data Access audit logs switched ON for it)")
    if not doc.get("auditConfigs"):
        print("\n  auditConfigs  none: Data Access audit logs stay off here (Google's default)")
    print(f"  etag          {doc.get('etag')}: a version stamp, so two people can't overwrite each other's change")
    res = doc.get("_resource", "")
    if not res.startswith("projects/"):
        print(f"\n  Every binding here also applies to every project under {res}.")


# ---------------------------------------------------------------- 4. decide

def cmd_decide(a) -> None:
    corp = Corp(with_fixes=a.fixes)
    if a.model and "/" not in a.model:
        a.model = f"publishers/{MODELS.get(a.model, 'google')}/models/{a.model}:predict"
    m = member(corp, a.principal)
    who = corp.identities(m)
    print(f"request   {_short(m)} wants {a.permission}")
    print(f"on        projects/{a.project}{'   model ' + a.model if a.model else ''}")
    print(f"as        {', '.join(sorted(_short(x) for x in who))}  (itself plus its groups)")
    print(f"world     {'fixes/' if a.fixes else 'examplecorp/ (today)'}\n")
    print("step 1  walk up the tree, nearest first: which bindings name it, and does the role include the permission?")
    found = None
    for res in corp.ancestry(a.project):
        hits = [b for b in corp.iam.get(res, {}).get("bindings", []) if who & set(b["members"])]
        if not hits:
            print(f"          {res:<32} no binding for it")
        for b in hits:
            ok = role_grants(b["role"], a.permission)
            print(f"          {res:<32} {b['role']:<44} {'YES' if ok else 'no'}")
            found = found or (ok and f"{b['role']} on {res}")
    if not found:
        print(f"\n=> DENIED: no role anywhere up the tree gives it {a.permission} (no allow = denied)")
        return
    if a.model:
        ok, text = corp.model_allowed(a.project, a.model)
        print(f"step 2  organization policy vertexai.allowedModels for {a.model}:")
        print(f"          {text}")
        if not ok:
            print("\n=> DENIED: IAM allows it, but the organization policy refuses this model")
            return
    else:
        print("step 2  organization policy: no model in this request, so vertexai.allowedModels doesn't apply")
    print(f"\n=> ALLOWED: {found} (inherited by {a.project}), and nothing refuses it")


# ---------------------------------------------------------------- 5. call

def cmd_call(a) -> None:
    corp = Corp(with_fixes=a.fixes)
    pub = MODELS[a.model]
    verb = "generateContent" if pub == "google" else "rawPredict"
    caller = f"apikey:{a.caller}" if a.caller in {k["displayName"] for k in corp.keys} else member(corp, a.caller)
    print(f"One {verb} call, as the app would send it (illustrative; nothing is sent):\n")
    loc = "global"
    print(f"  POST https://{AI}/v1/projects/{a.project}/locations/{loc}")
    print(f"       /publishers/{pub}/models/{a.model}:{verb}      (one URL, split here to fit)")
    print(f"  {'x-goog-api-key: <the key string>' if caller.startswith('apikey:') else 'Authorization: Bearer <access token>'}")
    print('  {"contents": {"role": "user", "parts": {"text": "Summarise ticket 4521 in one line."}}}\n')
    req = Request(caller, a.project, AI, "GenerateContent" if pub == "google" else "RawPredict",
                  "aiplatform.endpoints.predict", model=f"publishers/{pub}/models/{a.model}:predict",
                  source_ip=a.source_ip)
    d = evaluate(corp, req)
    print(f"Calling a model needs the IAM permission aiplatform.endpoints.predict. The checks, in order (from {a.source_ip}):")
    for ok, t in d.checks:
        print(f"  {'ok ' if ok else 'NO '} {t}")
    print(f"\n=> the call {'goes through' if d.allowed else 'is refused'}: every check must pass. "
          "If it goes through, the bill counts input and output tokens.")


# ---------------------------------------------------------------- 6. event

def cmd_event(a) -> None:
    rows = [json.loads(line) for line in AUDIT.read_text().splitlines() if line.strip()]
    hits = [(i, r) for i, r in enumerate(rows, 1) if r["protoPayload"]["methodName"].endswith("." + a.name)
            and (not a.source_ip or r["protoPayload"]["requestMetadata"]["callerIp"] == a.source_ip)]
    if not hits:
        sys.exit(f"no {a.name} entry" + (f" from {a.source_ip}" if a.source_ip else ""))
    i, r = hits[min(a.nth, len(hits)) - 1]
    p = r["protoPayload"]
    kind = r["logName"].rsplit("%2F", 1)[-1]
    auth = p.get("authorizationInfo", [{}])[0]
    print(f"Audit log entry {i} of {len(rows)} (fake, with the fields of Google's AuditLog format)\n")
    out = [("which", "logName", f".../cloudaudit.googleapis.com%2F{kind}   ({'Data Access' if kind == 'data_access' else 'Admin Activity' if kind == 'activity' else kind})"),
           ("who", "principalEmail", p["authenticationInfo"].get("principalEmail", "-")),
           ("what", "serviceName", p["serviceName"]),
           ("", "methodName", p["methodName"]),
           ("", "resourceName", p["resourceName"]),
           ("where", "callerIp", p["requestMetadata"]["callerIp"]),
           ("", "userAgent", p["requestMetadata"].get("callerSuppliedUserAgent", "-")),
           ("when", "timestamp", r["timestamp"]),
           ("how", "permission", f"{auth.get('permission', '-')}  granted={auth.get('granted', '-')}"),
           ("result", "status", json.dumps(p.get("status", {})) + ("  (empty: it worked)" if not p.get("status") else ""))]
    for g, k, v in out:
        print(f"  {g:<7}{k:<15}{v}")
    if kind == "data_access":
        print("\n  This entry exists only because Data Access logs are switched on for aiplatform in this project.")
        print("  not here: the prompt and the answer. The audit log records the call, not the conversation.")
    else:
        print("\n  Admin Activity entries are always written: nobody had to switch them on.")


# ---------------------------------------------------------------- main

def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="Look at how Google Cloud decides and records one request (GC10 lab, read-only).")
    sub = p.add_subparsers(dest="cmd", required=True)
    projects = sorted(Corp().projects)
    s = sub.add_parser("org"); s.add_argument("--fixes", action="store_true", help="show fixes/ applied")
    s.set_defaults(fn=cmd_org)
    s = sub.add_parser("auth"); s.set_defaults(fn=cmd_auth)
    s = sub.add_parser("policy"); s.add_argument("file", help="an allow policy, e.g. examplecorp/iam/folders-111111111111.json")
    s.set_defaults(fn=cmd_policy)
    s = sub.add_parser("decide"); s.add_argument("principal", help="alice, bob, legacy-etl, ci-deployer, chatbot-runtime, ...")
    s.add_argument("permission", help="e.g. aiplatform.endpoints.predict"); s.add_argument("project", choices=projects)
    s.add_argument("--model", help="e.g. publishers/google/models/gemini-3.5-flash:predict")
    s.add_argument("--fixes", action="store_true", help="apply fixes/"); s.set_defaults(fn=cmd_decide)
    s = sub.add_parser("call"); s.add_argument("caller", help="a principal (alice, chatbot-runtime, ...) or an API key name")
    s.add_argument("model", choices=sorted(MODELS)); s.add_argument("project", choices=projects)
    s.add_argument("--from", dest="source_ip", default="192.0.2.10", help="the caller's IP address")
    s.add_argument("--fixes", action="store_true", help="apply fixes/"); s.set_defaults(fn=cmd_call)
    s = sub.add_parser("event"); s.add_argument("name", help="the end of a methodName, e.g. GenerateContent, CreateKey")
    s.add_argument("--from", dest="source_ip", help="only entries from this IP address")
    s.add_argument("--nth", type=int, default=1, help="which matching entry (1 = the earliest)"); s.set_defaults(fn=cmd_event)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
