"""
explore.py: look at each piece of TSG Helpdesk on Gemini Enterprise Agent Platform, one step at a time, before you
check and attack the lab (GC11 lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's offline
twin (twin/<name>/plan.json and app.json, twin/requirements.json, twin/groups.json) and prints what it finds.

    python3 explore.py plan                    # 1. what a Terraform plan is: everything it WOULD create
    python3 explore.py model                   # 2. the model's full name, the endpoint the app calls, the allow-list
    python3 explore.py role                    # 3. who holds which role, on what, and what each role contains
    python3 explore.py route global            # 4. one location: where the prompt may be processed, and the path to it
    python3 explore.py network                 # 5. the network: VPC, subnet, VMs, external IPs, NAT, firewall
    python3 explore.py endpoint                # 6. the private door to Google APIs, and the fence around the project
    python3 explore.py keys                    # 7. the Cloud KMS key and what it protects
    python3 explore.py logging                 # 8. what gets recorded: audit logs, request-response logging, cache
    python3 explore.py record                  # 9. one Helpdesk call in two records, side by side

Most commands take a twin name: today (the default, the Helpdesk as it runs now), hardened (what terraform/ builds)
or global-endpoint (the hardened twin after a developer's change, README Step 6).
Everything is fake: example.com identities, placeholder project numbers, documentation IP ranges.
twin.py, which role, route, network and endpoint use, is a teaching model of Google Cloud's rules, not Google.
"""

from __future__ import annotations

import argparse
import collections

from twin import Deployment, ROLE_PERMISSIONS

TWINS = ("today", "hardened", "global-endpoint")
SA = "serviceAccount:chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com"

# What each kind of location promises about ML processing (Google's data residency page, checked 3 Nov 2026).
MULTI = {"eu": "aiplatform.eu.rep.googleapis.com", "us": "aiplatform.us.rep.googleapis.com"}


def _d(name: str) -> Deployment:
    return Deployment.load(name)


def _short(s: str, n: int = 64) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


# ---------------------------------------------------------------- 1. plan

def cmd_plan(a) -> None:
    d = _d(a.twin)
    rs = d.resources()
    print(f"Terraform plan, {a.twin}: twin/{a.twin}/plan.json")
    print(f"  shaped like `terraform show -json` (format {d.plan.get('format_version')}), written by hand for the lab")
    print(f"  {len(rs)} resources it WOULD create   (a plan changes nothing; apply would)\n")
    by_type = collections.defaultdict(list)
    for r in rs:
        by_type[r["type"]].append(r["name"])
    for t in sorted(by_type):
        print(f"  {len(by_type[t]):>2} x {t:<52} {_short(', '.join(by_type[t]), 56)}")
    print(f"\nPlus twin/{a.twin}/app.json: settings Terraform can't express (location, endpoint, logging, cache).")
    print(f"{len(rs)} resources. Nothing exists yet: this is the plan, read before anything is built.")


# ---------------------------------------------------------------- 2. model

def cmd_model(a) -> None:
    d = _d(a.twin)
    app = d.app
    print(f"The Helpdesk's model, {a.twin} (twin/{a.twin}/app.json):\n")
    print(f"  model (publisher model)  {app['model']}")
    print(f"  location                 {app['location']}")
    print(f"  endpoint the app calls   https://{app['endpoint_host']}")
    print(f"  path in each call        .../locations/{app['location']}/{app['model']}:generateContent")
    print(f"  runs as                  {app['service_account']}\n")
    pol = d.allowed_models_policy()
    print("Which models may be used at all? (Organization Policy vertexai.allowedModels)")
    if not pol:
        print("  no policy: every model and action is allowed")
    else:
        print(f"  set on {pol['parent']}:")
        for spec in pol.get("spec", []):
            for rule in spec.get("rules", []):
                for vals in rule.get("values", []):
                    for v in vals.get("allowed_values", []):
                        print(f"    allowed  {v}")
    for value in (f"{app['model']}:predict", "publishers/meta/models/llama3:deploy"):
        ok, why = d.model_allowed(value)
        print(f"  {'ALLOWED' if ok else 'refused':<8} {value}")
    print("\nGemini is Google's own model. A partner model (Claude, for example) is a managed API too, but switching")
    print("it on is a separate right: the Consumer Procurement Entitlement Manager role (lesson 11.1).")


# ---------------------------------------------------------------- 3. role

def cmd_role(a) -> None:
    d = _d(a.twin)
    print(f"Who holds which role, {a.twin}. Each grant = WHO (a principal) + WHICH ROLE + ON WHAT:\n")
    rows = []
    for v in d.values("google_project_iam_member"):
        rows.append((v["member"], v["role"], f"project {v['project']}"))
    for v in d.values("google_bigquery_dataset_iam_member"):
        rows.append((v["member"], v["role"], f"dataset {v['dataset_id']}"))
    for v in d.values("google_service_account_iam_member"):
        rows.append((v["member"], v["role"], f"service account {v['service_account_id'].rsplit('/', 1)[-1].split('@')[0]}"))
    for who, role, where in rows:
        print(f"  {_short(who.split('@')[0], 34):<34} {_short(role.rsplit('/', 1)[-1] if role.startswith('projects/') else role, 36):<36} on {where}")
    print("\nWhat the AI roles contain (twin.py's subset of Google's IAM reference):")
    seen = {r for _, r, _ in rows}
    for role in sorted(seen):
        perms = ROLE_PERMISSIONS.get(role) or d.custom_roles().get(role)
        if perms and ("aiplatform" in role or "helpdesk" in role or role in ("roles/editor", "roles/iam.serviceAccountTokenCreator")):
            short = role.rsplit("/", 1)[-1] + " (custom)" if role.startswith("projects/") else role
            print(f"  {short:<38} {_short(', '.join(sorted(perms)), 88)}")
    keys = d.sa_emails_with_keys()
    print(f"\nService account keys (JSON files someone could steal): {', '.join(sorted(keys)) or 'none'}")


# ---------------------------------------------------------------- 4. route

def cmd_route(a) -> None:
    d = _d("hardened")
    loc = a.location
    req = d.req
    if loc == "global":
        host, kind, promise = "aiplatform.googleapis.com", "global", "any Google Cloud location in the world"
    elif loc in MULTI:
        host, kind = MULTI[loc], "multi-region"
        promise = "inside that region only" + (" (EU member states)" if loc == "eu" else " (the United States)")
    else:
        host, kind = f"{loc}-aiplatform.googleapis.com", "regional"
        promise = "inside the broader jurisdiction of that region (for Europe: the EU)"
    print(f"One generateContent call from helpdesk-vm with location {loc}\n")
    print(f"  endpoint     https://{host}   ({kind})")
    print(f"  processing   {promise}")
    print("  at rest      stays in the location you selected, whichever endpoint you call")
    ok = loc in req["approved_locations"]
    print(f"\nExampleCo's rule: ML processing must stay in the {req['ml_processing_must_stay_in']} "
          f"(approved: {', '.join(req['approved_locations'])})")
    print(f"Verdict: {'fits the rule' if ok else 'BREAKS the rule'}")
    vm = d.vms()["helpdesk-vm"]
    reach, path, why = d.route_to(vm, host)
    print(f"\nCan the hardened Helpdesk VM reach it privately?  {'yes' if reach else 'NO'}")
    print("  " + why.replace(": Private Google Access", ":\n  Private Google Access").replace(", the all-apis", ",\n  the all-apis")
          .replace(": this network's", ":\n  this network's").replace(", and the egress", ",\n  and the egress"))


# ---------------------------------------------------------------- 5. network

def cmd_network(a) -> None:
    d = _d(a.twin)
    print(f"The Helpdesk's network, {a.twin}\n")
    for v in d.values("google_compute_network"):
        print(f"  VPC      {v['name']}   (a private network; subnets are regional)")
    for v in d.values("google_compute_subnetwork"):
        print(f"  subnet   {v['name']}  {v['ip_cidr_range']}  {v['region']}  "
              f"Private Google Access {'on' if v.get('private_ip_google_access') else 'off'}")
    for name, vm in d.vms().items():
        print(f"  VM       {name:<18} external IP {'YES' if vm['external_ip'] else 'none':<5} runs as {vm['sa'].split('@')[0]}")
    print(f"  Cloud NAT          {'yes (outbound to the internet for VMs with no external IP)' if d.has_nat() else 'none'}")
    allowed = d.egress_denied_except()
    if allowed is None:
        print("  egress firewall    no deny-all rule: VMs may send to any address they can route to")
    else:
        print(f"  egress firewall    deny all, except {', '.join(allowed)} (the private endpoints)")
    print("\nWhere can the Helpdesk VM send data?")
    vm = d.vms()["helpdesk-vm"]
    for host in (d.app["endpoint_host"], d.app.get("bigquery_host", "bigquery.googleapis.com"), "attacker.example"):
        ok, _, why = d.route_to(vm, host)
        print(f"  {'REACHES' if ok else 'blocked':<8} {host:<40} {why}")


# ---------------------------------------------------------------- 6. endpoint

def cmd_endpoint(a) -> None:
    d = _d(a.twin)
    psc = d.psc_endpoint()
    regional = d.regional_endpoints()
    print(f"The private doors to Google APIs, {a.twin}\n")
    if not psc and not regional:
        print("  Private Service Connect endpoint: NONE (calls to *.googleapis.com use public addresses)")
    else:
        for ep in regional:
            print(f"  regional PSC endpoint {ep['name']:<12} at {ep['address']}  serves only {ep['target_google_api']}")
        if psc:
            print(f"  Private Service Connect endpoint {psc['name']} at {d.psc_ip()}  bundle {psc['target']}"
                  f"   ({'only APIs that support VPC Service Controls' if psc['target'] == 'vpc-sc' else 'most Google APIs'})")
        for z in d.values("google_dns_managed_zone"):
            print(f"  private DNS zone {z['dns_name']} ({z['visibility']}) for {z['private_visibility_config'][0]['networks'][0]['network_url']}")
        for r in d.values("google_dns_record_set"):
            print(f"      {r['type']:<6} {r['name']:<20} -> {', '.join(r['rrdatas'])}")
    p = d.perimeter()
    print("\nThe fence: VPC Service Controls")
    if not p:
        print("  no perimeter: a valid token works from anywhere, and data can be copied to any project")
    else:
        enforced = bool(p["status"])
        cfg = p["status"] if enforced else p["spec"]
        print(f"  perimeter {p['name'].rsplit('/', 1)[-1]}: {'ENFORCED' if enforced else 'DRY RUN (logs violations, blocks nothing)'}")
        print(f"    protects     {', '.join(cfg.get('resources', []))}")
        print(f"    restricts    {', '.join(cfg.get('restricted_services', []))}")
        print(f"    ingress rules {len(cfg.get('ingress_policies', []))}, egress rules {len(cfg.get('egress_policies', []))}")
    print("\nWho gets past the fence? (the perimeter only; IAM still has to allow the call too)")
    for label, inside, ip, dest in (("Helpdesk VM, inside", True, "10.10.0.5", None),
                                    ("a stolen token, from 203.0.113.66", False, "203.0.113.66", None),
                                    ("Helpdesk VM copying to another project", True, "10.10.0.5", "projects/999999999999")):
        verdict, why = d.perimeter_check(SA, "bigquery.googleapis.com" if dest else "aiplatform.googleapis.com",
                                         inside, ip, dest)
        label_v = {"pass": "passes", "dryrun": "LOGGED", "deny": "BLOCKED", "none": "no fence"}[verdict]
        print(f"  {label_v:<8} {label}")
        print(f"           {why.replace('VPC Service Controls DRY RUN would block this, but only logs it: ', 'dry run, would block: ')}")


# ---------------------------------------------------------------- 7. keys

def cmd_keys(a) -> None:
    d = _d(a.twin)
    print(f"Encryption at rest, {a.twin}\n")
    rings = d.values("google_kms_key_ring")
    keys = d.values("google_kms_crypto_key")
    if not keys:
        print("  Cloud KMS keys in the plan: 0. Google encrypts everything with keys Google owns and controls,")
        print("  so there is no key of yours to disable.")
    for r in rings:
        print(f"  key ring  {r['name']} in {r['location']}   (key rings can't be deleted)")
    for k in keys:
        days = int(k.get("rotation_period", "0s").rstrip("s")) // 86400
        print(f"  key       {k['name']}  purpose {k.get('purpose')}  new version every {days} days")
    for m in d.values("google_kms_crypto_key_iam_member"):
        print(f"  may use   {m['member'].split(':', 1)[-1]}   ({m['role'].rsplit('/', 1)[-1]})")
    print("\nWhat holds customer data, and whose key protects it:")
    for name, ds in d.datasets().items():
        print(f"  BigQuery dataset {name:<17} {ds['location']:<13} "
              f"{'your key (CMEK)' if ds['cmek'] else 'Google default encryption'}")


# ---------------------------------------------------------------- 8. logging

def cmd_logging(a) -> None:
    d = _d(a.twin)
    app = d.app
    print(f"What gets recorded, {a.twin}\n")
    print("Cloud Audit Logs for aiplatform.googleapis.com (who called, from where; not the prompt):")
    print("  Admin Activity   always written, can't be switched off (changes: deploy, create, set policy)")
    on = d.data_access_logs_on()
    types = [c["log_type"] for v in d.values("google_project_iam_audit_config") for c in v.get("audit_log_config", [])]
    print(f"  Data Access      {'ON: ' + ', '.join(types) if on else 'OFF (the default): model calls leave no audit entry'}")
    rr = app.get("request_response_logging")
    print("\nRequest-response logging (what was asked and answered, per model and project):")
    if not rr or not rr.get("enabled"):
        print("  OFF (the default)")
    else:
        print(f"  on, sampling {rr['sampling_rate']} (1.0 = every call), into {rr['bigquery_destination']}")
    print("\nCaching (copies Google may keep to answer faster; lesson 11.3):")
    cc = app.get("cache_config")
    print(f"  {cc if cc else 'not set: Google default, which includes durable caching at rest'}")


# ---------------------------------------------------------------- 9. record

def cmd_record(a) -> None:
    print("ILLUSTRATIVE: Google's documented field and column names, fake values. Two records of one Helpdesk call.\n")
    print("1. Data Access audit log entry (Cloud Logging, log cloudaudit.googleapis.com/data_access):")
    print("   who      authenticationInfo.principalEmail  chatbot-runtime@example-chatbot-prod.iam.gserviceaccount.com")
    print("   from     requestMetadata.callerIp           10.10.0.5   (the VM's internal address)")
    print("   what     methodName                         google.cloud.aiplatform.v1.PredictionService.GenerateContent")
    print("   where    resourceName                       .../locations/europe-west4/publishers/google/models/gemini-3.1-flash-lite")
    print("   allowed  authorizationInfo                  aiplatform.endpoints.predict, granted")
    print("   said     (nothing)                          the pages we read don't say audit entries hold the prompt")
    print("\n2. Request-response logging row (BigQuery table ai_logs.request_response_logging):")
    print("   when     logging_time                       2026-10-19 09:10:00 UTC")
    print("   what     model, api_method                  gemini-3.1-flash-lite, generateContent")
    print("   said     full_request                       \"How do I reset my VPN token?\"")
    print("   answered full_response                      \"Open the self-service portal, choose...\"")
    print("   more     request_id, endpoint, metadata...  the full column list is on Google's request-response logging page")


# ---------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("plan", cmd_plan), ("model", cmd_model), ("role", cmd_role), ("network", cmd_network),
                     ("endpoint", cmd_endpoint), ("keys", cmd_keys), ("logging", cmd_logging)):
        s = sub.add_parser(name)
        s.add_argument("twin", nargs="?", choices=TWINS, default="today")
        s.set_defaults(fn=fn)
    s = sub.add_parser("route")
    s.add_argument("location", nargs="?", default="europe-west4",
                   help="global, a region such as europe-west4, or a multi-region: eu or us")
    s.set_defaults(fn=cmd_route)
    sub.add_parser("record").set_defaults(fn=cmd_record)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
