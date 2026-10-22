"""
checker.py: find the security gaps around Gemini on Agent Platform in a deployment twin (or your own plan).

    python3 checker.py                         # make check:       ExampleCo's TSG Helpdesk today
    python3 checker.py --twin hardened         # make check-hardened: what terraform/ builds
    python3 checker.py --plan plan.json --app app.json   # your own: terraform show -json plan.out > plan.json

Rules GC11-01 to GC11-15 cover lessons 11.1 to 11.5. GC11-16 is yours to write (README, Step 7).
Severity: HIGH, MEDIUM, LOW, WARNING (a control that exists but doesn't enforce yet).
"""

from __future__ import annotations

import argparse
import dataclasses
import sys

from twin import BROAD_AI_ROLES, Deployment

ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "WARNING": 3}


@dataclasses.dataclass
class Finding:
    severity: str
    rule: str
    where: str
    what: str
    fix: str


def ai_workload_sas(d: Deployment) -> set[str]:
    sas = {vm["sa"] for vm in d.vms().values() if vm["labels"].get("ai_workload") == "true"}
    if d.app.get("service_account"):
        sas.add(d.app["service_account"])
    return sas


# ---- 11.1 identity ----------------------------------------------------------------------------------------------
def rule_sa_keys(d):
    out = []
    for email in sorted(d.sa_emails_with_keys() & ai_workload_sas(d)):
        out.append(Finding("HIGH", "GC11-01", f"google_service_account_key for {email}",
                           "A user-managed JSON key exists for an AI workload's service account: anyone holding the "
                           "file can call your models from anywhere.",
                           "Delete the key; the workload uses its attached service account through ADC. Keep "
                           "iam.managed.disableServiceAccountKeyCreation enforced (GC10)."))
    return out


def rule_default_compute_sa(d):
    out = []
    for vm in d.vms().values():
        if vm["sa"].endswith("-compute@developer.gserviceaccount.com"):
            out.append(Finding("HIGH", "GC11-02", f"google_compute_instance {vm['name']}",
                               f"Runs as the Compute Engine default service account ({vm['sa']}), shared by every "
                               "workload that didn't choose one and often granted Editor.",
                               "Create one service account per workload and attach it."))
    return out


def rule_broad_ai_role(d):
    out = []
    for email in sorted(ai_workload_sas(d)):
        for role in d.project_roles(f"serviceAccount:{email}"):
            if role in BROAD_AI_ROLES:
                extra = (" (Agent Platform User includes aiplatform.endpoints.create and .deploy)"
                         if role == "roles/aiplatform.user" else "")
                out.append(Finding("MEDIUM", "GC11-03", f"project {d.project} {role}",
                                   f"{email} holds {role}: it can do far more than call a model{extra}.",
                                   "Grant a custom role with aiplatform.endpoints.predict only, on the project that "
                                   "calls the model."))
    return out


def rule_allowed_models(d):
    if d.req.get("has_organization") and not d.allowed_models_policy():
        return [Finding("MEDIUM", "GC11-04", "vertexai.allowedModels",
                        "No model allow-list in this deployment: every model and action, including new ones, is "
                        "allowed for anyone with the IAM permission.",
                        "Set an allow-list (publishers/P/models/M:predict) on the prod folder; dry run first (GC10).")]
    return []


def rule_impersonation(d):
    out = []
    for v in d.values("google_project_iam_member"):
        if v["role"] in ("roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser"):
            out.append(Finding("MEDIUM", "GC11-15", f"project {d.project} {v['role']}",
                               f"{v['member']} holds {v['role']} on the whole project: it can act as every service "
                               "account in it, including the Helpdesk's.",
                               "Grant it on the one service account that needs it (google_service_account_iam_member), "
                               "or not at all."))
    return out


# ---- 11.2 network -----------------------------------------------------------------------------------------------
def rule_external_ip(d):
    out = []
    for vm in d.vms().values():
        if vm["labels"].get("ai_workload") == "true" and (vm["external_ip"] or d.has_nat()):
            how = "has an external IP" if vm["external_ip"] else "reaches the internet through Cloud NAT"
            out.append(Finding("HIGH", "GC11-05", f"google_compute_instance {vm['name']}",
                               f"AI workload {how}: model calls cross the internet, and a hijacked app can post "
                               "data anywhere.",
                               "Remove the external IP and NAT; reach Google APIs through a PSC endpoint; add an "
                               "egress deny-all firewall rule with an allow for the endpoint."))
    return out


def rule_psc(d):
    if not d.psc_endpoint():
        return [Finding("MEDIUM", "GC11-06", "google_compute_global_forwarding_rule",
                        "No Private Service Connect endpoint for Google APIs.",
                        "Add a global internal address (purpose PRIVATE_SERVICE_CONNECT) and a forwarding rule with "
                        "target vpc-sc (or all-apis), plus a private googleapis.com zone.")]
    if not d.private_googleapis_zone():
        return [Finding("MEDIUM", "GC11-06", "google_dns_managed_zone googleapis.com",
                        "A PSC endpoint exists but no private googleapis.com zone points at it: clients still "
                        "resolve the public addresses.",
                        "Private zone googleapis.com: an A record to the endpoint IP and a CNAME *.googleapis.com.")]
    return []


def rule_pga(d):
    out = []
    for v in d.values("google_compute_subnetwork"):
        if not v.get("private_ip_google_access"):
            out.append(Finding("LOW", "GC11-07", f"google_compute_subnetwork {v['name']}",
                               "Private Google Access is off: VMs without an external IP can't reach Google APIs "
                               "if the PSC path fails.",
                               "Set private_ip_google_access = true (it doesn't cover *.rep.googleapis.com)."))
    return out


def rule_perimeter(d):
    if not d.req.get("has_organization"):
        return []
    p = d.perimeter()
    need = "aiplatform.googleapis.com"
    if not p:
        return [Finding("MEDIUM", "GC11-08", "VPC Service Controls",
                        f"No service perimeter restricts {need}: a stolen token works from anywhere and a hijacked "
                        "workload can copy data to any project.",
                        "Create a perimeter for the project restricting aiplatform, bigquery and storage; dry run "
                        "first, then enforce.")]
    if need in p["status"].get("restricted_services", []):
        return []
    if need in p["spec"].get("restricted_services", []):
        return [Finding("WARNING", "GC11-08", p["name"],
                        "The perimeter is in DRY RUN: violations are only logged (metadata.dryRun = true), nothing "
                        "is blocked.",
                        "Read a week of dry-run logs (make dryrun-report), add ingress/egress rules for legitimate "
                        "callers, then enforce (move the config to status).")]
    return [Finding("MEDIUM", "GC11-08", p["name"], f"The perimeter doesn't restrict {need}.",
                    f"Add {need} to restricted_services.")]


# ---- 11.3 encryption --------------------------------------------------------------------------------------------
def rule_dataset_cmek(d):
    if not d.req.get("cmek_required_for_customer_data_at_rest"):
        return []
    out = []
    for name, ds in d.datasets().items():
        if not ds["cmek"]:
            out.append(Finding("MEDIUM", "GC11-09", f"google_bigquery_dataset {name}",
                               "Holds customer data with Google default encryption; policy requires a customer-managed "
                               "key.",
                               "Set default_encryption_configuration.kms_key_name and grant the BigQuery service "
                               "account Encrypter/Decrypter on the key."))
    return out


def rule_key_rotation(d):
    out = []
    for v in d.values("google_kms_crypto_key"):
        if not v.get("rotation_period"):
            out.append(Finding("LOW", "GC11-10", f"google_kms_crypto_key {v['name']}",
                               "No automatic rotation period.", "Set rotation_period (e.g. 7776000s = 90 days)."))
    return out


def rule_durable_cache(d):
    if not d.req.get("cmek_required_for_customer_data_at_rest"):
        return []
    c = d.app.get("cache_config") or {}
    if c.get("disable_cache") or c.get("retention_type") == "EPHEMERAL":
        return []
    return [Finding("MEDIUM", "GC11-11", f"projects/{d.project}/cacheConfig",
                    "Caching is at Google's default: durable caching can store derived cache data at rest with "
                    "Google default encryption, and CMEK isn't supported for it.",
                    "Set retentionType EPHEMERAL (in-memory only) or disableCache true; record it in app.json.")]


# ---- 11.4 logging -----------------------------------------------------------------------------------------------
def rule_data_access_logs(d):
    out = []
    for svc in d.req.get("data_access_logs_required_for", []):
        if not d.data_access_logs_on(svc):
            out.append(Finding("HIGH", "GC11-12", f"auditConfigs {svc}",
                               f"Data Access (DATA_READ) audit logs are off for {svc}: model calls leave no audit "
                               "record.",
                               "google_project_iam_audit_config with DATA_READ for the service (or at the folder or "
                               "organization)."))
    return out


def rule_rr_logging(d):
    rr = d.app.get("request_response_logging") or {}
    need = float(d.req.get("request_response_logging_min_sampling_rate", 0))
    if not rr.get("enabled"):
        return [Finding("MEDIUM", "GC11-13", d.app.get("model", "model"),
                        "Request-response logging is off: no record of what was asked or answered.",
                        "Enable it per model and project (setPublisherModelConfig, v1beta1) into a CMEK dataset "
                        "only the incident team can read.")]
    if float(rr.get("sampling_rate", 0)) < need:
        return [Finding("LOW", "GC11-13", d.app.get("model", "model"),
                        f"Only {rr.get('sampling_rate')} of requests are logged (policy: {need}).",
                        "Raise samplingRate or accept and document the gap.")]
    dest = rr.get("bigquery_destination", "")
    ds = dest.replace("bq://", "").split(".")[1] if dest.count(".") >= 1 else ""
    if ds and ds in d.datasets() and not d.datasets()[ds]["cmek"]:
        return [Finding("MEDIUM", "GC11-13", dest, "Prompts and answers land in a dataset without CMEK.",
                        "Point bigqueryDestination at a CMEK dataset.")]
    return []


# ---- 11.5 residency ---------------------------------------------------------------------------------------------
def rule_location(d):
    loc = d.app.get("location", "")
    approved = d.req.get("approved_locations", [])
    if loc == "global" or (approved and loc not in approved):
        why = ("the global endpoint can process requests in any region and gives no data residency guarantee"
               if loc == "global" else f"'{loc}' is not on the approved list {approved}")
        return [Finding("HIGH", "GC11-14", f"app location {loc}",
                        f"Model calls use location '{loc}': {why}. Policy: ML processing must stay in the "
                        f"{d.req.get('ml_processing_must_stay_in')}.",
                        "Use an approved regional or multi-region location and check the model is offered there.")]
    return []


# ---- GC11-16: YOUR TURN (README, Step 7) ---------------------------------------------------------------------------
def rule_rep_endpoint_private_path(d):
    """GC11-16 (challenge): flag an app whose endpoint_host ends in .rep.googleapis.com when the only private
    paths are Private Google Access or a PSC endpoint for GLOBAL Google APIs (neither reaches rep endpoints).

    Return a list with one Finding("MEDIUM", "GC11-16", ...) when that's the case, else [].
    Hints: d.app["endpoint_host"], d.psc_endpoint(), d.pga_on(None), d.vms().
    """
    return []


RULES = [rule_sa_keys, rule_default_compute_sa, rule_broad_ai_role, rule_allowed_models, rule_external_ip, rule_psc,
         rule_pga, rule_perimeter, rule_dataset_cmek, rule_key_rotation, rule_durable_cache, rule_data_access_logs,
         rule_rr_logging, rule_location, rule_impersonation, rule_rep_endpoint_private_path]


def run(twin="today", plan=None, app=None) -> list[Finding]:
    d = Deployment.load(twin, plan=plan, app=app)
    out = [f for rule in RULES for f in rule(d)]
    return sorted(out, key=lambda f: (ORDER[f.severity], f.rule, f.where))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--twin", default="today")
    ap.add_argument("--plan", help="your own `terraform show -json` output")
    ap.add_argument("--app", help="your own app.json (location, endpoint, logging, cache)")
    args = ap.parse_args(argv)
    findings = run(args.twin, args.plan, args.app)
    label = args.plan or args.twin
    print(f"--- GC11 checker · {label} ---\n")
    for f in findings:
        print(f"  {f.severity:<7} {f.rule}  {f.where}")
        print(f"          {f.what}")
        print(f"          fix: {f.fix}")
    by = {s: sum(f.severity == s for f in findings) for s in ORDER}
    print(f"\n{by['HIGH']} HIGH, {by['MEDIUM']} MEDIUM, {by['LOW']} LOW, {by['WARNING']} WARNING  "
          f"({len(findings)} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
