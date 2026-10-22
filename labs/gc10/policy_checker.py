"""
policy_checker.py: find the AI-specific IAM, Organization Policy, API key, budget and logging mistakes in
ExampleCo's Google Cloud setup (or in your own exports).

    python3 policy_checker.py                     # ExampleCo today
    python3 policy_checker.py --with-fixes        # ExampleCo with fixes/ applied
    python3 policy_checker.py --keys my-keys.json # lint YOUR keys: gcloud services api-keys list --format=json > my-keys.json
    python3 policy_checker.py --iam my-iam.json   # lint YOUR allow policy: gcloud projects get-iam-policy PROJECT --format=json
    python3 policy_checker.py --orgpolicy my.json # lint an org policy file before you set it
    python3 policy_checker.py --scan PATH         # look for Google API key strings in a folder

Rules GC10-01 to GC10-16. Standard library only; nothing is sent anywhere.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import re
import sys

from gcp_eval import CORP, MODEL_ACTIONS, SA_API_KEY_BLOCK, SA_KEY_BLOCK, Corp, load_json

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "WARNING": 3}
AI_SERVICES = {"aiplatform.googleapis.com", "generativelanguage.googleapis.com"}
AI_ROLES = {"roles/aiplatform.user", "roles/aiplatform.admin", "roles/aiplatform.expressUser"}
BASIC_ROLES = {"roles/owner", "roles/editor"}
PUBLIC = {"allUsers", "allAuthenticatedUsers"}
MODEL_VALUE = re.compile(r"^publishers/[a-z0-9-]+/models/[A-Za-z0-9._@-]+:(predict|deploy|tune)$")
# Google API keys start with "AIza" followed by 35 URL-safe characters.
API_KEY_PATTERN = re.compile(r"AIza[0-9A-Za-z_\-]{35}")


@dataclasses.dataclass
class Finding:
    severity: str
    rule: str
    where: str
    what: str
    fix: str


# --- rules on allow policies ------------------------------------------------------------------------------------------
def check_bindings(resource, policy):
    out = []
    for b in policy.get("bindings", []):
        role, members = b["role"], b["members"]
        sas = [m for m in members if m.startswith("serviceAccount:")]
        if role in BASIC_ROLES and sas:
            for m in sas:
                out.append(Finding("HIGH", "GC10-01", f"{resource} {role}",
                                   f"Basic role {role} for {m.split(':', 1)[1]}: it can call any model, deploy endpoints and create keys.",
                                   "Grant the predefined role the workload needs (e.g. roles/aiplatform.user to call models)."))
        if set(members) & PUBLIC:
            out.append(Finding("HIGH", "GC10-02", f"{resource} {role}",
                               f"{role} is granted to {', '.join(sorted(set(members) & PUBLIC))}: anyone on the internet.",
                               "Remove the public principal."))
        if role in AI_ROLES and (resource.startswith("organizations/") or
                                 (resource.startswith("folders/") and sas)):
            out.append(Finding("MEDIUM", "GC10-03", f"{resource} {role}",
                               f"{role} granted on {resource.split('/')[0]}: every project below inherits it, including ones that never use AI.",
                               "Grant AI roles on the project that needs them, not on a folder or the organization."))
        if role == "roles/aiplatform.admin":
            for m in sas:
                out.append(Finding("HIGH", "GC10-04", f"{resource} {role}",
                                   f"Workload {m.split(':', 1)[1]} holds Agent Platform Admin: full access to every Agent Platform resource.",
                                   "A workload that only calls a model needs roles/aiplatform.user (aiplatform.endpoints.predict)."))
    return out


def check_audit_logging(project_id, policy, uses_ai):
    if not uses_ai:
        return []
    for cfg in policy.get("auditConfigs", []):
        if cfg.get("service") in ("aiplatform.googleapis.com", "allServices") and \
                any(c.get("logType") == "DATA_READ" for c in cfg.get("auditLogConfigs", [])):
            return []
    return [Finding("MEDIUM", "GC10-15", f"projects/{project_id}",
                    "Data Access (DATA_READ) audit logs are off for aiplatform.googleapis.com: model calls here leave no audit record.",
                    "Add an auditConfigs entry for aiplatform.googleapis.com with DATA_READ (cost: Cloud Logging ingestion past the free allotment).")]


# --- rules on API keys --------------------------------------------------------------------------------------------------
def check_keys(keys, prod_numbers=(), public_web_numbers=()):
    out = []
    for k in keys:
        if k.get("deleteTime"):
            continue
        name = k.get("displayName") or k.get("uid", "?")
        r = k.get("restrictions", {})
        targets = {t["service"] for t in r.get("apiTargets", [])}
        app = {x for x in ("browserKeyRestrictions", "serverKeyRestrictions", "androidKeyRestrictions",
                           "iosKeyRestrictions") if x in r}
        number = k.get("name", "projects/?/").split("/")[1]
        if not r:
            out.append(Finding("HIGH", "GC10-05", f"key {name}",
                               "Unrestricted API key: any API enabled in its project, from anywhere. Google: \"Unrestricted API keys are insecure.\"",
                               "Add an API restriction (apiTargets) AND an application restriction (IPs, referrers or apps)."))
        if k.get("serviceAccountEmail"):
            sev = "HIGH" if number in prod_numbers else "MEDIUM"
            out.append(Finding(sev, "GC10-06", f"key {name}",
                               f"Authorization key bound to {k['serviceAccountEmail']}: it works like a long-lived access token and its calls aren't in service account usage metrics.",
                               "Use the attached service account (ADC) instead; delete the key; keep iam.managed.disableServiceAccountApiKeyCreation enforced."))
        if (targets & AI_SERVICES or (not targets and r)) and not app:
            out.append(Finding("MEDIUM", "GC10-07", f"key {name}",
                               "Key can call an AI API but has no application restriction: anyone holding the string can use it from anywhere.",
                               "Add serverKeyRestrictions.allowedIps with your egress IPs (or a referrer/app restriction for client apps)."))
        if "generativelanguage.googleapis.com" in targets and "browserKeyRestrictions" in r:
            out.append(Finding("MEDIUM", "GC10-08", f"key {name}",
                               "A key built for a public web page can also call the Gemini API: its string is in your page source.",
                               "Remove generativelanguage.googleapis.com from this key; give Gemini callers their own server-side key or ADC."))
    return out


# --- rules on organization policy -----------------------------------------------------------------------------------------
def check_org_policy_file(pol):
    out = []
    name = pol.get("name", "?")
    if not name.endswith("/policies/vertexai.allowedModels"):
        return out
    vals = []
    for rule in pol.get("spec", {}).get("rules", []) + pol.get("dryRunSpec", {}).get("rules", []):
        v = rule.get("values", {})
        vals += v.get("allowedValues", []) + v.get("deniedValues", [])
        if v.get("deniedValues") and not v.get("allowedValues"):
            out.append(Finding("LOW", "GC10-12", name,
                               "Deny-list: it blocks the models it names and allows every model Google adds later.",
                               "Prefer an allow-list (allowedValues). Keep deny-lists as a second layer only."))
    for value in vals:
        if not MODEL_VALUE.match(value):
            out.append(Finding("WARNING", "GC10-13", name,
                               f"Value '{value}' isn't publishers/PUBLISHER/models/MODEL:ACTION with ACTION in {sorted(MODEL_ACTIONS)}.",
                               "Copy the model ID from its Model Garden card and add :predict, :deploy or :tune."))
    if len(vals) > 500:
        out.append(Finding("WARNING", "GC10-13", name, f"{len(vals)} values: the limit is 500 allowed and denied values combined.",
                           "List only approved models; split by folder."))
    return out


def check_org(corp: Corp):
    out = []
    sample_project = next(iter(corp.projects))
    on, src = corp.boolean_enforced(sample_project, SA_API_KEY_BLOCK)
    if not on:
        out.append(Finding("MEDIUM", "GC10-09", src,
                           f"{SA_API_KEY_BLOCK} is switched off: anyone with the right roles can bind API keys to service accounts.",
                           "Enforce it again at the organization (Google's default); allow exceptions per project only."))
    on, src = corp.boolean_enforced(sample_project, SA_KEY_BLOCK)
    if not on:
        out.append(Finding("MEDIUM", "GC10-10", "organization",
                           f"{SA_KEY_BLOCK} is {src}: anyone with iam.serviceAccountKeys.create can download a service account key.",
                           "Enforce it at the organization (the secure-by-default baseline for newer orgs)."))
    for pid, p in corp.projects.items():
        if "aiplatform.googleapis.com" not in p["enabledServices"]:
            continue
        allowed, _, _ = corp.effective_list(pid)
        if allowed is None:
            out.append(Finding("MEDIUM", "GC10-11", f"projects/{pid}",
                               "Agent Platform is enabled and no vertexai.allowedModels allow-list applies: every model and action, including new ones, is allowed.",
                               "Set an allow-list at the folder or organization with the approved publishers/P/models/M:ACTION values."))
    for pol in corp.org_policies.values():
        out += check_org_policy_file(pol)
    return out


# --- rules on budgets ---------------------------------------------------------------------------------------------------------
def check_budgets(corp: Corp):
    out = []
    capped = set()
    for b in corp.budgets:
        if b.get("spendCap"):
            for p in b.get("budgetFilter", {}).get("projects", []):
                capped.add(p.split("/")[1])
    for pid, p in corp.projects.items():
        if "aiplatform.googleapis.com" in p["enabledServices"] and p["projectNumber"] not in capped:
            out.append(Finding("MEDIUM", "GC10-14", f"projects/{pid}",
                               "Agent Platform is enabled but no spend cap budget covers it: alerts-only budgets don't cap spending.",
                               "Add a spend cap budget for this project + Agent Platform; keep alert budgets for everything else."))
    return out


# --- secrets in source --------------------------------------------------------------------------------------------------------
def scan_for_keys(root):
    out = []
    root = pathlib.Path(root)
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
    for f in sorted(files):
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for m in API_KEY_PATTERN.finditer(line):
                shown = m.group(0)[:8] + "..." + m.group(0)[-4:]
                out.append(Finding("HIGH", "GC10-16", f"{f.relative_to(root.parent) if root.is_dir() else f.name}:{n}",
                                   f"Google API key string {shown} in source code.",
                                   "Treat it as leaked: restrict or delete the key in the console, then remove it from the code and history."))
    return out


# --- run ---------------------------------------------------------------------------------------------------------------------
def run(with_fixes=False):
    corp = Corp(with_fixes=with_fixes)
    findings = []
    for res, pol in corp.iam.items():
        findings += check_bindings(res, pol)
    for pid, p in corp.projects.items():
        findings += check_audit_logging(pid, corp.iam.get(f"projects/{pid}", {}),
                                        "aiplatform.googleapis.com" in p["enabledServices"])
    prod = {p["projectNumber"] for pid, p in corp.projects.items() if corp.env_of(pid) == "prod"}
    findings += check_keys(corp.keys, prod_numbers=prod)
    findings += check_org(corp)
    findings += check_budgets(corp)
    findings += scan_for_keys(CORP / "repo")
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule, f.where))


def show(findings, title):
    print(f"--- GC10 policy checker · {title} ---\n")
    for f in findings:
        print(f"  {f.severity:<7} {f.rule}  {f.where}")
        print(f"          {f.what}")
        print(f"          fix: {f.fix}")
    by = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    print(f"\n{by['HIGH']} HIGH, {by['MEDIUM']} MEDIUM, {by['LOW']} LOW, {by['WARNING']} WARNING  ({len(findings)} findings)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--with-fixes", action="store_true")
    ap.add_argument("--keys", help="JSON from gcloud services api-keys list --format=json")
    ap.add_argument("--iam", help="JSON from gcloud projects get-iam-policy PROJECT --format=json")
    ap.add_argument("--orgpolicy", help="an organization policy file (JSON)")
    ap.add_argument("--scan", help="a file or folder to scan for Google API key strings")
    args = ap.parse_args(argv)

    if args.keys or args.iam or args.orgpolicy or args.scan:
        findings = []
        if args.keys:
            data = load_json(args.keys)
            findings += check_keys(data["keys"] if isinstance(data, dict) else data)
        if args.iam:
            pol = load_json(args.iam)
            findings += check_bindings(pol.get("_resource", "projects/YOUR_PROJECT"), pol)
            findings += check_audit_logging("YOUR_PROJECT", pol, True)
        if args.orgpolicy:
            findings += check_org_policy_file(load_json(args.orgpolicy))
        if args.scan:
            findings += scan_for_keys(args.scan)
        show(sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule)), "your files")
    else:
        show(run(args.with_fixes), "ExampleCo with fixes/" if args.with_fixes else "ExampleCo today")
    return 0


if __name__ == "__main__":
    sys.exit(main())
