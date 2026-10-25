"""
checker.py: review ExampleCo's self-hosted summariser on Agent Platform (formerly Vertex AI) the way you'd review
the pull request. Offline, standard library only.

    python3 checker.py first-draft     # make check
    python3 checker.py hardened        # make check-hardened

30 rules, GC15-01 to GC15-30, each tagged with the lesson that explains it. Each rule reads only the files in
setups/<name>/ (API-shaped bodies plus lab notes) and the model files the deployment would load. IAM rules don't
pattern-match policy text: they ask the twin concrete questions ("may ds-bob move the prod alias?").
Exit code 1 if any HIGH finding, so it can fail a pipeline.
"""

from __future__ import annotations

import datetime as dt
import sys
from dataclasses import dataclass

import model_files
import twin

C = twin.COMPANY
EP = "endpoint:" + C["endpoint"]
MODEL = "model:" + C["model"]
PROD = C["prod_project"]
SECRET_WORDS = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "ACCESS_KEY")
PEOPLE = ("ds-alice", "ds-bob")                       # data scientists
HUMANS = ("ds-alice", "ds-bob", "tsg-model-approver")  # people who are not the platform admin


@dataclass
class Finding:
    rule: str
    severity: str
    lesson: str
    message: str

    def __str__(self):
        return f"[{self.severity:6}] {self.rule} ({self.lesson}) {self.message}"


def _today():
    return dt.date.fromisoformat(C["lab_today"])


def _image(s):
    return twin.deployed_version(s)["containerSpec"]["imageUri"]


def _deployed_files(s):
    return twin.World(s).snapshots[twin.deployed_version(s)["versionId"]]


# --------------------------------------------------------------------------------------------------------------------
# 15.1 What you now own: the serving image
# --------------------------------------------------------------------------------------------------------------------
def rule_01(s):
    info = twin.IMAGES["images"].get(_image(s))
    if not info:
        return [Finding("GC15-01", "MEDIUM", "15.1", f"image {_image(s)} is not in the image catalog: nobody knows when it was built or what it contains")]
    age = (_today() - dt.date.fromisoformat(info["built"])).days
    if age > twin.IMAGES["rebuild_days"]:
        return [Finding("GC15-01", "MEDIUM", "15.1", f"the serving image was built {age} days ago (ExampleCo rebuilds every {twin.IMAGES['rebuild_days']}): "
                        "a fix in the inference server only reaches the endpoint when you rebuild and redeploy")]
    return []


def rule_02(s):
    info = twin.IMAGES["images"].get(_image(s), {})
    if info.get("open_critical_findings"):
        return [Finding("GC15-02", "HIGH", "15.1", f"Artifact Analysis reported {info['open_critical_findings']} CRITICAL vulnerabilities in the serving image, and it still serves production")]
    return []


def rule_03(s):
    info = twin.IMAGES["images"].get(_image(s), {})
    if info and (_today() - dt.date.fromisoformat(info["last_pulled"])).days > twin.IMAGES["monitoring_window_days"]:
        return [Finding("GC15-03", "LOW", "15.4", "the image hasn't been pulled for more than 30 days: Artifact Analysis stops updating its results, so 'no new findings' means nothing")]
    return []


def rule_04(s):
    if "@sha256:" not in _image(s):
        return [Finding("GC15-04", "MEDIUM", "15.1", "the serving image is pinned by tag, not by digest: the same tag can point at different bytes tomorrow")]
    return []


# --------------------------------------------------------------------------------------------------------------------
# 15.2 Network isolation and hardening
# --------------------------------------------------------------------------------------------------------------------
def rule_05(s):
    if not twin.perimeter_on(s):
        return [Finding("GC15-05", "HIGH", "15.2", "no enforced VPC Service Controls perimeter restricts aiplatform.googleapis.com around the project: "
                        "the serving environment keeps its default internet access, and stolen credentials work from anywhere")]
    return []


def rule_06(s):
    why = twin.deploy_blocked_by_perimeter_timing(s)
    return [Finding("GC15-06", "HIGH", "15.2", why + " (Google: endpoints must be created after the project is added to the perimeter)")] if why else []


def rule_07(s):
    ident = twin.runtime_identity(s)
    if ident is None:
        return []
    sa = "sa:" + twin.sa_email(ident)
    roles = [b["role"].rsplit("/", 1)[-1] for b in s.iam["projects"].get(PROD, []) if twin.member(ident) in b["members"]]
    if ident == "compute-default" or roles:
        return [Finding("GC15-07", "HIGH", "15.2", f"the deployed model runs as {ident}, which holds {', '.join(roles) or 'project roles'} on {PROD}: "
                        "code in the container (a pickle payload, a bug in the server) acts with all of it")]
    return []


def rule_08(s):
    pol = s.orgpolicy.get("constraints/iam.automaticIamGrantsForDefaultServiceAccounts") or {}
    editor = any(b["role"] == "roles/editor" and twin.member("compute-default") in b["members"] for b in s.iam["projects"].get(PROD, []))
    if not pol.get("enforce") or editor:
        return [Finding("GC15-08", "MEDIUM", "15.2", "the Compute Engine default service account has Editor"
                        + (" and iam.automaticIamGrantsForDefaultServiceAccounts isn't enforced" if not pol.get("enforce") else "")
                        + ": every VM, notebook or endpoint that defaults to it inherits Editor")]
    return []


def rule_09(s):
    out = []
    for n in PEOPLE:
        sas = [sa for sa in ("tsg-ci-deployer", "tsg-summariser-runtime", "compute-default")
               if twin.decide(s, n, "iam.serviceAccounts.actAs", "sa:" + twin.sa_email(sa))[0]]
        if sas:
            out.append(Finding("GC15-09", "HIGH", "15.2", f"{n} may act as {', '.join(sas)} (Service Account User): anything they start, a notebook or a deployment, can run as that account"))
    return out


def rule_10(s):
    out = []
    for sa, keys in s.iam.get("keys", {}).items():
        if keys:
            out.append(Finding("GC15-10", "HIGH", "15.2", f"{sa} has {len(keys)} user-managed key(s): a key file works from any laptop until someone deletes it"))
    return out


def rule_11(s):
    env = twin.env_of(twin.deployed_version(s))
    hits = [k for k in env if any(w in k.upper() for w in SECRET_WORDS)]
    if hits:
        readers = [n for n in (*HUMANS, "all-staff") if twin.decide(s, n, "aiplatform.models.get", MODEL)[0]]
        return [Finding("GC15-11", "HIGH", "15.2", f"secret-looking value in containerSpec.env ({', '.join(hits)}): models.get returns it to {', '.join(readers) or 'anyone who can read the model'}")]
    return []


def rule_12(s):
    out = []
    if not s.endpoint["endpoint"].get("encryptionSpec"):
        out.append(Finding("GC15-12", "MEDIUM", "15.2", "the endpoint has no encryptionSpec: the model files used for the deployment use Google's default encryption, not a key you control"))
    if not s.registry.get("encryptionSpec"):
        out.append(Finding("GC15-12", "MEDIUM", "15.2", "the Model has no encryptionSpec: the uploaded model files use Google's default encryption, not your key"))
    return out


def rule_13(s):
    out = []
    for name, inst in s.workbench["instances"].items():
        r = twin.workbench_reach(s, inst)
        if r["internet"]:
            out.append(Finding("GC15-13", "HIGH", "15.2", f"Workbench instance {name} can reach the internet ({r['why']}): anything a notebook can read can be uploaded"))
    return out


def rule_14(s):
    out = []
    for name, inst in s.workbench["instances"].items():
        md = inst["gceSetup"].get("metadata", {})
        on = [k.replace("notebook-disable-", "") for k in ("notebook-disable-root", "notebook-disable-terminal", "notebook-disable-downloads")
              if md.get(k, "false") != "true"]
        if on:
            out.append(Finding("GC15-14", "MEDIUM", "15.2", f"Workbench instance {name} has {', '.join(on)} enabled (the defaults)"))
    return out


def rule_15(s):
    out = []
    for name, inst in s.workbench["instances"].items():
        ident = twin.workbench_identity(inst)
        if inst.get("_access_mode") == "service-account" and len(inst.get("_users", [])) > 1:
            out.append(Finding("GC15-15", "HIGH", "15.2", f"Workbench instance {name} is shared in 'Service account' mode by {', '.join(inst['_users'])} and runs as {ident}: "
                               "everyone's code runs as one identity, and the logs can't tell who did what"))
        elif ident == "compute-default":
            out.append(Finding("GC15-15", "HIGH", "15.2", f"Workbench instance {name} runs as the Compute Engine default service account"))
    return out


def rule_16(s):
    out = []
    for name, inst in s.workbench["instances"].items():
        if inst.get("_project") == PROD:
            out.append(Finding("GC15-16", "MEDIUM", "15.2", f"Workbench instance {name} lives in the production project {PROD}: experiments sit next to the production model and its data"))
    return out


def rule_17(s):
    missing = [c for c in ("ainotebooks.restrictPublicIp", "ainotebooks.disableRootAccess", "ainotebooks.disableTerminal",
                           "ainotebooks.disableFileDownloads") if not twin._enforced(s, c)]
    if missing:
        return [Finding("GC15-17", "MEDIUM", "15.2", f"org policy doesn't enforce {', '.join(missing)}: today's instances are fine, but the next one "
                        "anybody creates gets the defaults (challenge 1)")]
    return []


# --------------------------------------------------------------------------------------------------------------------
# 15.3 Endpoints, Model Garden, Model Registry, allow-lists
# --------------------------------------------------------------------------------------------------------------------
def rule_18(s):
    kind = twin.endpoint_kind(s)
    if kind in ("shared-public", "dedicated-public"):
        return [Finding("GC15-18", "HIGH", "15.3", f"the summariser is on a {kind.replace('-', ' ')} endpoint, but only an internal app calls it: "
                        "use a Private Service Connect endpoint (a dedicated public endpoint doesn't support VPC Service Controls at all)")]
    if kind == "psa":
        return [Finding("GC15-18", "LOW", "15.3", "private services access endpoint: no TLS, no traffic split, no access logging by default; prefer Private Service Connect")]
    return []


def rule_19(s):
    who = [n for n in HUMANS if twin.decide(s, n, "aiplatform.endpoints.predict", EP)[0]]
    if who:
        return [Finding("GC15-19", "MEDIUM", "15.3", f"{', '.join(who)} may call predict on the production endpoint: only the Helpdesk app needs to")]
    return []


def rule_20(s):
    res = model_files.scan_files(_deployed_files(s))
    bad = [p for p in res["problems"] if p["kind"] in ("pickle", "numpy", "code")]
    if bad:
        detail = "; ".join(f"{p['name']} ({p['kind']}{': imports ' + ', '.join(p['unsafe_globals']) if p['unsafe_globals'] else ''})" for p in bad)
        return [Finding("GC15-20", "HIGH", "15.3", f"the deployed version's files are not safetensors-only: {detail}")]
    return []


def rule_21(s):
    src = s.app.get("_next_release", "")
    bucket = src[5:].split("/", 1)[0]
    writers = [n for n in PEOPLE if twin.decide(s, n, "storage.objects.create", "bucket:" + src[5:])[0]]
    if writers and not s.app.get("upload_verifies_hashes"):
        return [Finding("GC15-21", "HIGH", "15.3", f"{', '.join(writers)} may write the folder the next release is uploaded from ({src}) and the pipeline "
                        "doesn't re-check hashes before models.upload: files swapped after the scan get copied into the registry")]
    if writers:
        return [Finding("GC15-21", "MEDIUM", "15.3", f"{', '.join(writers)} may write {bucket}, the pipeline's release bucket (the hash check catches a swap, but why allow it)")]
    return []


def rule_22(s):
    v = twin.deployed_version(s)
    labels = v.get("labels", {})
    out = []
    if not any(k.startswith(model_files.HASH_PREFIX) for k in labels):
        out.append(Finding("GC15-22", "MEDIUM", "15.3", f"version {v['versionId']} records no file hashes: nobody can prove the files serving today are the ones that were reviewed"))
    lic = labels.get("licence")
    if lic not in C["approved_licences"]:
        out.append(Finding("GC15-22", "MEDIUM", "15.3", f"version {v['versionId']}: licence {'not recorded' if not lic else lic + ' is not on the approved list'} (checking the licence is your job, not Google's)"))
    return out


def rule_23(s):
    out = []
    for n in PEOPLE:
        can = [p.split(".", 2)[2] for p in ("aiplatform.models.upload", "aiplatform.endpoints.deploy", "aiplatform.models.update")
               if twin.decide(s, n, p, MODEL if p.startswith("aiplatform.models") else EP)[0]]
        if can:
            out.append(Finding("GC15-23", "HIGH", "15.3", f"{n} may {', '.join(can)} in {PROD}: a data scientist can ship and promote a model with no second pair of eyes"))
    return out


def rule_24(s):
    if not s.orgpolicy.get("constraints/vertexai.allowedModels"):
        return [Finding("GC15-24", "MEDIUM", "15.3", "no vertexai.allowedModels policy: any Model Garden model can be deployed (Google: with no policy, all models and actions are allowed)")]
    return []


def rule_25(s):
    if not s.app.get("approval_gate"):
        return [Finding("GC15-25", "MEDIUM", "15.3", "no promotion gate: nothing checks formats, hashes, licence and reviewer before the prod alias moves (challenge 2)")]
    return []


# --------------------------------------------------------------------------------------------------------------------
# 15.4 Watching it in production
# --------------------------------------------------------------------------------------------------------------------
def rule_26(s):
    cfg = s.endpoint["endpoint"].get("predictRequestResponseLoggingConfig") or {}
    if not cfg.get("enabled"):
        return []
    out = []
    readers = s.endpoint.get("_bigquery_dataset_readers", [])
    wide = [r for r in readers if r.startswith("group:")]
    if wide:
        out.append(Finding("GC15-26", "HIGH", "15.4", f"request-response logging writes every prompt and answer (sampling {cfg.get('samplingRate')}) to a dataset "
                           f"{', '.join(wide)} can read: those logs are as sensitive as the tickets"))
    if not s.endpoint.get("_bigquery_dataset_cmek"):
        out.append(Finding("GC15-26", "MEDIUM", "15.4", "the request-response log dataset isn't encrypted with your key"))
    return out


def rule_27(s):
    if "aiplatform.googleapis.com" not in s.app.get("data_access_logs", []):
        return [Finding("GC15-27", "MEDIUM", "15.4", "Data Access audit logs are off for aiplatform.googleapis.com (the default): predict calls leave no audit record")]
    return []


def rule_28(s):
    if not s.endpoint["deployModel"]["deployedModel"].get("enableAccessLogging"):
        return [Finding("GC15-28", "LOW", "15.4", "access logging is off on the deployed model (the default): no per-request timestamp and latency in Cloud Logging")]
    return []


def rule_29(s):
    out = []
    if s.app.get("server_logs_prompts"):
        out.append(Finding("GC15-29", "MEDIUM", "15.4", "the inference server prints prompts to stdout, and container logging sends stdout to Cloud Logging: ticket text sits in logs most engineers can read"))
    if not s.app.get("alerts"):
        out.append(Finding("GC15-29", "LOW", "15.4", "no alerts on predict volume, errors or deploys outside the pipeline"))
    return out


def rule_30(s):
    if "Model Monitoring" in s.app.get("monitoring_plan", ""):
        return [Finding("GC15-30", "LOW", "15.4", "the monitoring plan relies on Model Monitoring, which tracks feature drift for tabular models: it won't tell you a summariser is leaking or being abused")]
    return []


RULES = [rule_01, rule_02, rule_03, rule_04, rule_05, rule_06, rule_07, rule_08, rule_09, rule_10, rule_11, rule_12,
         rule_13, rule_14, rule_15, rule_16, rule_17, rule_18, rule_19, rule_20, rule_21, rule_22, rule_23, rule_24,
         rule_25, rule_26, rule_27, rule_28, rule_29, rule_30]
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run(setup: twin.Setup) -> list[Finding]:
    out = []
    for r in RULES:
        out += r(setup)
    return sorted(out, key=lambda f: (ORDER[f.severity], f.rule))


def main(argv):
    if len(argv) != 1:
        print(__doc__)
        return 2
    found = run(twin.Setup(argv[0]))
    for f in found:
        print(f)
    n = {k: sum(f.severity == k for f in found) for k in ORDER}
    print(f"\n{n['HIGH']} HIGH, {n['MEDIUM']} MEDIUM, {n['LOW']} LOW  ({len(found)} findings)")
    return 1 if n["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
