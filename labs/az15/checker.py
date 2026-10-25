"""
checker.py: review one setup the way a security engineer reviews a pull request. 28 rules, AZ15-01 to AZ15-28.

    python3 checker.py first-draft     # make check
    python3 checker.py hardened        # make check-hardened

Exit code 1 if any HIGH finding (so it can fail a pipeline), 0 otherwise. Every rule names the lesson that teaches it.
"""

from __future__ import annotations

import datetime as dt
import re
import sys
from dataclasses import dataclass

import model_files
import twin

C = twin.COMPANY
WS, EP = C["endpoint_workspace"], C["endpoint"]
PEOPLE = [p for p in C["principals"] if p not in C["admins"]]
SECRET = re.compile(r"(token|secret|password|key|sas)", re.I)
TODAY = dt.date.fromisoformat(C["today"])


@dataclass
class Finding:
    rule: str
    lesson: str
    severity: str
    text: str

    def __str__(self):
        return f"[{self.severity:<6}] {self.rule} ({self.lesson}) {self.text}"


def run(s: twin.Setup) -> list[Finding]:
    out: list[Finding] = []

    def add(rule, lesson, sev, text):
        out.append(Finding(rule, lesson, sev, text))

    deps = {k: v for k, v in s.deployments.items() if not k.startswith("_")}

    # ------------------------------------------------------------------ 15.1 the image
    for name, d in deps.items():
        env = d["environment"]
        image = env.get("image") if isinstance(env, dict) else env
        if str(image).startswith(("docker.io/", "ghcr.io/", "quay.io/")) or str(image).endswith(":latest"):
            add("AZ15-01", "15.1", "HIGH", f"deployment '{name}' runs {image}: a public image by a moving tag. The bytes can change under you, and once you bring your own image, vulnerability management is yours")
        this, newest, newest_date = twin.newest_curated(image)
        if this and newest_date and (dt.date.fromisoformat(newest_date) - dt.date.fromisoformat(this)).days > 30:
            add("AZ15-02", "15.1", "MEDIUM", f"deployment '{name}' pins curated environment version {image.rsplit('/', 1)[1]} ({this}); version {newest} ({newest_date}) is out. Patched images get a new version: nothing updates yours")

    # ------------------------------------------------------------------ 15.2 network, identity, secrets, keys
    for ws, w in s.workspace.items():
        if ws.startswith("_"):
            continue
        mode = twin.isolation_mode(s, ws)
        if mode != "AllowOnlyApprovedOutbound":
            add("AZ15-03", "15.2", "HIGH", f"workspace {ws} managed network is '{mode}': code in deployments and notebooks can send data to the internet")
        fqdn = [r["destination"] for r in w.get("managedNetwork", {}).get("outboundRules", {}).values() if r["type"] == "FQDN"]
        if mode == "AllowOnlyApprovedOutbound" and fqdn:
            add("AZ15-04", "15.2", "MEDIUM", f"workspace {ws} has FQDN outbound rules ({', '.join(fqdn)}): they deploy a billed Azure Firewall ({w.get('managedNetwork', {}).get('firewallSku', 'Standard')}), and Microsoft can't guarantee exfiltration protection to those destinations")
        if str(w.get("publicNetworkAccess", "Enabled")).lower() != "disabled":
            add("AZ15-05", "15.2", "HIGH", f"workspace {ws} has public network access enabled: a stolen token works from anywhere")
    if str(s.endpoint.get("public_network_access", "enabled")).lower() != "disabled":
        add("AZ15-06", "15.2", "HIGH", f"endpoint {EP} has public_network_access enabled (the default): scoring requests are accepted from the internet")
    ident = twin.endpoint_identity(s)
    wide = [a for a in s.rbac.get("assignments", []) if a["principal"] == ident and a["scope"] in ("sub",) + tuple(f"rg:{w['resource_group']}" for w in C["workspaces"].values()) and a["role"] != "AcrPull"]
    wide += [a for a in s.rbac.get("assignments", []) if a["principal"] == ident and a["role"] in ("Owner", "Contributor")]
    for a in {id(a): a for a in wide}.values():
        add("AZ15-07", "15.2", "HIGH", f"endpoint identity {ident} has {a['role']} at {a['scope']}: anything in the container can use it far beyond the model's own files")
    for ws, stores in s.datastores.items():
        if ws.startswith("_"):
            continue
        for name, d in stores.items():
            if d.get("credentials"):
                add("AZ15-08", "15.2", "HIGH", f"datastore {ws}/{name} stores a credential ({', '.join(d['credentials'])}) in the workspace key vault: other workspace users with enough permissions can retrieve it")
    for name, d in deps.items():
        for k, v in d.get("environment_variables", {}).items():
            if SECRET.search(k) or str(v).startswith(("hf_", "sk-")):
                add("AZ15-09", "15.2", "HIGH", f"secret-looking value in deployment '{name}' environment_variables ({k}): Microsoft says secrets in the deployment definition are exposed there")
    if C["standard"]["requires_cmk"]:
        for ws, w in s.workspace.items():
            if not ws.startswith("_") and w.get("encryption", {}).get("status") != "Enabled":
                add("AZ15-10", "15.2", "LOW", f"workspace {ws} uses Microsoft-managed keys; Contoso's standard asks for a customer-managed key (in a vault with purge protection)")

    # ------------------------------------------------------------------ 15.3 who can call, what it loads, who said so
    if s.endpoint.get("auth_mode", "key") != "aad_token":
        add("AZ15-11", "15.3", "HIGH", f"endpoint {EP} uses auth_mode '{s.endpoint.get('auth_mode', 'key')}': keys don't expire, need no role to use, and the traffic log records no identity")
    if s.endpoint.get("auth_mode", "key") == "key":
        who = [p for p in PEOPLE if twin.decide(s, p, twin.A_LIST_KEYS, twin.endpoint_scope(s))[0]]
        if who:
            add("AZ15-12", "15.3", "HIGH", f"{', '.join(who)} can call listKeys on {EP}: anyone holding a key can call the endpoint, no role needed")
    writers = [p for p in ("ds-alice", "ds-bob") if twin.decide(s, p, twin.A_DEPLOY_WRITE, f"deployment:{WS}/{EP}/blue")[0]]
    if writers:
        add("AZ15-13", "15.3", "HIGH", f"{', '.join(writers)} can write production deployments: a model can go from a notebook to the live endpoint without review")
    where, key, rec = twin.resolve_model(s, deps["blue"]["model"])
    if not where.startswith("registry:"):
        add("AZ15-14", "15.3", "HIGH", f"deployment 'blue' runs workspace model {key}, not a version promoted into {C['registry']['name']}: nobody's approval is part of what runs")
    if "tagged" in s.app.get("release_process", ""):
        add("AZ15-15", "15.3", "HIGH", f"the release process deploys by tag ('{s.app['release_process']}'): tags are writable by anyone who can write the model, including its author")
    scan = model_files.scan_files(model_files.build(rec["files"]))
    if not scan["safe"]:
        bad = ", ".join(f"{p['name']} ({p['kind']}" + (f": imports {', '.join(p['unsafe_globals'])})" if p["unsafe_globals"] else ")") for p in scan["problems"])
        add("AZ15-16", "15.3", "HIGH", f"the deployed model files are not safetensors-only: {bad}")
    acct, container = rec["stored_in"].split(":", 1)[1].split("/")[:2]
    can_write = [p for p in PEOPLE if p not in ("tsg-ci-deployer",) and twin.decide(s, p, twin.D_BLOB_WRITE, f"storage:{acct}/{container}", data=True)[0]]
    if can_write:
        add("AZ15-17", "15.3", "HIGH", f"{', '.join(can_write)} may overwrite the files the deployment loads ({rec['stored_in']}): the next restart or scale-out loads whatever is there")
    hashes = [k for k in rec.get("tags", {}) if k.startswith(model_files.HASH_PREFIX)]
    if not hashes or not s.app.get("deploy_verifies_hashes"):
        add("AZ15-18", "15.3", "MEDIUM", "no file hashes recorded on the deployed version, or the deploy step doesn't compare them: nobody can prove the files running are the ones approved")
    if not rec.get("tags", {}).get("licence"):
        add("AZ15-18", "15.3", "MEDIUM", "licence not recorded on the deployed version: Microsoft says complying with a model's licence terms is your job")
    idle = [d for d, pct in s.endpoint.get("traffic", {}).items() if pct == 0]
    if idle:
        add("AZ15-19", "15.3", "MEDIUM", f"deployment(s) {', '.join(idle)} at 0% traffic on the production endpoint: the azureml-model-deployment header still routes to them")
    deny_registry = [a for a in s.policy_assignments() if "OnlyDeployAllowedRegistryModels" in a.get("source", "") and a.get("effect") == "Deny"]
    if not deny_registry:
        add("AZ15-20", "15.3", "MEDIUM", f"no Azure Policy denies registry models from outside {C['registry']['name']}: a catalog or Hugging Face model can be deployed straight from its public registry")
    ms = s.monitoring.get("model_scanning", {})
    private = any(w.get("privateEndpoint") for k, w in s.workspace.items() if not k.startswith("_"))
    if not ms.get("ci_scan"):
        why = "and Defender's AI model security doesn't support private-link workspaces" if private else "and Defender's AI model security scans once a week, after the upload"
        add("AZ15-21", "15.3", "MEDIUM", f"model files are not scanned in CI before registration {why}")
    if not s.app.get("approval_gate"):
        add("AZ15-22", "15.3", "MEDIUM", "no promotion gate: nothing checks formats, hashes, licence and who registered it before a version is approved (challenge 2)")

    # ------------------------------------------------------------------ 15.2 enforcement (Azure Policy)
    quick = twin.workspace_request("policy-probe", {"publicNetworkAccess": "Enabled", "managedNetwork": {"isolationMode": "AllowInternetOutbound"}})
    pol = twin.policy_check(s, quick)
    if not pol["denied"]:
        extra = ""
        for a in s.policy_assignments():
            pd = a.get("parameter_definitions", {}).get("isolationMode")
            if pd and "isolationMode" not in a.get("parameters", {}):
                extra = f"; assignment '{a['name']}' leaves isolationMode at its default '{pd.get('defaultValue')}', so it flags the wrong workspaces"
        add("AZ15-23", "15.2", "MEDIUM", "no Azure Policy in Deny for the managed network mode and public network access: an admin's quick test can still create an open workspace (challenge 1)" + extra)

    # ------------------------------------------------------------------ 15.4 watching
    diag = s.monitoring.get("diagnostic_settings", {})
    if "AmlOnlineEndpointTrafficLog" not in diag.get(f"endpoint:{WS}/{EP}", []):
        add("AZ15-24", "15.4", "MEDIUM", f"no diagnostic setting sends AmlOnlineEndpointTrafficLog for {EP} to Log Analytics: no record of who called which deployment")
    pc = s.monitoring.get("payload_collection", {})
    collecting = any(d.get("data_collector") for d in deps.values())
    if collecting and (set(pc.get("readers", [])) - {"tsg-security"} or not pc.get("expires_after_days")):
        add("AZ15-25", "15.4", "MEDIUM", f"payload collection (full requests and responses) goes to {pc.get('destination')} read by {', '.join(pc.get('readers', []))}, expiry {pc.get('expires_after_days')}: every ticket the model saw, in someone else's container")
    if not s.monitoring.get("alerts"):
        add("AZ15-26", "15.4", "LOW", "no alerts on 4xx responses, request volume or listKeys: probing and abuse show up there first")
    if any("model monitoring" in p.lower() for p in s.monitoring.get("plan", [])) and C["standard"]["isolation_mode"] == "AllowOnlyApprovedOutbound":
        add("AZ15-27", "15.4", "LOW", "the monitoring plan relies on Azure Machine Learning model monitoring, which doesn't support the AllowOnlyApprovedOutbound mode Contoso's standard requires")
    if s.monitoring.get("activity_log_export_days", 0) <= 90:
        add("AZ15-28", "15.4", "LOW", "the Activity Log isn't exported: Azure keeps it for 90 days, and listKeys or deployment writes older than that are gone")
    return out


def _main(argv):
    if not argv:
        print(__doc__)
        return 2
    s = twin.Setup(argv[0])
    found = run(s)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for f in sorted(found, key=lambda f: (order[f.severity], f.rule)):
        print(f)
    n = {k: sum(f.severity == k for f in found) for k in order}
    print(f"\n{n['HIGH']} HIGH, {n['MEDIUM']} MEDIUM, {n['LOW']} LOW  ({len(found)} findings)")
    return 1 if n["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
