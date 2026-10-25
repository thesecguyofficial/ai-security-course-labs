"""
evaluate.py: 15 attacks and 6 normal requests against one setup. Offline, standard library only.

    python3 evaluate.py first-draft    # make attack
    python3 evaluate.py hardened       # make hardened
    python3 evaluate.py hardened -v    # every step of every case

An attack "worked" if it reached its goal in the twin. A normal request "works" if the business still gets what it
needs. A setup is only good when the first number is 0 AND the second is 6 of 6.
"""

from __future__ import annotations

import sys

import gate
import model_files
import twin

C = twin.COMPANY
EP = "endpoint:" + C["endpoint"]
MODEL = "model:" + C["model"]
PROD, DEV = C["prod_project"], C["dev_project"]
ANALYTICS_OBJECT = "bucket:" + C["buckets"]["analytics"] + "/exports/tickets-2027-01.csv"
UNVETTED_GARDEN_MODEL = "publishers/hf-someone/models/fast-summariser-7b:deploy"


def _say(ok, why):
    return f"{'allowed' if ok else 'DENIED'} ({why})"


def _ds_project(s):
    return s.app.get("_ds_project", PROD)


def _sa(name):
    return "sa:" + twin.sa_email(name)


# --------------------------------------------------------------------------------------------------------------------
# Attacks. Each returns (worked, [lines that explain what happened]).
# --------------------------------------------------------------------------------------------------------------------
def a1(s):
    world = twin.World(s)
    r = twin.load_model(s, world)
    return r["ok"] and r["code_ran"], [r["why"]] + world.events + ([] if r["code_ran"] else ["no pickle-based weights: nothing ran at load"])


def a2(s):
    src = s.app["_next_release"]
    ok, why = twin.decide(s, "ds-bob", "storage.objects.create", "bucket:" + src[5:] + "model.safetensors")
    lines = [f"ds-bob writes into {src} after the pipeline scanned it: {_say(ok, why)}"]
    if not ok:
        return False, lines
    world = twin.World(s)
    up = twin.pipeline_upload(s, world, src, swap_after_scan=True)
    lines.append(up["why"])
    if not up["ok"]:
        return False, lines
    code = [n for n, d in up["files"].items() if model_files.is_pickle_weights(n, d) and model_files.scan_bytes(n, d)["unsafe_globals"]]
    lines.append(f"the registry now holds {', '.join(sorted(up['files']))}: " + ("a pickle the scan never saw" if code else "no pickle"))
    return bool(code), lines


def a3(s):
    steps = [("aiplatform.models.upload", MODEL), ("aiplatform.endpoints.deploy", EP)]
    lines, all_ok = [], True
    for perm, res in steps:
        ok, why = twin.decide(s, "ds-bob", perm, res)
        lines.append(f"ds-bob {perm.split('.', 1)[1]} a hotfix from gs://{C['buckets']['models']}/bob/experiment/ in {PROD}: {_say(ok, why)}")
        all_ok &= ok
    runtime = s.endpoint["deployModel"]["deployedModel"].get("serviceAccount")
    if runtime:
        ok, why = twin.decide(s, "ds-bob", "iam.serviceAccounts.actAs", "sa:" + runtime)
        lines.append(f"ds-bob acts as the deployed model's service account: {_say(ok, why)}")
        all_ok &= ok
    return all_ok, lines


def a4(s):
    ok, why = twin.decide(s, "ds-bob", "aiplatform.models.update", MODEL)
    return ok, [f"ds-bob moves the prod alias onto version 2, which he trained himself: {_say(ok, why)}"]


def a5(s):
    r = twin.container_reach(s)
    return r["internet"], [f"code in the serving container posts a ticket to https://{C['attacker_host']}: "
                           + ("sent" if r["internet"] else "blocked") + f" ({r['why']})"]


def a6(s):
    ident = twin.container_reach(s)["identity"]
    if ident is None:
        return False, ["the container runs as the service account Agent Platform manages: it can read the model copy and nothing else"]
    ok, why = twin.decide(s, ident, "storage.objects.get", ANALYTICS_OBJECT)
    return ok, [f"code in the container reads the analytics team's export as {ident}: {_say(ok, why)}"]


def a7(s):
    keys = twin.user_keys(s, "tsg-helpdesk-app")
    if not keys:
        return False, ["tsg-helpdesk-app has no user-managed keys: there is no key file to steal"]
    ok, why = twin.decide(s, "tsg-helpdesk-app", "aiplatform.endpoints.predict", EP, origin="internet")
    return ok, [f"the app's leaked key file, used from {C['attacker_ip']} on the internet: {_say(ok, why)}"]


def a8(s):
    cfg = s.endpoint["endpoint"].get("predictRequestResponseLoggingConfig") or {}
    if not cfg.get("enabled"):
        return False, ["request-response logging is off: there is no table of prompts to read"]
    readers = s.endpoint.get("_bigquery_dataset_readers", [])
    ok = any(twin._is_member("ds-bob", r) for r in readers)
    table = cfg["bigqueryDestination"]["outputUri"]
    return ok, [f"ds-bob reads yesterday's prompts and summaries in {table}: " + ("allowed (all-staff can read the dataset)" if ok else "DENIED (not a reader of the dataset)")]


def a9(s):
    inst = next((i for i in s.workbench["instances"].values() if twin.can_open(i, "ds-bob")), None)
    if inst is None:
        return False, ["ds-bob has no Workbench instance"]
    ident = twin.workbench_identity(inst)
    ok, why = twin.decide(s, ident, "aiplatform.endpoints.deploy", EP)
    return ok, [f"from his notebook (running as {ident}), ds-bob deploys a model to the production endpoint: {_say(ok, why)}"]


def a10(s):
    inst = next((i for i in s.workbench["instances"].values() if twin.can_open(i, "ds-bob")), None)
    if inst is None:
        return False, ["ds-bob has no Workbench instance"]
    r = twin.workbench_reach(s, inst)
    return r["internet"], [f"a notebook uploads a ticket export to https://{C['attacker_host']}: " + ("sent" if r["internet"] else "blocked") + f" ({r['why']})"]


def a11(s):
    ok1, w1 = twin.decide(s, "ds-bob", "iam.serviceAccounts.actAs", _sa("tsg-ci-deployer"))
    ok2, w2 = twin.decide(s, "ds-bob", "notebooks.instances.create", "project:" + _ds_project(s))
    lines = [f"ds-bob acts as tsg-ci-deployer: {_say(ok1, w1)}", f"ds-bob creates a Workbench instance that runs as it: {_say(ok2, w2)}"]
    if ok1 and ok2:
        ok3, w3 = twin.decide(s, "tsg-ci-deployer", "storage.objects.create", "bucket:" + C["buckets"]["models"] + "/tsg-summariser/v3/model.safetensors")
        lines.append(f"as the pipeline, he writes the release folder: {_say(ok3, w3)}")
        return ok3, lines
    return False, lines


def a12(s):
    v = twin.deployed_version(s)
    secrets = [k for k in twin.env_of(v) if any(w in k.upper() for w in ("TOKEN", "SECRET", "KEY", "PASSWORD"))]
    if not secrets:
        return False, ["the deployed version's containerSpec.env holds no secrets"]
    ok, why = twin.decide(s, "ds-bob", "aiplatform.models.get", MODEL)
    return ok, [f"ds-bob calls models.get and reads {', '.join(secrets)} from containerSpec.env: {_say(ok, why)}"]


def a13(s):
    ok, why = twin.decide(s, "ds-alice", "aiplatform.endpoints.deploy", "project:" + _ds_project(s))
    lines = [f"ds-alice deploys {UNVETTED_GARDEN_MODEL.split(':')[0]} from Model Garden in {_ds_project(s)}: {_say(ok, why)}"]
    if not ok:
        return False, lines
    ok2, why2 = twin.allowed_models_ok(s, UNVETTED_GARDEN_MODEL)
    lines.append(f"org policy: {_say(ok2, why2)}")
    return ok2, lines


def a14(s):
    project = _ds_project(s)
    new = {"_project": project, "_access_mode": "service-account", "_users": ["ds-bob"],
           "gceSetup": {"disablePublicIp": False, "serviceAccounts": [{"email": twin.sa_email("compute-default")}], "metadata": {}}}
    ok, why = twin.decide(s, "ds-bob", "notebooks.instances.create", "project:" + project)
    lines = [f"ds-bob creates 'bob-quick' with the console defaults (external IP, root, terminal, downloads): {_say(ok, why)}"]
    if not ok:
        return False, lines
    bad = twin.workbench_violations(s, new)
    lines.append("org policy refuses it: " + "; ".join(bad) if bad else "no ainotebooks.* constraint is enforced: the instance is created")
    return not bad, lines


def a15(s):
    ok, why = twin.decide(s, "tsg-model-approver", "aiplatform.models.update", MODEL)
    lines = [f"the ML lead moves the prod alias onto version 2 in a hurry (pickle weights, no licence, no hashes): {_say(ok, why)}"]
    if not ok:
        return False, lines
    if s.app.get("approval_gate"):
        v = twin.version(s, "2")
        reasons = gate.check_before_promotion(v, twin.World(s).snapshots["2"], "tsg-model-approver", C)
        lines.append("promotion gate: " + ("refused: " + "; ".join(reasons) if reasons else "passed it"))
        return not reasons, lines
    lines.append("no promotion gate: the alias moves, and the pipeline's next deploy of tsg-summariser@prod serves version 2")
    return True, lines


ATTACKS = [
    ("A1", "Booby-trapped model file: the weights are a pickle, and loading it runs code in the container", "15.3", a1),
    ("A2", "Swap after the scan: a data scientist changes the release folder before models.upload copies it", "15.3", a2),
    ("A3", "Unreviewed model to production: a hotfix uploaded and deployed straight from a notebook", "15.3", a3),
    ("A4", "Self-promotion: the author moves the prod alias onto their own version", "15.3", a4),
    ("A5", "Data out of the container: code in the serving container posts tickets to the internet", "15.2", a5),
    ("A6", "Container identity: code in the container reads another team's bucket", "15.2", a6),
    ("A7", "Leaked key file: predict from the internet with the app's service account key", "15.2", a7),
    ("A8", "Prompt logs for everyone: request-response logs in a dataset all staff can read", "15.4", a8),
    ("A9", "Shared notebook identity: a notebook running as the default service account changes production", "15.2", a9),
    ("A10", "Notebook exfiltration: a Workbench instance uploads data to the internet", "15.2", a10),
    ("A11", "actAs escalation: a data scientist runs a notebook as the pipeline's service account", "15.2", a11),
    ("A12", "Secret in the model: models.get shows the Hugging Face token", "15.2", a12),
    ("A13", "Unvetted Model Garden model: an open model nobody reviewed is deployed", "15.3", a13),
    ("A14", "Defaults come back: a new Workbench instance with external IP, root, terminal and downloads", "15.2", a14),
    ("A15", "Promotion in a hurry: the ML lead promotes a version that fails every check", "15.3", a15),
]


# --------------------------------------------------------------------------------------------------------------------
# Normal requests
# --------------------------------------------------------------------------------------------------------------------
def n1(s):
    ok, why = twin.decide(s, "tsg-helpdesk-app", "aiplatform.endpoints.predict", EP, origin="vpc")
    r = twin.load_model(s, twin.World(s))
    path = s.app["client"]["path"]
    return ok and r["ok"], [f"the Helpdesk asks for a ticket summary ({path} path, from ExampleCo's VPC): {_say(ok, why)}; endpoint: {r['why']}"]


def n2(s):
    src = s.app["_next_release"]
    runtime = s.endpoint["deployModel"]["deployedModel"].get("serviceAccount")
    steps = [twin.decide(s, "tsg-ci-deployer", "aiplatform.models.upload", MODEL),
             twin.decide(s, "tsg-ci-deployer", "aiplatform.endpoints.deploy", EP)]
    if runtime:
        steps.append(twin.decide(s, "tsg-ci-deployer", "iam.serviceAccounts.actAs", "sa:" + runtime))
    up = twin.pipeline_upload(s, twin.World(s), src)
    ok = all(o for o, _ in steps) and up["ok"]
    return ok, [f"the pipeline uploads {src} and deploys it: {', '.join(_say(o, w) for o, w in steps)}; {up['why']}"]


def n3(s):
    clean = next(v for v in s.registry["versions"] if v.get("_story") == "clean")
    ok, why = twin.decide(s, "tsg-model-approver", "aiplatform.models.update", MODEL)
    lines = [f"the ML lead moves the prod alias onto clean version {clean['versionId']}: {_say(ok, why)}"]
    if ok and s.app.get("approval_gate"):
        reasons = gate.check_before_promotion(clean, twin.World(s).snapshots[clean["versionId"]], "tsg-model-approver", C)
        lines.append("promotion gate: " + ("refused: " + "; ".join(reasons) if reasons else "passed"))
        ok = not reasons
    return ok, lines


def n4(s):
    inst = next((n for n, i in s.workbench["instances"].items() if twin.can_open(i, "ds-alice")), None)
    if inst is None:
        return False, ["ds-alice has no Workbench instance she can open"]
    bad = twin.workbench_violations(s, s.workbench["instances"][inst])
    return not bad, [f"ds-alice opens JupyterLab on {inst}: " + ("works" if not bad else "the instance breaks org policy: " + "; ".join(bad))]


def n5(s):
    approved = C["approved_garden_models"][0]
    ok1, w1 = twin.decide(s, "ds-alice", "aiplatform.endpoints.deploy", "project:" + _ds_project(s))
    ok2, w2 = twin.allowed_models_ok(s, approved)
    return ok1 and ok2, [f"ds-alice deploys the approved base model in {_ds_project(s)} to evaluate it: {_say(ok1, w1)}; org policy: {_say(ok2, w2)}"]


def n6(s):
    r = twin.load_model(s, twin.World(s))
    return r["ok"], [f"the endpoint starts and loads its model: {r['why']}"]


NORMAL = [("N1", "The Helpdesk gets a ticket summary", n1), ("N2", "The pipeline uploads and deploys a release", n2),
          ("N3", "The ML lead promotes a clean version", n3), ("N4", "A data scientist opens her own notebook", n4),
          ("N5", "A data scientist evaluates the approved base model", n5), ("N6", "The endpoint starts", n6)]


def run_case(case, setup):
    cid, title, *rest = case
    fn = rest[-1]
    worked, lines = fn(setup)
    return {"id": cid, "title": title, "worked": worked, "works": worked, "lines": lines}


def run_suite(setup) -> dict:
    s = setup if isinstance(setup, twin.Setup) else twin.Setup(setup)
    return {"attacks": [run_case(a, s) for a in ATTACKS], "normal": [run_case(n, s) for n in NORMAL]}


def main(argv):
    if len([a for a in argv if a != "-v"]) != 1:
        print(__doc__)
        return 2
    verbose = "-v" in argv
    argv = [a for a in argv if a != "-v"]
    res = run_suite(argv[0])
    for r in res["attacks"]:
        print(f"  {r['id']:<4} {'WORKED ' if r['worked'] else 'blocked'}  {r['title']}")
        if verbose or r["worked"]:
            shown = r["lines"]
        else:   # the line that says what stopped it
            shown = [next((x for x in r["lines"] if "DENIED" in x or "blocked" in x or "refused" in x
                           or x.startswith(("no ", "the container runs as", "tsg-helpdesk-app has no", "request-response logging is off",
                                            "the deployed version's", "org policy"))), r["lines"][-1])]
        for line in shown:
            print(f"         . {line}")
    print()
    for r in res["normal"]:
        print(f"  {r['id']:<4} {'works  ' if r['works'] else 'BROKEN '}  {r['title']}")
        if verbose or not r["works"]:
            for line in r["lines"]:
                print(f"         . {line}")
    bad = [r["id"] for r in res["attacks"] if r["worked"]]
    good = sum(r["works"] for r in res["normal"])
    print(f"\nAttacks that worked: {len(bad)} of {len(ATTACKS)}  ({', '.join(bad) or 'none'})   |   normal requests that work: {good} of {len(NORMAL)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
