"""
evaluate.py: 15 attacks and 6 normal requests against one setup. Offline, standard library only.

    python3 evaluate.py first-draft    # make attack
    python3 evaluate.py hardened       # make hardened
    python3 evaluate.py hardened -v    # every step of every case

An attack "worked" if it reached its goal in the twin. A normal request "works" if the business still gets what it
needs. A setup is only good when the first number is 0 AND the second is 6 of 6.
"""

from __future__ import annotations

import re
import sys

import gate
import model_files
import twin

C = twin.COMPANY
WS, EP = C["endpoint_workspace"], C["endpoint"]
REG = C["registry"]["name"]
SECRET = re.compile(r"(token|secret|password|key|sas)", re.I)


def _say(ok, why):
    return f"{'allowed' if ok else 'DENIED'} ({why})"


def _deployed(s, dep="blue"):
    return twin.resolve_model(s, s.deployments[dep]["model"])


# --------------------------------------------------------------------------------------------------------------------
# Attacks. Each returns (worked, [lines that explain what happened]).
# --------------------------------------------------------------------------------------------------------------------
def a1(s):
    world = twin.World(s)
    r = twin.load_model(s, world)
    return r["ok"] and r["code_ran"], world.events + [r["why"]] + ([] if r["code_ran"] else ["no pickle-based weights: nothing ran at load"])


def a2(s):
    if s.app.get("deploy_from") == "registry":
        ok, why = twin.decide(s, "ds-bob", twin.A_REGISTRY_ASSET_WRITE, f"regasset:{REG}/tsg-summariser/3")
        return ok, [f"ds-bob tags his version for release, but releases come from {REG} only; he tries to create version 3 there: {_say(ok, why)}"]
    ok, why = twin.decide(s, "ds-bob", twin.A_MODEL_WRITE, f"model:{WS}/bob-experiment/1")
    lines = [f"ds-bob sets tags.stage=Prod on his own bob-experiment:1 (tags are the one thing you can change on a version): {_say(ok, why)}"]
    if ok:
        lines.append(f"release process: '{s.app['release_process']}': bob's model is next")
    return ok, lines


def a3(s):
    ref = "azureml:bob-experiment:1"
    ok, why = twin.decide(s, "ds-bob", twin.A_DEPLOY_WRITE, f"deployment:{WS}/{EP}/blue")
    lines = [f"ds-bob updates the live 'blue' deployment to {ref}: {_say(ok, why)}"]
    pol = twin.policy_check(s, twin.deployment_request(ref))
    lines.append("Azure Policy: " + (f"DENIED by {', '.join(pol['denied'])}" if pol["denied"] else
                                     "nothing to deny (the registry-model rules only fire for models from a registry)"))
    return ok and not pol["denied"], lines


def a4(s):
    where, key, rec = _deployed(s)
    path = rec["stored_in"]
    acct, container = path.split(":", 1)[1].split("/")[:2]
    ok, why = twin.decide(s, "ds-bob", twin.D_BLOB_WRITE, f"storage:{acct}/{container}", data=True)
    lines = [f"ds-bob overwrites the files of {key} in {path}: {_say(ok, why)}"]
    if not ok:
        return False, lines
    world = twin.World(s)
    world.store[path] = model_files.swapped(world.files(path))
    r = twin.load_model(s, world)
    lines += world.events + [f"next scale-out or restart: {r['why']}"]
    return r["ok"] and r["code_ran"], lines


def a5(s):
    ok, why = twin.egress(s, WS, f"internet:{C['collector_host']}")
    return ok, [f"code in the deployment's container (a booby-trapped file, a bad package) posts a ticket to https://{C['collector_host']}: {'sent' if ok else 'BLOCKED'} ({why})"]


def a6(s):
    o = C["other_team_storage"]
    ok, why = twin.egress(s, WS, f"storage:{o['account']}")
    lines = [f"code in the container calls {o['account']}.blob.core.windows.net: {'reachable' if ok else 'BLOCKED'} ({why})"]
    if not ok:
        return False, lines
    ident = twin.endpoint_identity(s)
    ok2, why2 = twin.decide(s, ident, twin.D_BLOB_READ, f"storage:{o['account']}/{o['container']}", data=True)
    lines.append(f"... and reads {o['container']}/{o['blob']} with the endpoint identity {ident}: {_say(ok2, why2)}")
    return ok2, lines


def a7(s):
    if s.endpoint.get("auth_mode", "key") != "key":
        r = twin.invoke(s, "outsider", "internet", "key")
        return False, [f"a key found in an old notebook, used from the internet: {r['why']}"]
    r = twin.invoke(s, "outsider", "internet", "key")
    return r["ok"], [f"a key found in an old notebook, used from the internet: {'200 OK' if r['ok'] else 'refused'} ({r['why']})",
                     "keys don't expire: it keeps working until someone regenerates it"]


def a8(s):
    key, why = twin.list_keys(s, "tsg-reporting")
    lines = [f"tsg-reporting (it only needed usage numbers) calls listKeys: {why}"]
    for ds in ("ds-alice", "ds-bob"):
        k2, w2 = twin.list_keys(s, ds)
        if k2:
            lines.append(f"so can {ds}: {w2}")
    if not key:
        return False, lines
    r = twin.invoke(s, "tsg-reporting", "internet", "key")
    lines.append(f"the key, used from outside Contoso's network: {'200 OK' if r['ok'] else 'refused'} ({r['why']})")
    return r["ok"], lines


def a9(s):
    cred = s.app.get("app_credential", "key")
    r = twin.invoke(s, "tsg-helpdesk-app", "vnet", cred, header="debug")
    if not r["ok"]:
        return False, [f"a caller adds the header azureml-model-deployment: debug: {r['why']}"]
    _, key, rec = _deployed(s, "debug")
    return True, [f"a caller adds the header azureml-model-deployment: debug: 200 OK ({r['why']})",
                  f"'debug' runs {key}, which nobody approved"]


def a10(s):
    host = C["personal_hub_repo"]
    ok, why = twin.egress(s, "tsg-ml-dev", f"internet:{host}")
    return ok, [f"a notebook on ci-bob uploads a ticket export to https://{host}: {'sent' if ok else 'BLOCKED'} ({why})"]


def a11(s):
    lines, worked = [], False
    for name, d in s.datastores.get(WS, {}).items():
        if not d.get("credentials"):
            continue
        ok, why = twin.decide(s, "ds-bob", twin.A_DATASTORE_SECRETS, f"datastore:{WS}/{name}")
        lines.append(f"datastore {name} keeps an account key in the workspace key vault; ds-bob lists its secrets: {_say(ok, why)}")
        worked |= ok
    if not lines:
        lines.append("every datastore is identity-based: there is no stored key to retrieve")
    return worked, lines


def a12(s):
    lines, worked = [], False
    for dep, d in s.deployments.items():
        if dep.startswith("_"):
            continue
        for k, v in d.get("environment_variables", {}).items():
            if SECRET.search(k) or str(v).startswith(("hf_", "sk-")):
                ok, why = twin.decide(s, "ds-bob", twin.A_DEPLOY_READ, f"deployment:{WS}/{EP}/{dep}")
                lines.append(f"{k} in deployment '{dep}': az ml online-deployment show prints it to ds-bob: {_say(ok, why)}")
                worked |= ok
    if not lines:
        lines.append("no secrets in any deployment definition")
    return worked, lines


def a13(s):
    lines, worked = [], False
    for ws in C["workspaces"]:
        net, nwhy = twin.inbound(s, ws, "internet")
        ok, why = twin.decide(s, "ds-bob", twin.A_DATASTORE_READ, f"ws:{ws}")
        lines.append(f"ds-bob's stolen token, from the internet, lists datastores in {ws}: network {'open' if net else 'BLOCKED'} ({nwhy}); role {_say(ok, why)}")
        worked |= net and ok
    return worked, lines


def a14(s):
    ok, why = twin.decide(s, "tsg-platform-admin", twin.A_WORKSPACE_WRITE, "rg:rg-tsg-ml-dev")
    req = twin.workspace_request("tsg-quicktest", {"publicNetworkAccess": "Enabled",
                                                   "managedNetwork": {"isolationMode": "AllowInternetOutbound"}})
    pol = twin.policy_check(s, req)
    lines = [f"tsg-platform-admin creates a quick-test workspace (internet outbound, public access on): {_say(ok, why)}",
             "Azure Policy: " + (f"DENIED by {', '.join(pol['denied'])}" if pol["denied"] else
                                 f"not denied (audit only: {', '.join(pol['audited']) or 'no rule matched'})")]
    return ok and not pol["denied"], lines


def _approve(s, version: str, who: str):
    """The approval step for a dev-workspace version: promotion into the registry (hardened) or a stage=Prod tag
    (first draft). Returns (ok, lines)."""
    rec = s.models["workspace:tsg-ml-dev"][f"tsg-summariser:{version}"]
    if s.app.get("deploy_from") == "registry":
        ok, why = twin.decide(s, who, twin.A_REGISTRY_ASSET_WRITE, f"regasset:{REG}/tsg-summariser/{version}")
        lines = [f"{who} promotes tsg-summariser:{version} into {REG}: {_say(ok, why)}"]
    else:
        ok, why = twin.decide(s, who, twin.A_MODEL_WRITE, f"model:tsg-ml-dev/tsg-summariser/{version}")
        lines = [f"{who} tags tsg-summariser:{version} stage=Prod: {_say(ok, why)}"]
    if ok and s.app.get("approval_gate"):
        files = twin.World(s).files(rec["stored_in"])
        reasons = gate.check_before_promotion(rec, files, who, C)
        lines.append("promotion gate: " + ("passed" if not reasons else "REFUSED: " + "; ".join(reasons)))
        ok = not reasons
    elif ok:
        lines.append("no gate: nothing looked at the files, the hashes, the licence or who registered it")
    return ok, lines


def a15(s):
    return _approve(s, "3", "tsg-ml-approver")


ATTACKS = [
    ("A1", "Booby-trapped model file: the weights are a pickle, and loading it runs code in the container", a1),
    ("A2", "Approval by tag: the author marks his own model for release", a2),
    ("A3", "Notebook to production: a data scientist points the live deployment at his own model", a3),
    ("A4", "A swap underneath: a data scientist overwrites the files behind the released version", a4),
    ("A5", "Data out of the container: code in the deployment posts tickets to the internet", a5),
    ("A6", "A wide endpoint identity: code in the container reads another team's storage", a6),
    ("A7", "A leaked key, used from the internet", a7),
    ("A8", "The scoring role that hands out keys: listKeys by a job that only needed numbers", a8),
    ("A9", "The hidden deployment: a 0% deployment still answers when you name it", a9),
    ("A10", "Notebook exfiltration through an allowed FQDN: an upload to a personal Hugging Face repo", a10),
    ("A11", "Keys in the datastore: another workspace user retrieves the storage account key", a11),
    ("A12", "Secret in the deployment: the Hugging Face token in environment_variables", a12),
    ("A13", "A workspace on the internet: a stolen data scientist token used from anywhere", a13),
    ("A14", "Isolation dropped: an admin's quick-test workspace with internet outbound and public access", a14),
    ("A15", "Approval in a hurry: the approver approves a version that fails every check", a15),
]


# --------------------------------------------------------------------------------------------------------------------
# Normal requests. Each returns (works, [lines]).
# --------------------------------------------------------------------------------------------------------------------
def n1(s):
    cred = s.app.get("app_credential", "key")
    r = twin.invoke(s, "tsg-helpdesk-app", s.app.get("app_network", "vnet"), cred)
    lines = [f"the Helpdesk asks for a summary from Contoso's network: {'200 OK' if r['ok'] else 'refused'} ({r['why']})"]
    if not r["ok"]:
        return False, lines
    world = twin.World(s)
    ld = twin.load_model(s, world, r["deployment"])
    lines.append(f"the deployment's instances start: {'ok' if ld['ok'] else 'FAILED'} ({ld['why']})")
    return ld["ok"], lines


def n2(s):
    ref = s.deployments["blue"]["model"]
    ok, why = twin.decide(s, "tsg-ci-deployer", twin.A_DEPLOY_WRITE, f"deployment:{WS}/{EP}/blue")
    pol = twin.policy_check(s, twin.deployment_request(ref))
    lines = [f"the pipeline deploys {ref} to 'blue': {_say(ok, why)}",
             "Azure Policy: " + (f"DENIED by {', '.join(pol['denied'])}" if pol["denied"] else "allowed")]
    if not ok or pol["denied"]:
        return False, lines
    ld = twin.load_model(s, twin.World(s))
    lines.append(f"new instances start: {'ok' if ld['ok'] else 'FAILED'} ({ld['why']})")
    return ld["ok"], lines


def n3(s):
    return _approve(s, "4", "tsg-ml-approver")


def n4(s):
    ok, why = twin.decide(s, "ds-alice", twin.A_MODEL_WRITE, "model:tsg-ml-dev/alice-experiment/1")
    net, nwhy = twin.egress(s, "tsg-ml-dev", f"storage:{C['workspaces']['tsg-ml-dev']['storage']}")
    return ok and net, [f"ds-alice registers an experiment in tsg-ml-dev: {_say(ok, why)}",
                        f"her notebook writes to the dev workspace storage: {'ok' if net else 'BLOCKED'} ({nwhy})"]


def n5(s):
    ok, why = twin.decide(s, "ds-bob", twin.A_DEPLOY_READ, f"deployment:{WS}/{EP}/blue")
    return ok, [f"ds-bob reads the production deployment's settings to debug a ticket: {_say(ok, why)}"]


def n6(s):
    ok, why = twin.decide(s, "tsg-platform-admin", twin.A_WORKSPACE_WRITE, "rg:rg-tsg-ml-dev")
    req = twin.workspace_request("tsg-ml-newteam", {"publicNetworkAccess": "Disabled",
                                                    "managedNetwork": {"isolationMode": "AllowOnlyApprovedOutbound"}})
    pol = twin.policy_check(s, req)
    return ok and not pol["denied"], [f"tsg-platform-admin creates a new team's workspace, approved outbound and private: {_say(ok, why)}",
                                      "Azure Policy: " + (f"DENIED by {', '.join(pol['denied'])}" if pol["denied"] else "allowed")]


NORMAL = [
    ("N1", "The Helpdesk gets a ticket summary", n1),
    ("N2", "The pipeline deploys the released version", n2),
    ("N3", "The approver approves a clean version (v4)", n3),
    ("N4", "A data scientist runs and registers an experiment in the dev workspace", n4),
    ("N5", "A data scientist reads the production deployment's settings", n5),
    ("N6", "The platform team creates a new, correctly configured workspace", n6),
]


def run_suite(setup) -> dict:
    s = twin.Setup(setup) if isinstance(setup, str) else setup
    attacks = []
    for aid, title, fn in ATTACKS:
        worked, lines = fn(s.copy())
        attacks.append({"id": aid, "title": title, "worked": bool(worked), "lines": lines})
    normal = []
    for nid, title, fn in NORMAL:
        works, lines = fn(s.copy())
        normal.append({"id": nid, "title": title, "works": bool(works), "lines": lines})
    return {"attacks": attacks, "normal": normal}


def _main(argv):
    if not argv:
        print(__doc__)
        return 2
    verbose = "-v" in argv
    name = [a for a in argv if not a.startswith("-")][0]
    r = run_suite(name)
    for a in r["attacks"]:
        print(f"  {a['id']:<4} {'WORKED ' if a['worked'] else 'blocked'}  {a['title']}")
        if verbose or a["id"] in ("A1", "A5") or not a["worked"]:
            for ln in a["lines"]:
                print(f"         . {ln}")
    print()
    for n in r["normal"]:
        print(f"  {n['id']:<4} {'works  ' if n['works'] else 'BROKEN '}  {n['title']}")
        if verbose or not n["works"]:
            for ln in n["lines"]:
                print(f"         . {ln}")
    worked = [a["id"] for a in r["attacks"] if a["worked"]]
    ok = sum(n["works"] for n in r["normal"])
    print(f"\nAttacks that worked: {len(worked)} of {len(r['attacks'])}" + (f"  ({', '.join(worked)})" if worked else "")
          + f"   |   normal requests that work: {ok} of {len(r['normal'])}")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
