"""
evaluate.py: 15 attacks and 6 normal requests against one setup. Offline, standard library only.

    python3 evaluate.py first-draft    # make attack
    python3 evaluate.py hardened       # make hardened
    python3 evaluate.py hardened -v    # every step of every case
    python3 evaluate.py first-draft --only A5   # one case, every step (README Step 1b)

An attack "worked" if it reached its goal in the twin. A normal request "works" if the business still gets what it
needs. A setup is only good when the first number is 0 AND the second is 6 of 6.
"""

from __future__ import annotations

import sys

import gate
import model_files
import twin

C = twin.COMPANY
EP = C["endpoint_arn"]
PROD_ROLE = twin.arn_role("tsg-summariser-exec")
DS_ROLE = twin.arn_role("tsg-ds-exec")
PASS = {"iam:PassedToService": "sagemaker.amazonaws.com"}
ANALYTICS_OBJECT = twin.arn_s3(C["buckets"]["analytics"], "exports/tickets-2027-01.csv")


def _deployed_prefix(s):
    kind, where = twin.model_source(twin.effective_container(s))
    return where if kind == "s3" else None


def _say(ok, why):
    return f"{'allowed' if ok else 'DENIED'} ({why})"


# --------------------------------------------------------------------------------------------------------------------
# Attacks. Each returns (worked, [lines that explain what happened]).
# --------------------------------------------------------------------------------------------------------------------
def a1(s):
    world = twin.World(s)
    r = twin.load_model(s, world)
    return r["ok"] and r["code_ran"], [r["why"]] + world.events + ([] if r["code_ran"] else ["no pickle-based weights: nothing ran at load"])


def a2(s):
    prefix = _deployed_prefix(s)
    if prefix is None:
        return False, ["the model is downloaded from the Hub at start: nobody at AnyCompany can overwrite those files (and nobody checks them)"]
    bucket, key = prefix[5:].split("/", 1)
    ok, why = twin.decide(s, "ds-bob", "s3:PutObject", twin.arn_s3(bucket, key + "pytorch_model.bin"))
    lines = [f"ds-bob writes into {prefix}: {_say(ok, why)}"]
    if not ok:
        return False, lines
    world = twin.World(s)
    world.store[prefix] = model_files.swapped(world.files(prefix))
    r = twin.load_model(s, world)
    lines += [f"next deploy or scale-out: {r['why']}"] + world.events
    return r["ok"] and r["code_ran"], lines


def a3(s):
    steps = [("sagemaker:CreateModel", twin.arn_sm("model", "tsg-summariser-hotfix"), {"sagemaker:NetworkIsolation": "false"}),
             ("sagemaker:CreateEndpointConfig", twin.arn_sm("endpoint-config", "tsg-summariser-hotfix"), {}),
             ("sagemaker:UpdateEndpoint", EP, {})]
    lines, all_ok = [], True
    for action, res, extra in steps:
        ok, why = twin.decide(s, "ds-bob", action, res, extra)
        lines.append(f"ds-bob {action.split(':')[1]} on {res.rsplit(':', 1)[1]}: {_say(ok, why)}")
        all_ok &= ok
    return all_ok, lines


def a4(s):
    ok, why = twin.decide(s, "ds-bob", "sagemaker:UpdateModelPackage", C["model_package_arn_prefix"] + "3")
    return ok, [f"ds-bob registered version 3, then approves it himself: {_say(ok, why)}"]


def a5(s):
    r = twin.container_reach(s)
    return r["internet"], [f"code in the container posts a ticket to https://{C['attacker_host']}: "
                           + ("sent" if r["internet"] else "blocked") + f" ({r['why']})"]


def a6(s):
    r = twin.container_reach(s)
    if not r["credentials"]:
        return False, [f"code in the container asks for the execution role's credentials: none ({r['why']})"]
    ok, why = twin.decide(s, "tsg-summariser-exec", "s3:GetObject", ANALYTICS_OBJECT)
    return ok, [f"code in the container reads the analytics team's export with the execution role: {_say(ok, why)}"]


def a7(s):
    ok, why = twin.decide(s, "tsg-helpdesk-app", "sagemaker:InvokeEndpoint", EP, via_vpce=False)
    return ok, [f"the app's leaked keys, used from a laptop on the internet: {_say(ok, why)}"]


def a8(s):
    ok, why = twin.decide(s, "collector-role", "sagemaker:InvokeEndpoint", C["outsider_endpoint_arn"], via_vpce=True)
    return ok, [f"someone in the VPC uses their OWN account's keys, through AnyCompany's runtime endpoint, to send tickets to their endpoint: {_say(ok, why)}"]


def a9(s):
    ssm = [v for v in s.endpoint_config["ProductionVariants"] if v.get("EnableSSMAccess")]
    if not ssm:
        return False, ["EnableSSMAccess is off on every variant: no shell to open"]
    if s.model.get("EnableNetworkIsolation"):
        return False, ["network isolation is on: AWS says you can't start an SSM session for that container"]
    ok, why = twin.decide(s, "ds-bob", "ssm:StartSession", EP)
    return ok, [f"ds-bob starts an SSM session in the production container: {_say(ok, why)}"]


def a10(s):
    r = twin.studio_reach(s)
    return r["internet"], [f"a notebook uploads a ticket export to https://{C['attacker_host']}: " + ("sent" if r["internet"] else "blocked") + f" ({r['why']})"]


def a11(s):
    ok, why = twin.decide(s, "ds-bob", "sagemaker:CreatePresignedDomainUrl", twin.arn_sm("user-profile", f"{C['domain_id']}/alice"))
    return ok, [f"ds-bob creates a presigned Studio URL for alice's profile: {_say(ok, why)}"]


def a12(s):
    ok1, why1 = twin.decide(s, "ds-bob", "iam:PassRole", PROD_ROLE, PASS)
    ok2, why2 = twin.decide(s, "ds-bob", "sagemaker:CreateProcessingJob", twin.arn_sm("processing-job", "ds-bob-scratch"))
    ok3, why3 = twin.decide(s, "tsg-summariser-exec", "s3:GetObject", ANALYTICS_OBJECT)
    lines = [f"ds-bob passes tsg-summariser-exec: {_say(ok1, why1)}", f"ds-bob starts a processing job: {_say(ok2, why2)}"]
    if ok1 and ok2:
        lines.append(f"the job reads the analytics export as tsg-summariser-exec: {_say(ok3, why3)}")
    return ok1 and ok2 and ok3, lines


def a13(s):
    env = twin.effective_container(s).get("Environment", {})
    secrets = [k for k in env if "TOKEN" in k.upper() or "SECRET" in k.upper() or "KEY" in k.upper()]
    ok, why = twin.decide(s, "ds-bob", "sagemaker:DescribeModel", twin.arn_sm("model", s.model["ModelName"]))
    if not secrets:
        return False, ["the model's Environment holds no secrets"]
    return ok, [f"ds-bob calls DescribeModel and reads {', '.join(secrets)}: {_say(ok, why)}"]


def a14(s):
    lines, worked = [], False
    for label, extra in (("EnableNetworkIsolation left out", {}), ("EnableNetworkIsolation false", {"sagemaker:NetworkIsolation": "false"})):
        ok, why = twin.decide(s, "tsg-platform-admin", "sagemaker:CreateModel", twin.arn_sm("model", "quick-test"), extra)
        lines.append(f"tsg-platform-admin CreateModel ({label}, no VpcConfig): {_say(ok, why)}")
        worked |= ok
    return worked, lines


def a15(s):
    ok, why = twin.decide(s, "tsg-model-approver", "sagemaker:UpdateModelPackage", C["model_package_arn_prefix"] + "3")
    lines = [f"the ML lead approves version 3 in a hurry (pickle weights, no licence, no hashes): {_say(ok, why)}"]
    if not ok:
        return False, lines
    if s.app.get("approval_gate"):
        pkg = twin.package(s, 3)
        files = twin.World(s).files(pkg["InferenceSpecification"]["Containers"][0]["ModelDataSource"]["S3DataSource"]["S3Uri"])
        reasons = gate.check_before_approval(pkg, files, "tsg-model-approver", C)
        lines.append("approval gate: " + ("refused: " + "; ".join(reasons) if reasons else "passed it"))
        return not reasons, lines
    lines.append("no approval gate: the status is now Approved and the pipeline deploys it")
    return True, lines


ATTACKS = [
    ("A1", "Booby-trapped model file: the weights are a pickle, and loading it runs code in the container", "15.3", a1),
    ("A2", "Artifact swap after approval: a data scientist overwrites the files the endpoint loads", "15.3", a2),
    ("A3", "Unapproved model to production: a hotfix model straight from a notebook onto the live endpoint", "15.3", a3),
    ("A4", "Self-approval: the author approves their own model version", "15.3", a4),
    ("A5", "Data out of the container: code in the model container posts tickets to the internet", "15.2", a5),
    ("A6", "Container credentials: code in the container reads another team's bucket with the execution role", "15.2", a6),
    ("A7", "Stolen app keys: InvokeEndpoint from the internet", "15.3", a7),
    ("A8", "Outsider through the private endpoint: someone else's account sends data out via AnyCompany's VPC endpoint", "15.3", a8),
    ("A9", "Shell into the endpoint: SSM access on the production container", "15.3", a9),
    ("A10", "Studio exfiltration: a notebook uploads data to the internet", "15.2", a10),
    ("A11", "Studio impersonation: a presigned URL for someone else's profile", "15.2", a11),
    ("A12", "PassRole escalation: a job started by a data scientist runs as the production role", "15.2", a12),
    ("A13", "Secret in the model definition: DescribeModel shows the Hugging Face token", "15.2", a13),
    ("A14", "Isolation dropped: an admin's quick test creates a model with no isolation and no VPC", "15.2", a14),
    ("A15", "Approval in a hurry: the approver approves a version that fails every check", "15.3", a15),
]


# --------------------------------------------------------------------------------------------------------------------
# Normal requests
# --------------------------------------------------------------------------------------------------------------------
def n1(s):
    ok, why = twin.decide(s, "tsg-helpdesk-app", "sagemaker:InvokeEndpoint", EP, via_vpce=True)
    r = twin.load_model(s, twin.World(s))
    return ok and r["ok"], [f"the Helpdesk asks for a ticket summary through the VPC endpoint: {_say(ok, why)}; endpoint: {r['why']}"]


def n2(s):
    ctx = {"sagemaker:NetworkIsolation": "true", "sagemaker:VpcSubnets": ["subnet-0a1b2c3d4e5f60011", "subnet-0a1b2c3d4e5f60012"],
           "sagemaker:VpcSecurityGroupIds": ["sg-0a1b2c3d4e5f60021"]}
    steps = [twin.decide(s, "tsg-ci-deployer", "sagemaker:CreateModel", twin.arn_sm("model", "tsg-summariser-v4"), ctx),
             twin.decide(s, "tsg-ci-deployer", "iam:PassRole", PROD_ROLE, PASS),
             twin.decide(s, "tsg-ci-deployer", "sagemaker:UpdateEndpoint", EP)]
    return all(ok for ok, _ in steps), [f"the pipeline deploys version 4 (isolated, in the VPC): {', '.join(_say(ok, w) for ok, w in steps)}"]


def n3(s):
    ok, why = twin.decide(s, "tsg-model-approver", "sagemaker:UpdateModelPackage", C["model_package_arn_prefix"] + "4")
    lines = [f"the ML lead approves clean version 4: {_say(ok, why)}"]
    if ok and s.app.get("approval_gate"):
        pkg = twin.package(s, 4)
        files = twin.World(s).files(pkg["InferenceSpecification"]["Containers"][0]["ModelDataSource"]["S3DataSource"]["S3Uri"])
        reasons = gate.check_before_approval(pkg, files, "tsg-model-approver", C)
        lines.append("approval gate: " + ("refused: " + "; ".join(reasons) if reasons else "passed"))
        ok = not reasons
    return ok, lines


def n4(s):
    ok, why = twin.decide(s, "ds-alice", "sagemaker:CreatePresignedDomainUrl", twin.arn_sm("user-profile", f"{C['domain_id']}/alice"))
    return ok, [f"alice opens her own Studio profile: {_say(ok, why)}"]


def n5(s):
    ok1, w1 = twin.decide(s, "ds-alice", "iam:PassRole", DS_ROLE, PASS)
    ok2, w2 = twin.decide(s, "ds-alice", "sagemaker:CreateProcessingJob", twin.arn_sm("processing-job", "ds-alice-eval"))
    return ok1 and ok2, [f"alice runs an evaluation job with the data science role: {_say(ok1, w1)}, {_say(ok2, w2)}"]


def n6(s):
    r = twin.load_model(s, twin.World(s))
    return r["ok"], [f"the endpoint starts and loads its model: {r['why']}"]


NORMAL = [("N1", "The Helpdesk gets a ticket summary", n1), ("N2", "The pipeline deploys an approved version", n2),
          ("N3", "The ML lead approves a clean version", n3), ("N4", "A data scientist opens her own Studio profile", n4),
          ("N5", "A data scientist runs a job with the data science role", n5), ("N6", "The endpoint starts", n6)]


def run_case(case, setup):
    cid, title, *rest = case
    fn = rest[-1]
    worked, lines = fn(setup)
    return {"id": cid, "title": title, "worked": worked, "works": worked, "lines": lines}


def run_suite(setup) -> dict:
    s = setup if isinstance(setup, twin.Setup) else twin.Setup(setup)
    return {"attacks": [run_case(a, s) for a in ATTACKS], "normal": [run_case(n, s) for n in NORMAL]}


def only(setup_name, cid) -> int:
    """One case, every step, read from the top (README Step 1b)."""
    s = twin.Setup(setup_name)
    case = next((c for c in ATTACKS + NORMAL if c[0].lower() == cid.lower()), None)
    if case is None:
        print(f"no case {cid}: choose A1 to A{len(ATTACKS)} or N1 to N{len(NORMAL)}")
        return 2
    r = run_case(case, s)
    attack = case in ATTACKS
    print(f"setup: {setup_name}   (twin.py, offline: nothing is sent to AWS)")
    print(f"group: {'attack (it should be blocked)' if attack else 'normal request (it must keep working)'}\n")
    verdict = ("WORKED " if r["worked"] else "blocked") if attack else ("works  " if r["works"] else "BROKEN ")
    print(f"  {r['id']:<4} {verdict}  {r['title']}")
    for line in r["lines"]:
        print(f"         . {line}")
    return 0


def main(argv):
    if "--only" in argv:
        i = argv.index("--only")
        rest = [a for j, a in enumerate(argv) if j not in (i, i + 1)]
        if len(rest) != 1 or i + 1 >= len(argv):
            print(__doc__)
            return 2
        return only(rest[0], argv[i + 1])
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
            shown = [next((x for x in r["lines"] if "DENIED" in x or "blocked" in x or "refused" in x or ": none" in x
                           or x.startswith(("no ", "network isolation", "EnableSSMAccess", "the model's"))), r["lines"][-1])]
        for line in shown:
            print(f"         . {line}")
    print()
    for r in res["normal"]:
        print(f"  {r['id']:<4} {'works  ' if r['works'] else 'BROKEN '}  {r['title']}")
    bad = [r["id"] for r in res["attacks"] if r["worked"]]
    good = sum(r["works"] for r in res["normal"])
    print(f"\nAttacks that worked: {len(bad)} of {len(ATTACKS)}  ({', '.join(bad) or 'none'})   |   normal requests that work: {good} of {len(NORMAL)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
