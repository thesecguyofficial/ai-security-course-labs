"""
hunt.py: investigate a morning of CloudTrail records from AnyCompany's account. Offline, standard library only.

    python3 hunt.py              # make hunt

Q1. Models created outside the pipeline (CreateModel not by tsg-ci-deployer, or not from a registry version)
Q2. Self-approvals (UpdateModelPackage to Approved by the identity that registered the version)
Q3. Presigned Studio URLs for someone else's profile
Q4. InvokeEndpoint calls that did not come through AnyCompany's runtime VPC endpoint   (challenge 3: you write it)

Q1 to Q3 use management events, which CloudTrail records by default. Q4 needs data events for
AWS::SageMaker::Endpoint, which are off until a trail selects them (lesson 15.4).
"""

from __future__ import annotations

import json
import pathlib

import twin

HERE = pathlib.Path(__file__).resolve().parent
C = twin.COMPANY


def load(path: pathlib.Path = HERE / "data" / "incident" / "cloudtrail.json") -> list[dict]:
    return json.loads(path.read_text())["Records"]


def role_of(record: dict) -> str:
    """arn:aws:sts::111122223333:assumed-role/<role>/<session> -> <role>"""
    arn = record["userIdentity"]["arn"]
    return arn.split("/")[1] if ":assumed-role/" in arn else arn


def models_outside_pipeline(trail: list[dict]) -> list[dict]:
    out = []
    for r in trail:
        if r["eventName"] != "CreateModel" or r.get("errorCode"):
            continue
        req = r["requestParameters"]
        from_registry = "modelPackageName" in req.get("primaryContainer", {})
        if role_of(r) != "tsg-ci-deployer" or not from_registry:
            out.append({"time": r["eventTime"], "who": role_of(r), "model": req["modelName"],
                        "from_registry": from_registry, "isolation": req.get("enableNetworkIsolation", False)})
    return out


def self_approvals(trail: list[dict]) -> list[dict]:
    created_by = {r["responseElements"]["modelPackageArn"]: role_of(r) for r in trail
                  if r["eventName"] == "CreateModelPackage" and r.get("responseElements")}
    out = []
    for r in trail:
        req = r["requestParameters"]
        if r["eventName"] == "UpdateModelPackage" and req.get("modelApprovalStatus") == "Approved":
            arn = req["modelPackageArn"]
            if created_by.get(arn) == role_of(r):
                out.append({"time": r["eventTime"], "who": role_of(r), "version": arn.rsplit("/", 1)[1]})
    return out


def presigned_for_others(trail: list[dict]) -> list[dict]:
    out = []
    for r in trail:
        if r["eventName"] != "CreatePresignedDomainUrl":
            continue
        own = C["user_profiles"].get(role_of(r))
        target = r["requestParameters"]["userProfileName"]
        if target != own:
            out.append({"time": r["eventTime"], "who": role_of(r), "own_profile": own, "signed_in_as": target})
    return out


def find_outside_invocations(trail: list[dict]) -> list[dict]:
    """Challenge 3 (lesson 15.4): InvokeEndpoint data events on AnyCompany's endpoint whose vpcEndpointId is not
    AnyCompany's runtime endpoint (missing = the call came over the internet). Return one dict per call with
    "time", "who" and "source_ip", oldest first."""
    raise NotImplementedError("challenge 3: write find_outside_invocations()")


def main():
    trail = load()
    print("Q1. Models created outside the pipeline")
    for x in models_outside_pipeline(trail):
        print(f"   {x['time']}  {x['model']:<24} by {x['who']:<10} from registry: {x['from_registry']}   network isolation: {x['isolation']}")
    print("\nQ2. Self-approvals")
    for x in self_approvals(trail):
        print(f"   {x['time']}  version {x['version']} approved by {x['who']}, who registered it")
    print("\nQ3. Presigned Studio URLs for someone else's profile")
    for x in presigned_for_others(trail):
        print(f"   {x['time']}  {x['who']} (own profile: {x['own_profile']}) signed in as {x['signed_in_as']}")
    print("\nQ4. InvokeEndpoint calls that skipped the private endpoint (challenge 3)")
    try:
        rows = find_outside_invocations(trail)
        for x in rows:
            print(f"   {x['time']}  {x['who']:<18} from {x['source_ip']}")
        if not rows:
            print("   none found")
    except NotImplementedError as e:
        print(f"   not written yet: {e}")


if __name__ == "__main__":
    main()
