"""
hunt.py: investigate a morning of Cloud Audit Logs from ExampleCo's production project. Offline, standard library only.

    python3 hunt.py              # make hunt

Q1. Uploads and deploys not made by the pipeline (UploadModel or DeployModel by anyone but tsg-ci-deployer)
Q2. Self-promotion (MergeVersionAliases that puts "prod" on a version uploaded by the same principal)
Q3. New user-managed service account keys (CreateServiceAccountKey)
Q4. Predict calls that didn't come from ExampleCo's network   (challenge 3: you write it)

Q1 to Q3 use Admin Activity audit logs, which are always written. Q4 needs Data Access audit logs for
aiplatform.googleapis.com, which are off until you turn them on (lesson 15.4).
"""

from __future__ import annotations

import json
import pathlib

import twin

HERE = pathlib.Path(__file__).resolve().parent
C = twin.COMPANY
PIPELINE = twin.sa_email("tsg-ci-deployer")


def load(path: pathlib.Path = HERE / "data" / "incident" / "audit-logs.json") -> list[dict]:
    return json.loads(path.read_text())["entries"]


def method(e: dict) -> str:
    """google.cloud.aiplatform.v1.ModelService.UploadModel -> UploadModel"""
    return e["protoPayload"]["methodName"].rsplit(".", 1)[-1]


def who(e: dict) -> str:
    return twin.name_of(e["protoPayload"]["authenticationInfo"]["principalEmail"])


def outside_pipeline(log: list[dict]) -> list[dict]:
    out = []
    for e in log:
        if method(e) in ("UploadModel", "DeployModel") and e["protoPayload"]["authenticationInfo"]["principalEmail"] != PIPELINE:
            req = e["protoPayload"].get("request", {})
            what = req.get("model", {}).get("artifactUri") or req.get("deployedModel", {}).get("model", "")
            out.append({"time": e["timestamp"], "who": who(e), "action": method(e), "what": what})
    return out


def self_promotions(log: list[dict]) -> list[dict]:
    uploaded_by = {e["protoPayload"].get("response", {}).get("_lab_version_id"): e["protoPayload"]["authenticationInfo"]["principalEmail"]
                   for e in log if method(e) == "UploadModel"}
    out = []
    for e in log:
        if method(e) != "MergeVersionAliases":
            continue
        req = e["protoPayload"]["request"]
        version = req["name"].rsplit("@", 1)[-1]
        if "prod" in req.get("versionAliases", []) and uploaded_by.get(version) == e["protoPayload"]["authenticationInfo"]["principalEmail"]:
            out.append({"time": e["timestamp"], "who": who(e), "version": version})
    return out


def new_keys(log: list[dict]) -> list[dict]:
    out = []
    for e in log:
        if method(e) == "CreateServiceAccountKey":
            sa = e["protoPayload"]["request"]["name"].rsplit("/", 1)[-1]
            out.append({"time": e["timestamp"], "who": who(e), "for": twin.name_of(sa), "key": e["protoPayload"].get("response", {}).get("name", "")})
    return out


def find_outside_predictions(log: list[dict]) -> list[dict]:
    """Challenge 3 (lesson 15.4): Predict (or RawPredict) calls on ExampleCo's endpoint whose requestMetadata has no
    callerNetwork, or a callerNetwork that isn't C["caller_network"]. Return one dict per call with "time", "who"
    (the lab's short name, use who(e)), "source_ip" and "key" (authenticationInfo.serviceAccountKeyName, or "" if
    none), oldest first."""
    raise NotImplementedError("challenge 3: write find_outside_predictions()")


def main():
    log = load()
    print("Q1. Uploads and deploys not made by the pipeline")
    for x in outside_pipeline(log):
        print(f"   {x['time']}  {x['action']:<12} by {x['who']:<9} {x['what']}")
    print("\nQ2. Self-promotion: prod alias moved by the principal who uploaded that version")
    for x in self_promotions(log):
        print(f"   {x['time']}  version {x['version']} promoted to prod by {x['who']}, who uploaded it")
    print("\nQ3. New user-managed service account keys")
    for x in new_keys(log):
        print(f"   {x['time']}  {x['who']} created a key for {x['for']}: {x['key'].rsplit('/', 1)[-1]}")
    print("\nQ4. Predict calls from outside ExampleCo's network (challenge 3)")
    try:
        rows = find_outside_predictions(log)
        for x in rows:
            print(f"   {x['time']}  {x['who']:<17} from {x['source_ip']:<14} key {x['key'].rsplit('/', 1)[-1] or '-'}")
        if not rows:
            print("   none found")
    except NotImplementedError as e:
        print(f"   not written yet: {e}")


if __name__ == "__main__":
    main()
