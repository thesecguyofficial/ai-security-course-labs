"""
cloud/gate.py: the deploy gate against YOUR AWS sandbox account (GUIDED-BUILD.md). Optional; costs a few cents.

    python3 cloud/gate.py --bucket $BUCKET --release 1.1.0-hardened --setup hardened
    python3 cloud/gate.py --bucket $BUCKET --release 1.1.0-hardened --setup first-draft     # the fail-open version
    python3 cloud/gate.py --bucket $BUCKET --teardown

What it does, in order:
    1. lists the S3 object versions under tsg-guard/<release>/ (so the evidence names the exact bytes it checked)
    2. downloads them into a FRESH folder, cloud/out/<release>/ (never verify a copy that existed before)
    3. runs deploy.gate() from the lab on that folder: the same checks as the offline lab
    4. only if every check passed: CreateModelPackage (PendingManualApproval, evidence in CustomerMetadataProperties),
       then UpdateModelPackage to Approved, with the reason in ApprovalDescription
If anything fails it exits 1 and calls nothing in SageMaker AI. It uses the AWS CLI v2 (no extra Python packages).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import deploy  # noqa: E402
import lab     # noqa: E402

GROUP = "tsg-guard-lab"
OUT = lab.HERE / "cloud" / "out"


def aws(region: str, *args: str) -> dict:
    cmd = ["aws", "--region", region, "--output", "json", *args]
    print("  $ " + " ".join(cmd))
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise SystemExit(f"aws failed ({res.returncode}): {res.stderr.strip()[:400]}")
    return json.loads(res.stdout) if res.stdout.strip() else {}


def gate(a) -> int:
    prefix = f"tsg-guard/{a.release}/"
    versions = aws(a.region, "s3api", "list-object-versions", "--bucket", a.bucket, "--prefix", prefix)
    latest = {v["Key"][len(prefix):]: v["VersionId"] for v in versions.get("Versions", []) if v.get("IsLatest")}
    if not latest:
        print(f"REFUSED: nothing under s3://{a.bucket}/{prefix}")
        return 1
    local = OUT / a.release
    if local.exists():
        shutil.rmtree(local)
    aws(a.region, "s3", "cp", "--recursive", f"s3://{a.bucket}/{prefix}", str(local))

    print(f"GATE [{a.setup}] on the copy downloaded from S3:")
    try:
        evidence = deploy.gate(a.setup, local)
    except deploy.Refused as e:
        print(f"  REFUSED: {e}\n  nothing was registered in SageMaker AI")
        return 1
    request = deploy.model_package_request(local, evidence)
    request["InferenceSpecification"]["Containers"][0]["ModelDataSource"]["S3DataSource"]["S3Uri"] = \
        f"s3://{a.bucket}/{prefix}model/"
    request["CustomerMetadataProperties"]["s3-version-weights"] = latest.get("model/model.safetensors", "?")
    request["CustomerMetadataProperties"]["gate-setup"] = a.setup
    OUT.mkdir(parents=True, exist_ok=True)
    body = OUT / "create-model-package.json"
    lab.write_json(body, request)
    arn = aws(a.region, "sagemaker", "create-model-package", "--cli-input-json", f"file://{body}")["ModelPackageArn"]
    aws(a.region, "sagemaker", "update-model-package", "--model-package-arn", arn,
        "--model-approval-status", "Approved",
        "--approval-description", f"M25 gate ({a.setup}): signature {evidence['verify']}, "
                                  f"{len(evidence['warnings'])} warning(s)")
    print(f"  REGISTERED and approved: {arn}")
    if evidence["warnings"]:
        print("  ...with warnings. This is what fail-open looks like in a real account. Delete it: make cloud-down")
    return 0


def teardown(a) -> int:
    pkgs = aws(a.region, "sagemaker", "list-model-packages", "--model-package-group-name", GROUP)
    for p in pkgs.get("ModelPackageSummaryList", []):
        aws(a.region, "sagemaker", "delete-model-package", "--model-package-name", p["ModelPackageArn"])
    aws(a.region, "sagemaker", "delete-model-package-group", "--model-package-group-name", GROUP)
    while True:
        v = aws(a.region, "s3api", "list-object-versions", "--bucket", a.bucket)
        objs = [{"Key": x["Key"], "VersionId": x["VersionId"]} for x in v.get("Versions", []) + v.get("DeleteMarkers", [])]
        if not objs:
            break
        OUT.mkdir(parents=True, exist_ok=True)
        batch = OUT / "delete.json"
        lab.write_json(batch, {"Objects": objs[:1000], "Quiet": True})
        aws(a.region, "s3api", "delete-objects", "--bucket", a.bucket, "--delete", f"file://{batch}")
    aws(a.region, "s3api", "delete-bucket", "--bucket", a.bucket)
    print("Done: model packages, the group, every object version and the bucket are deleted.")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--release", default="1.1.0-hardened")
    ap.add_argument("--setup", default="hardened")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--teardown", action="store_true")
    a = ap.parse_args()
    sys.exit(teardown(a) if a.teardown else gate(a))


if __name__ == "__main__":
    main()
