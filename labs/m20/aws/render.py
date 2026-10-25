"""
aws/render.py: write the IAM and CloudTrail documents for the guided build, for YOUR account (GUIDED-BUILD.md).

    python3 aws/render.py --account 123456789012 --region us-east-1 --launcher-arn <your role or user ARN> --bucket <name>

Reads aws/setups/hardened.json (the setup the checker passes with 0 findings), swaps in your account, Region and
launcher, and writes aws/out/: trust-<role>.json, policy-<role>.json, selectors.json, bucket-policy.json.
aws/out/ is git-ignored. Nothing here talks to AWS.
"""
import argparse
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent

p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
p.add_argument("--account", required=True)
p.add_argument("--region", default="us-east-1")
p.add_argument("--launcher-arn", required=True, help="the IAM user or role you run the AWS CLI as (aws sts get-caller-identity)")
p.add_argument("--bucket", required=True, help="the S3 bucket name for the trail")
p.add_argument("--trail", default="tsg-m20-trail")
a = p.parse_args()

setup = json.loads((HERE / "setups" / "hardened.json").read_text())
text = json.dumps(setup).replace("111122223333", a.account).replace("us-east-1", a.region)
setup = json.loads(text)
out = HERE / "out"
out.mkdir(exist_ok=True)
for role, r in setup["roles"].items():
    trust = r["trust"]
    for st in trust["Statement"]:
        st["Principal"] = {"AWS": a.launcher_arn}
        st["Action"] = ["sts:AssumeRole", "sts:SetSourceIdentity"]   # session tags not used in the guided build
    (out / f"trust-{role}.json").write_text(json.dumps(trust, indent=2) + "\n")
    (out / f"policy-{role}.json").write_text(json.dumps(r["policy"], indent=2) + "\n")
(out / "selectors.json").write_text(json.dumps(setup["cloudtrail"]["advanced_event_selectors"], indent=2) + "\n")
trail_arn = f"arn:aws:cloudtrail:{a.region}:{a.account}:trail/{a.trail}"
bucket_policy = {"Version": "2012-10-17", "Statement": [
    {"Sid": "AWSCloudTrailAclCheck", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
     "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{a.bucket}",
     "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}}},
    {"Sid": "AWSCloudTrailWrite", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
     "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{a.bucket}/AWSLogs/{a.account}/*",
     "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceArn": trail_arn}}}]}
(out / "bucket-policy.json").write_text(json.dumps(bucket_policy, indent=2) + "\n")
for f in sorted(out.iterdir()):
    print("wrote", f.relative_to(HERE.parent))
