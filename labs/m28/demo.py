"""
demo.py: two short demonstrations for the README.

    python3 demo.py two-locks     # make two-locks: loosen the raw bucket's policy by mistake; the raw key still says no
    python3 demo.py tokens        # make tokens: the same customer gets the same token in every redacted record
"""

from __future__ import annotations

import json
import sys

import detect
import lab
import pipeline
import redact
from kms import AccessDenied


def two_locks():
    env = pipeline.build("hardened")
    s3 = env["s3"]
    key = s3.list_objects(lab.RAW_BUCKET)[0]
    print(f"raw object: {key.rsplit('/', 1)[-1]}  (account IDs print as <account>)")
    try:
        s3.get_object(lab.RAW_BUCKET, key, lab.ANALYST)
    except AccessDenied as exc:
        print(f"1. tsg-analytics, bucket policy as built:  REFUSED  {lab.hide(str(exc))}")
    # A mistake someone could make: replace the raw bucket's policy with one that lets analysts read.
    cfg = s3.config(lab.RAW_BUCKET)
    cfg["policy"]["Statement"] = [st for st in cfg["policy"]["Statement"] if st["Sid"] != "NoAnalystsOnRaw"]
    cfg["policy"]["Statement"].append({"Sid": "OopsAnalystsToo", "Effect": "Allow", "Principal": {"AWS": [lab.ANALYST]},
                                       "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{lab.RAW_BUCKET}/*"})
    s3.create_bucket(cfg)
    try:
        s3.get_object(lab.RAW_BUCKET, key, lab.ANALYST)
        print("2. after the bucket-policy mistake:        READ (the key policy should have stopped this)")
    except AccessDenied as exc:
        print(f"2. after the bucket-policy mistake:        REFUSED  {lab.hide(str(exc))}")
    print("\nThe refusal is in the trail (state/cloudtrail.jsonl), last event:")
    last = [json.loads(l) for l in (lab.state_dir() / "cloudtrail.jsonl").read_text().splitlines()][-1]
    keep = {k: last[k] for k in ("eventSource", "eventName", "errorCode")}
    keep["userIdentity.arn"] = last["userIdentity"]["arn"]
    keep["requestParameters.keyId"] = last["requestParameters"]["keyId"]
    keep["requestParameters.encryptionContext"] = last["requestParameters"]["encryptionContext"]
    print(lab.hide(json.dumps(keep, indent=2)))


def tokens():
    env = pipeline.build("hardened")
    s3 = env["s3"]
    dana = redact.token("EMAIL_ADDRESS", "dana.reyes@customer.example")
    for key in s3.list_objects(lab.REDACTED_BUCKET):
        if "/data/" in key:
            continue
        rec = json.loads(s3.get_object(lab.REDACTED_BUCKET, key, lab.ANALYST))
        for path, text in detect.walk_strings(rec):
            if dana in text:
                where = {"$.input": "request", "$.output": "response", "$.requestMetadata": "metadata"}.get(path.split(".")[0] + "." + path.split(".")[1].split("[")[0], path)
                print(f"{rec['timestamp']}  {rec['identity']['arn'].split('/')[1]:<17} {where:<9} {text}")
    print(f"\n{dana} is the same customer each time. Who it is stays with the tokenisation key.")


if __name__ == "__main__":
    {"two-locks": two_locks, "tokens": tokens}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
