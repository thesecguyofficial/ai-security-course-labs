"""
redactor.py: the M28 guided build's redaction Lambda (Python 3.12 runtime, boto3 from the runtime, nothing else).

Trigger: S3 "ObjectCreated" events on the RAW bucket. For each new object it reads the invocation-log record(s),
replaces sensitive values with type labels, removes embedding vectors, and writes the result under the same key to
the REDACTED bucket (that bucket's default encryption applies its own KMS key). The detectors are the same simple
ones as the offline lab's detect.py; real detection is a best guess, so Macie checks the result (GUIDED-BUILD Step 7).

Environment variable: REDACTED_BUCKET.
"""

import gzip
import json
import os
import re
import urllib.parse

import boto3

s3 = boto3.client("s3")
REDACTED = os.environ["REDACTED_BUCKET"]

PATTERNS = [
    ("EMAIL_ADDRESS", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("TSG_CUSTOMER_ID", re.compile(r"TSG-CUST-\d{6}", re.IGNORECASE)),
    ("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS_SECRET_KEY", re.compile(r"(?i)(aws_secret_access_key\s*[=:]\s*)[A-Za-z0-9/+=]{40}")),
    ("PHONE_NUMBER", re.compile(r"(?<!\d)(?:\+1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)")),
]
CARD = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
KEEP = {"schemaType", "schemaVersion", "timestamp", "accountId", "region", "requestId", "operation", "modelId"}


def luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total, alt = total + d, not alt
    return total % 10 == 0


def redact_text(text):
    for name, rx in PATTERNS:
        if name == "AWS_SECRET_KEY":
            text = rx.sub(lambda m: m.group(1) + "[AWS_CREDENTIALS]", text)
        else:
            text = rx.sub(f"[{name}]", text)
    return CARD.sub(lambda m: "[CREDIT_CARD_NUMBER]" if luhn_ok(re.sub(r"[ -]", "", m.group())) else m.group(), text)


def scrub(obj, key=None):
    if isinstance(obj, dict):
        return {k: (v if k in KEEP or k == "identity" else scrub(v, k)) for k, v in obj.items()}
    if isinstance(obj, list):
        if len(obj) >= 32 and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in obj):
            return {"removed": "embedding vector", "length": len(obj)}
        return [scrub(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


def handler(event, context):
    for rec in event["Records"]:
        bucket = rec["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(rec["s3"]["object"]["key"])
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        gz = body[:2] == b"\x1f\x8b"
        text = gzip.decompress(body).decode() if gz else body.decode()
        lines = [l for l in text.splitlines() if l.strip()]
        try:
            docs, jsonl = [json.loads(text)], False
        except json.JSONDecodeError:
            docs, jsonl = [json.loads(l) for l in lines], True
        out = "\n".join(json.dumps(scrub(d)) for d in docs) if jsonl else json.dumps(scrub(docs[0]))
        data = gzip.compress(out.encode()) if gz else out.encode()
        s3.put_object(Bucket=REDACTED, Key=key, Body=data)
        print(json.dumps({"redacted": key, "records": len(docs)}))
    return {"ok": True}
