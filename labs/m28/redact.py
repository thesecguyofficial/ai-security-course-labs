"""
redact.py: the redaction pipeline. In AWS this is a Lambda function behind an S3 event on the raw-log bucket
(GUIDED-BUILD.md). Here it is a function the pipeline calls once for every raw object.

It reads each raw record as the redactor role, replaces what its detectors find, and writes the result to the
redacted bucket, encrypted under that bucket's key. What it looks at, what it does with a match and what it does with
embeddings and large bodies all come from the setup's pipeline.json ("redactor") and identifiers.json.

Two ways to replace a value:
- "label":  dana.reyes@customer.example -> [EMAIL_ADDRESS]
- "token":  dana.reyes@customer.example -> [EMAIL_ADDRESS:4f1c09ab]  (HMAC-SHA256 of the lower-cased value with a
            tokenisation key that only the pipeline holds). Same value, same token: investigators can still say "the
            same customer wrote three times" without seeing who. Lab shortcut: the key is a file in state/; in AWS it
            belongs in Secrets Manager, readable by the redactor role only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re

import detect
import lab
from s3 import LocalS3

_INPUT_ONLY = re.compile(r"^\$\.input\.inputBodyJson\.(messages\[\d+\]\.content\[\d+\]\.text|inputText)$")


def tokenisation_key() -> bytes:
    p = lab.state_dir() / "tokenisation.key"
    if not p.exists():
        p.write_bytes(os.urandom(32))
    return p.read_bytes()


def token(kind: str, value: str) -> str:
    digest = hmac.new(tokenisation_key(), value.strip().lower().encode(), hashlib.sha256).hexdigest()[:8]
    return f"[{kind}:{digest}]"


def _crm_names() -> list[str]:
    return [c["name"] for c in json.loads((lab.DATA / "crm.json").read_text())["customers"]]


def redact_text(text: str, setup: dict) -> tuple[str, list[str]]:
    cfg, ids = setup["redactor"], setup["identifiers"]
    custom = (ids.get("custom_data_identifiers", []) if cfg.get("use_custom_ids") else []) + ids.get("redactor_patterns", [])
    matches = detect.find(text, use_managed=cfg.get("use_managed", False), custom_ids=custom,
                          known_names=_crm_names() if cfg.get("crm_names") else [])
    kinds = []
    for m in sorted(matches, key=lambda m: m.start, reverse=True):
        repl = token(m.type, m.value) if cfg.get("mode") == "token" else f"[{m.type}]"
        text = text[:m.start] + repl + text[m.end:]
        kinds.append(m.type)
    return text, kinds


def _set(doc, path: str, value):
    parts = re.findall(r"\.([^.\[]+)|\[(\d+)\]", path[1:])
    cur = doc
    for name, idx in parts[:-1]:
        cur = cur[name] if name else cur[int(idx)]
    name, idx = parts[-1]
    if name:
        cur[name] = value
    else:
        cur[int(idx)] = value


def redact_record(doc: dict, setup: dict) -> tuple[dict, dict]:
    """Return (redacted copy, report) for one invocation-log record or large body."""
    cfg = setup["redactor"]
    doc = json.loads(json.dumps(doc))
    report = {"replaced": [], "vectors_removed": 0}
    if cfg.get("strip_vectors"):
        for path in list(detect.vector_paths(doc)):
            _set(doc, path, {"removed": "embedding vector", "dimensions": "see dimensions in the request"})
            report["vectors_removed"] += 1
    for path, text in list(detect.walk_strings(doc)):
        if cfg.get("fields") == "input_only" and not _INPUT_ONLY.match(path):
            continue
        if path.startswith("$.identity") or path in ("$.requestId", "$.modelId", "$.timestamp", "$.accountId",
                                                        "$.region", "$.operation", "$.schemaType", "$.schemaVersion"):
            continue   # the metadata investigators need; none of it holds customer data
        new, kinds = redact_text(text, setup)
        if kinds:
            _set(doc, path, new)
            report["replaced"] += kinds
    return doc, report


def run(s3: LocalS3, setup: dict) -> dict:
    """Process every current raw object into the redacted bucket. Returns a small report."""
    cfg = setup["redactor"]
    raw, red = lab.RAW_BUCKET, lab.REDACTED_BUCKET
    totals = {"records": 0, "large_bodies": 0, "copied_unredacted": 0, "replaced": 0, "vectors_removed": 0}
    for key in s3.list_objects(raw):
        is_large = "/data/" in key
        body = s3.get_object(raw, key, lab.REDACTOR)
        when = lab.parse_time(s3.object_info(raw, key)["last_modified"])
        if is_large and cfg.get("large_data") == "copy":
            # First-draft habit: "copy the big ones across so the analytics view is complete".
            s3.put_object(red, key, body, lab.REDACTOR, when)
            totals["copied_unredacted"] += 1
            continue
        if is_large and cfg.get("large_data") == "skip":
            continue
        doc, rep = redact_record(json.loads(body), setup)
        if "inputBodyS3Path" in doc.get("input", {}):
            doc["input"]["inputBodyS3Path"] = doc["input"]["inputBodyS3Path"].replace(raw, red)
        s3.put_object(red, key, json.dumps(doc).encode(), lab.REDACTOR, when)
        totals["large_bodies" if is_large else "records"] += 1
        totals["replaced"] += len(rep["replaced"])
        totals["vectors_removed"] += rep["vectors_removed"]
    return totals
