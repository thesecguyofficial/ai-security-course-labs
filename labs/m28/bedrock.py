"""
bedrock.py: writes the lab's model invocation logs, the way Amazon Bedrock model invocation logging would.

Record fields follow AWS's invocation-logging page (schemaType "ModelInvocationLog", schemaVersion "1.0", timestamp,
accountId, region, requestId, operation, modelId, identity.arn, requestMetadata, input.inputBodyJson,
input.inputTokenCount, output.outputBodyJson, output.outputTokenCount). Bodies are shaped like the Converse API and the
Titan Text Embeddings V2 API (inputText in, an `embedding` array out).

Lab stand-ins, said plainly:
- One record per S3 object, under AWSLogs/<account>/BedrockModelInvocationLogs/<region>/YYYY/MM/DD/HH/. Real file
  names and batching differ: look at your own bucket.
- Bodies over 100 KB go to separate objects under a `data/` prefix (AWS: "Binary data or JSON bodies larger than 100
  KB will be uploaded as individual objects ... under the data prefix"). The pointer field in the record,
  `inputBodyS3Path`, is this lab's own name: the AWS page doesn't show the real one.
- With embeddingDataDeliveryEnabled false, this stand-in leaves the embedding arrays out of the record. Check what your
  real logs contain after changing the setting (GUIDED-BUILD.md, Step 5).
- Token counts are rough (words x 1.3); no model runs.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import random

import lab
from s3 import LocalS3

LARGE = 100 * 1024


def _tokens(text: str) -> int:
    return max(1, int(len(text.split()) * 1.3))


def _vector(text: str, dims: int = 256) -> list[float]:
    rnd = random.Random(hashlib.sha256(text.encode()).digest())
    return [round(rnd.uniform(-0.12, 0.12), 6) for _ in range(dims)]


def _complaint_file() -> str:
    """A pasted document of about 120 KB: delivery notes with the customer's details repeated inside."""
    lines = []
    for i in range(1, 1300):
        lines.append(f"Delivery note {i:04d}: parcel scanned at depot 7, route B, no exception recorded.")
        if i % 400 == 0:
            lines.append("Customer on file: Lee Moreau, lee.moreau@customer.example, phone 617-555-0119.")
    return "\n".join(lines)


def records(calls: list[dict], setup: dict) -> list[tuple[dict, dict | None]]:
    """Build (record, large_body_or_None) pairs for each call."""
    cfg = setup["logging"]
    out = []
    for c in calls:
        when = lab.NOW - dt.timedelta(days=c["days_ago"])
        request_id = str(hashlib.sha256(c["id"].encode()).hexdigest()[:8]) + "-lab0-4m28-" + c["id"] + "-0000000000"
        rec = {"schemaType": "ModelInvocationLog", "schemaVersion": "1.0", "timestamp": lab.iso(when),
               "accountId": lab.ACCOUNT, "region": lab.REGION, "requestId": request_id,
               "operation": c["operation"], "modelId": c["model"],
               "identity": {"arn": f"arn:aws:sts::{lab.ACCOUNT}:assumed-role/{c['role']}/session-{c['id']}"},
               "requestMetadata": c.get("metadata", {})}
        large = None
        if c["operation"] == "InvokeModel":   # Titan Text Embeddings V2
            vec = _vector(c["input"])
            rec["input"] = {"inputContentType": "application/json",
                            "inputBodyJson": {"inputText": c["input"], "dimensions": 256, "normalize": True},
                            "inputTokenCount": _tokens(c["input"])}
            body = {"inputTextTokenCount": _tokens(c["input"])}
            if cfg.get("embeddingDataDeliveryEnabled"):
                body = {"embedding": vec, "inputTextTokenCount": _tokens(c["input"]), "embeddingsByType": {"float": vec}}
            rec["output"] = {"outputContentType": "application/json", "outputBodyJson": body, "outputTokenCount": 0}
        else:                                  # Converse
            text = c["input"] + ("\n\n" + _complaint_file() if c.get("large_input") else "")
            in_body = {"messages": [{"role": "user", "content": [{"text": text}]}],
                       "inferenceConfig": {"maxTokens": 512}}
            out_body = {"output": {"message": {"role": "assistant", "content": [{"text": c["output"]}]}},
                        "stopReason": "end_turn",
                        "usage": {"inputTokens": _tokens(text), "outputTokens": _tokens(c["output"]),
                                  "totalTokens": _tokens(text) + _tokens(c["output"])}}
            rec["input"] = {"inputContentType": "application/json", "inputTokenCount": _tokens(text)}
            if len(json.dumps(in_body).encode()) > LARGE:
                large = in_body
            else:
                rec["input"]["inputBodyJson"] = in_body
            rec["output"] = {"outputContentType": "application/json", "outputBodyJson": out_body,
                             "outputTokenCount": _tokens(c["output"])}
        out.append((rec, large))
    return out


def deliver(s3: LocalS3, calls: list[dict], setup: dict) -> list[str]:
    """Write every record into the raw bucket as the Bedrock service principal. Returns the keys written."""
    bucket = setup["logging"]["s3Config"]["bucketName"]
    prefix = setup["logging"]["s3Config"].get("keyPrefix", "")
    keys = []
    for rec, large in records(calls, setup):
        when = lab.parse_time(rec["timestamp"])
        base = f"{prefix}{lab.LOG_PREFIX}{lab.REGION}/"
        if large is not None:
            data_key = f"{base}data/{rec['requestId']}-input.json.gz"
            s3.put_object(bucket, data_key, json.dumps(large).encode(), lab.BEDROCK, when)
            rec["input"]["inputBodyS3Path"] = f"s3://{bucket}/{data_key}"
            keys.append(data_key)
        key = f"{base}{when:%Y/%m/%d/%H}/{rec['requestId']}.json.gz"
        s3.put_object(bucket, key, json.dumps(rec).encode(), lab.BEDROCK, when)
        keys.append(key)
    return keys


def load_calls(*files: str) -> list[dict]:
    calls = []
    for f in files:
        calls += json.loads((lab.DATA / f).read_text())["calls"]
    return calls
