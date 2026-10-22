"""
TSG Helpdesk, M11 lab version: one question in, one answer out, through the bedrock-runtime VPC endpoint.

The function never logs the question or the answer itself: Bedrock model invocation logging does that, into a
KMS-encrypted log group that only investigators can read (lesson 11.4).
"""

import os

import boto3
from botocore.exceptions import ParamValidationError

SYSTEM = (
    "You are TSG Helpdesk, the IT helpdesk assistant for AnyCompany staff. Answer IT questions briefly. "
    "If a question is not about IT support, say you can only help with IT support."
)

client = boto3.client("bedrock-runtime")  # private DNS sends this to the VPC endpoint


def handler(event, context):
    question = str((event or {}).get("question", ""))[:2000]
    if not question:
        return {"error": "send {\"question\": \"...\"}"}
    request = {
        "modelId": os.environ["MODEL_ID"],
        "system": [{"text": SYSTEM}],
        "messages": [{"role": "user", "content": [{"text": question}]}],
        "inferenceConfig": {"maxTokens": int(os.environ.get("MAX_TOKENS", "300"))},
        # Shows up as requestMetadata in the invocation log, so you can filter by app (lesson 11.4).
        "requestMetadata": {"app": "tsg-helpdesk", "env": "m11-lab"},
    }
    try:
        resp = client.converse(**request)
    except ParamValidationError:
        # An older boto3 in the runtime may not know requestMetadata yet: retry without it.
        request.pop("requestMetadata")
        resp = client.converse(**request)
    text = "".join(part.get("text", "") for part in resp["output"]["message"]["content"])
    return {"answer": text, "usage": resp.get("usage", {})}
