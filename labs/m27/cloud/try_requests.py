"""try_requests.py: the guided build's example requests (GUIDED-BUILD.md, Part D). Runs on YOUR laptop with YOUR
AWS credentials, against the Code Interpreter you created in YOUR sandbox account.

    python3 cloud/try_requests.py <code-interpreter-id> <lab-bucket> <other-bucket>

It starts one session, sends four short snippets with executeCode, prints what comes back and stops the session.
The snippets only list your own buckets and look up two names. Nothing is uploaded or sent anywhere.
"""

from __future__ import annotations

import sys

import boto3

REGION = "us-east-1"

SNIPPETS = {
    "R1 normal: list the lab bucket": """
import boto3
r = boto3.client("s3", region_name="us-east-1").list_objects_v2(Bucket="{lab}", MaxKeys=5)
print("keys:", [o["Key"] for o in r.get("Contents", [])])
""",
    "R2 allowed name: look up the S3 endpoint name": """
import socket
print(sorted({{a[4][0] for a in socket.getaddrinfo("s3.us-east-1.amazonaws.com", 443)}})[:2])
""",
    "R3 name not on the list: look up example.com": """
import socket
try:
    print(socket.getaddrinfo("example.com", 443))
except OSError as e:
    print("lookup failed:", e)
""",
    "R4 bucket outside the endpoint policy: list your other bucket": """
import boto3, botocore
try:
    boto3.client("s3", region_name="us-east-1").list_objects_v2(Bucket="{other}", MaxKeys=1)
    print("listed")
except botocore.exceptions.ClientError as e:
    print(e.response["Error"]["Code"], "-", e.response["Error"]["Message"])
""",
}


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 2
    ci_id, lab, other = argv[1:]
    dp = boto3.client("bedrock-agentcore", region_name=REGION)
    session = dp.start_code_interpreter_session(codeInterpreterIdentifier=ci_id, name="m27-guided",
                                                sessionTimeoutSeconds=900)["sessionId"]
    print("session", session)
    try:
        for label, code in SNIPPETS.items():
            resp = dp.invoke_code_interpreter(codeInterpreterIdentifier=ci_id, sessionId=session, name="executeCode",
                                              arguments={"language": "python", "code": code.format(lab=lab, other=other)})
            print(f"\n== {label}")
            for event in resp["stream"]:
                for item in event.get("result", {}).get("content", []):
                    if item.get("type") == "text":
                        print(item["text"])
    finally:
        dp.stop_code_interpreter_session(codeInterpreterIdentifier=ci_id, sessionId=session)
        print("\nsession stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
