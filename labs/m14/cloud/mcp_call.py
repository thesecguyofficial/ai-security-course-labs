"""
mcp_call.py: call your AgentCore Gateway's MCP endpoint with a bearer token. Standard library only (guided build).

    export GATEWAY_URL=...   # terraform output -raw gateway_url   (ends in /mcp)
    export TOKEN=...         # a Cognito access token (GUIDED-BUILD shows the command)
    python3 cloud/mcp_call.py list
    python3 cloud/mcp_call.py call reset_mfa '{"target_username": "bob", "caller_username": "bob"}'
    python3 cloud/mcp_call.py call reset_mfa '{"target_username": "bob", "caller_username": "bob"}' --session bob-2027-01-23

The request body is MCP JSON-RPC 2.0 (method tools/list or tools/call) as in AWS's policy-session examples. Tool
names on the gateway are <target>___<tool>; this script adds the HelpdeskTools___ prefix for you.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

TARGET = "HelpdeskTools"


def post(url: str, token: str, body: dict, session: str | None) -> dict:
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    if session:
        headers["x-amzn-bedrock-agentcore-policy-session-id"] = session
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return {"status": r.status, "body": json.loads(r.read().decode() or "{}")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode()[:500], "www-authenticate": e.headers.get("WWW-Authenticate")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("method", choices=["list", "call"])
    ap.add_argument("tool", nargs="?")
    ap.add_argument("arguments", nargs="?", default="{}")
    ap.add_argument("--session", help="policy session ID (x-amzn-bedrock-agentcore-policy-session-id)")
    a = ap.parse_args()
    url, token = os.environ.get("GATEWAY_URL"), os.environ.get("TOKEN")
    if not url or not token:
        sys.exit("set GATEWAY_URL and TOKEN first (GUIDED-BUILD.md, Part A)")
    if a.method == "list":
        body = {"jsonrpc": "2.0", "id": "list-1", "method": "tools/list"}
    else:
        body = {"jsonrpc": "2.0", "id": "call-1", "method": "tools/call",
                "params": {"name": f"{TARGET}___{a.tool}", "arguments": json.loads(a.arguments)}}
    print(json.dumps(post(url, token, body, a.session), indent=2))


if __name__ == "__main__":
    main()
