"""
helpdesk_cloud.py: the Helpdesk BACKEND for the real cloud build (GUIDED-BUILD.md). Needs `pip install boto3` and
your sandbox credentials. Every call goes to YOUR account.

    python3 cloud/helpdesk_cloud.py retrieve --as bob@example.com "What are the salary bands for 2027?"
    python3 cloud/helpdesk_cloud.py ask --as bob@example.com "What's new in the VPN client?"

`--as` stands in for your identity provider: in a real app this value comes from the verified sign-in token on the
SERVER, never from the browser. That is the whole point of lesson 13.1.

What the backend does for `ask` (lesson 13.2):
  * sends the question to the AgentCore harness with InvokeHarness (only this backend has that permission)
  * when the model calls the inline function search_kb, the BACKEND runs Retrieve with userContext.userId = the
    signed-in user, and returns the chunks as the toolResult
  * when the model calls reset_mfa, the BACKEND shows the real arguments, asks the person to confirm, checks that
    they're allowed (authorise), and only then would act. In this lab it only prints what it would do.

Env vars (set by GUIDED-BUILD.md): AWS_REGION, KB_ID, HARNESS_ARN.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid

IT_STAFF = {"alice@example.com"}          # stand-in for the identity provider's "it-staff" group
MAX_ROUNDS = 6


def clients():
    import boto3
    region = os.environ.get("AWS_REGION", "us-east-1")
    return boto3.client("bedrock-agent-runtime", region_name=region), boto3.client("bedrock-agentcore", region_name=region)


def retrieve(kb_rt, kb_id: str, user: str | None, query: str, n: int = 3) -> dict:
    req = {"knowledgeBaseId": kb_id, "retrievalQuery": {"text": query},
           "retrievalConfiguration": {"managedSearchConfiguration": {"numberOfResults": n}}}
    if user:
        req["userContext"] = {"userId": user}
    return kb_rt.retrieve(**req)


def authorise(caller: str, target: str) -> bool:
    return target.lower() == caller.lower() or caller in IT_STAFF


def confirm(tool: str, args: dict, caller: str) -> bool:
    print(f"\n  CONFIRMATION for {caller}: the assistant wants to run {tool} with {json.dumps(args)}")
    return input("  Allow? [y/N] ").strip().lower() == "y"


def read_stream(stream) -> tuple[str, list[dict], str | None]:
    """Collect text, inline tool calls and the last stopReason from an InvokeHarness event stream (harness-tools)."""
    text, calls, blocks, stop = [], [], {}, None
    for event in stream:
        if "contentBlockStart" in event:
            st = event["contentBlockStart"]
            tu = st.get("start", {}).get("toolUse")
            if tu:
                blocks[st["contentBlockIndex"]] = {"toolUseId": tu["toolUseId"], "name": tu["name"], "input": ""}
        elif "contentBlockDelta" in event:
            d = event["contentBlockDelta"]
            delta = d.get("delta", {})
            if "text" in delta:
                text.append(delta["text"])
            if "toolUse" in delta and d.get("contentBlockIndex") in blocks:
                blocks[d["contentBlockIndex"]]["input"] += delta["toolUse"].get("input", "")
        elif "messageStop" in event:
            stop = event["messageStop"].get("stopReason")
        elif "runtimeClientError" in event:
            raise SystemExit(f"harness error: {event['runtimeClientError'].get('message')}")
    for b in blocks.values():
        b["input"] = json.loads(b["input"] or "{}")
        calls.append(b)
    return "".join(text), calls, stop


def ask(kb_rt, ac, harness_arn: str, kb_id: str, caller: str, question: str) -> None:
    session = f"tsg-m13-{uuid.uuid4()}"          # runtimeSessionId must be at least 33 characters
    messages = [{"role": "user", "content": [{"text": question}]}]
    for _ in range(MAX_ROUNDS):
        resp = ac.invoke_harness(harnessArn=harness_arn, runtimeSessionId=session, messages=messages)
        text, calls, stop = read_stream(resp["stream"])
        if text:
            print(f"A: {text}")
        if stop != "tool_use" or not calls:
            return
        results = []
        for c in calls:
            if c["name"] == "search_kb":
                r = retrieve(kb_rt, kb_id, caller, c["input"].get("query", question))
                chunks = [x["content"]["text"] for x in r["retrievalResults"]]
                print(f"  . search_kb -> Retrieve as {caller}: {len(chunks)} result(s)")
                out, status = json.dumps(chunks), "success"
            elif c["name"] == "reset_mfa":
                target = c["input"].get("target_email", "")
                if not confirm("reset_mfa", c["input"], caller):
                    out, status = "The user declined.", "error"
                elif not authorise(caller, target):
                    out, status = f"{caller} is not allowed to reset MFA for {target}.", "error"
                else:
                    print(f"  . [lab] would reset MFA for {target} (no identity provider is called)")
                    out, status = f"MFA reset for {target}.", "success"
            else:
                out, status = f"Unknown tool {c['name']}", "error"
            results.append({"toolResult": {"toolUseId": c["toolUseId"], "content": [{"text": out}], "status": status}})
        messages = [{"role": "user", "content": results}]
    print("  . stopped: too many tool rounds")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["retrieve", "ask"])
    ap.add_argument("--as", dest="user", help="the signed-in user (omit with retrieve to send no userContext)")
    ap.add_argument("question")
    a = ap.parse_args(argv)
    kb_id = os.environ["KB_ID"]
    kb_rt, ac = clients()
    if a.cmd == "retrieve":
        print(json.dumps(retrieve(kb_rt, kb_id, a.user, a.question)["retrievalResults"], indent=2, default=str))
    else:
        if not a.user:
            raise SystemExit("ask needs --as: the backend always knows who is signed in")
        ask(kb_rt, ac, os.environ["HARNESS_ARN"], kb_id, a.user, a.question)


if __name__ == "__main__":
    main(sys.argv[1:])
