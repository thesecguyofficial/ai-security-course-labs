"""
hunt.py: investigate a morning on the Helpdesk from three logs (data/incident/). Offline, standard library only.

    python3 hunt.py            # make hunt

  cloudtrail.jsonl  CloudTrail records: UpdateGateway (management event) and InvokeAgentRuntime (data event on
                    AWS::BedrockAgentCore::Runtime, which trails only log if you add a data event selector)
  spans.jsonl       gateway spans from the aws/spans log group. Attribute names that start with aws.agentcore are
                    AWS's (observability-policy-metrics); lab.tool, lab.principal and lab.input are LAB ADDITIONS
                    so you can read the samples (AWS documents ToolName as a metric dimension, not a span attribute)
  app-log.jsonl     YOUR backend's log: who was signed in, which runtimeSessionId and runtimeUserId it sent

The records are illustrative: the field names follow the CloudTrail record format and AWS's span attribute table;
the values are invented for the lab.

Three questions answered for you, one for you to write (challenge 3: find_session_reuse).
"""

from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
INCIDENT = HERE / "data" / "incident"


def load(name: str, folder: pathlib.Path = INCIDENT) -> list[dict]:
    return [json.loads(line) for line in (folder / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def mode_changes(trail: list[dict]) -> list[dict]:
    """Q1. Who changed the gateway's policy enforcement, and to what? (UpdateGateway with LOG_ONLY, or no engine)"""
    out = []
    for e in trail:
        if e["eventName"] == "UpdateGateway" and "policyEngineConfiguration" in e["requestParameters"]:
            cfg = e["requestParameters"]["policyEngineConfiguration"]
            out.append({"time": e["eventTime"], "who": e["userIdentity"]["arn"], "mode": cfg["mode"] if cfg else "REMOVED"})
    return out


def would_have_been_denied(spans: list[dict]) -> list[dict]:
    """Q2. Tool calls the policy said DENY while the gateway ran in LOG_ONLY: these went through."""
    return [{"time": s["startTime"], "tool": s["lab.tool"], "principal": s["lab.principal"], "input": s["lab.input"]}
            for s in spans if s["attributes"]["aws.agentcore.gateway.policy.mode"] == "LOG_ONLY"
            and s["attributes"]["aws.agentcore.policy.authorization_decision"] == "DENY"]


def user_id_mismatch(trail: list[dict], app_log: list[dict]) -> list[dict]:
    """Q3. InvokeAgentRuntime calls whose runtimeUserId is not the user our backend had signed in."""
    signed_in = {r["request_id"]: r["signed_in_user"] for r in app_log}
    out = []
    for e in trail:
        if e["eventName"] == "InvokeAgentRuntime" and "runtimeUserId" in e["requestParameters"]:
            who = signed_in.get(e["requestID"])
            if who and who != e["requestParameters"]["runtimeUserId"]:
                out.append({"time": e["eventTime"], "signed_in": who, "runtimeUserId": e["requestParameters"]["runtimeUserId"],
                            "session": e["requestParameters"]["runtimeSessionId"][:16] + "..."})
    return out


def find_session_reuse(app_log: list[dict]) -> list[dict]:
    """Challenge 3 (14.2 + 14.7): runtimeSessionIds used by MORE THAN ONE signed-in user.

    AgentCore does not enforce session-to-user mappings, so only your own log can show this. Return one dict per
    reused session: {"session": <the full runtime_session_id>, "users": <sorted list of the signed-in users>,
    "first_time": <earliest time>, "last_time": <latest time>}, sorted by first_time.
    """
    raise NotImplementedError("challenge 3: write find_session_reuse()")


def main(folder: pathlib.Path = INCIDENT):
    trail, spans, app_log = load("cloudtrail.jsonl", folder), load("spans.jsonl", folder), load("app-log.jsonl", folder)
    print("Q1. Policy enforcement changes (CloudTrail UpdateGateway)")
    for r in mode_changes(trail):
        print(f"   {r['time']}  {r['mode']:<9} by {r['who']}")
    print("\nQ2. Calls the policy said DENY that ran anyway (spans in LOG_ONLY mode)")
    for r in would_have_been_denied(spans):
        print(f"   {r['time']}  {r['tool']}  principal={r['principal']}  input={json.dumps(r['input'])}")
    print("\nQ3. runtimeUserId that is not the signed-in user (CloudTrail data events + app log)")
    for r in user_id_mismatch(trail, app_log):
        print(f"   {r['time']}  signed in: {r['signed_in']}  runtimeUserId sent: {r['runtimeUserId']}  session {r['session']}")
    print("\nQ4. Runtime sessions shared by more than one user (challenge 3)")
    try:
        rows = find_session_reuse(app_log)
        for r in rows:
            print(f"   {r['session'][:16]}...  users={r['users']}  {r['first_time']} -> {r['last_time']}")
        if not rows:
            print("   none")
    except NotImplementedError as e:
        print(f"   not written yet: {e}")


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else INCIDENT)
