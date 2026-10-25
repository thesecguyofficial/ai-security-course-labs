"""Regenerate aws/data/cloudtrail.jsonl and aws/data/app-log.jsonl (lesson 20.5).

    python3 aws/make_samples.py

ILLUSTRATIVE records: the field names follow AWS's documentation (CloudTrail record contents, the IAM source
identity example, the AgentCore Identity API request members); the values are made up for one lab morning.
The guided build (aws/GUIDED-BUILD.md) shows you the real records from your own account.
"""
import datetime
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
ACCT, REGION = "111122223333", "us-east-1"
DIR = f"arn:aws:bedrock-agentcore:{REGION}:{ACCT}:workload-identity-directory/default"
VAULT = f"arn:aws:bedrock-agentcore:{REGION}:{ACCT}:token-vault/default"
T0 = datetime.datetime(2027, 1, 21, 9, 0, 0)
ct, app, counter = [], [], [0]


def ts(sec):
    return (T0 + datetime.timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")


def rid():
    counter[0] += 1
    return f"req-{counter[0]:04d}"


def assume(sec, role, session, si):
    rp = {"roleArn": f"arn:aws:iam::{ACCT}:role/{role}", "roleSessionName": session, "durationSeconds": 900}
    if si:
        rp["sourceIdentity"] = si
    ct.append({"eventVersion": "1.11", "eventTime": ts(sec), "eventSource": "sts.amazonaws.com", "eventName": "AssumeRole",
               "userIdentity": {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCT}:assumed-role/tsg-agent-launcher/web-1"},
               "requestParameters": rp, "requestID": rid(), "eventCategory": "Management"})


def agentcore(sec, role, session, si, event, wi, provider=None):
    ui = {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCT}:assumed-role/{role}/{session}",
          "sessionContext": {"sessionIssuer": {"type": "Role", "arn": f"arn:aws:iam::{ACCT}:role/{role}", "userName": role}}}
    if si:
        ui["sessionContext"]["sourceIdentity"] = si
    if event == "GetWorkloadAccessTokenForJWT":
        rp = {"workloadName": wi, "userToken": "HIDDEN_DUE_TO_SECURITY_REASONS"}
        res = [{"type": "AWS::BedrockAgentCore::WorkloadIdentity", "ARN": f"{DIR}/workload-identity/{wi}"}]
    else:
        rp = {"resourceCredentialProviderName": provider, "oauth2Flow": "USER_FEDERATION",
              "scopes": ["tickets.read"] if provider == "tickets-saas" else ["mail.send"],
              "workloadIdentityToken": "HIDDEN_DUE_TO_SECURITY_REASONS"}
        res = [{"type": "AWS::BedrockAgentCore::TokenVault", "ARN": VAULT}]
    ct.append({"eventVersion": "1.11", "eventTime": ts(sec), "eventSource": "bedrock-agentcore.amazonaws.com",
               "eventName": event, "userIdentity": ui, "requestParameters": rp, "requestID": rid(),
               "eventCategory": "Data", "resources": res})


def run(sec, agent, role, wi, sub, si, provider=None, run_id=None, jwt_sub=None):
    app.append({"ts": ts(sec), "run_id": run_id, "agent": agent,
                "jwt_iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE",
                "jwt_sub": jwt_sub or sub, "source_identity": si})
    assume(sec, role, run_id, si)
    agentcore(sec + 2, role, run_id, si, "GetWorkloadAccessTokenForJWT", wi)
    if provider:
        agentcore(sec + 4, role, run_id, si, "GetResourceOauth2Token", wi, provider)


A, B = "u-1001-alice", "u-1002-bob"
run(0, "orchestrator", "tsg-agent-orchestrator", "tsg-orchestrator", A, "user-" + A, run_id="orchestrator-run-0901")
run(10, "tickets", "tsg-agent-tickets", "tsg-tickets", A, "user-" + A, "tickets-saas", run_id="tickets-run-0901")
run(20, "mail", "tsg-agent-mail", "tsg-mail", A, "user-" + A, "mail-saas", run_id="mail-run-0901")
run(300, "orchestrator", "tsg-agent-orchestrator", "tsg-orchestrator", B, "user-" + B, run_id="orchestrator-run-0905")
run(310, "tickets", "tsg-agent-tickets", "tsg-tickets", B, "user-" + B, "tickets-saas", run_id="tickets-run-0905")
# an old deployment still on the shared role: no SourceIdentity, one identity for two agents
run(900, "tickets", "tsg-agent-helpdesk", "tsg-helpdesk", B, None, "tickets-saas", run_id="helpdesk-0915")
run(905, "mail", "tsg-agent-helpdesk", "tsg-helpdesk", B, None, "mail-saas", run_id="helpdesk-0915b")
# a launcher bug: the JWT was Bob's, the role session says Alice
run(1500, "tickets", "tsg-agent-tickets", "tsg-tickets", A, "user-" + A, "tickets-saas", run_id="tickets-run-0925", jwt_sub=B)

(HERE / "data" / "cloudtrail.jsonl").write_text("".join(json.dumps(r) + "\n" for r in ct))
(HERE / "data" / "app-log.jsonl").write_text("".join(json.dumps(r) + "\n" for r in app))
print(f"wrote {len(ct)} CloudTrail records and {len(app)} launcher log rows")
