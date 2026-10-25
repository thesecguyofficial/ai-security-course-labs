"""
scenarios.py: builds the lab's CloudTrail-shaped events, the attacker timelines and the poisoned alerts.

The record shape follows the CloudTrail examples in the AWS docs (eventSource, eventName, awsRegion,
sourceIPAddress, userAgent, userIdentity.accessKeyId, readOnly, errorCode, vpcEndpointId, managementEvent ...).
Every value is a lab fake. Model IDs are illustrative. Nothing here is a working payload: the "directives" inside
userAgent strings are LAB-PLACEHOLDER markers that only this lab's stand-in model reacts to.
"""

from __future__ import annotations

import datetime as dt
import hashlib

from lab import ORG, iso, ts

DAY = "2027-04-10"
NAT_IP = "192.0.2.10"            # the org's own egress address (documentation range)
ATTACKER_IP = "198.51.100.23"    # "somewhere else" (documentation range)
HONEY_KEY = ORG["decoys"][0]["access_key_id"]
APP = ORG["app_principals"][0]

READ_ONLY = {"GetCallerIdentity", "ListFoundationModels", "GetModelInvocationLoggingConfiguration",
             "ListInferenceProfiles", "ListModels"}
DATA_EVENTS = {("bedrock-mantle.amazonaws.com", "CreateInference")}


def ct(when: str, account: str, region: str, source: str, name: str, *, user: str | None = None,
       role: str | None = None, key: str = "", ip: str = NAT_IP, agent: str = "Boto3/1.40.0 (lab)",
       params: dict | None = None, error: str | None = None, vpce: str | None = None) -> dict:
    """One CloudTrail record (the 'detail' of an EventBridge 'AWS API Call via CloudTrail' event)."""
    if role:
        identity = {"type": "AssumedRole", "arn": f"arn:aws:sts::{account}:assumed-role/{role}/lab-session",
                    "accountId": account, "accessKeyId": key or "TSGLABSESSION0000000"}
    else:
        identity = {"type": "IAMUser", "arn": f"arn:aws:iam::{account}:user/{user}", "accountId": account,
                    "userName": user}
        if key:
            identity["accessKeyId"] = key
    data_event = (source, name) in DATA_EVENTS
    rec = {
        "eventVersion": "1.11",
        "userIdentity": identity,
        "eventTime": f"{DAY}T{when}Z",
        "eventSource": source,
        "eventName": name,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userAgent": agent,
        "requestParameters": params or {},
        "responseElements": None,
        "requestID": "lab-" + hashlib.sha256(f"{when}{account}{name}{user}{role}{region}".encode()).hexdigest()[:12],
        "eventID": "lab-" + hashlib.sha256(f"e{when}{account}{name}{user}{role}{region}{ip}".encode()).hexdigest()[:12],
        "readOnly": name in READ_ONLY,
        "eventType": "AwsApiCall",
        "managementEvent": not data_event,
        "recipientAccountId": account,
        "eventCategory": "Data" if data_event else "Management",
        "tlsDetails": {"clientProvidedHostHeader": host_for(source, region)},
    }
    if error:
        rec["errorCode"] = error
        rec["errorMessage"] = "User is not authorized to perform this action (lab)"
    if vpce:
        rec["vpcEndpointId"] = vpce
    return rec


def host_for(source: str, region: str) -> str:
    if source == "bedrock.amazonaws.com":
        return f"bedrock-runtime.{region}.amazonaws.com"
    if source == "bedrock-mantle.amazonaws.com":
        return f"bedrock-mantle.{region}.api.aws"
    return source.replace(".amazonaws.com", f".{region}.amazonaws.com")


def envelope(rec: dict) -> dict:
    """Wrap a record the way EventBridge delivers it (fields test-event-pattern requires: id, account, source,
    time, region, resources, detail-type). The 'source' convention aws.<service> is the lab's simplification."""
    return {
        "version": "0",
        "id": rec["eventID"],
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws." + rec["eventSource"].split(".")[0],
        "account": rec["recipientAccountId"],
        "time": rec["eventTime"],
        "region": rec["awsRegion"],
        "resources": [],
        "detail": rec,
    }


# ---------------------------------------------------------------- the org's day (lesson 29.1, make hunt)

def org_day() -> list[dict]:
    """A quiet working day across the org: normal use, the security team's audit, and five pieces of shadow AI."""
    claude = "anthropic.claude-sonnet-4-6"
    ev = []
    # normal: the helpdesk batch job, always through its VPC endpoint
    for h in ("09:00:05", "09:15:05", "09:30:05", "11:00:05", "14:00:05"):
        ev.append(ct(h, "222222222222", "us-east-1", "bedrock.amazonaws.com", "InvokeModel",
                     user=APP["user"], key=APP["access_key_id"], ip="10.20.1.15",
                     params={"modelId": claude}, vpce=APP["expected_vpc_endpoint"]))
    # normal: data science notebooks on registered models
    ev.append(ct("10:12:40", "333333333333", "us-east-1", "bedrock.amazonaws.com", "Converse", role="ds-notebook",
                 params={"modelId": claude}))
    ev.append(ct("10:14:02", "333333333333", "us-east-1", "bedrock.amazonaws.com", "Converse", role="ds-notebook",
                 params={"modelId": "amazon.nova-pro-v1:0"}))
    # normal: the security team's read-only audit in every Region
    for region in ORG["regions"]:
        ev.append(ct("08:00:00", "555555555555", region, "bedrock.amazonaws.com", "ListFoundationModels",
                     role="security-audit"))
    # D0: an unregistered model in a registered account, InvokeModel, us-east-1 (the obvious one)
    ev.append(ct("09:41:17", "222222222222", "us-east-1", "bedrock.amazonaws.com", "InvokeModel",
                 role="helpdesk-experiments", params={"modelId": "deepseek.r1-v1:0"}))
    # D1: Bedrock in an account that isn't in the register at all, eu-west-1
    ev.append(ct("13:05:51", "444444444444", "eu-west-1", "bedrock.amazonaws.com", "InvokeModel",
                 role="marketing-content", params={"modelId": "amazon.nova-premier-v1:0"}))
    # D2: Converse, not InvokeModel (a separate CloudTrail event name)
    ev.append(ct("15:22:09", "222222222222", "us-east-1", "bedrock.amazonaws.com", "Converse",
                 role="helpdesk-experiments", params={"modelId": "meta.llama4-scout-17b-instruct-v1:0"}))
    # D3: inference on the bedrock-mantle endpoint (a DATA event: only logged if you turn data events on)
    ev.append(ct("16:40:33", "333333333333", "us-east-1", "bedrock-mantle.amazonaws.com", "CreateInference",
                 user="svc-ds-prototype", params={"model": "openai.gpt-oss-120b", "callWithBearerToken": True}))
    return sorted(ev, key=lambda e: e["eventTime"])


def org_day_dns() -> list[dict]:
    """Route 53 Resolver query log rows (field names from the AWS docs; values are lab fakes)."""
    def q(t, account, region, vpc, name, instance, src):
        return {"version": "1.1", "account_id": account, "region": region, "vpc_id": vpc,
                "query_timestamp": f"{DAY}T{t}Z", "query_name": name + ".", "query_type": "A", "rcode": "NOERROR",
                "srcaddr": src, "srcids": {"instance": instance}}
    return [
        q("09:00:04", "222222222222", "us-east-1", "vpc-0lab0222", "bedrock-runtime.us-east-1.amazonaws.com",
          "i-0lab00000000000222", "10.20.1.15"),
        q("10:30:12", "333333333333", "us-east-1", "vpc-0lab0333", "api.anthropic.com", "i-0lab00000000000333",
          "10.30.4.21"),
        # D4: an EC2 instance in the marketing sandbox calling an outside AI API nobody approved
        q("11:47:30", "444444444444", "eu-west-1", "vpc-0lab0444", "api.openai.com", "i-0lab00000000000444",
          "10.40.2.9"),
        q("12:01:00", "444444444444", "eu-west-1", "vpc-0lab0444", "updates.example.com", "i-0lab00000000000444",
          "10.40.2.9"),
    ]


# ---------------------------------------------------------------- timelines for the detection cases (29.4, 29.7)

def honeytoken_read_only() -> list[dict]:
    """H1: the first thing anyone does with a found key is check it. Both calls are read-only."""
    return [
        ct("10:00:00", "222222222222", "us-east-1", "sts.amazonaws.com", "GetCallerIdentity",
           user="svc-reporting-legacy", key=HONEY_KEY, ip=ATTACKER_IP, agent="aws-cli/2.x (lab)"),
        ct("10:00:20", "222222222222", "us-east-1", "bedrock.amazonaws.com", "ListFoundationModels",
           user="svc-reporting-legacy", key=HONEY_KEY, ip=ATTACKER_IP, agent="aws-cli/2.x (lab)",
           error="AccessDeniedException"),
    ]


def honeytoken_denied_invoke(region: str = "us-east-1") -> list[dict]:
    """H2/H3: an InvokeModel try with the decoy. It has no permissions, so it ALWAYS fails."""
    return [ct("10:01:05", "222222222222", region, "bedrock.amazonaws.com", "InvokeModel",
               user="svc-reporting-legacy", key=HONEY_KEY, ip=ATTACKER_IP, agent="aws-cli/2.x (lab)",
               params={"modelId": "anthropic.claude-sonnet-4-6"}, error="AccessDeniedException")]


def decoy_api_key_used() -> list[dict]:
    """H4 (challenge 2): the decoy Bedrock API key used on bedrock-mantle. The API key itself is never logged:
    the record names the IAM user behind it."""
    return [ct("10:03:40", "333333333333", "us-east-1", "bedrock-mantle.amazonaws.com", "CreateInference",
               user="svc-bedrock-trial", ip=ATTACKER_IP, agent="python-requests/2.x (lab)",
               params={"model": "openai.gpt-oss-120b", "callWithBearerToken": True},
               error="AccessDeniedException")]


def app_key_from_elsewhere() -> list[dict]:
    """N1: the real helpdesk key, used from an address that isn't the VPC endpoint."""
    return [ct("10:02:10", "222222222222", "us-east-1", "bedrock.amazonaws.com", "InvokeModel",
               user=APP["user"], key=APP["access_key_id"], ip=ATTACKER_IP, agent="python-requests/2.x (lab)",
               params={"modelId": "anthropic.claude-sonnet-4-6"})]


def logging_switched_off() -> list[dict]:
    """N2: invocation logging deleted, as reported in LLMjacking cases."""
    return [ct("10:02:55", "222222222222", "us-east-1", "bedrock.amazonaws.com",
               "DeleteModelInvocationLoggingConfiguration", user=APP["user"], key=APP["access_key_id"],
               ip=ATTACKER_IP, agent="python-requests/2.x (lab)")]


def normal_app_call() -> list[dict]:
    return [ct("09:00:05", "222222222222", "us-east-1", "bedrock.amazonaws.com", "InvokeModel", user=APP["user"],
               key=APP["access_key_id"], ip="10.20.1.15", params={"modelId": "anthropic.claude-sonnet-4-6"},
               vpce=APP["expected_vpc_endpoint"])]


def security_audit_calls() -> list[dict]:
    return [ct("08:00:00", "555555555555", r, "bedrock.amazonaws.com", "ListFoundationModels", role="security-audit")
            for r in ORG["regions"]]


# ---------------------------------------------------------------- the attacker's 30 minutes with the app key (R1, R2)

def attack_timeline() -> list[dict]:
    """Calls made with the leaked helpdesk key from 10:02:10 for 30 minutes, one every 30 seconds.
    At +20 s the attacker swaps the key for session credentials (GetSessionToken) and uses those from then on."""
    start = ts(f"{DAY}T10:02:10Z")
    calls = [{"time": iso(start), "key": APP["access_key_id"], "kind": "long-term", "call": "InvokeModel"},
             {"time": iso(start + dt.timedelta(seconds=20)), "key": APP["access_key_id"], "kind": "long-term",
              "call": "GetSessionToken"}]
    t = start + dt.timedelta(seconds=30)
    while t < start + dt.timedelta(minutes=30):
        calls.append({"time": iso(t), "key": "TSGLABSESSIONKEY0003", "kind": "session", "call": "InvokeModel",
                      "parent_user": APP["user"]})
        t += dt.timedelta(seconds=30)
    return calls


# ---------------------------------------------------------------- alerts for the SOC triage agent (29.6)

def poisoned_alert(directive: str) -> dict:
    """An honest honeytoken alert whose userAgent (a field the CALLER chooses) carries a lab directive."""
    rec = honeytoken_denied_invoke()[0]
    rec = dict(rec, userAgent=f"aws-cli/2.x LAB-PLACEHOLDER-DIRECTIVE: {directive}")
    return {"id": "AL-T" + hashlib.sha256(directive.encode()).hexdigest()[:4], "rule": "honeytoken-key-used",
            "severity": "high", "event": rec}


def clean_alert() -> dict:
    return {"id": "AL-CLEAN", "rule": "honeytoken-key-used", "severity": "high", "event": honeytoken_denied_invoke()[0]}
