"""
explore.py: look at each piece of TSG Helpdesk on Amazon Bedrock, one step at a time, before you attack the lab
(M11 lab, README Step 1b).

Read-only. Nothing here changes a file, starts a program or uses the network. Every command reads the lab's
offline twin (the Terraform plans in twin/) and its JSON files, and prints what it finds.

    python3 explore.py plan                    # 1. what a Terraform plan is: everything it WOULD create
    python3 explore.py model                   # 2. one model, three names, and who may subscribe to it
    python3 explore.py role                    # 3. the Helpdesk role's IAM policy, line by line
    python3 explore.py route us.anthropic.claude-haiku-4-5-20251001-v1:0
                                               # 4. one call through an inference profile: every check, every Region
    python3 explore.py network                 # 5. the private network: VPC, subnets, routes, the endpoint
    python3 explore.py endpoint                # 6. the endpoint policy, and who it lets through
    python3 explore.py keys hardened prompts   # 7. the KMS keys and who may use them
    python3 explore.py logging                 # 8. what gets recorded: invocation logging and the trail
    python3 explore.py record                  # 9. one prompt-log record and one CloudTrail record, side by side

Most commands take a plan name: first-draft (the default, the pull request) or hardened.
Everything is fake: AWS documentation example account IDs, AnyCompany (AWS's own placeholder company name).
iam_eval.py, which `route` and `endpoint` use, is a teaching model of AWS policy evaluation, not the real engine.
"""

from __future__ import annotations

import argparse
import collections
import json

import attack as A
import plan as P
from iam_eval import DEFAULT_ENDPOINT_POLICY, Request, evaluate

PLANS = A.PLANS
COMPANY = A.COMPANY


def _load(name: str) -> dict:
    return P.load(PLANS[name])


def _short(x, n: int = 96) -> str:
    s = x if isinstance(x, str) else json.dumps(x)
    return s if len(s) <= n else s[: n - 3] + "..."


def _actions(st: dict) -> list:
    return P.as_list(st.get("Action") or st.get("NotAction"))


def _cond_lines(cond: dict | None) -> list[str]:
    out = []
    for op, keys in (cond or {}).items():
        for k, v in keys.items():
            out.append(f"{op} {k} = {_short(v, 80)}")
    return out


# ---------------------------------------------------------------- 1. plan

def cmd_plan(a) -> None:
    p = _load(a.plan)
    rs = P.resources(p)
    acts = collections.Counter("+".join(rc["change"]["actions"]) for rc in p["resource_changes"])
    print(f"Terraform plan, {a.plan}: {PLANS[a.plan]}")
    print(f"  written by {p.get('terraform_version')} (format {p.get('format_version')}), offline, with mock credentials")
    print(f"  actions: {', '.join(f'{n} to {k}' for k, n in acts.items())}   (a plan changes nothing; apply would)\n")
    by_type = collections.defaultdict(list)
    for r in rs:
        by_type[r["type"]].append(r["name"] + (f"[{r['index']}]" if "index" in r else ""))
    for t in sorted(by_type):
        print(f"  {len(by_type[t]):>2} x {t:<52} {', '.join(by_type[t])}")
    print(f"\n{len(rs)} resources. Nothing exists yet: this is the plan, read before anything is built.")


# ---------------------------------------------------------------- 2. model

def cmd_model(a) -> None:
    ap = COMPANY["approved"]
    acct = COMPANY["organization"]["production_account"]
    fm = ap["foundation_model"]
    print("One approved model, Claude Haiku 4.5, and its three names (AWS model card):\n")
    print(f"  foundation model ID   {fm}")
    print(f"      as an ARN         arn:aws:bedrock:us-east-1::foundation-model/{fm}   (no account: AWS's model)")
    print(f"  inference profile     {ap['runtime_profile']}   (bedrock-runtime: 'us.' = US Regions only)")
    print(f"      as an ARN         arn:aws:bedrock:us-east-1:{acct}:inference-profile/{ap['runtime_profile']}")
    print(f"  bedrock-mantle model  {ap['mantle_model']}   (the second endpoint uses other names)\n")
    print("Who may start a Marketplace subscription (the first call to a third-party model does it)?")
    for mode in ("first-draft", "hardened"):
        pols = A.identity_policies("helpdesk", _load(mode))
        mk = [x for _, d in pols for st in P.statements(d) for x in _actions(st) if x.startswith("aws-marketplace")]
        print(f"  Helpdesk role, {mode:<11}  aws-marketplace actions: {', '.join(mk) if mk else 'none'}")
    print("  On a real account: AWS says the first call needs aws-marketplace:Subscribe, Unsubscribe and")
    print("  ViewSubscriptions; after that, callers need no Marketplace permissions.")


# ---------------------------------------------------------------- 3. role

def cmd_role(a) -> None:
    p = _load(a.plan)
    for name, doc in A.identity_policies("helpdesk", p):
        print(f"The Helpdesk role's policy, {a.plan}: {name}")
        print(f"  Version  {doc.get('Version')}   (the policy language edition, not a date you pick)\n")
        for i, st in enumerate(P.statements(doc), 1):
            print(f"  Statement {i}  Sid {st.get('Sid', '(none)')}")
            print(f"    Effect     {st.get('Effect')}")
            print(f"    Action     {', '.join(_actions(st))}")
            for r in P.as_list(st.get("Resource")):
                print(f"    Resource   {r}")
            for line in _cond_lines(st.get("Condition")):
                print(f"    Condition  {line}")
            if not st.get("Condition"):
                print("    Condition  (none)")
            print()


# ---------------------------------------------------------------- 4. route

def cmd_route(a) -> None:
    rule = COMPANY["data_residency"]
    target = a.target
    checks = A.invoke("helpdesk", target)
    print(f"One Converse call from us-east-1 (the source Region) with modelId {target}\n")
    print("The checks IAM makes (AWS's cross-Region inference pages), and where each one points:")
    regions = []
    for i, r in enumerate(checks, 1):
        reg = r.context.get("aws:RequestedRegion")
        via = "  with bedrock:InferenceProfileArn set" if "bedrock:InferenceProfileArn" in r.context else ""
        kind = "the profile" if ":inference-profile/" in r.resource else "the model"
        print(f"  {i}. {kind:<11} Region {reg:<12} {r.resource}")
        if via:
            print(f"     {'':<11} {'':<19}{via.strip()}")
        if kind == "the model":
            regions.append(reg)
    allowed = set(rule["allowed_processing_regions"])
    ok = all(r in allowed for r in regions)
    print(f"\nWhere the prompt may be processed: {', '.join(regions)}")
    if "unspecified" in regions:
        print("  'unspecified' = the Region-less model ARN: AWS says any supported commercial Region worldwide.")
    print(f"AnyCompany's rule: {rule['rule']}")
    print(f"Verdict: {'fits the rule' if ok else 'BREAKS the rule'}")


# ---------------------------------------------------------------- 5. network

def cmd_network(a) -> None:
    p = _load(a.plan)
    vpc = P.one(p, "aws_vpc")
    print(f"The Helpdesk's network, {a.plan}\n")
    print(f"  VPC        {vpc['values']['cidr_block']}   (a private network: AWS gives it no way out by default)")
    for s in P.resources(p, "aws_subnet"):
        v = s["values"]
        print(f"  subnet     {v['cidr_block']:<15} {v['availability_zone']:<11} {s['name']}")
    nat = P.resources(p, "aws_nat_gateway")
    igw = P.resources(p, "aws_internet_gateway")
    via_nat = P.references(p, "aws_route_table.private", "route")
    print(f"  internet gateway  {'yes' if igw else 'none'}")
    print(f"  NAT gateway       {'yes' if nat else 'none'}")
    print(f"  private route table: 0.0.0.0/0 -> {'NAT gateway (the internet)' if via_nat else 'nothing (no way out)'}")
    for e in P.resources(p, "aws_vpc_endpoint"):
        v = e["values"]
        print(f"  VPC endpoint      {v['service_name']}  ({v['vpc_endpoint_type']}, private DNS "
              f"{'on' if v.get('private_dns_enabled') else 'off'}, policy {'custom' if v.get('policy') else 'DEFAULT'})")
    sg = P.one(p, "aws_security_group") and [r for r in P.resources(p, "aws_security_group") if r["name"] == "endpoint"]
    ing = (sg[0]["values"].get("ingress") or []) if sg else []
    for rule in ing:
        print(f"  endpoint accepts  port {rule['from_port']} from {', '.join(rule['cidr_blocks'])} (the whole VPC)")
    for r in P.resources(p, "aws_vpc_security_group_ingress_rule"):
        src = P.references(p, r["address"], "referenced_security_group_id")
        print(f"  endpoint accepts  port {r['values']['from_port']} from {src[-1] if src else '?'} only")
    names = [e["values"]["service_name"].rsplit(".", 1)[-1] for e in P.resources(p, "aws_vpc_endpoint")]
    print("\nA call to bedrock-runtime uses the endpoint (private DNS sends it there).")
    if "bedrock-mantle" not in names:
        print(f"A call to bedrock-mantle has no endpoint: {'it goes out through the NAT gateway' if via_nat else 'it has nowhere to go'}.")


# ---------------------------------------------------------------- 6. endpoint

def cmd_endpoint(a) -> None:
    p = _load(a.plan)
    name, doc = A.endpoint_policy(p)
    print(f"The bedrock-runtime endpoint's policy, {a.plan}: {name}\n")
    for st in P.statements(doc):
        print(f"  Sid        {st.get('Sid', '(none)')}")
        print(f"  Effect     {st.get('Effect')}")
        note = ""
        if st.get("Principal") == "*":
            note = "(anyone, from any AWS account)" if not st.get("Condition") else "(anyone... then the Condition narrows it)"
        print(f"  Principal  {_short(st.get('Principal'))}   {note}".rstrip())
        print(f"  Action     {', '.join(_actions(st))}")
        print(f"  Resource   {', '.join(P.as_list(st.get('Resource')))}")
        for line in _cond_lines(st.get("Condition")) or ["(none)"]:
            print(f"  Condition  {line}")
    print("\nWho gets through this door? (endpoint policy only; IAM still has to allow the call too)")
    model = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0"
    allow_all = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    for who in ("helpdesk", "data-science", "outsider"):
        pr = A.principal(who)
        req = Request(pr["arn"], "bedrock:InvokeModel", model, A.ctx(who, "us-east-1"))
        d = evaluate(req, [("own-policy", allow_all)], [], scps_apply=False, endpoint_policy=(name, doc))
        print(f"  {'THROUGH' if d.allowed else 'refused':<8} {pr['arn']}  (account {pr['account']})")


# ---------------------------------------------------------------- 7. keys

def cmd_keys(a) -> None:
    p = _load(a.plan)
    keys = P.resources(p, "aws_kms_key")
    shown = [k for k in keys if not a.key or k["name"] == a.key]
    print(f"KMS keys in the plan, {a.plan}: {len(keys)}" + (f"   (showing: {a.key})" if a.key else "") + "\n")
    if not keys:
        print("  none. CloudWatch Logs still encrypts the prompt log, with a key the service manages, so")
        print("  IAM alone decides who can read the prompts: permission to read the log group is enough.")
        return
    for k in shown:
        v = k["values"]
        print(f"  {k['address']}: {v['description']}")
        print(f"    rotation {'on' if v.get('enable_key_rotation') else 'off'}, deletion waits {v.get('deletion_window_in_days')} days"
              f" after someone schedules it\n")
        for st in P.statements(P.policy(v["policy"])):
            pr = st.get("Principal", {})
            who = (pr.get("Service") or pr.get("AWS")) if isinstance(pr, dict) else pr
            who = who.split(":")[-1] if who.startswith("arn:") else who
            cond = sorted({k2 for keys2 in (st.get("Condition") or {}).values() for k2 in keys2})
            print(f"    {st.get('Sid', '')}")
            print(f"        who  {who:<44} may  {_short(', '.join(_actions(st)), 60)}")
            if cond:
                print(f"        only if  {', '.join(cond)}")
        print()


# ---------------------------------------------------------------- 8. logging

def cmd_logging(a) -> None:
    p = _load(a.plan)
    cfg = P.one(p, "aws_bedrock_model_invocation_logging_configuration")
    print(f"What gets recorded, {a.plan}\n")
    print("Model invocation logging (the prompt and the answer; bedrock-runtime calls only):")
    if not cfg:
        print("  OFF")
    else:
        lc = cfg["values"]["logging_config"][0]
        mods = [m for m in ("text", "image", "embedding", "video") if lc.get(f"{m}_data_delivery_enabled")]
        cw = (lc.get("cloudwatch_config") or [{}])[0]
        big = cw.get("large_data_delivery_s3_config") or []
        print(f"  on, for: {', '.join(mods)}   (for every model in this account and Region)")
        print(f"  to CloudWatch Logs group {cw.get('log_group_name')}")
        print(f"  bodies over 100 KB: {'to S3 bucket ' + big[0]['bucket_name'] if big else 'nowhere (no S3 bucket set)'}")
        print(f"  {A._prompt_log_line(p).replace('Prompt log: question + answer in ', 'stored in ')}")
    trails = P.resources(p, "aws_cloudtrail")
    print("\nCloudTrail (who called what, from where; never the prompt):")
    print("  event history: management events such as InvokeModel and Converse, 90 days, free, always on")
    if not trails:
        print("  trail: NONE, so no data events (bedrock-mantle inference) and no network activity events")
    for t in trails:
        v = t["values"]
        print(f"  trail {v['name']}: multi-Region {v.get('is_multi_region_trail')}, "
              f"log file validation {v.get('enable_log_file_validation')}")
        for sel in v.get("advanced_event_selector") or []:
            print(f"    selects: {sel['name']}")


# ---------------------------------------------------------------- 9. record

RECORD = {   # illustrative: the field names of AWS's documented invocation-log record, fake values
    "schemaType": "ModelInvocationLog",
    "schemaVersion": "1.0",
    "timestamp": "2026-10-30T09:14:02Z",
    "accountId": "111122223333",
    "region": "us-east-1",
    "requestId": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
    "operation": "Converse",
    "modelId": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "identity": {"arn": "arn:aws:sts::111122223333:assumed-role/tsg-helpdesk-app/tsg-helpdesk"},
    "requestMetadata": {"app": "tsg-helpdesk", "env": "m11-lab"},
    "input": {"inputContentType": "application/json", "inputTokenCount": 61,
              "inputBodyJson": {"messages": [{"role": "user", "content": [{"text": "How do I reset my VPN token?"}]}]}},
    "output": {"outputContentType": "application/json", "outputTokenCount": 48,
               "outputBodyJson": {"output": {"message": {"content": [{"text": "Open the VPN portal, choose..."}]}}}},
}


def cmd_record(a) -> None:
    r = RECORD
    print("ILLUSTRATIVE: AWS's documented field names, fake values. Two records of the same Helpdesk call.\n")
    print("1. Prompt log (model invocation logging, in your log group):")
    print(f"   who        identity.arn      {r['identity']['arn']}")
    print(f"   what       operation         {r['operation']}  on modelId {r['modelId']}")
    print(f"   where      region            {r['region']}   account {r['accountId']}")
    print(f"   said       inputBodyJson     \"{r['input']['inputBodyJson']['messages'][0]['content'][0]['text']}\"")
    print(f"   answered   outputBodyJson    \"{r['output']['outputBodyJson']['output']['message']['content'][0]['text']}\"")
    print(f"   size       tokens            {r['input']['inputTokenCount']} in, {r['output']['outputTokenCount']} out")
    print(f"   caller's   requestMetadata   {json.dumps(r['requestMetadata'])}   <- the ONLY field the caller writes")
    print("\n2. CloudTrail event (event history, management event):")
    print("   who        userIdentity      AssumedRole tsg-helpdesk-app")
    print("   what       eventSource       bedrock.amazonaws.com   eventName Converse")
    print("   where      awsRegion         us-east-1, and for a profile: additionalEventData.inferenceRegion")
    print("   said       (nothing)         CloudTrail keeps the call, not the conversation")


# ---------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("plan", cmd_plan), ("role", cmd_role), ("network", cmd_network), ("endpoint", cmd_endpoint),
                     ("keys", cmd_keys), ("logging", cmd_logging)):
        s = sub.add_parser(name)
        s.add_argument("plan", nargs="?", choices=list(PLANS), default="first-draft")
        if name == "keys":
            s.add_argument("key", nargs="?", help="show one key only, e.g. prompts")
        s.set_defaults(fn=fn)
    sub.add_parser("model").set_defaults(fn=cmd_model)
    sub.add_parser("record").set_defaults(fn=cmd_record)
    s = sub.add_parser("route")
    s.add_argument("target", nargs="?", default=COMPANY["approved"]["runtime_profile"])
    s.set_defaults(fn=cmd_route)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
