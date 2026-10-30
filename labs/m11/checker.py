"""
checker.py: check a Terraform plan of TSG Helpdesk on Amazon Bedrock against the M11 controls.

    python3 checker.py                                  # the first draft (twin/first-draft.plan.json)
    python3 checker.py twin/hardened.plan.json          # the hardened version: expect 0 findings
    python3 checker.py my-plan.json                     # YOUR plan: terraform show -json tfplan > my-plan.json
    python3 checker.py --only=M11-05,M11-06             # just these rules (the exit code still counts all)

One rule per control, each tied to a lesson:
  11.1 least privilege    M11-01 to M11-03
  11.2 private network    M11-04 to M11-07
  11.3 encryption         M11-08, M11-13, M11-14
  11.4 logging            M11-09 to M11-12, M11-16, and M11-17 (yours: the challenge)
  11.5 residency          M11-15

It reads only what the plan says. It is a teaching tool, not a full policy engine: for real reviews, add IAM
Access Analyzer policy validation and a test in a sandbox. Standard library only, no network.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass

import plan as P
from iam_eval import action_matches

COMPANY = json.loads((P.HERE / "anycompany.json").read_text())
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Actions a chatbot's role never needs (lesson 11.1): they change logging, spend money or enable models.
NEVER_FOR_AN_APP = [
    "bedrock:DeleteModelInvocationLoggingConfiguration", "bedrock:PutModelInvocationLoggingConfiguration",
    "bedrock:CreateProvisionedModelThroughput", "bedrock:CreateModelCustomizationJob",
    "bedrock:CreateModelInvocationJob", "bedrock:PutUseCaseForModelAccess", "aws-marketplace:Subscribe",
    "bedrock-mantle:CreateInference", "bedrock-mantle:PutAccountDataRetention",
]


@dataclass
class Finding:
    rule: str
    severity: str
    where: str
    message: str
    fix: str


def _app_role_policies(plan: dict) -> list[tuple[str, dict]]:
    out = []
    for r in P.resources(plan, "aws_iam_role_policy"):
        role = r["values"].get("role")
        refs = P.references(plan, r["address"], "role")
        if any(ref.startswith("aws_iam_role.app") for ref in refs) or role == "tsg-helpdesk-app":
            out.append((r["address"], P.policy(r["values"].get("policy"))))
    return out


# ------------------------------------------------------------------ 11.1 least privilege

def rule_wildcard_actions(plan):
    """M11-01: the app role allows every action of a service (bedrock:*, bedrock-mantle:*, *)."""
    out = []
    for addr, doc in _app_role_policies(plan):
        for st in P.statements(doc):
            if st.get("Effect") != "Allow":
                continue
            wild = [a for a in P.as_list(st.get("Action")) if a == "*" or a.endswith(":*")]
            if wild:
                out.append(Finding("M11-01", "HIGH", f"{addr} [{st.get('Sid', 'no Sid')}]",
                                   f"The Helpdesk role allows {', '.join(wild)}: every model, every setting, both endpoints.",
                                   "List only bedrock:InvokeModel and bedrock:InvokeModelWithResponseStream (lesson 11.1)."))
    return out


def rule_any_model(plan):
    """M11-02: the app can invoke on Resource "*", or reach foundation models without going through its profile."""
    out = []
    for addr, doc in _app_role_policies(plan):
        for st in P.statements(doc):
            if st.get("Effect") != "Allow":
                continue
            if not any(action_matches(a, "bedrock:InvokeModel") for a in P.as_list(st.get("Action"))):
                continue
            res = P.as_list(st.get("Resource"))
            cond = json.dumps(st.get("Condition", {})).lower()
            if "*" in res:
                out.append(Finding("M11-02", "HIGH", f"{addr} [{st.get('Sid', 'no Sid')}]",
                                   "Can invoke ANY model, through any route, in any Region (Resource \"*\").",
                                   "Name the profile ARN, plus the model ARN in each destination Region with a "
                                   "bedrock:InferenceProfileArn condition (AWS's geographic example policy)."))
            elif any(":foundation-model/" in r for r in res) and "bedrock:inferenceprofilearn" not in cond:
                out.append(Finding("M11-02", "HIGH", f"{addr} [{st.get('Sid', 'no Sid')}]",
                                   "Can call the foundation model directly, in any listed Region, skipping the approved profile.",
                                   "Add a bedrock:InferenceProfileArn condition to the foundation-model statement."))
    return out


def rule_admin_actions(plan):
    """M11-03: the app role can change logging, buy capacity, enable models or use the mantle endpoint."""
    out = []
    for addr, doc in _app_role_policies(plan):
        hits = sorted({a for st in P.statements(doc) if st.get("Effect") == "Allow"
                       for pat in P.as_list(st.get("Action")) for a in NEVER_FOR_AN_APP if action_matches(pat, a)})
        if hits:
            out.append(Finding("M11-03", "MEDIUM", addr,
                               f"An app role that can also: {', '.join(h.split(':')[1] for h in hits)}.",
                               "Remove them. Logging belongs to the security admin; Marketplace subscriptions to the "
                               "platform team, once per approved model (lesson 11.1)."))
    return out


# ------------------------------------------------------------------ 11.2 private networking

def _runtime_endpoint(plan):
    for r in P.resources(plan, "aws_vpc_endpoint"):
        if r["values"].get("service_name", "").endswith(".bedrock-runtime"):
            return r
    return None


def rule_endpoint_exists(plan):
    """M11-04: no bedrock-runtime interface endpoint, or private DNS off, or the VPC can't resolve it."""
    ep = _runtime_endpoint(plan)
    vpc = P.one(plan, "aws_vpc")
    if not ep:
        return [Finding("M11-04", "HIGH", "network", "No bedrock-runtime interface endpoint: model calls leave the VPC.",
                        "Add aws_vpc_endpoint com.amazonaws.<region>.bedrock-runtime, Interface, private DNS on.")]
    out = []
    if not ep["values"].get("private_dns_enabled"):
        out.append(Finding("M11-04", "HIGH", ep["address"], "Private DNS is off: SDKs still resolve the public endpoint.",
                           "Set private_dns_enabled = true (or point the SDK at the endpoint URL)."))
    if vpc and not (vpc["values"].get("enable_dns_support") and vpc["values"].get("enable_dns_hostnames")):
        out.append(Finding("M11-04", "HIGH", vpc["address"], "The VPC can't use private DNS for interface endpoints.",
                           "Set enable_dns_support and enable_dns_hostnames to true."))
    return out


def rule_endpoint_policy(plan):
    """M11-05: the endpoint has the default policy (full access) or lets any principal through."""
    ep = _runtime_endpoint(plan)
    if not ep:
        return []
    doc = P.policy(ep["values"].get("policy"))
    if doc is None and not P.references(plan, ep["address"], "policy"):
        return [Finding("M11-05", "HIGH", ep["address"],
                        "No endpoint policy, so the default applies: any principal, any action, any resource. "
                        "Credentials from ANY AWS account work through this endpoint.",
                        "Attach a policy: only your account or org (aws:PrincipalAccount / aws:PrincipalOrgID), "
                        "only the invoke actions (lesson 11.2).")]
    out = []
    for st in P.statements(doc):
        if st.get("Effect") != "Allow":
            continue
        cond = json.dumps(st.get("Condition", {})).lower()
        if st.get("Principal") in ("*", {"AWS": "*"}) and not any(
                k in cond for k in ("aws:principalaccount", "aws:principalorgid", "aws:principalarn", "aws:principalorgpaths")):
            out.append(Finding("M11-05", "HIGH", f"{ep['address']} [{st.get('Sid', 'no Sid')}]",
                               "Principal \"*\" with no principal condition: credentials from any AWS account pass.",
                               "Add aws:PrincipalAccount or aws:PrincipalOrgID (identity perimeter)."))
        if "*" in P.as_list(st.get("Action")):
            out.append(Finding("M11-05", "MEDIUM", f"{ep['address']} [{st.get('Sid', 'no Sid')}]",
                               "Every Bedrock action is allowed through the endpoint.",
                               "List the actions the app calls."))
    return out


def rule_internet_path(plan):
    """M11-06: the app's network has a way to the internet, so the endpoint isn't the only door."""
    nat = P.resources(plan, "aws_nat_gateway")
    igw = P.resources(plan, "aws_internet_gateway")
    if nat or igw:
        what = ", ".join(r["address"] for r in nat + igw)
        return [Finding("M11-06", "HIGH", what,
                        "The app's VPC can reach the internet: it can call bedrock-mantle or any other public endpoint, "
                        "and the endpoint policy never sees those calls.",
                        "Remove the NAT/internet route; add an interface endpoint for each AWS service the app needs.")]
    return []


def rule_endpoint_sg(plan):
    """M11-07: the endpoint's security group accepts HTTPS from a whole CIDR instead of the app's group."""
    out = []
    for sg in P.resources(plan, "aws_security_group"):
        if "endpoint" not in sg["name"]:
            continue
        for rule in sg["values"].get("ingress") or []:
            if rule.get("cidr_blocks"):
                out.append(Finding("M11-07", "MEDIUM", sg["address"],
                                   f"Endpoint accepts HTTPS from {', '.join(rule['cidr_blocks'])}: anything in that range "
                                   "can use it.", "Allow 443 only from the app's security group."))
    return out


# ------------------------------------------------------------------ 11.3 / 11.4 logs, keys, buckets

def _prompt_log_group(plan):
    cfg = P.one(plan, "aws_bedrock_model_invocation_logging_configuration")
    if not cfg:
        return None
    lc = (cfg["values"].get("logging_config") or [{}])[0]
    cw = (lc.get("cloudwatch_config") or [{}])[0]
    name = cw.get("log_group_name")
    for lg in P.resources(plan, "aws_cloudwatch_log_group"):
        if lg["values"].get("name") == name:
            return lg
    return None


def rule_log_group_key(plan):
    """M11-08: prompts and answers sit in a log group without a customer managed key."""
    lg = _prompt_log_group(plan)
    if lg and not P.known_or_referenced(plan, lg, "kms_key_id"):
        return [Finding("M11-08", "HIGH", lg["address"],
                        "Prompt logs (every question and answer) are not encrypted with a key you control: logs read "
                        "access in IAM is all anyone needs to read them.",
                        "Set kms_key_id to a customer managed key whose policy limits who can decrypt (lesson 11.3).")]
    return []


def rule_log_retention(plan):
    """M11-09: prompt logs are kept forever."""
    lg = _prompt_log_group(plan)
    if lg and not lg["values"].get("retention_in_days"):
        return [Finding("M11-09", "MEDIUM", lg["address"], "Prompt logs never expire (no retention set).",
                        "Set retention_in_days to what investigations need, and an S3 lifecycle rule (lesson 11.4).")]
    return []


def rule_invocation_logging(plan):
    """M11-10: invocation logging off, text off, or CloudWatch-only with no bucket for large bodies."""
    cfg = P.one(plan, "aws_bedrock_model_invocation_logging_configuration")
    if not cfg:
        return [Finding("M11-10", "HIGH", "account", "Model invocation logging is not configured (it is off by default).",
                        "Add aws_bedrock_model_invocation_logging_configuration (lesson 11.4).")]
    lc = (cfg["values"].get("logging_config") or [{}])[0]
    out = []
    if not lc.get("text_data_delivery_enabled"):
        out.append(Finding("M11-10", "HIGH", cfg["address"], "Text delivery is off: prompts aren't logged.",
                           "text_data_delivery_enabled = true"))
    cw = (lc.get("cloudwatch_config") or [None])[0]
    if cw and not cw.get("large_data_delivery_s3_config") and not lc.get("s3_config"):
        out.append(Finding("M11-10", "MEDIUM", cfg["address"],
                           "CloudWatch only: request or response bodies over 100 KB, and binary data, can only go to S3, "
                           "so they are not logged.", "Add large_data_delivery_s3_config (an encrypted bucket)."))
    return out


def rule_modalities(plan):
    """M11-11: logging collects data types a text-only app never sends."""
    cfg = P.one(plan, "aws_bedrock_model_invocation_logging_configuration")
    if not cfg:
        return []
    lc = (cfg["values"].get("logging_config") or [{}])[0]
    extra = [k.split("_")[0] for k in ("image_data_delivery_enabled", "embedding_data_delivery_enabled",
                                       "video_data_delivery_enabled") if lc.get(k)]
    if extra:
        return [Finding("M11-11", "LOW", cfg["address"],
                        f"Also logs {', '.join(extra)} data, for every model in the account and Region.",
                        "Log only the modalities you need: logging applies to all models that use them.")]
    return []


def rule_logging_role(plan):
    """M11-12: the role Bedrock assumes to write logs can be used by any Bedrock configuration, or is over-broad."""
    out = []
    for role in P.resources(plan, "aws_iam_role"):
        trust = P.policy(role["values"].get("assume_role_policy"))
        for st in P.statements(trust):
            svc = P.as_list((st.get("Principal") or {}).get("Service") if isinstance(st.get("Principal"), dict) else None)
            if "bedrock.amazonaws.com" not in svc:
                continue
            cond = json.dumps(st.get("Condition", {})).lower()
            if "aws:sourceaccount" not in cond or "aws:sourcearn" not in cond:
                out.append(Finding("M11-12", "HIGH", role["address"],
                                   "Bedrock's service principal may assume this role with no check of which account or "
                                   "resource it acts for (no aws:SourceAccount and aws:SourceArn): confused deputy.",
                                   "Add both conditions, as in AWS's invocation-logging example (lesson 11.4)."))
    for rp in P.resources(plan, "aws_iam_role_policy"):
        if any(ref.startswith("aws_iam_role.bedrock_logging") for ref in P.references(plan, rp["address"], "role")):
            for st in P.statements(P.policy(rp["values"].get("policy"))):
                if "*" in P.as_list(st.get("Resource")) or any(a.endswith(":*") for a in P.as_list(st.get("Action"))):
                    out.append(Finding("M11-12", "MEDIUM", rp["address"],
                                       "The logging role can do far more than write one log stream.",
                                       "logs:CreateLogStream + logs:PutLogEvents on the log group's "
                                       "aws/bedrock/modelinvocations stream only."))
    return out


def rule_buckets(plan):
    """M11-13: a log bucket without KMS (customer managed key), public access block, ACLs off, or a TLS-only rule."""
    out = []
    for b in P.resources(plan, "aws_s3_bucket"):
        name = b["values"].get("bucket")

        def for_bucket(rtype):
            for r in P.resources(plan, rtype):
                refs = P.references(plan, r["address"], "bucket")
                if r["values"].get("bucket") == name or any(ref.startswith(b["address"]) for ref in refs):
                    return r
            return None

        sse = for_bucket("aws_s3_bucket_server_side_encryption_configuration")
        rule = ((sse or {}).get("values", {}).get("rule") or [{}])[0]
        dflt = (rule.get("apply_server_side_encryption_by_default") or [{}])[0]
        if not sse or dflt.get("sse_algorithm") != "aws:kms" or not P.known_or_referenced(
                plan, sse, "rule.apply_server_side_encryption_by_default.kms_master_key_id"):
            out.append(Finding("M11-13", "MEDIUM", b["address"], "Not encrypted with a customer managed KMS key.",
                               "SSE-KMS with your key, bucket_key_enabled = true."))
        pab = for_bucket("aws_s3_bucket_public_access_block")
        if not pab or not all(pab["values"].get(k) for k in ("block_public_acls", "block_public_policy",
                                                             "ignore_public_acls", "restrict_public_buckets")):
            out.append(Finding("M11-13", "MEDIUM", b["address"], "Public access is not fully blocked.",
                               "aws_s3_bucket_public_access_block with all four settings true."))
        own = for_bucket("aws_s3_bucket_ownership_controls")
        if not own or (own["values"].get("rule") or [{}])[0].get("object_ownership") != "BucketOwnerEnforced":
            out.append(Finding("M11-13", "MEDIUM", b["address"], "ACLs are enabled.",
                               "object_ownership = BucketOwnerEnforced (AWS: the bucket ACL must be disabled for the "
                               "logging bucket policy to take effect)."))
        pol = for_bucket("aws_s3_bucket_policy")
        doc = P.policy((pol or {}).get("values", {}).get("policy"))
        if not any(st.get("Effect") == "Deny" and "aws:securetransport" in json.dumps(st.get("Condition", {})).lower()
                   for st in P.statements(doc)):
            out.append(Finding("M11-13", "LOW", b["address"], "No rule refusing plain-HTTP requests.",
                               "Deny s3:* when aws:SecureTransport is false."))
    return out


def rule_keys(plan):
    """M11-14: a KMS key without rotation, or a key policy statement that any principal or any service caller can use."""
    out = []
    for k in P.resources(plan, "aws_kms_key"):
        if not k["values"].get("enable_key_rotation"):
            out.append(Finding("M11-14", "MEDIUM", k["address"], "Automatic key rotation is off.",
                               "enable_key_rotation = true"))
        for st in P.statements(P.policy(k["values"].get("policy"))):
            if st.get("Effect") != "Allow":
                continue
            pr = st.get("Principal")
            cond = json.dumps(st.get("Condition", {})).lower()
            if pr in ("*", {"AWS": "*"}) and not cond.strip("{}"):
                out.append(Finding("M11-14", "HIGH", f"{k['address']} [{st.get('Sid', 'no Sid')}]",
                                   "Any principal may use this key.", "Name the principals."))
            if isinstance(pr, dict) and "Service" in pr and not any(
                    c in cond for c in ("aws:sourcearn", "aws:sourceaccount", "kms:encryptioncontext", "kms:viaservice")):
                out.append(Finding("M11-14", "MEDIUM", f"{k['address']} [{st.get('Sid', 'no Sid')}]",
                                   f"{pr['Service']} may use the key on behalf of anyone.",
                                   "Add aws:SourceAccount/aws:SourceArn or an encryption-context condition."))
    if not P.resources(plan, "aws_kms_key"):
        out.append(Finding("M11-14", "MEDIUM", "account", "No customer managed keys: nothing but IAM decides who can read the prompt logs.",
                           "Create keys for prompt logs and for audit logs, with separate readers (lesson 11.3)."))
    return out


# ------------------------------------------------------------------ 11.5 residency

def rule_residency(plan):
    """M11-15: the app uses a global profile, or its role allows the Region-less (global) foundation-model ARN."""
    out = []
    allowed = COMPANY["data_residency"]["allowed_processing_regions"]
    for fn in P.resources(plan, "aws_lambda_function"):
        model = (((fn["values"].get("environment") or [{}])[0]).get("variables") or {}).get("MODEL_ID", "")
        if model.startswith("global."):
            out.append(Finding("M11-15", "HIGH", fn["address"],
                               f"MODEL_ID {model} is a GLOBAL profile: requests can be processed in any supported "
                               f"commercial Region. Residency rule: {COMPANY['data_residency']['rule']}",
                               "Use the geographic profile (us.) and allow-list only its destination Regions."))
    for addr, doc in _app_role_policies(plan):
        for st in P.statements(doc):
            for r in P.as_list(st.get("Resource")):
                if r.startswith("arn:aws:bedrock:::foundation-model/"):
                    out.append(Finding("M11-15", "HIGH", addr, "The role allows the Region-less global model ARN.",
                                       "Remove it; list the model in each allowed destination Region instead."))
                elif r.startswith("arn:aws:bedrock:") and r.split(":")[3] not in ("*", "", *allowed):
                    out.append(Finding("M11-15", "MEDIUM", addr, f"Allows a model in {r.split(':')[3]}, outside the "
                                       "allowed Regions.", "Remove that Region."))
    return out


def rule_trail(plan):
    """M11-16: no trail, so only the 90-day event history: no data events, no network activity, no integrity check."""
    trails = P.resources(plan, "aws_cloudtrail")
    if not trails:
        return [Finding("M11-16", "MEDIUM", "account",
                        "No CloudTrail trail: management events stay 90 days in event history; data events "
                        "(including bedrock-mantle inference) and endpoint network activity are not recorded at all.",
                        "Add a trail with log file validation and KMS, selecting the Bedrock data events you need.")]
    out = []
    for t in trails:
        if not t["values"].get("enable_log_file_validation"):
            out.append(Finding("M11-16", "MEDIUM", t["address"], "Log file validation is off.",
                               "enable_log_file_validation = true"))
        if not P.known_or_referenced(plan, t, "kms_key_id"):
            out.append(Finding("M11-16", "LOW", t["address"], "Trail logs not encrypted with your KMS key.",
                               "kms_key_id = your audit key"))
    return out


# ------------------------------------------------------------------ the challenge

def rule_trail_covers_mantle(plan):
    """M11-17 (YOUR TURN, lesson 11.4): flag a plan where NO trail records bedrock-mantle data events.

    Inference on the bedrock-mantle endpoint (OpenAI-compatible and Anthropic Messages APIs) is a CloudTrail DATA
    event with resources.type AWS::BedrockMantle::Project, and model invocation logging doesn't capture it at all.
    So unless a trail has an advanced event selector with eventCategory = Data and
    resources.type = AWS::BedrockMantle::Project, a mantle call leaves no record in your account.

    Return one Finding("M11-17", "HIGH", <where>, <message>, <fix>) when no trail in the plan has such a selector,
    and [] when one does. Look at t["values"]["advanced_event_selector"]: a list of
    {"name": ..., "field_selector": [{"field": ..., "equals": [...], ...}, ...]}.
    """
    return []  # TODO: write the rule (make challenge)


RULES = [rule_wildcard_actions, rule_any_model, rule_admin_actions, rule_endpoint_exists, rule_endpoint_policy,
         rule_internet_path, rule_endpoint_sg, rule_log_group_key, rule_log_retention, rule_invocation_logging,
         rule_modalities, rule_logging_role, rule_buckets, rule_keys, rule_residency, rule_trail,
         rule_trail_covers_mantle]


def run(path="twin/first-draft.plan.json") -> list[Finding]:
    plan = P.load(path)
    out = [f for rule in RULES for f in rule(plan)]
    return sorted(out, key=lambda f: (SEV_ORDER[f.severity], f.rule))


def main():
    args = [x for x in sys.argv[1:] if not x.startswith("--only")]
    only = [x.split("=", 1)[1] for x in sys.argv[1:] if x.startswith("--only=")]
    path = args[0] if args else "twin/first-draft.plan.json"
    findings = run(path)
    if only:    # --only=M11-08,M11-14: show just these rules (the exit code still counts every finding)
        keep = {r.strip().upper() for r in only[0].split(",")}
        shown = [f for f in findings if f.rule in keep]
        print(f"--- M11 plan checker · {path} · only {', '.join(sorted(keep))} ---\n")
        for f in shown:
            print(f"  {f.severity:<7} {f.rule}  {f.where}")
            print(f"          {f.message}")
            print(f"          fix: {f.fix}")
        print(f"\n{len(shown)} of {len(findings)} findings shown")
        sys.exit(1 if any(f.severity == "HIGH" for f in findings) else 0)
    print(f"--- M11 plan checker · {path} ---\n")
    for f in findings:
        print(f"  {f.severity:<7} {f.rule}  {f.where}")
        print(f"          {f.message}")
        print(f"          fix: {f.fix}")
    counts = {s: sum(f.severity == s for f in findings) for s in SEV_ORDER}
    print(f"\n{counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW  ({len(findings)} findings)")
    if not findings:
        print("No findings: every M11 control this checker knows about is in the plan.")
    sys.exit(1 if any(f.severity == "HIGH" for f in findings) else 0)


if __name__ == "__main__":
    main()
