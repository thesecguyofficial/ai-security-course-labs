"""
attack.py: what can go wrong with TSG Helpdesk on Bedrock, deployed from a plan? And what would you see in the logs?

    python3 attack.py                      # the first draft  (twin/first-draft.plan.json + its Region guard SCP)
    python3 attack.py --plan hardened      # the hardened plan (twin/hardened.plan.json + org/scp-region-guard.json)

For every request it answers two questions:
  1. Would AWS allow it?  Checked by iam_eval.py (a teaching model of AWS policy evaluation) against the policies
     IN THE PLAN (the app role, the VPC endpoint policy), AnyCompany's org SCPs, and the network: can the request
     even leave the VPC?
  2. Who would know?      Which record it leaves in AnyCompany's account: CloudTrail event history, a trail
     (data events, network activity), and Bedrock model invocation logs (the prompt and the answer).

Nothing here talks to AWS. AnyCompany is fictional; all account IDs and ARNs are AWS documentation example values.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field

import plan as P
from iam_eval import DEFAULT_ENDPOINT_POLICY, Decision, Request, evaluate_all

COMPANY = json.loads((P.HERE / "anycompany.json").read_text())
ORG_ACCOUNTS = COMPANY["organization"]["accounts_in_org"]
REGION = "us-east-1"

PLANS = {"first-draft": "twin/first-draft.plan.json", "hardened": "twin/hardened.plan.json"}
REGION_GUARD = {"first-draft": "org/scp-region-guard.first-draft.json", "hardened": "org/scp-region-guard.json"}

# Where a us. profile called from us-east-1 may send a request (AWS model card for Claude Haiku 4.5:
# us-east-1, us-east-2, us-west-2). AWS evaluates the profile (source Region), then the foundation model in each
# candidate destination Region with aws:RequestedRegion = that Region and bedrock:InferenceProfileArn set.
# For a global. profile: the profile, the model in the source Region, and the Region-less model ARN
# arn:aws:bedrock:::foundation-model/... with aws:RequestedRegion = "unspecified".
US_DESTINATIONS = ["us-east-1", "us-east-2", "us-west-2"]


def principal(name: str) -> dict:
    return COMPANY["principals"][name]


def ctx(name: str, region: str, **extra) -> dict:
    c = {"aws:PrincipalAccount": principal(name)["account"], "aws:RequestedRegion": region}
    if principal(name)["account"] in ORG_ACCOUNTS:
        c["aws:PrincipalOrgID"] = COMPANY["organization"]["id"]
    c.update({k.replace("__", ":"): v for k, v in extra.items()})
    return c


def invoke(name: str, target: str, region: str = REGION) -> list[Request]:
    """InvokeModel / Converse, directly on a model or through a system-defined inference profile."""
    p = principal(name)
    if not target.startswith(("us.", "global.")):
        return [Request(p["arn"], "bedrock:InvokeModel", f"arn:aws:bedrock:{region}::foundation-model/{target}",
                        ctx(name, region))]
    prefix, fm = target.split(".", 1)
    profile = f"arn:aws:bedrock:{region}:{p['account']}:inference-profile/{target}"
    checks = [Request(p["arn"], "bedrock:InvokeModel", profile, ctx(name, region))]
    if prefix == "us":
        for dest in US_DESTINATIONS:
            checks.append(Request(p["arn"], "bedrock:InvokeModel", f"arn:aws:bedrock:{dest}::foundation-model/{fm}",
                                  ctx(name, dest, bedrock__InferenceProfileArn=profile)))
    else:
        checks.append(Request(p["arn"], "bedrock:InvokeModel", f"arn:aws:bedrock:{region}::foundation-model/{fm}",
                              ctx(name, region, bedrock__InferenceProfileArn=profile)))
        checks.append(Request(p["arn"], "bedrock:InvokeModel", f"arn:aws:bedrock:::foundation-model/{fm}",
                              ctx(name, "unspecified", bedrock__InferenceProfileArn=profile)))
    return checks


def mantle(name: str, model: str, region: str = REGION) -> list[Request]:
    """bedrock-mantle: bedrock-mantle:CreateInference on a project, model in the bedrock-mantle:Model key."""
    p = principal(name)
    return [Request(p["arn"], "bedrock-mantle:CreateInference",
                    f"arn:aws:bedrock-mantle:{region}:{p['account']}:project/default",
                    ctx(name, region, **{"bedrock-mantle__Model": model}))]


def call(name: str, action: str, resource: str = "*", region: str = REGION) -> list[Request]:
    return [Request(principal(name)["arn"], action, resource, ctx(name, region))]


@dataclass
class Step:
    sid: str
    actor: str
    what: str
    checks: list[Request]
    path: str                       # "endpoint" (bedrock-runtime VPC endpoint), "vpc-to-mantle", "internet"
    record: str                     # "runtime-invoke", "mantle-invoke", "control-plane"
    legit: bool = False
    expect: dict = field(default_factory=dict)  # {"first-draft": allowed?, "hardened": allowed?}


def app_target(plan: dict) -> str:
    fn = P.one(plan, "aws_lambda_function")
    return fn["values"]["environment"][0]["variables"]["MODEL_ID"]


def steps_for(plan: dict) -> list[Step]:
    s = [
        Step("X1", "outsider", "Outsider's own AWS keys, used from inside the VPC through AnyCompany's endpoint",
             invoke("outsider", "anthropic.claude-opus-4-7"), "endpoint", "runtime-invoke"),
        Step("X2", "helpdesk", "Stolen Helpdesk role: Converse with a model nobody approved (Claude Opus 4.7)",
             invoke("helpdesk", "anthropic.claude-opus-4-7"), "internet", "runtime-invoke"),
        Step("X3", "helpdesk", "Stolen Helpdesk role: the approved model, called directly in us-west-2 (no profile)",
             invoke("helpdesk", "anthropic.claude-haiku-4-5-20251001-v1:0", region="us-west-2"), "internet",
             "runtime-invoke"),
        Step("X4", "helpdesk", "Stolen Helpdesk role: the GLOBAL profile (may run outside the US)",
             invoke("helpdesk", "global.anthropic.claude-haiku-4-5-20251001-v1:0"), "internet", "runtime-invoke"),
        Step("X5", "helpdesk", "Stolen Helpdesk role: DeleteModelInvocationLoggingConfiguration",
             call("helpdesk", "bedrock:DeleteModelInvocationLoggingConfiguration"), "internet", "control-plane"),
        Step("X6", "helpdesk", "Stolen Helpdesk role: CreateProvisionedModelThroughput (billed by the hour)",
             call("helpdesk", "bedrock:CreateProvisionedModelThroughput",
                  f"arn:aws:bedrock:{REGION}::foundation-model/anthropic.claude-opus-4-7"), "internet", "control-plane"),
        Step("X7", "helpdesk", "A code change: the function calls bedrock-mantle (OpenAI SDK) from inside the VPC",
             mantle("helpdesk", "anthropic.claude-haiku-4-5"), "vpc-to-mantle", "mantle-invoke"),
        Step("L1", "helpdesk", f"Helpdesk function: Converse via its configured profile ({app_target(plan)})",
             invoke("helpdesk", app_target(plan)), "endpoint", "runtime-invoke", legit=True),
        Step("L2", "security-admin", "Security admin: GetModelInvocationLoggingConfiguration",
             call("security-admin", "bedrock:GetModelInvocationLoggingConfiguration"), "internet", "control-plane",
             legit=True),
    ]
    for st in s:
        st.expect = {"first-draft": True, "hardened": st.legit}
    return s


# ------------------------------------------------------------------ evaluation

def identity_policies(name: str, plan: dict) -> list[tuple[str, dict]]:
    if name == "helpdesk":
        out = []
        for r in P.resources(plan, "aws_iam_role_policy"):
            if any(ref.startswith("aws_iam_role.app") for ref in P.references(plan, r["address"], "role")):
                out.append((r["address"], P.policy(r["values"]["policy"])))
        return out
    return [(f"{name}-policy", principal(name)["inline_policy"])]


def endpoint_policy(plan: dict) -> tuple[str, dict]:
    for r in P.resources(plan, "aws_vpc_endpoint"):
        if r["values"]["service_name"].endswith(".bedrock-runtime"):
            doc = P.policy(r["values"].get("policy"))
            return (r["address"], doc) if doc else (f"{r['address']} (default policy)", DEFAULT_ENDPOINT_POLICY)
    return None


def scps(mode: str) -> list[tuple[str, dict]]:
    return [(n.split("/")[-1].removesuffix(".json"), P.load(n))
            for n in ("org/FullAWSAccess.json", REGION_GUARD[mode])]


def network_block(step: Step, plan: dict) -> str | None:
    """Can the request leave the VPC at all? Only requests made from inside the VPC are affected."""
    if step.path == "vpc-to-mantle":
        services = [r["values"]["service_name"] for r in P.resources(plan, "aws_vpc_endpoint")]
        has_internet = bool(P.resources(plan, "aws_nat_gateway"))
        if not has_internet and not any(s.endswith(".bedrock-mantle") for s in services):
            return "no network path: no NAT or internet gateway, and no bedrock-mantle endpoint in this VPC"
    return None


def run_step(step: Step, mode: str, plan: dict | None = None) -> Decision:
    plan = plan or P.load(PLANS[mode])
    blocked = network_block(step, plan)
    if blocked:
        return Decision(False, blocked)
    in_org = principal(step.actor)["account"] in ORG_ACCOUNTS
    ep = endpoint_policy(plan) if step.path == "endpoint" else None
    return evaluate_all(step.checks, identity_policies(step.actor, plan), scps(mode), scps_apply=in_org,
                        endpoint_policy=ep)


# ------------------------------------------------------------------ who would know?

def records(step: Step, plan: dict, decision: Decision) -> list[str]:
    allowed = decision.allowed
    if decision.reason.startswith("no network path"):
        return ["nothing: the request never left the VPC"]
    out = []
    if principal(step.actor)["account"] not in ORG_ACCOUNTS:
        out.append("CloudTrail: the API call is recorded in THEIR account's CloudTrail, not AnyCompany's")
        if _trail_selects(plan, "NetworkActivity"):
            denied = "" if allowed else ", refused at the endpoint (filter: errorCode VpceAccessDenied)"
            out.append(f"AnyCompany trail: network activity event, as the endpoint owner{denied}")
        else:
            out.append("AnyCompany: nothing (no trail records network activity on its endpoint)")
        return out
    if step.record in ("runtime-invoke", "control-plane"):
        err = "" if allowed else ", with an access-denied errorCode"
        out.append(f"CloudTrail event history: management event{err} (90 days, free)")
    if step.record == "runtime-invoke" and allowed:
        out.append(_prompt_log_line(plan))
    if step.record == "mantle-invoke":
        out.append("CloudTrail: data event in trail" if _trail_selects(plan, "AWS::BedrockMantle::Project")
                   else "CloudTrail: NOTHING (mantle inference is a data event, and no trail selects it)")
        if allowed:
            out.append("Prompt log: NOT captured (invocation logging covers bedrock-runtime only)")
    return out


def _trail_selects(plan: dict, needle: str) -> bool:
    for t in P.resources(plan, "aws_cloudtrail"):
        for sel in t["values"].get("advanced_event_selector") or []:
            for f in sel.get("field_selector") or []:
                if needle in (f.get("equals") or []):
                    return True
    return False


def _prompt_log_line(plan: dict) -> str:
    cfg = P.one(plan, "aws_bedrock_model_invocation_logging_configuration")
    if not cfg:
        return "Prompt log: none (invocation logging off)"
    lc = cfg["values"]["logging_config"][0]
    cw = (lc.get("cloudwatch_config") or [{}])[0]
    lg = next((g for g in P.resources(plan, "aws_cloudwatch_log_group")
               if g["values"].get("name") == cw.get("log_group_name")), None)
    if not lg:
        return "Prompt log: S3 only"
    key = "your KMS key" if P.known_or_referenced(plan, lg, "kms_key_id") else "no KMS key of yours"
    days = lg["values"].get("retention_in_days")
    keep = f"kept {days} days" if days else "kept FOREVER"
    return f"Prompt log: question + answer in {lg['values']['name']} ({key}, {keep})"


GROUPS = {"X": "Attacks and mistakes", "L": "Legitimate traffic · must keep working"}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", choices=list(PLANS), default="first-draft")
    ap.add_argument("--verbose", action="store_true", help="print every authorization check")
    a = ap.parse_args()
    plan = P.load(PLANS[a.plan])
    ep = endpoint_policy(plan)
    print(f"--- M11 lab · {a.plan.upper()} · {PLANS[a.plan]} ---")
    print(f"    org SCPs: FullAWSAccess, {REGION_GUARD[a.plan].split('/')[-1]} · endpoint policy: {ep[0] if ep else 'no endpoint'}")
    print("    (iam_eval.py: a teaching model of AWS policy evaluation; nothing is sent to AWS)\n")
    bad = n_bad = ok = n_ok = 0
    group = ""
    for s in steps_for(plan):
        if s.sid[0] != group:
            group = s.sid[0]
            print(GROUPS[group])
        d = run_step(s, a.plan, plan)
        print(f"  [{s.sid}] {'ALLOWED' if d.allowed else 'DENIED '}  {s.what}")
        print(f"         why:  {d.reason}")
        for line in records(s, plan, d):
            print(f"         seen: {line}")
        if a.verbose:
            for r in s.checks:
                print(f"         check {r.action} on {r.resource}  {r.context}")
        if s.legit:
            n_ok += 1
            ok += d.allowed
        else:
            n_bad += 1
            bad += d.allowed
        if s.sid == "X7":
            print()
    print(f"\n{bad} of {n_bad} attacks and mistakes allowed; {ok} of {n_ok} legitimate requests allowed.")


if __name__ == "__main__":
    main()
