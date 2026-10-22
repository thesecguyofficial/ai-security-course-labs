"""
attack.py: what can a thief do with AnyCompany's AWS AI setup? And what do the fixes stop?

    python3 attack.py --mode vulnerable   # AnyCompany's SCPs today: FullAWSAccess + a DeepSeek deny-list
    python3 attack.py --mode safe         # + the three SCPs in fixes/

Nothing here talks to AWS. Every request is checked by iam_eval.py, a small teaching model of AWS policy
evaluation, against the JSON policies in anycompany/ and fixes/. The attacker steps follow what Sysdig's Threat
Research Team reported from real LLMjacking intrusions (lesson 10.5): list the models, check whether invocation
logging is on, switch it off, then run expensive models.

All account IDs, ARNs and key IDs are AWS documentation example values. AnyCompany is fictional.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field

from iam_eval import Decision, Request, evaluate_all, load

ORG = load("anycompany/principals.json")
MGMT = ORG["organization"]["management_account"]
PROD, SANDBOX = "111122223333", "444455556666"

VULNERABLE_SCPS = ["anycompany/scps/FullAWSAccess.json", "anycompany/scps/deny-deepseek.json"]
FIX_SCPS = ["fixes/scp-model-allowlist.json", "fixes/scp-bedrock-api-keys.json",
            "fixes/scp-protect-ai-logging-and-spend.json"]

# Where each system-defined inference profile may send a request (for this lab). A real profile lists its
# Regions: `aws bedrock get-inference-profile --inference-profile-identifier <id>`. The us. profiles used here route
# from us-east-1 to us-east-1, us-east-2 and us-west-2 (AWS model cards for Nova Lite and Claude Haiku 4.5).
# For a global profile, AWS's example policy lists the foundation model in the source Region AND with an empty
# Region ("arn:aws:bedrock:::foundation-model/..."), so the lab checks both. "{src}" = the caller's Region.
PROFILE_REGIONS = {
    "us.": ["us-east-1", "us-east-2", "us-west-2"],
    "global.": ["{src}", ""],
}


def principal(name: str) -> dict:
    return ORG["principals"][name]


def identity_policies(name: str) -> list[tuple[str, dict]]:
    return [(p, load(f"anycompany/{p}")) for p in principal(name)["policies"]]


def base_ctx(name: str, region: str) -> dict:
    return {"aws:PrincipalAccount": principal(name)["account"], "aws:RequestedRegion": region}


def bearer_check(name: str, service: str, bearer: str | None, region: str) -> list[Request]:
    """A call made with a Bedrock API key is also authorized as <service>:CallWithBearerToken."""
    if not bearer:
        return []
    ctx = base_ctx(name, region) | {f"{service}:BearerTokenType": bearer}
    return [Request(principal(name)["arn"], f"{service}:CallWithBearerToken", "*", ctx)]


def invoke(name: str, model_or_profile: str, region: str = "us-east-1", bearer: str | None = None,
           action: str = "bedrock:InvokeModel") -> list[Request]:
    """InvokeModel / Converse (Converse is authorized as bedrock:InvokeModel). Through an inference profile,
    IAM checks the profile AND the foundation model in each destination Region."""
    arn = principal(name)["arn"]
    acct = principal(name)["account"]
    checks = bearer_check(name, "bedrock", bearer, region)
    prefix = next((p for p in PROFILE_REGIONS if model_or_profile.startswith(p)), None)
    if prefix is None:
        checks.append(Request(arn, action, f"arn:aws:bedrock:{region}::foundation-model/{model_or_profile}",
                              base_ctx(name, region)))
        return checks
    profile_arn = f"arn:aws:bedrock:{region}:{acct}:inference-profile/{model_or_profile}"
    fm = model_or_profile[len(prefix):]
    checks.append(Request(arn, action, profile_arn, base_ctx(name, region)))
    for dest in PROFILE_REGIONS[prefix]:
        dest = region if dest == "{src}" else dest
        ctx = base_ctx(name, region) | {"bedrock:InferenceProfileArn": profile_arn}
        checks.append(Request(arn, action, f"arn:aws:bedrock:{dest}::foundation-model/{fm}", ctx))
    return checks


def mantle(name: str, model: str, region: str = "us-east-1", bearer: str | None = None) -> list[Request]:
    """OpenAI-compatible / Messages API on bedrock-mantle.<region>.api.aws: a DIFFERENT IAM namespace,
    bedrock-mantle:CreateInference on a project, with the model in the bedrock-mantle:Model condition key."""
    p = principal(name)
    project = f"arn:aws:bedrock-mantle:{region}:{p['account']}:project/proj_example"
    return bearer_check(name, "bedrock-mantle", bearer, region) + [
        Request(p["arn"], "bedrock-mantle:CreateInference", project, base_ctx(name, region) | {"bedrock-mantle:Model": model})]


def call(name: str, action: str, resource: str = "*", region: str = "us-east-1", bearer: str | None = None,
         extra: dict | None = None) -> list[Request]:
    svc = action.split(":")[0]
    pre = bearer_check(name, svc, bearer, region) if svc in ("bedrock", "bedrock-mantle") else []
    return pre + [Request(principal(name)["arn"], action, resource, base_ctx(name, region) | (extra or {}))]


@dataclass
class Step:
    sid: str
    actor: str
    what: str
    checks: list[Request]
    legit: bool = False
    note: str = ""
    expect: dict = field(default_factory=dict)   # {"vulnerable": bool, "safe": bool} = allowed?


KEY = "BedrockAPIKey-x7k2"
ROLE = "HelpdeskAppRole"

STEPS = [
    # Attacker 1: a long-term Bedrock API key leaked (prod account, never expires, AmazonBedrockLimitedAccess)
    Step("A1", KEY, "ListFoundationModels: which models can I reach?", call(KEY, "bedrock:ListFoundationModels", bearer="LONG_TERM"),
         expect={"vulnerable": True, "safe": False}),
    Step("A2", KEY, "GetModelInvocationLoggingConfiguration: is anyone logging prompts?",
         call(KEY, "bedrock:GetModelInvocationLoggingConfiguration", bearer="LONG_TERM"), expect={"vulnerable": True, "safe": False}),
    Step("A3", KEY, "Converse with an expensive model nobody approved (Claude Opus 4.7)",
         invoke(KEY, "anthropic.claude-opus-4-7", bearer="LONG_TERM"), expect={"vulnerable": True, "safe": False}),
    Step("A4", KEY, "Same model through the OpenAI-compatible bedrock-mantle endpoint",
         mantle(KEY, "anthropic.claude-opus-4-7", bearer="LONG_TERM"), expect={"vulnerable": True, "safe": False}),
    Step("A5", KEY, "CreateProvisionedModelThroughput: buy capacity billed by the hour",
         call(KEY, "bedrock:CreateProvisionedModelThroughput", "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-4-7",
              bearer="LONG_TERM"), expect={"vulnerable": True, "safe": False}),
    # Attacker 2: stolen temporary credentials of the chatbot's role (e.g. read from a vulnerable web server)
    Step("B1", ROLE, "DeleteModelInvocationLoggingConfiguration: switch off prompt logging",
         call(ROLE, "bedrock:DeleteModelInvocationLoggingConfiguration"), expect={"vulnerable": True, "safe": False}),
    Step("B2", ROLE, "Converse through the GLOBAL Claude Opus 4.7 profile (not approved)",
         invoke(ROLE, "global.anthropic.claude-opus-4-7"), expect={"vulnerable": True, "safe": False}),
    Step("B3", ROLE, "InvokeModel on a DeepSeek model (the old deny-list catches this one)",
         invoke(ROLE, "deepseek.r1-v1:0"), expect={"vulnerable": False, "safe": False}),
    Step("B4", ROLE, "bedrock-mantle CreateInference with an unapproved model (no API key: plain SigV4)",
         mantle(ROLE, "anthropic.claude-opus-4-7"), note="challenge", expect={"vulnerable": True, "safe": True}),
    # Attacker 3: a sandbox admin (or someone who phished one) makes a key that never expires
    Step("C1", "SandboxAdminRole", "CreateServiceSpecificCredential for Bedrock with NO expiry (never expires)",
         call("SandboxAdminRole", "iam:CreateServiceSpecificCredential", "arn:aws:iam::444455556666:user/sandbox-explorer",
              extra={"iam:ServiceSpecificCredentialServiceName": "bedrock.amazonaws.com"}),
         note="challenge", expect={"vulnerable": True, "safe": True}),
    Step("C2", "SandboxAdminRole", "CreateServiceSpecificCredential for Bedrock valid for 365 days",
         call("SandboxAdminRole", "iam:CreateServiceSpecificCredential", "arn:aws:iam::444455556666:user/sandbox-explorer",
              extra={"iam:ServiceSpecificCredentialServiceName": "bedrock.amazonaws.com", "iam:ServiceSpecificCredentialAgeDays": "365"}),
         expect={"vulnerable": True, "safe": False}),
    # Legitimate traffic: the fixes must not break it
    Step("L1", ROLE, "Helpdesk chatbot: Converse via the approved US cross-Region profile",
         invoke(ROLE, "us.anthropic.claude-haiku-4-5-20251001-v1:0"), legit=True),
    Step("L2", ROLE, "Helpdesk chatbot: ApplyGuardrail on its guardrail",
         call(ROLE, "bedrock:ApplyGuardrail", "arn:aws:bedrock:us-east-1:111122223333:guardrail/gr-helpdesk-example"), legit=True),
    Step("L3", ROLE, "Helpdesk chatbot: Retrieve from its knowledge base",
         call(ROLE, "bedrock:Retrieve", "arn:aws:bedrock:us-east-1:111122223333:knowledge-base/KBHELPDESK1"), legit=True),
    Step("L4", ROLE, "Helpdesk chatbot: approved model (Claude Haiku 4.5) on the bedrock-mantle endpoint",
         mantle(ROLE, "anthropic.claude-haiku-4-5"), legit=True),
    Step("L5", "DataScienceRole", "Data science: InvokeModel on approved Nova Lite in us-west-2",
         invoke("DataScienceRole", "amazon.nova-lite-v1:0", region="us-west-2"), legit=True),
    Step("L6", "SecurityAdmin", "Security admin: PutModelInvocationLoggingConfiguration (turn logging on)",
         call("SecurityAdmin", "bedrock:PutModelInvocationLoggingConfiguration"), legit=True),
    Step("L7", "SandboxAdminRole", "Sandbox admin: a Bedrock API key that expires in 30 days",
         call("SandboxAdminRole", "iam:CreateServiceSpecificCredential", "arn:aws:iam::444455556666:user/sandbox-explorer",
              extra={"iam:ServiceSpecificCredentialServiceName": "bedrock.amazonaws.com", "iam:ServiceSpecificCredentialAgeDays": "30"}),
         legit=True),
    Step("L8", "sandbox-explorer", "Sandbox user: Converse on Nova Lite with their 30-day API key",
         invoke("sandbox-explorer", "amazon.nova-lite-v1:0", bearer="LONG_TERM"), legit=True),
    Step("L9", "PlatformAdminRole", "Platform admin: CreateProvisionedModelThroughput (approved purchase)",
         call("PlatformAdminRole", "bedrock:CreateProvisionedModelThroughput",
              "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1:0"), legit=True),
]
for s in STEPS:
    if s.legit:
        s.expect = {"vulnerable": True, "safe": True}


def scps_for(mode: str, allowlist: str | None = None) -> list[tuple[str, dict]]:
    fixes = [allowlist if (allowlist and f.endswith("model-allowlist.json")) else f for f in FIX_SCPS]
    names = VULNERABLE_SCPS + (fixes if mode == "safe" else [])
    return [(n.split("/")[-1].removesuffix(".json"), load(n)) for n in names]


def run_step(step: Step, mode: str, allowlist: str | None = None) -> Decision:
    acct = principal(step.actor)["account"]
    return evaluate_all(step.checks, identity_policies(step.actor), scps_for(mode, allowlist), scps_apply=(acct != MGMT))


ACTORS = {
    "A": f"Attacker 1 · a long-term Bedrock API key for IAM user {KEY} leaked (prod account, never expires)",
    "B": f"Attacker 2 · stolen temporary credentials of {ROLE} (identity policy: bedrock:* and bedrock-mantle:* on *)",
    "C": "Attacker 3 · a sandbox admin session used to mint long-lived keys",
    "L": "Legitimate traffic · must keep working after the fixes",
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["vulnerable", "safe"], default="vulnerable")
    ap.add_argument("--verbose", action="store_true", help="print every authorization check")
    ap.add_argument("--allowlist", help="safe mode: use this model allow-list SCP instead of fixes/scp-model-allowlist.json")
    a = ap.parse_args()
    names = ", ".join(n for n, _ in scps_for(a.mode, a.allowlist))
    print(f"--- M10 lab · {a.mode.upper()} · SCPs on the org root: {names} ---")
    print("    (iam_eval.py: a teaching model of AWS policy evaluation; nothing is sent to AWS)\n")
    attacks_allowed = attacks = legit_ok = legits = 0
    group = ""
    for s in STEPS:
        if s.sid[0] != group:
            group = s.sid[0]
            print(ACTORS[group])
        d = run_step(s, a.mode, a.allowlist)
        tag = "ALLOWED" if d.allowed else "DENIED "
        flag = ""
        if not s.legit and d.allowed and a.mode == "safe" and s.note == "challenge":
            flag = "   <-- still open: make challenge"
        print(f"  [{s.sid}] {tag}  {s.what}{flag}")
        print(f"         why: {d.reason}")
        if a.verbose:
            for r in s.checks:
                print(f"           check {r.action} on {r.resource}")
        if s.legit:
            legits += 1
            legit_ok += d.allowed
        else:
            attacks += 1
            attacks_allowed += d.allowed
        if s.sid in ("A5", "B4", "C2"):
            print()
    print()
    print(f"{attacks_allowed} of {attacks} attacker requests allowed; {legit_ok} of {legits} legitimate requests allowed.")


if __name__ == "__main__":
    main()
