"""
policy_checker.py: find the over-broad AI permissions in AnyCompany's AWS setup, before an attacker does.

    python3 policy_checker.py                       # AnyCompany today
    python3 policy_checker.py --with-fixes          # same, with the SCPs in fixes/ added to the org root
    python3 policy_checker.py --policy FILE.json    # lint one identity policy (e.g. your own)
    python3 policy_checker.py --scp FILE.json       # lint one SCP

It reads JSON files only. It is a teaching linter for the AI-specific mistakes in lessons 10.3 to 10.5, not a
replacement for IAM Access Analyzer (which checks grammar and 100+ general rules; see the README's optional AWS
step). Every rule says why it matters and what to do.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
from dataclasses import dataclass

from iam_eval import Request, action_matches, evaluate, load

HERE = pathlib.Path(__file__).resolve().parent
TODAY = dt.date(2026, 10, 14)          # the lab's "today", so the output never changes
SANDBOX_ACCOUNTS = {"444455556666"}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "WARNING": 3}


@dataclass
class Finding:
    rule: str
    severity: str
    where: str
    message: str
    fix: str

    def line(self) -> str:
        return f"  {self.severity:<7} {self.rule}  {self.where}\n          {self.message}\n          fix: {self.fix}"


def _list(x) -> list:
    return [] if x is None else (x if isinstance(x, list) else [x])


def _allows(st: dict, action: str) -> bool:
    return st.get("Effect") == "Allow" and any(action_matches(a, action) for a in _list(st.get("Action")))


def _sid(st: dict) -> str:
    return st.get("Sid", "no Sid")


# ---------------------------------------------------------------- identity policies

def check_identity_policy(name: str, policy: dict, purpose: str = "") -> list[Finding]:
    out = []
    for st in _list(policy.get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        res = _list(st.get("Resource"))
        any_res = "*" in res
        acts = _list(st.get("Action"))
        where = f"{name} [{_sid(st)}]"
        # M10-01: every Bedrock (or bedrock-mantle) action on every resource
        for svc, harm in (("bedrock", "any model, delete invocation logging, buy Provisioned Throughput"),
                          ("bedrock-mantle", "any model on the OpenAI-compatible endpoint, plus projects, files and fine-tuning")):
            if any(a in ("*", f"{svc}:*") for a in acts) and any_res:
                out.append(Finding("M10-01", "HIGH", where,
                                   f"Allows every {svc} action on every resource: {harm}.",
                                   "List only the actions the workload calls, on the exact model/profile ARNs (lesson 10.3)."))
        # M10-02: model invocation on any model, no condition
        invoke_any = any(action_matches(a, "bedrock:InvokeModel") or action_matches(a, "bedrock-mantle:CreateInference")
                         for a in acts) and not any(a in ("*", "bedrock:*", "bedrock-mantle:*") for a in acts)
        wide_res = any_res or any(r.endswith("foundation-model/*") for r in res)
        if invoke_any and wide_res and not st.get("Condition"):
            out.append(Finding("M10-02", "MEDIUM", where,
                               "Can invoke ANY model in ANY Region, including the most expensive ones.",
                               "Name the approved model and inference-profile ARNs, and back it with an org SCP allow-list."))
        # M10-03: can mint service-specific credentials (= long-term Bedrock API keys) without limits
        if _allows(st, "iam:CreateServiceSpecificCredential"):
            cond = json.dumps(st.get("Condition", {})).lower()
            if "servicespecificcredentialservicename" not in cond or "servicespecificcredentialagedays" not in cond:
                out.append(Finding("M10-03", "HIGH", where,
                                   "Can create long-term API keys (service-specific credentials) with no service or expiry limit.",
                                   "Add conditions on iam:ServiceSpecificCredentialServiceName and iam:ServiceSpecificCredentialAgeDays, "
                                   "and cap them org-wide with an SCP (lesson 10.4)."))
        # M10-04: can switch prompt logging off (only the security admin should)
        if purpose != "security-admin" and (_allows(st, "bedrock:DeleteModelInvocationLoggingConfiguration")
                                            or _allows(st, "bedrock:PutModelInvocationLoggingConfiguration")):
            out.append(Finding("M10-04", "MEDIUM", where,
                               "Can change or delete Bedrock model invocation logging: attackers check and switch it off.",
                               "Remove it from workload roles; deny it org-wide except your security admin role (SCP)."))
    return out


# ---------------------------------------------------------------- Bedrock API key inventory

def check_api_keys(name: str, p: dict) -> list[Finding]:
    out = []
    for k in p.get("bedrock_api_keys", []):
        if k.get("status") != "Active":
            continue
        where = f"{name} key {k['service_specific_credential_id']}"
        if not k.get("expires"):
            out.append(Finding("M10-05", "HIGH", where, "Long-term Bedrock API key that NEVER expires.",
                               "Deactivate it, move the caller to short-term keys or IAM roles; cap expiry with an SCP."))
        else:
            days = (dt.date.fromisoformat(k["expires"]) - TODAY).days
            if days > 90:
                out.append(Finding("M10-05", "HIGH", where, f"Long-term key valid for {days} more days.",
                                   "Shorten it; AWS recommends long-term keys for exploration only."))
        if p.get("account") not in SANDBOX_ACCOUNTS:
            out.append(Finding("M10-06", "HIGH", where,
                               f"Long-term Bedrock API key in account {p.get('account')}, which is not the sandbox.",
                               "AWS: long-term keys are for exploration; use short-term keys or roles in production (lesson 10.4)."))
    if p.get("bedrock_api_keys"):
        ident = [(pol, load(f"anycompany/{pol}")) for pol in p.get("policies", [])]
        probe = Request(p["arn"], "bedrock:CreateProvisionedModelThroughput",
                        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-4-7")
        any_model = Request(p["arn"], "bedrock:InvokeModel", "arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-opus-4-7")
        if evaluate(probe, ident, [], scps_apply=False).allowed or evaluate(any_model, ident, [], scps_apply=False).allowed:
            out.append(Finding("M10-07", "MEDIUM", name,
                               "The key's IAM user can invoke any model in any Region"
                               + (" and buy Provisioned Throughput" if evaluate(probe, ident, [], scps_apply=False).allowed else "")
                               + " (AmazonBedrockLimitedAccess is the console default).",
                               "Replace the managed policy with one that names the approved model ARNs only."))
    return out


# ---------------------------------------------------------------- SCPs

def check_scp(name: str, scp: dict) -> list[Finding]:
    out = []
    for st in _list(scp.get("Statement")):
        if st.get("Effect") != "Deny":
            continue
        where = f"{name} [{_sid(st)}]"
        acts = _list(st.get("Action"))
        if any(a in ("bedrock:*", "*") for a in acts) and "NotResource" in st:
            out.append(Finding("M10-12", "WARNING", where,
                               "Denies ALL Bedrock actions on everything except the listed models: that also blocks "
                               "Guardrails, Knowledge Bases, inference profiles and ListFoundationModels.",
                               "Scope the Action to bedrock:InvokeModel* and list approved inference-profile ARNs too."))
        res = _list(st.get("Resource"))
        if any("foundation-model/" in r for r in res):
            out.append(Finding("M10-09", "LOW", where,
                               "A deny-list: it blocks the models it names and allows every model released later.",
                               "Prefer an allow-list (Deny with NotResource = approved models). Keep deny-lists as a second layer."))
    return out


def check_org_scps(scps: list[tuple[str, dict]]) -> list[Finding]:
    """Questions about the whole set of SCPs on the org root."""
    out = []
    sts = [(n, st) for n, s in scps for st in _list(s.get("Statement")) if st.get("Effect") == "Deny"]

    def denies(action: str) -> bool:
        """A Deny that applies to the action on every resource (Resource "*"), whatever its conditions."""
        return any(any(action_matches(a, action) for a in _list(st.get("Action"))) and "*" in _list(st.get("Resource"))
                   for _, st in sts)

    allowlist_runtime = [(n, st) for n, st in sts if "NotResource" in st
                         and any(action_matches(a, "bedrock:InvokeModel") for a in _list(st.get("Action")))]
    if not allowlist_runtime:
        out.append(Finding("M10-08", "MEDIUM", "org root", "No SCP allow-lists models: every model AWS adds is usable on day one.",
                           "Add an SCP that denies bedrock:InvokeModel* with NotResource = approved model + profile ARNs."))
    mantle_guard = [st for _, st in sts if any(action_matches(a, "bedrock-mantle:CreateInference") for a in _list(st.get("Action")))
                    and "bedrock-mantle:model" in json.dumps(st.get("Condition", {})).lower()]
    if allowlist_runtime and not mantle_guard:
        out.append(Finding("M10-13", "MEDIUM", "org root",
                           "The model allow-list covers bedrock-runtime only. bedrock-mantle (OpenAI-compatible and Messages API endpoint) "
                           "uses a separate IAM namespace: bedrock-mantle:CreateInference is not limited.",
                           "Add a statement on bedrock-mantle:CreateInference using the bedrock-mantle:Model condition key."))
    if not denies("bedrock:DeleteModelInvocationLoggingConfiguration"):
        out.append(Finding("M10-10", "MEDIUM", "org root", "Nothing at org level stops a workload role from deleting Bedrock invocation logging.",
                           "SCP: deny Delete/PutModelInvocationLoggingConfiguration except for the security admin role."))
    if not denies("bedrock:CallWithBearerToken") and not denies("iam:CreateServiceSpecificCredential"):
        out.append(Finding("M10-11", "MEDIUM", "org root", "No SCP limits long-term Bedrock API keys (creation, expiry or use).",
                           "SCP: deny bedrock:CallWithBearerToken for LONG_TERM keys outside the sandbox; cap key age."))
    return out


# ---------------------------------------------------------------- run

def run(with_fixes: bool = False) -> list[Finding]:
    org = load("anycompany/principals.json")
    findings: list[Finding] = []
    seen_files = set()
    for name, p in org["principals"].items():
        for pol in p.get("policies", []):
            if pol in seen_files or pol.startswith("aws-managed/"):
                continue
            seen_files.add(pol)
            findings += check_identity_policy(pol, load(f"anycompany/{pol}"), p.get("purpose", ""))
        findings += check_api_keys(name, p)
    scp_files = list(org["organization"]["scps_on_root"])
    scps = [(f, load(f"anycompany/{f}")) for f in scp_files]
    if with_fixes:
        scps += [(f"../fixes/{f.name}", json.loads(f.read_text())) for f in sorted((HERE / "fixes").glob("scp-*.json"))]
    for n, s in scps:
        findings += check_scp(n, s)
    findings += check_org_scps(scps)
    return findings


def print_findings(findings: list[Finding], title: str, severity: str = "") -> None:
    print(f"--- M10 policy checker · {title}{' · showing ' + severity + ' only' if severity else ''} ---\n")
    for f in sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule, f.where)):
        if severity and f.severity != severity:
            continue
        print(f.line())
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    print("\n" + ", ".join(f"{v} {k}" for k, v in counts.items()) + f"  ({len(findings)} findings)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--with-fixes", action="store_true", help="add the SCPs in fixes/ to the org root")
    ap.add_argument("--policy", help="lint one identity policy JSON file")
    ap.add_argument("--scp", help="lint one SCP JSON file")
    ap.add_argument("--severity", choices=list(SEVERITY_ORDER), help="print only findings of this severity (the totals still count all)")
    a = ap.parse_args()
    if a.policy:
        print_findings(check_identity_policy(a.policy, json.loads(pathlib.Path(a.policy).read_text())), a.policy)
    elif a.scp:
        doc = json.loads(pathlib.Path(a.scp).read_text())
        print_findings(check_scp(a.scp, doc) + check_org_scps([(a.scp, doc)]), a.scp + " (as if it were the only deny SCP)")
    else:
        print_findings(run(a.with_fixes), "AnyCompany" + (" + fixes/ SCPs" if a.with_fixes else " today"), a.severity or "")


if __name__ == "__main__":
    main()
