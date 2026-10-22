"""
iam_eval.py: a small, readable model of how AWS decides "allowed or denied" for one request.

It is a TEACHING MODEL, not the real AWS policy engine. It covers what this lab needs:

  * identity-based policies (attached to a user or role) and service control policies (SCPs)
  * Effect Allow/Deny, Action/NotAction, Resource/NotResource, wildcards * and ?
  * condition operators: String*, Arn*, Numeric*, Bool, Null, the ...IfExists suffix,
    and the ForAnyValue:/ForAllValues: prefixes
  * the documented rules this lab relies on:
      - no matching Allow  -> denied (implicit deny)
      - any matching Deny  -> denied, whatever allows it (explicit deny wins)
      - an SCP never grants anything; the request must be allowed by the identity policy AND the SCPs
      - SCPs don't apply to the management account (we model that with a flag)
      - a condition key missing from the request makes a normal operator FALSE,
        a negated operator (StringNotLike, ArnNotLike, ...) TRUE; Null tests presence;
        ForAllValues with a missing key is TRUE, ForAnyValue with a missing key is FALSE
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html

It does NOT model: resource-based policies, RCPs, permissions boundaries, session policies, VPC endpoint policies,
every condition operator, or the IAM policy grammar checks. Use IAM Access Analyzer (README, optional AWS step)
to validate real policies.

Standard library only. No network.
"""

from __future__ import annotations

import fnmatch
import json
import pathlib
from dataclasses import dataclass, field

HERE = pathlib.Path(__file__).resolve().parent


def load(path: str | pathlib.Path) -> dict:
    p = pathlib.Path(path)
    if not p.is_absolute():
        p = HERE / p
    return json.loads(p.read_text())


def _as_list(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


# ---------------------------------------------------------------- matching

def _glob(pattern: str, value: str, case_sensitive: bool = True) -> bool:
    """IAM-style wildcard match: * = any run of characters (including none), ? = exactly one."""
    if not case_sensitive:
        pattern, value = pattern.lower(), value.lower()
    # fnmatch also treats [..] as a character class; IAM doesn't, so escape '['.
    pattern = pattern.replace("[", "[[]")
    return fnmatch.fnmatchcase(value, pattern)


def action_matches(pattern: str, action: str) -> bool:
    """Actions are case-insensitive: 'bedrock:invokemodel' == 'bedrock:InvokeModel'."""
    return _glob(pattern, action, case_sensitive=False)


def arn_matches(pattern: str, arn: str) -> bool:
    """Match an ARN segment by segment. The 6th segment (the resource) may itself contain ':',
    e.g. 'foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0'."""
    if pattern == "*":
        return True
    p_parts, a_parts = pattern.split(":", 5), arn.split(":", 5)
    if len(p_parts) != 6 or len(a_parts) != 6:
        return _glob(pattern, arn)
    return all(_glob(p, a) for p, a in zip(p_parts, a_parts))


# ---------------------------------------------------------------- conditions

def _cond_value_match(base_op: str, policy_vals: list, req_val) -> bool:
    """True if req_val (one value) matches ANY of the policy values under base_op (positive form)."""
    rv = str(req_val)
    for pv in policy_vals:
        pv = str(pv)
        if base_op in ("StringEquals",) and rv == pv:
            return True
        if base_op == "StringEqualsIgnoreCase" and rv.lower() == pv.lower():
            return True
        if base_op == "StringLike" and _glob(pv, rv):
            return True
        if base_op in ("ArnEquals",) and rv == pv:
            return True
        if base_op == "ArnLike" and arn_matches(pv, rv):
            return True
        if base_op.startswith("Numeric"):
            try:
                a, b = float(rv), float(pv)
            except ValueError:
                continue
            if (base_op == "NumericEquals" and a == b) or (base_op == "NumericLessThan" and a < b) \
                    or (base_op == "NumericLessThanEquals" and a <= b) or (base_op == "NumericGreaterThan" and a > b) \
                    or (base_op == "NumericGreaterThanEquals" and a >= b):
                return True
        if base_op == "Bool" and rv.lower() == pv.lower():
            return True
    return False


NEGATED = {
    "StringNotEquals": "StringEquals",
    "StringNotEqualsIgnoreCase": "StringEqualsIgnoreCase",
    "StringNotLike": "StringLike",
    "ArnNotEquals": "ArnEquals",
    "ArnNotLike": "ArnLike",
    "NumericNotEquals": "NumericEquals",
}


def _lookup(context: dict, key: str):
    """Condition key names are case-insensitive. Returns (present, value)."""
    for k, v in context.items():
        if k.lower() == key.lower():
            return True, v
    return False, None


def condition_matches(condition: dict | None, context: dict) -> bool:
    """All operators must be true (AND); within an operator all keys must be true (AND);
    a key with several values is true if the request value matches ANY of them (OR)."""
    if not condition:
        return True
    for raw_op, keys in condition.items():
        op = raw_op
        set_op = None
        if ":" in op:
            set_op, op = op.split(":", 1)            # ForAnyValue / ForAllValues
        if_exists = op.endswith("IfExists")
        if if_exists:
            op = op[: -len("IfExists")]
        for key, pvals in keys.items():
            pvals = _as_list(pvals)
            present, rval = _lookup(context, key)
            if op == "Null":
                want_absent = str(pvals[0]).lower() == "true"
                if want_absent != (not present):
                    return False
                continue
            if not present:
                if if_exists:
                    continue                          # ...IfExists: missing key -> true
                if set_op == "ForAllValues":
                    continue                          # ForAllValues: missing key -> true (IAM docs; pair it with Null)
                if set_op == "ForAnyValue":
                    return False                      # ForAnyValue: missing key -> false
                if op in NEGATED:
                    continue                          # negated operator: missing key -> true
                return False                          # normal operator: missing key -> false
            negated = op in NEGATED
            base = NEGATED.get(op, op)
            rvals = _as_list(rval)

            def one(v) -> bool:                       # does ONE request value satisfy the (possibly negated) operator?
                hit = _cond_value_match(base, pvals, v)
                return not hit if negated else hit

            if set_op == "ForAllValues":
                ok = all(one(v) for v in rvals)       # every request value must satisfy it
            elif set_op == "ForAnyValue":
                ok = any(one(v) for v in rvals)       # at least one request value must satisfy it
            else:                                     # single-valued key
                ok = one(rvals[0]) if rvals else False
            if not ok:
                return False
    return True


# ---------------------------------------------------------------- statements and requests

@dataclass
class Request:
    """One authorization check: a principal asks to do `action` on `resource`."""
    principal_arn: str
    action: str
    resource: str = "*"
    context: dict = field(default_factory=dict)
    label: str = ""


def statement_matches(st: dict, req: Request) -> bool:
    if "Action" in st:
        if not any(action_matches(a, req.action) for a in _as_list(st["Action"])):
            return False
    elif "NotAction" in st:
        if any(action_matches(a, req.action) for a in _as_list(st["NotAction"])):
            return False
    if "Resource" in st:
        if not any(arn_matches(r, req.resource) for r in _as_list(st["Resource"])):
            return False
    elif "NotResource" in st:
        if any(arn_matches(r, req.resource) for r in _as_list(st["NotResource"])):
            return False
    ctx = dict(req.context)
    ctx.setdefault("aws:PrincipalArn", req.principal_arn)
    return condition_matches(st.get("Condition"), ctx)


def _statements(policy: dict) -> list[dict]:
    return _as_list(policy.get("Statement"))


@dataclass
class Decision:
    allowed: bool
    reason: str

    def __str__(self) -> str:
        return ("ALLOWED  " if self.allowed else "DENIED   ") + self.reason


def evaluate(req: Request, identity_policies: list[tuple[str, dict]], scps: list[tuple[str, dict]],
             scps_apply: bool = True) -> Decision:
    """identity_policies / scps: lists of (name, policy_document)."""
    # 1. Explicit deny anywhere wins.
    for name, pol in identity_policies:
        for st in _statements(pol):
            if st.get("Effect") == "Deny" and statement_matches(st, req):
                return Decision(False, f"explicit Deny in identity policy {name} ({st.get('Sid', 'no Sid')})")
    if scps_apply:
        for name, pol in scps:
            for st in _statements(pol):
                if st.get("Effect") == "Deny" and statement_matches(st, req):
                    return Decision(False, f"explicit Deny in SCP {name} ({st.get('Sid', 'no Sid')})")
        # 2. An SCP must also ALLOW the action (FullAWSAccess usually does). SCPs never grant on their own.
        if not any(st.get("Effect") == "Allow" and statement_matches(st, req)
                   for _, pol in scps for st in _statements(pol)):
            return Decision(False, "no SCP allows it (implicit deny from the SCPs)")
    # 3. The identity policy must allow it.
    for name, pol in identity_policies:
        for st in _statements(pol):
            if st.get("Effect") == "Allow" and statement_matches(st, req):
                return Decision(True, f"allowed by {name} ({st.get('Sid', 'no Sid')})")
    return Decision(False, "no identity policy allows it (implicit deny)")


def evaluate_all(reqs: list[Request], identity_policies, scps, scps_apply: bool = True) -> Decision:
    """Some API calls need several authorization checks (e.g. a call through a cross-Region inference
    profile checks the profile AND the foundation model in the destination Region; a call made with a
    Bedrock API key also checks CallWithBearerToken). All must pass."""
    for r in reqs:
        d = evaluate(r, identity_policies, scps, scps_apply)
        if not d.allowed:
            return Decision(False, f"{d.reason}  [check: {r.action} on {r.resource}]")
    return Decision(True, "every check passed: " + "; ".join(f"{r.action}" for r in reqs))


if __name__ == "__main__":
    # Tiny self-demo of the missing-key rule that lesson 10.4 relies on.
    deny_old_keys = {"Statement": [{"Effect": "Deny", "Action": "iam:CreateServiceSpecificCredential",
                                    "Resource": "*", "Condition": {"NumericGreaterThan":
                                                                   {"iam:ServiceSpecificCredentialAgeDays": "30"}}}]}
    allow_all = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    for ctx in ({"iam:ServiceSpecificCredentialAgeDays": "90"}, {}):
        r = Request("arn:aws:iam::111122223333:user/example", "iam:CreateServiceSpecificCredential", "*", ctx)
        print(ctx or "{no age in the request}", "->", evaluate(r, [("allow-all", allow_all)], [("deny-old-keys", deny_old_keys), ("FullAWSAccess", allow_all)]))
