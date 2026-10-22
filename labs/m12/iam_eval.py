"""
iam_eval.py: a SMALL TEACHING MODEL of IAM policy evaluation, enough for lesson 12.3. It is not the AWS policy engine.

Rules it follows (AWS IAM User Guide, policy evaluation logic and condition operators):
  * no Allow = implicit deny; an explicit Deny beats any Allow
  * Action and Resource support * and ? wildcards
  * condition operators: StringEquals, StringNotEquals, StringLike, StringNotLike, ArnLike, ArnNotLike (+ ...IfExists)
  * a key missing from the request: a positive operator is FALSE, a negated operator (StringNotEquals, ArnNotLike...)
    is TRUE, so a Deny with a negated operator applies to requests that carry no guardrail at all
It does not model SCPs, RCPs, permissions boundaries, session policies or resource-based policies. Use IAM Access Analyzer
and the IAM policy simulator (README Step 8) for real policies.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field


@dataclass
class Request:
    action: str
    resources: list[str]
    context: dict = field(default_factory=dict)


def _as_list(x):
    return x if isinstance(x, list) else [x]


def _match(pattern: str, value: str) -> bool:
    return fnmatch.fnmatchcase(value, pattern)


def _cond_ok(op: str, key: str, expected, ctx: dict) -> bool:
    if_exists = op.endswith("IfExists")
    base = op[:-8] if if_exists else op
    present = key in ctx
    if not present:
        if if_exists:
            return True
        return "Not" in base  # negated operators are true when the key is missing
    value = str(ctx[key])
    expected = [str(e) for e in _as_list(expected)]
    if base in ("StringEquals", "ArnEquals"):
        return value in expected
    if base in ("StringNotEquals", "ArnNotEquals"):
        return value not in expected
    if base in ("StringLike", "ArnLike"):
        return any(_match(e, value) for e in expected)
    if base in ("StringNotLike", "ArnNotLike"):
        return not any(_match(e, value) for e in expected)
    raise ValueError(f"operator not modelled: {op}")


def _statement_applies(st: dict, req: Request, resource: str) -> bool:
    if not any(_match(a.lower(), req.action.lower()) for a in _as_list(st.get("Action", []))):
        return False
    if not any(_match(r, resource) for r in _as_list(st.get("Resource", []))):
        return False
    for op, kv in (st.get("Condition") or {}).items():
        for key, expected in kv.items():
            if not _cond_ok(op, key, expected, req.context):
                return False
    return True


def evaluate(policy: dict, req: Request) -> tuple[bool, str]:
    """Every resource in the request must be allowed and none denied. Returns (allowed, reason)."""
    for resource in req.resources:
        allowed_by = None
        for st in policy.get("Statement", []):
            if _statement_applies(st, req, resource):
                if st["Effect"] == "Deny":
                    return False, f"explicit Deny ({st.get('Sid', 'no Sid')}) on {resource}"
                allowed_by = st.get("Sid", "an Allow")
        if not allowed_by:
            return False, f"implicit deny: nothing allows {req.action} on {resource}"
    return True, "allowed"
