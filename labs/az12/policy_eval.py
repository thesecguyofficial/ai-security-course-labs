"""
policy_eval.py: evaluate Microsoft's built-in content-filtering policy definitions (copied verbatim into
policy-definitions/ from github.com/Azure/azure-policy) against the lab's deployments, OFFLINE.

It understands exactly the operators these six definitions use: field + equals / in / notIn, count + where, allOf,
anyOf and [parameters('...')]. Azure Policy compares strings case-insensitively; so does this.
It is a teaching evaluator, not Azure Policy: Azure evaluates `Microsoft.CognitiveServices.Data` resource-provider
mode policies itself, on its own schedule ("It takes some time for Azure Policy to perform a compliance scan").
"""

import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))


def load_definition(file_name: str) -> dict:
    with open(os.path.join(HERE, "policy-definitions", file_name), encoding="utf-8") as f:
        return json.load(f)


def _norm(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v).lower()


def _param(v, params):
    if isinstance(v, str):
        m = re.fullmatch(r"\[parameters\('([^']+)'\)\]", v)
        if m:
            return params[m.group(1)]
    return v


def _field(path: str, res: dict, item: dict | None):
    if path == "type":
        return res["type"]
    tail = re.sub(r"^Microsoft\.CognitiveServices\.Data/accounts/(projects/agents|deployments)/", "", path)
    if tail.startswith("raiPolicy.contentFilters[*]."):
        return (item or {}).get(tail.split(".")[-1])
    if tail == "raiPolicy.mode":
        return res.get("raiPolicy", {}).get("mode")
    return res.get(tail)


def _cond(c: dict, res: dict, params: dict, item: dict | None = None) -> bool:
    if "allOf" in c:
        return all(_cond(x, res, params, item) for x in c["allOf"])
    if "anyOf" in c:
        return any(_cond(x, res, params, item) for x in c["anyOf"])
    if "count" in c:
        items = res.get("raiPolicy", {}).get("contentFilters", [])
        where = c["count"].get("where")
        n = sum(1 for it in items if where is None or _cond(where, res, params, it))
        return n == int(_param(c["equals"], params))
    val = _field(c["field"], res, item)
    if "equals" in c:
        return _norm(val) == _norm(_param(c["equals"], params))
    if "in" in c:
        return _norm(val) in [_norm(x) for x in _param(c["in"], params)]
    if "notIn" in c:
        return _norm(val) not in [_norm(x) for x in _param(c["notIn"], params)]
    raise ValueError(f"operator not supported by this teaching evaluator: {c}")


def evaluate(definition: dict, parameters: dict, res: dict) -> str:
    """Returns 'NonCompliant' when the rule's `if` matches (effect Audit), else 'Compliant'."""
    props = definition["properties"]
    params = {k: v.get("defaultValue") for k, v in props["parameters"].items()}
    params.update(parameters or {})
    if params.get("effect", "Audit") == "Disabled":
        return "Compliant"
    return "NonCompliant" if _cond(props["policyRule"]["if"], res, params) else "Compliant"


def deployment_resource(folder: str, deployment: dict) -> dict:
    """The deployment as Azure Policy sees it: its guardrail resolved into raiPolicy.*"""
    import guardrail_twin as gt
    pol = gt.resolve_policy(folder, deployment["properties"]["raiPolicyName"])
    return {"type": "Microsoft.CognitiveServices.Data/accounts/deployments", "name": deployment["name"],
            "raiPolicy": {"mode": pol["properties"].get("mode", "Default"), "contentFilters": pol["properties"].get("contentFilters", [])}}


def compliance(folder: str, assignments_folder: str | None = None) -> list[dict]:
    """Evaluate every assignment in <assignments_folder>/policy-assignments.json against <folder>'s deployments."""
    import guardrail_twin as gt
    assigns = gt.load(assignments_folder or folder, "policy-assignments.json")["assignments"]
    out = []
    for dep in gt.load(folder, "deployments.json")["deployments"]:
        res = deployment_resource(folder, dep)
        for a in assigns:
            d = load_definition(a["definition"])
            if d["properties"]["policyRule"]["if"]["allOf"][0]["equals"] != res["type"]:
                continue
            out.append({"assignment": a["name"], "deployment": dep["name"], "state": evaluate(d, a.get("parameters", {}), res)})
    return out
