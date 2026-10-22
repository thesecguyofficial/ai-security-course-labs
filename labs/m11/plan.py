"""
plan.py: read a Terraform plan in JSON form (`terraform show -json tfplan > plan.json`).

The checker never talks to AWS. It reads what Terraform is ABOUT to create, which is the cheapest moment to catch
a mistake: before it exists. Works with Terraform and OpenTofu plans (same JSON format). Standard library only.
"""

from __future__ import annotations

import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent


def load(path: str | pathlib.Path) -> dict:
    p = pathlib.Path(path)
    if not p.is_absolute():
        p = HERE / p
    return json.loads(p.read_text())


def _walk(module: dict):
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from _walk(child)


def resources(plan: dict, rtype: str | None = None) -> list[dict]:
    """Planned resources: [{address, type, name, values}, ...], optionally of one type."""
    out = list(_walk(plan.get("planned_values", {}).get("root_module", {})))
    return [r for r in out if rtype is None or r["type"] == rtype]


def one(plan: dict, rtype: str) -> dict | None:
    rs = resources(plan, rtype)
    return rs[0] if rs else None


def policy(value) -> dict | None:
    """IAM/endpoint/key policies are JSON strings in a plan. None = not set (or unknown until apply)."""
    if not value:
        return None
    return json.loads(value) if isinstance(value, str) else value


def statements(doc: dict | None) -> list[dict]:
    if not doc:
        return []
    st = doc.get("Statement", [])
    return st if isinstance(st, list) else [st]


def as_list(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _config_resources(plan: dict) -> dict:
    return {r["address"]: r for r in plan.get("configuration", {}).get("root_module", {}).get("resources", [])}


def references(plan: dict, address: str, attribute: str) -> list[str]:
    """What an attribute points at in the Terraform code, e.g. a log group's kms_key_id ->
    ['aws_kms_key.prompts.arn', 'aws_kms_key.prompts']. Values like ARNs of new resources are unknown at plan
    time, but the reference tells us which resource they will come from."""
    address = address.split("[")[0]
    expr = _config_resources(plan).get(address, {}).get("expressions", {})
    node = expr
    for part in attribute.split("."):
        if isinstance(node, list):
            node = node[0] if node else {}
        node = node.get(part, {}) if isinstance(node, dict) else {}
    if isinstance(node, list):
        node = node[0] if node else {}
    return node.get("references", []) if isinstance(node, dict) else []


def known_or_referenced(plan: dict, res: dict, attribute: str) -> bool:
    """True if the attribute has a value, or will get one from another resource at apply time."""
    v = res["values"]
    for part in attribute.split("."):
        if isinstance(v, list):
            v = v[0] if v else {}
        v = v.get(part) if isinstance(v, dict) else None
    return bool(v) or bool(references(plan, res["address"], attribute))
