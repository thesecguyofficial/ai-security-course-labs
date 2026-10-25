"""
pdp.py: the policy decision point. It answers one question, "may this principal do this action on this resource,
in this context?", and knows nothing about models, prompts or tickets.

Two engines, same answer:
  * CedarPDP: the real Cedar engine (Rust) through the cedarpy package. Default deny, forbid wins, and a policy whose
    condition hits an error (a missing attribute, a wrong type) is skipped and reported, as Cedar's documentation
    describes. With a schema, Cedar also checks the policies when they load and every request before deciding.
  * OpaPDP: Open Policy Agent, if the `opa` binary is on your PATH (optional, `make opa`). rego/tools.rego says the
    same things in Rego.

Both return a Decision: effect Allow / Deny / NoDecision (the request could not be evaluated), the IDs of the policies
that determined it, and any errors. What to DO with a NoDecision is the PEP's choice (pep.py): that choice is where
"fail closed" lives.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
from dataclasses import dataclass, field

import cedarpy

import lab


class PolicyLoadError(Exception):
    """The policies could not be loaded (syntax error, schema validation failure, missing @id)."""


@dataclass
class Decision:
    effect: str                                   # "Allow" | "Deny" | "NoDecision"
    policies: list = field(default_factory=list)  # determining policy IDs (the file names)
    errors: list = field(default_factory=list)


ID_RE = re.compile(r'@id\("([A-Za-z0-9_]+)"\)')


def load_policy_text(policy_dir: pathlib.Path) -> tuple[str, set]:
    """Concatenate the .cedar files. Each must carry @id("<file name>"). Returns (text, IDs marked @on_deny("defer"))."""
    files = sorted(policy_dir.glob("*.cedar"))
    if not files:
        raise PolicyLoadError(f"no .cedar files in {policy_dir}")
    parts = []
    for f in files:
        t = f.read_text()
        ids = ID_RE.findall(t)
        if ids != [f.stem]:
            raise PolicyLoadError(f'{f.name}: must contain exactly one policy with @id("{f.stem}")')
        parts.append(t)
    text = "\n".join(parts)
    try:
        parsed = json.loads(cedarpy.policies_to_json_str(text))
    except Exception as e:  # cedarpy raises ValueError on a syntax error
        raise PolicyLoadError(f"Cedar syntax error: {str(e)[:300]}") from e
    defer = {p.get("annotations", {}).get("id") for p in parsed.get("staticPolicies", {}).values()
             if p.get("annotations", {}).get("on_deny") == "defer"}
    return text, defer


def uid(e: dict) -> str:
    return f'{e["type"]}::{json.dumps(e["id"])}'


class CedarPDP:
    name = "cedar"

    def __init__(self, policy_dir: pathlib.Path, use_schema: bool):
        self.text, self.defer_ids = load_policy_text(policy_dir)
        self.schema = lab.SCHEMA.read_text() if use_schema else None
        if self.schema:
            v = cedarpy.validate_policies(self.text, self.schema)
            if not v.validation_passed:
                raise PolicyLoadError("schema validation failed: " + "; ".join(str(e) for e in v.errors)[:600])

    def decide(self, req: dict) -> Decision:
        entities, context = [], json.loads(json.dumps(req["context"]))
        for e in (req["principal"], req["resource"]):
            entities.append({"uid": {"type": e["type"], "id": e["id"]}, "attrs": e.get("attrs", {}), "parents": []})
        appr = context.get("approval", {}).get("approver")
        if appr:
            entities.append({"uid": {"type": appr["type"], "id": appr["id"]}, "attrs": appr["attrs"], "parents": []})
            context["approval"]["approver"] = {"__entity": {"type": appr["type"], "id": appr["id"]}}
        request = {"principal": uid(req["principal"]), "action": f'TSG::Action::{json.dumps(req["action"])}',
                   "resource": uid(req["resource"]), "context": context}
        r = cedarpy.is_authorized(request, self.text, entities, schema=self.schema)
        names = r.diagnostics.id_annotations_by_reason or {}
        effect = {"Allow": "Allow", "Deny": "Deny"}.get(r.decision.name if hasattr(r.decision, "name") else str(r.decision),
                                                          "NoDecision")
        return Decision(effect, [names.get(p, p) for p in r.diagnostics.reasons], list(r.diagnostics.errors))


class OpaPDP:
    """Ask OPA (`opa eval`) the same question. Needs the opa binary: https://www.openpolicyagent.org/docs#running-opa"""
    name = "opa"
    REGO = lab.LAB / "rego"

    def __init__(self, policy_dir=None, use_schema=True):
        self.exe = shutil.which("opa")
        if not self.exe:
            raise PolicyLoadError("opa is not installed (optional: see the README, step 7)")
        out = self._eval("data.tsg.tools.defer_ids", {})
        self.defer_ids = set(out or [])

    def _eval(self, query: str, inp: dict):
        p = subprocess.run([self.exe, "eval", "--format", "json", "--stdin-input", "--data", str(self.REGO), query],
                           input=json.dumps(inp), capture_output=True, text=True, timeout=30)
        if p.returncode != 0:
            raise PolicyLoadError(f"opa eval failed: {p.stderr.strip()[:300]}")
        res = json.loads(p.stdout).get("result", [])
        return res[0]["expressions"][0]["value"] if res else None

    def decide(self, req: dict) -> Decision:
        out = self._eval("data.tsg.tools.result", req)
        if not out:
            return Decision("NoDecision", [], ["opa returned no result"])
        if out["invalid"]:
            return Decision("NoDecision", [], sorted(out["invalid"]))
        if out["forbids"]:
            return Decision("Deny", sorted(out["forbids"]))
        if out["permits"]:
            return Decision("Allow", sorted(out["permits"]))
        return Decision("Deny", [])


def make(engine: str, policy_dir: pathlib.Path, use_schema: bool):
    return {"cedar": CedarPDP, "opa": OpaPDP}[engine](policy_dir, use_schema)
