"""
enforce.py: who can call a model WITHOUT the guardrail? (lesson 12.3)

Six requests, replayed against AnyCompany's IAM policies and its organization-level Amazon Bedrock policy:

  R1  Helpdesk, Converse, guardrail tsghelpdesk01 version 1                 (the approved call)
  R2  Helpdesk, Converse, no guardrail at all                               (a developer "testing quickly")
  R3  Helpdesk, Converse, guardrail tsghelpdesk01 DRAFT                      (the working draft, editable by anyone with UpdateGuardrail)
  R4  Helpdesk, Converse, another team's guardrail with almost no filters   (any guardrail will do?)
  R5  Helpdesk, Converse, guardrail version 1, but only a harmless sentence inside guardContent (input tags)
  R6  OpsToolsRole, bedrock-mantle CreateInference                          (the M11 ops tool: an endpoint with no Guardrails support)

    python3 enforce.py                      # the first draft: no IAM enforcement, the first-draft org policy
    python3 enforce.py --role enforced --org fixed
    python3 enforce.py --role any-version --org fixed

How the condition key is filled in: AWS's examples compare bedrock:GuardrailIdentifier with the guardrail ARN plus
":<version>" for a numbered version, and with the bare ARN for the DRAFT version. The simulation builds the request value
the same way.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

import iam_eval

HERE = pathlib.Path(__file__).resolve().parent
CO = json.loads((HERE / "anycompany.json").read_text(encoding="utf-8"))
G = CO["helpdesk"]["guardrail_arn"]
PROFILE = CO["helpdesk"]["runtime_profile"]
MODEL = CO["helpdesk"]["foundation_model"]
MODEL_ARNS = [f"arn:aws:bedrock:{r}::foundation-model/{MODEL}" for r in ("us-east-1", "us-east-2", "us-west-2")]
OTHER = "arn:aws:bedrock:us-east-1:111122223333:guardrail/devnofilters"


def gid(arn: str, version: str | None) -> str | None:
    if arn is None:
        return None
    return arn if version == "DRAFT" else f"{arn}:{version}"


REQUESTS = [
    ("R1", "helpdesk", "runtime", gid(G, "1"), "all", "approved call"),
    ("R2", "helpdesk", "runtime", None, "all", "no guardrail"),
    ("R3", "helpdesk", "runtime", gid(G, "DRAFT"), "all", "DRAFT version"),
    ("R4", "helpdesk", "runtime", gid(OTHER, "3"), "all", "another team's weak guardrail"),
    ("R5", "helpdesk", "runtime", gid(G, "1"), "tagged-harmless", "user text left outside guardContent"),
    ("R6", "ops-tools", "mantle", None, "all", "bedrock-mantle endpoint"),
]


def load_role(principal: str, role_variant: str) -> dict:
    if principal == "ops-tools":
        return json.loads((HERE / "policies/ops-tools-role.json").read_text(encoding="utf-8"))
    return json.loads((HERE / f"policies/helpdesk-role.{role_variant}.json").read_text(encoding="utf-8"))


def org_config(org_variant: str) -> dict | None:
    if org_variant == "none":
        return None
    doc = json.loads((HERE / f"org/bedrock-policy.{org_variant}.json").read_text(encoding="utf-8"))
    return doc["bedrock"]["guardrail_inference"]["us-east-1"]["config_1"]


def org_identifier_valid(cfg: dict) -> tuple[bool, str]:
    ident = cfg["identifier"]["@@assign"]
    parts = ident.split(":")
    mgmt = CO["organization"]["management_account"]
    if len(parts) < 7 or not parts[6].isdigit():
        return False, "identifier has no numeric version (AWS: the version cannot be DRAFT)"
    if parts[4] != mgmt:
        return False, "the guardrail is not owned by the management account"
    return True, ""


def simulate(role_variant: str, org_variant: str) -> list[dict]:
    rows = []
    ocfg = org_config(org_variant)
    for rid, who, endpoint, guardrail, tagging, label in REQUESTS:
        policy = load_role(who, role_variant)
        if endpoint == "mantle":
            req = iam_eval.Request("bedrock-mantle:CreateInference", ["*"], {})
        else:
            ctx = {"bedrock:InferenceProfileArn": PROFILE}
            if guardrail:
                ctx["bedrock:GuardrailIdentifier"] = guardrail
            req = iam_eval.Request("bedrock:InvokeModel", [PROFILE] + MODEL_ARNS, ctx)
        allowed, reason = iam_eval.evaluate(policy, req)

        guards = []
        if allowed and endpoint == "runtime":
            if guardrail:
                name = guardrail.split("/")[-1]
                guards.append(f"{name} on " + ("ONLY the harmless tagged sentence" if tagging == "tagged-harmless" else "the prompt"))
            if ocfg:
                ok, why = org_identifier_valid(ocfg)
                excluded = MODEL in ocfg.get("model_enforcement", {}).get("excluded_models", {}).get("@@assign", [])
                messages = ocfg.get("selective_content_guarding", {}).get("messages", {}).get("@@assign", "comprehensive")
                if not ok:
                    guards.append(f"org baseline BROKEN: {why}")
                elif excluded:
                    guards.append("org baseline: Helpdesk model EXCLUDED")
                elif tagging == "tagged-harmless" and messages == "selective":
                    guards.append("org baseline on the tagged sentence only (selective)")
                else:
                    guards.append("org baseline on everything (comprehensive)")
        elif allowed and endpoint == "mantle":
            guards.append("NONE: Guardrails is not supported on bedrock-mantle")
        unguarded_user_text = allowed and not any(
            ("prompt" in g or "everything" in g) and "BROKEN" not in g and "EXCLUDED" not in g for g in guards)
        rows.append({"id": rid, "label": label, "allowed": allowed, "reason": reason, "guardrails": guards,
                     "user_text_unguarded": unguarded_user_text})
    return rows


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Who can call a model without the guardrail?")
    p.add_argument("--role", default="first-draft", choices=["first-draft", "enforced", "any-version"])
    p.add_argument("--org", default="first-draft", choices=["none", "first-draft", "fixed"])
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    rows = simulate(a.role, a.org)
    if a.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(f"== Helpdesk role: helpdesk-role.{a.role}.json   |   org Bedrock policy: {a.org}\n")
    for r in rows:
        verdict = "ALLOWED" if r["allowed"] else "DENIED "
        print(f"{r['id']} {r['label']:38} {verdict}  {'; '.join(r['guardrails']) if r['allowed'] else r['reason']}")
    bad = [r["id"] for r in rows if r["user_text_unguarded"]]
    print(f"\nCalls that reach a model with the user's text unguarded: {len(bad)} of {len(rows)}"
          + (f" ({', '.join(bad)})" if bad else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
