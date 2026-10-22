#!/usr/bin/env python3
"""
cloud_simulate.py: OPTIONAL and free. Ask the REAL IAM policy simulator whether policies/helpdesk-role.enforced.json
allows bedrock:InvokeModel with and without the guardrail (lesson 12.3). No resources are created and no model is called.

Needs boto3 and AWS credentials allowed to call iam:SimulateCustomPolicy.

    python3 cloud/cloud_simulate.py [--policy policies/helpdesk-role.enforced.json]

The simulator only sees the context keys you pass it. That is the same limit as the real thing: IAM can check WHICH
guardrail a request names, never what text the guardrail evaluated (request R5 in enforce.py).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent.parent
CO = json.loads((HERE / "anycompany.json").read_text(encoding="utf-8"))
G = CO["helpdesk"]["guardrail_arn"]

CASES = [
    ("version 1", G + ":1"),
    ("no guardrail", None),
    ("DRAFT", G),
    ("another guardrail", "arn:aws:bedrock:us-east-1:111122223333:guardrail/devnofilters:3"),
]


def simulate(iam, policy_json: str) -> list[tuple[str, str]]:
    out = []
    for label, value in CASES:
        ctx = [{"ContextKeyName": "bedrock:InferenceProfileArn", "ContextKeyValues": [CO["helpdesk"]["runtime_profile"]],
                "ContextKeyType": "string"}]
        if value:
            ctx.append({"ContextKeyName": "bedrock:GuardrailIdentifier", "ContextKeyValues": [value],
                        "ContextKeyType": "string"})
        r = iam.simulate_custom_policy(PolicyInputList=[policy_json], ActionNames=["bedrock:InvokeModel"],
                                       ResourceArns=[CO["helpdesk"]["runtime_profile"]], ContextEntries=ctx)
        out.append((label, r["EvaluationResults"][0]["EvalDecision"]))
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--policy", default="policies/helpdesk-role.enforced.json")
    a = p.parse_args(argv)
    import boto3
    policy_json = (HERE / a.policy).read_text(encoding="utf-8")
    for label, decision in simulate(boto3.client("iam"), policy_json):
        print(f"InvokeModel with {label:18} -> {decision}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
