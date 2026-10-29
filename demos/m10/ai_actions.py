#!/usr/bin/env python3
"""How much does "bedrock:*" really allow? Count the IAM actions of AWS's AI services.

Lesson 10.1 / 10.3 demo for "AI Security Engineer" (The Sec Guy).

It reads AWS's own machine-readable Service Authorization Reference (public JSON, no AWS account, no credentials,
nothing is created or changed) and prints, for each AI service prefix: how many IAM actions it has, how many of them
change something (write), how many manage permissions, and how many take no resource ARN at all (so a policy
cannot narrow them to "this model"). Then it looks up a few actions this module talks about.

    python3 demos/m10/ai_actions.py

Standard library only. Needs internet access to servicereference.us-east-1.amazonaws.com.
Source: https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

BASE = "https://servicereference.us-east-1.amazonaws.com/v1/{0}/{0}.json"
SERVICES = ["bedrock", "bedrock-mantle", "bedrock-agentcore", "sagemaker"]
LOOK_UP = [
    ("bedrock", "InvokeModel"),
    ("bedrock", "CallWithBearerToken"),
    ("bedrock", "DeleteModelInvocationLoggingConfiguration"),
    ("bedrock", "CreateProvisionedModelThroughput"),
    ("bedrock-mantle", "CreateInference"),
]


def fetch(service: str) -> dict | None:
    req = urllib.request.Request(BASE.format(service), headers={"User-Agent": "tsg-course-demo"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        print(f"  {service}: not in the reference ({e.code})")
    except (urllib.error.URLError, TimeoutError) as e:
        sys.exit(f"Could not reach the AWS service reference: {e}")
    return None


def props(action: dict) -> dict:
    return (action.get("Annotations") or {}).get("Properties") or {}


def main() -> None:
    print("AWS Service Authorization Reference · read live, no account needed\n")
    print(f"{'service prefix':<20}{'actions':>8}{'write':>8}{'permissions':>13}{'no resource':>13}")
    data: dict[str, dict] = {}
    for svc in SERVICES:
        ref = fetch(svc)
        if not ref:
            continue
        data[svc] = ref
        actions = ref.get("Actions") or []
        write = sum(1 for a in actions if props(a).get("IsWrite"))
        perm = sum(1 for a in actions if props(a).get("IsPermissionManagement"))
        nores = sum(1 for a in actions if not a.get("Resources"))
        print(f"{svc + ':*':<20}{len(actions):>8}{write:>8}{perm:>13}{nores:>13}")

    print("\nA few actions from this module:")
    for svc, name in LOOK_UP:
        acts = {a.get("Name"): a for a in (data.get(svc) or {}).get("Actions") or []}
        a = acts.get(name)
        if not a:
            print(f"  {svc + ':' + name:<58} not listed")
            continue
        res = ", ".join(r.get("Name", "?") for r in a.get("Resources") or []) or "none (only *)"
        kind = "write" if props(a).get("IsWrite") else "read/list"
        print(f"  {svc + ':' + name:<58} {kind:<10} resources: {res}")

    total = sum(len(r.get("Actions") or []) for r in data.values())
    print(f"\nThese {len(data)} AI prefixes together: {total} IAM actions. A chatbot calls a handful of them.")


if __name__ == "__main__":
    main()
