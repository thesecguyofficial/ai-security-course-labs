"""
inventory.py: build an AI inventory the way Security Hub's AI inventory does (lesson 16.3), from three signals,
and mark everything that isn't on the approved register.

    python3 inventory.py            # the table
    python3 inventory.py --json     # the same as JSON

Signals (data/inventory/):
    config-items.json     AWS Config configuration items       -> Managed AI resources (Bedrock, AgentCore, SageMaker)
    inspector-sbom.json   Amazon Inspector software inventories -> SelfHosted::AI::Model / ::InferenceEndpoint / ::Agent
    dns.jsonl             DNS queries from EC2 instances        -> SelfHosted::AI::ExternalEndpoint
    sanctioned.json       your approved-AI register             -> SANCTIONED or UNSANCTIONED

This is a lab twin, not Security Hub. It copies the documented rules that matter for a security review:
self-hosted discovery works on EC2 instances (and ECR images) only; external endpoints come from DNS on EC2 only
(calls from Lambda, Fargate, EKS and SageMaker aren't attributed); and self-hosted resources have no findings in this
release, so an inference server open to the internet is your check to write. The last part of the output does that.
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter, defaultdict

HERE = pathlib.Path(__file__).resolve().parent
INV = HERE / "data" / "inventory"

MANAGED_PREFIXES = ("AWS::Bedrock::", "AWS::BedrockAgentCore::", "AWS::SageMaker::")
SERVING = {"vllm", "ollama", "torchserve", "tritonserver", "text-generation-inference", "sglang", "llama.cpp",
           "localai", "bentoml", "xinference", "ray-serve", "gpt4all"}
AGENTS = {"openclaw"}
MODEL_TYPES = {"huggingface-model", "ollama-model"}
EXTERNAL_AI = {"api.openai.com", "api.anthropic.com", "api.cohere.com", "api.mistral.ai",
               "generativelanguage.googleapis.com"}
SERVING_PORTS = {"ollama": 11434, "vllm": 8000}


def load():
    cis = json.loads((INV / "config-items.json").read_text())["configurationItems"]
    sbom = {k: v for k, v in json.loads((INV / "inspector-sbom.json").read_text()).items() if not k.startswith("_")}
    dns = [json.loads(x) for x in (INV / "dns.jsonl").read_text().splitlines() if x.strip()]
    reg = json.loads((INV / "sanctioned.json").read_text())
    return cis, sbom, dns, reg


def build() -> dict:
    cis, sbom, dns, reg = load()
    hosts = {c["resourceId"]: c for c in cis if c["resourceType"] == "AWS::EC2::Instance"}
    rows = []
    for c in cis:
        if c["resourceType"].startswith(MANAGED_PREFIXES):
            rows.append({"discovery": "Managed", "type": c["resourceType"], "id": c["resourceId"], "host": "",
                         "owner": c["tags"].get("owner", "(no owner tag)"),
                         "sanctioned": c["resourceId"] in reg["managed"], "signal": "AWS Config configuration item"})
    for inst, comps in sbom.items():
        for comp in comps:
            name = comp["name"].lower()
            if comp["type"] in MODEL_TYPES:
                typ, cid = "SelfHosted::AI::Model", f"model/{comp['name']}"
            elif name in SERVING:
                typ, cid = "SelfHosted::AI::InferenceEndpoint", f"inference-endpoint/{name}"
            elif name in AGENTS:
                typ, cid = "SelfHosted::AI::Agent", f"agent/{name}"
            else:
                continue
            rows.append({"discovery": "SelfHosted", "type": typ, "id": cid, "host": inst,
                         "owner": hosts.get(inst, {}).get("tags", {}).get("owner", "?"),
                         "sanctioned": cid in reg["self_hosted"],
                         "signal": f"Inspector SBOM: {comp['name']} {comp['version']} at {comp['path']}".rstrip()})
    calls = Counter()
    unattributed = Counter()
    for q in dns:
        domain = q["query_name"].rstrip(".")
        if domain not in EXTERNAL_AI:
            continue
        inst = q.get("srcids", {}).get("instance")
        if inst:
            calls[(domain, inst)] += 1
        else:
            unattributed[(domain, q["srcaddr"])] += 1
    for (domain, inst), n in sorted(calls.items()):
        rows.append({"discovery": "SelfHosted", "type": "SelfHosted::AI::ExternalEndpoint", "id": domain, "host": inst,
                     "owner": hosts.get(inst, {}).get("tags", {}).get("owner", "?"),
                     "sanctioned": domain in reg["external_endpoints"], "signal": f"DNS: {n} queries"})
    exposed = []
    for inst, comps in sbom.items():
        names = {c["name"].lower() for c in comps}
        for ing in hosts.get(inst, {}).get("lab.securityGroupIngress", []):
            for srv, port in SERVING_PORTS.items():
                if srv in names and ing["port"] == port and ing["cidr"] == "0.0.0.0/0":
                    exposed.append({"host": inst, "server": srv, "port": port})
    return {"rows": rows, "unattributed": [{"domain": d, "srcaddr": a, "queries": n} for (d, a), n in unattributed.items()],
            "exposed": exposed}


def main(argv):
    inv = build()
    if "--json" in argv:
        print(json.dumps(inv, indent=1))
        return
    rows = inv["rows"]
    by = Counter(r["discovery"] for r in rows)
    print(f"AI inventory: {len(rows)} AI assets ({by['Managed']} managed, {by['SelfHosted']} self-hosted)\n")
    groups = defaultdict(list)
    for r in rows:
        groups[r["discovery"]].append(r)
    for disc in ("Managed", "SelfHosted"):
        print(f"{disc}")
        for r in groups[disc]:
            mark = "sanctioned  " if r["sanctioned"] else "UNSANCTIONED"
            host = f" on {r['host']}" if r["host"] else ""
            print(f"  {mark} {r['type']:34} {r['id']}{host}  (owner: {r['owner']})")
        print()
    for u in inv["unattributed"]:
        print(f"Not attributed: {u['queries']} DNS queries to {u['domain']} from {u['srcaddr']}, which is not an EC2 "
              "instance. Security Hub doesn't attribute Lambda, Fargate, EKS or SageMaker calls: find the owner of "
              "that address yourself (VPC flow logs, ENI description).")
    for e in inv["exposed"]:
        print(f"Your check: {e['server']} on {e['host']} listens on port {e['port']} and its security group allows "
              "0.0.0.0/0. Self-hosted AI resources have no Security Hub findings in this release.")
    un = sum(not r["sanctioned"] for r in rows)
    print(f"\n{un} of {len(rows)} AI assets are not on the approved register.")


if __name__ == "__main__":
    main(sys.argv[1:])
