"""
inventory.py: build Contoso's AI inventory from three signals (lesson 16.3) and mark everything that isn't on the
approved register.

    python3 inventory.py            # the table
    python3 inventory.py --json     # the same as JSON

Signals (data/inventory/):
    resource-graph.json   Azure Resource Graph rows       -> every AI resource that exists in Azure Resource Manager
    ai-bom.json           Defender CSPM AI posture (AI-SPM) -> AI workloads in Azure, plus connected AWS and Google Cloud;
                                                            agents only with a Microsoft Agent 365 licence
    nsg.json              network security group rules    -> your own check: a model server open to the internet
    sanctioned.json       your approved-AI register        -> SANCTIONED or UNSANCTIONED

This is a lab twin, not Defender for Cloud. It keeps the documented limits that matter for a security review:
AI-SPM covers the services Microsoft lists (Azure OpenAI, Foundry, Azure Machine Learning, Amazon Bedrock, Google
Vertex AI), agent-level discovery needs an Agent 365 licence from 1 July 2026, and a model server you run yourself on
a VM isn't on that list, so finding it is your job. The last part of the output does that.
"""

from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
INV = HERE / "data" / "inventory"

AI_TYPES = {"microsoft.cognitiveservices/accounts", "microsoft.cognitiveservices/accounts/projects",
            "microsoft.search/searchservices", "microsoft.machinelearningservices/workspaces",
            "microsoft.apimanagement/service"}
SERVING_PORTS = {"11434": "Ollama", "8000": "vLLM"}
OPEN_SOURCES = {"*", "Internet", "0.0.0.0/0", "Any"}


def load(name: str) -> dict:
    return json.loads((INV / name).read_text())


def build() -> dict:
    arg, bom, nsg, reg = load("resource-graph.json"), load("ai-bom.json"), load("nsg.json"), load("sanctioned.json")
    approved = set(reg["azure_resources"]) | set(reg["other_clouds"])
    rows = []
    for r in arg["data"]:
        if r["type"] in AI_TYPES:
            rows.append({"signal": "Resource Graph", "cloud": "Azure", "type": r["type"], "id": r["name"],
                         "owner": r["tags"].get("owner", "(no owner tag)"), "sanctioned": r["name"] in approved})
    in_azure = {r["id"] for r in rows}
    for w in bom["workloads"]:
        if w["cloud"] != "Azure" and w["resource"] not in in_azure:
            rows.append({"signal": "Defender CSPM AI-SPM", "cloud": w["cloud"], "type": w["service"], "id": w["resource"],
                         "owner": "(connector owner)", "sanctioned": w["resource"] in approved})
    agents_visible = bool(bom["licences"].get("agent365"))
    agents = [a for a in bom["agents"] if agents_visible]
    for a in agents:
        rows.append({"signal": "Defender AI agents", "cloud": "Azure", "type": "agent", "id": a["name"], "owner": a["project"],
                     "sanctioned": a["name"] in reg["agents"]})
    exposed_in_bom = [w["resource"] for w in bom["workloads"] if w.get("internet_exposed")]
    exposed_vms = []
    for rule in nsg["rules"]:
        port = rule["destinationPortRange"]
        if (rule["direction"], rule["access"]) == ("Inbound", "Allow") and port in SERVING_PORTS \
                and rule["sourceAddressPrefix"] in OPEN_SOURCES:
            exposed_vms.append({"vm": rule["vm"], "nsg": rule["nsg"], "rule": rule["name"], "port": int(port),
                                "server": SERVING_PORTS[port]})
    for e in exposed_vms:
        rows.append({"signal": "your NSG check", "cloud": "Azure", "type": f"self-hosted model server ({e['server']})",
                     "id": e["vm"], "owner": next((r["tags"].get("owner", "?") for r in arg["data"] if r["name"] == e["vm"]), "?"),
                     "sanctioned": e["vm"] in approved})
    return {"rows": rows, "agents_visible": agents_visible, "agents_hidden": 0 if agents_visible else len(bom["agents"]),
            "unconfirmed_agents": [] if agents_visible else list(reg["agents"]),
            "exposed_ai_services": exposed_in_bom, "exposed_vms": exposed_vms}


def main(argv):
    inv = build()
    if "--json" in argv:
        print(json.dumps(inv, indent=1))
        return
    rows = inv["rows"]
    print(f"AI inventory: {len(rows)} AI assets\n")
    for r in rows:
        mark = "sanctioned  " if r["sanctioned"] else "UNSANCTIONED"
        print(f"  {mark} {r['cloud']:6} {r['type']:46} {r['id']:32} owner: {r['owner']}   ({r['signal']})")
    if not inv["agents_visible"]:
        print(f"\nAgents: {inv['agents_hidden']} agent records not shown. From 1 July 2026 agent-level discovery needs a "
              "Microsoft Agent 365 licence;\n  Defender CSPM still lists the Foundry accounts and projects. Not confirmed: "
              + ", ".join(inv["unconfirmed_agents"]) + " (on the register).")
    print("\nInternet exposure AI-SPM reports: " + ", ".join(inv["exposed_ai_services"]))
    for e in inv["exposed_vms"]:
        print(f"Your check: {e['vm']} allows the internet to port {e['port']} ({e['server']}'s default) in "
              f"{e['nsg']}/{e['rule']}. A model server on a VM isn't an AI service AI-SPM lists.")
    un = sum(not r["sanctioned"] for r in rows)
    print(f"\n{un} of {len(rows)} AI assets are not on the approved register.")


if __name__ == "__main__":
    main(sys.argv[1:])
