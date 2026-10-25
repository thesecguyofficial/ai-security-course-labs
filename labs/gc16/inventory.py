"""
inventory.py: an AI inventory the way Security Command Center's AI Protection shows one (lesson 16.3), plus the two
checks it leaves to you, and a mark on everything that isn't on the approved register.

    python3 inventory.py                    # Premium: what the AI inventory lists, the register diff, your checks
    python3 inventory.py --tier standard    # the same organization on SCC Standard: no Gemini models
    python3 inventory.py --json

Inputs (data/inventory/):
    ai-assets.json    what the AI inventory lists: models, endpoints, data sources, agents, apps, MCP servers
    sanctioned.json   your approved-AI register             -> SANCTIONED or UNSANCTIONED
    dns.jsonl         Cloud DNS query logs                   -> outside AI APIs (your check)
    firewall.json     Compute Engine VMs and firewall rules  -> self-hosted inference open to the internet (your check)

This is a lab twin, not Security Command Center. It copies the documented rules that matter for a security review:
Gemini models show up only on Premium (AI Discovery), MCP servers only when they're in Agent Registry, and nothing in
the inventory's categories covers software on your own VMs or calls to outside AI APIs. Cloud DNS logs name the VM
only for queries "initiated by Compute Engine VMs"; anything else is an address you have to trace yourself.
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter

HERE = pathlib.Path(__file__).resolve().parent
INV = HERE / "data" / "inventory"
EXTERNAL_AI = {"api.openai.com", "api.anthropic.com", "api.mistral.ai", "api.cohere.com",
               "generativelanguage.googleapis.com"}
INFERENCE_PORTS = {"11434": "ollama", "8000": "vllm"}


def load():
    assets = json.loads((INV / "ai-assets.json").read_text())["assets"]
    reg = json.loads((INV / "sanctioned.json").read_text())
    dns = [json.loads(x) for x in (INV / "dns.jsonl").read_text().splitlines() if x.strip()]
    fw = json.loads((INV / "firewall.json").read_text())
    return assets, reg, dns, fw


def build(tier: str = "premium") -> dict:
    assets, reg, dns, fw = load()
    rows, hidden = [], 0
    for a in assets:
        if a.get("gemini") and tier != "premium":
            hidden += 1
            continue
        rows.append({"source": "AI inventory", "category": a["category"], "name": a["name"], "project": a["project"],
                     "owner": a["owner"], "sanctioned": a["name"] in reg["assets"],
                     "armor_gap": tier == "premium" and a.get("gemini") and not a.get("modelArmorProtected")})
    calls, unattributed = Counter(), Counter()
    for q in dns:
        p = q["jsonPayload"]
        domain = p["queryName"].rstrip(".")
        if domain not in EXTERNAL_AI:
            continue
        if p.get("vmInstanceName"):
            calls[(domain, p["vmInstanceName"], p["vmProjectId"])] += 1
        else:
            unattributed[(domain, p["sourceIP"], p.get("vmProjectId") or p.get("project_id", "?"))] += 1
    for (domain, vm, proj), n in sorted(calls.items()):
        rows.append({"source": "Cloud DNS (your check)", "category": "Outside AI API", "name": f"{domain} from {vm}",
                     "project": proj, "owner": "?", "sanctioned": domain in reg["external_ai_domains"],
                     "armor_gap": False, "queries": n})
    exposed = []
    for f in fw["firewalls"]:
        if f["direction"] != "INGRESS" or f["disabled"] or "0.0.0.0/0" not in f["sourceRanges"]:
            continue
        for rule in f["allowed"]:
            for port in rule.get("ports", []):
                if port in INFERENCE_PORTS:
                    vms = [i["name"] for i in fw["instances"] if set(i["tags"]) & set(f["targetTags"])]
                    exposed.append({"rule": f["name"], "project": f["project"], "port": port,
                                    "server": INFERENCE_PORTS[port], "vms": vms})
    return {"tier": tier, "rows": rows, "hidden_gemini": hidden, "exposed": exposed,
            "unattributed": [{"domain": d, "sourceIP": ip, "project": pr, "queries": n}
                             for (d, ip, pr), n in unattributed.items()]}


def main(argv):
    tier = argv[argv.index("--tier") + 1] if "--tier" in argv else "premium"
    inv = build(tier)
    if "--json" in argv:
        print(json.dumps(inv, indent=1))
        return
    rows = inv["rows"]
    print(f"AI inventory (SCC {tier.title()}): {len(rows)} AI assets\n")
    for r in rows:
        mark = "sanctioned  " if r["sanctioned"] else "UNSANCTIONED"
        print(f"  {mark} {r['category']:14} {r['name']}  [{r['project']}, owner: {r['owner']}]")
    if inv["hidden_gemini"]:
        print(f"\n{inv['hidden_gemini']} Gemini models aren't listed: on Standard, AI Discovery doesn't detect Gemini.")
    for r in rows:
        if r["armor_gap"]:
            print(f"Finding: Gemini model not protected by Model Armor: {r['name']} in {r['project']}")
    for u in inv["unattributed"]:
        print(f"Not attributed: {u['queries']} DNS queries to {u['domain']} from {u['sourceIP']} in {u['project']}, "
              "with no vmInstanceName (not a Compute Engine VM). Find the owner of that address yourself "
              "(GKE pod, Cloud Run, a connector).")
    for e in inv["exposed"]:
        print(f"Your check: firewall rule {e['rule']} allows 0.0.0.0/0 to port {e['port']} ({e['server']}) on "
              f"{', '.join(e['vms'])} in {e['project']}. Software on your own VMs isn't in the AI inventory.")
    un = sum(not r["sanctioned"] for r in rows)
    print(f"\n{un} of {len(rows)} AI assets are not on the approved register.")


if __name__ == "__main__":
    main(sys.argv[1:])
