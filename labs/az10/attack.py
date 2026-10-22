"""
attack.py: what can a thief do with Contoso's Azure AI setup? And what do the fixes stop?

    python3 attack.py --mode vulnerable   # Contoso today
    python3 attack.py --mode safe         # with everything in fixes/

Nothing here talks to Azure. Each request is decided by azure_model.py, a small teaching model of Azure RBAC,
key access and Azure Policy, using the JSON in contoso/ and fixes/. The story follows the pattern Microsoft's
Digital Crimes Unit described for Storm-2139 (lesson 10.5): credentials found in public places, used to get into
Azure OpenAI, "altered the capabilities", then access resold. The individual steps are this lab's own
reconstruction, not Microsoft's indicators.

Contoso is fictional ("Contoso" is the placeholder company in Microsoft's own documentation).
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from azure_model import Azure, Decision

OAI = "azureml://registries/azure-openai/models/"
FABRIKAM_MODEL = {"publisher": "Fabrikam", "name": "fabrikam-chat-xl", "version": "3",
                  "assetId": "azureml://registries/fabrikam-models/models/fabrikam-chat-xl/versions/3"}   # fictional
GPT54 = {"publisher": "OpenAI", "name": "gpt-5.4", "version": "1", "assetId": OAI + "gpt-5.4/versions/1"}
GPT52_V2 = {"publisher": "OpenAI", "name": "gpt-5.2", "version": "2", "assetId": OAI + "gpt-5.2/versions/2"}
GPT5_V1 = {"publisher": "OpenAI", "name": "gpt-5", "version": "1", "assetId": OAI + "gpt-5/versions/1"}

MODES = {
    "vulnerable": dict(estate="contoso/estate.json", assignments="contoso/role-assignments.json",
                       policies="contoso/policy-assignments.json"),
    "safe": dict(estate="fixes/estate.json", assignments="fixes/role-assignments.json",
                 policies="fixes/policy-assignments.json", custom_roles=["fixes/custom-role-foundry-deployer.json"]),
}


@dataclass
class Step:
    sid: str
    who: str            # "attacker" or "legit"
    actor: str          # principal name, or "thief"
    text: str
    op: str
    account: str
    kw: dict
    safe_kw: dict | None = None    # different call in safe mode (e.g. the app moves from a key to Entra ID)


STEPS = [
    # A: a thief with keys copied from a public repository (contoso/repo-snapshot/)
    Step("A1", "attacker", "thief", "Leaked PROD key: list the models on the helpdesk resource", "inference",
         "contoso-helpdesk-ai", dict(key_of="contoso-helpdesk-ai")),
    Step("A2", "attacker", "thief", "Leaked PROD key: chat with helpdesk-gpt5 on Contoso's bill", "inference",
         "contoso-helpdesk-ai", dict(key_of="contoso-helpdesk-ai", deployment="helpdesk-gpt5")),
    Step("A3", "attacker", "thief", "Leaked SANDBOX key: chat with sandbox-gpt52", "inference",
         "contoso-sandbox-ai", dict(key_of="contoso-sandbox-ai", deployment="sandbox-gpt52")),
    # B: a thief with the ci-deployer service principal's client secret (same repo)
    Step("B1", "attacker", "ci-deployer", "Stolen CI secret: call the model with an Entra ID token", "inference",
         "contoso-helpdesk-ai", dict(deployment="helpdesk-gpt5")),
    Step("B2", "attacker", "ci-deployer", "Stolen CI secret: read the PROD keys (listKeys)", "listKeys",
         "contoso-helpdesk-ai", {}),
    Step("B3", "attacker", "ci-deployer", "Stolen CI secret: deploy an unapproved model (fabrikam-chat-xl)",
         "deploymentWrite", "contoso-sandbox-ai", dict(deployment="resale-xl", model=FABRIKAM_MODEL)),
    Step("B4", "attacker", "ci-deployer", "Stolen CI secret: deploy gpt-5.4 (not on Contoso's list)", "deploymentWrite",
         "contoso-sandbox-ai", dict(deployment="resale-54", model=GPT54)),
    Step("B5", "attacker", "ci-deployer", "Stolen CI secret: replace the content filter (raiPolicies/write)",
         "raiPolicyWrite", "contoso-helpdesk-ai", {}),
    Step("B6", "attacker", "ci-deployer", "Stolen CI secret: give itself Foundry User (roleAssignments/write)",
         "roleAssignmentWrite", "contoso-helpdesk-ai", {}),
    Step("B7", "attacker", "ci-deployer", "Stolen CI secret: switch key access back on (disableLocalAuth=false)",
         "accountWrite", "contoso-helpdesk-ai", dict(set_props={"disableLocalAuth": False})),
    Step("B8", "attacker", "ci-deployer", "Stolen CI secret: deploy gpt-5.2 version 2 (only version 1 is approved)",
         "deploymentWrite", "contoso-sandbox-ai", dict(deployment="resale-52", model=GPT52_V2)),
    Step("B9", "attacker", "platform-admin", "Phished ADMIN session: switch key access back on (Owner!)",
         "accountWrite", "contoso-helpdesk-ai", dict(set_props={"disableLocalAuth": False})),
    # legitimate work that must keep working
    Step("L1", "legit", "helpdesk-app", "Helpdesk app answers a customer (today: key; fixed: Entra ID token)",
         "inference", "contoso-helpdesk-ai", dict(key_of="contoso-helpdesk-ai", deployment="helpdesk-gpt5"),
         safe_kw=dict(deployment="helpdesk-gpt5")),
    Step("L2", "legit", "ci-deployer", "CI pipeline rolls out approved gpt-5 version 1", "deploymentWrite",
         "contoso-helpdesk-ai", dict(deployment="helpdesk-gpt5", model=GPT5_V1)),
    Step("L3", "legit", "data-science", "Data scientist calls sandbox-gpt52 with an Entra ID token", "inference",
         "contoso-sandbox-ai", dict(deployment="sandbox-gpt52")),
    Step("L4", "legit", "contractor", "Contractor reads the sandbox resource's settings", "read",
         "contoso-sandbox-ai", {}),
    Step("L5", "legit", "platform-admin", "Platform admin reads the prod keys during a planned rotation", "listKeys",
         "contoso-helpdesk-ai", {}),
]


def world(mode: str) -> Azure:
    return Azure(**MODES[mode])


def run_step(step: Step, mode: str, az: Azure | None = None) -> Decision:
    az = az or world(mode)
    kw = step.safe_kw if (mode == "safe" and step.safe_kw is not None) else step.kw
    return az.request(step.actor, step.op, step.account, **kw)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=MODES, default="vulnerable")
    ap.add_argument("-v", "--verbose", action="store_true", help="show every role and policy that was checked")
    a = ap.parse_args()
    az = world(a.mode)
    print(f"--- AZ10 lab · {a.mode.upper()} · {'contoso/' if a.mode == 'vulnerable' else 'fixes/'} ---")
    print("    (azure_model.py: a teaching model of Azure RBAC, keys and Azure Policy; nothing is sent to Azure)\n")
    tally = {"attacker": [0, 0], "legit": [0, 0]}
    for s in STEPS:
        d = run_step(s, a.mode, az)
        tally[s.who][0] += d.allowed
        tally[s.who][1] += 1
        verdict = ("ALLOWED" if d.allowed else "DENIED ") + f" {d.status:<5}"
        mark = ("!!" if d.allowed else "ok") if s.who == "attacker" else ("ok" if d.allowed else "!!")
        print(f"  {mark} {s.sid}  {verdict}  {s.text}")
        decisive = [r for r in d.why if r.startswith(("GRANT", "POLICY", "key", "disableLocalAuth", "a key", "the key"))]
        reasons = d.why if a.verbose else (decisive[-1:] if d.allowed and decisive else d.why[-1:])
        for r in reasons:
            print(f"                     {r}")
    at, lg = tally["attacker"], tally["legit"]
    print(f"\nAttacker requests allowed: {at[0]} of {at[1]}   ·   legitimate requests allowed: {lg[0]} of {lg[1]}")


if __name__ == "__main__":
    main()
