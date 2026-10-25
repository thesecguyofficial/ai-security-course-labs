"""
hunt.py: investigate a morning of Contoso's Azure logs (lesson 15.4). Offline, standard library only.

    python3 hunt.py          # make hunt

The data in data/incident/ uses the real column names of two Azure Monitor tables:
  * AzureActivity (the Activity Log): control-plane writes and actions, such as a deployment write or listKeys.
  * AmlOnlineEndpointTrafficLog: one row per scoring request, with AuthType (Key, AMLToken, AADToken) and
    IdentityData (the caller's object ID from the Entra token). It has no client IP and no request body.
Every value is invented. The story: last week the team moved tsg-summariser to Entra auth. The old key-auth endpoint
tsg-summariser-legacy was meant to be deleted.

Q1 to Q3 are written. Q4 is challenge 3: write find_key_calls().
"""

from __future__ import annotations

import json
import pathlib

import twin

DATA = pathlib.Path(__file__).resolve().parent / "data" / "incident"
OP = "Microsoft.MachineLearningServices/workspaces/onlineEndpoints"


def load() -> dict:
    return {"activity": json.loads((DATA / "azure-activity.json").read_text())["rows"],
            "traffic": json.loads((DATA / "endpoint-traffic.json").read_text())["rows"],
            "context": json.loads((DATA / "context.json").read_text())}


def _endpoint(resource_id: str) -> str:
    parts = resource_id.split("/")
    return parts[parts.index("onlineEndpoints") + 1]


def q1_deployments_outside_pipeline(d: dict) -> list[dict]:
    """Deployment writes that succeeded and weren't made by the pipeline."""
    return [{"time": r["TimeGenerated"], "who": twin.name_for_oid(r["Caller"]), "ip": r["CallerIpAddress"],
             "deployment": r["_ResourceId"].rsplit("/", 1)[1], "endpoint": _endpoint(r["_ResourceId"])}
            for r in d["activity"]
            if r["OperationNameValue"].lower() == f"{OP}/deployments/write".lower()
            and r["ActivityStatusValue"] == "Succeeded" and r["Caller"] != d["context"]["pipeline"]]


def q2_key_listings(d: dict) -> list[dict]:
    """listKeys calls by anyone but the platform team: whoever holds a key can call the endpoint, no role needed."""
    return [{"time": r["TimeGenerated"], "who": twin.name_for_oid(r["Caller"]), "ip": r["CallerIpAddress"],
             "endpoint": _endpoint(r["_ResourceId"])}
            for r in d["activity"]
            if r["OperationNameValue"].lower() == f"{OP}/listKeys/action".lower()
            and r["ActivityStatusValue"] == "Succeeded" and r["Caller"] not in d["context"]["admins"]]


def q3_calls_outside_the_split(d: dict) -> list[dict]:
    """Requests served by a deployment with a 0% traffic share: someone named it with the azureml-model-deployment
    header."""
    share = d["context"]["traffic"]
    return [{"time": r["TimeGenerated"], "endpoint": r["EndpointName"], "deployment": r["DeploymentName"],
             "who": twin.name_for_oid(r["IdentityData"]) if r["IdentityData"] else "(no identity)", "agent": r["UserAgent"]}
            for r in d["traffic"] if share.get(r["EndpointName"], {}).get(r["DeploymentName"], 0) == 0]


def find_key_calls(d: dict) -> list[dict] | None:
    """CHALLENGE 3 (lesson 15.4): return the scoring requests made with a key, on any endpoint.

    Each row: {"time": TimeGenerated, "endpoint": EndpointName, "agent": UserAgent}, in time order.
    These are the calls no identity can be pinned on: AuthType says Key and IdentityData is empty. Then look at Q2
    again: who could have had that key?
    """
    return None  # TODO (challenge 3)


def _print(title, rows, fmt):
    print(title)
    if rows is None:
        print("   not written yet: challenge 3: write find_key_calls()\n")
        return
    if not rows:
        print("   (nothing found)\n")
        return
    for r in rows:
        print("   " + fmt(r))
    print()


def main():
    d = load()
    _print("Q1. Deployment writes not made by the pipeline (AzureActivity)", q1_deployments_outside_pipeline(d),
           lambda r: f"{r['time']}  {r['endpoint']}/{r['deployment']:<8} by {r['who']:<14} from {r['ip']}")
    _print("Q2. Endpoint keys listed by someone outside the platform team (AzureActivity)", q2_key_listings(d),
           lambda r: f"{r['time']}  {r['endpoint']:<22} by {r['who']:<14} from {r['ip']}")
    _print("Q3. Calls served by a deployment with 0% traffic (AmlOnlineEndpointTrafficLog)", q3_calls_outside_the_split(d),
           lambda r: f"{r['time']}  {r['endpoint']}/{r['deployment']:<8} identity: {r['who']:<14} agent: {r['agent']}")
    _print("Q4. Calls made with a key (challenge 3)", find_key_calls(d),
           lambda r: f"{r['time']}  {r['endpoint']:<22} agent: {r['agent']}")


if __name__ == "__main__":
    main()
