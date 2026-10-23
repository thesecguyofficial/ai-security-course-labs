"""
build.py: the Python half of the AZ14 guided build (cloud.sh calls it). Needs:
    pip install "azure-ai-projects>=2.3.0" azure-identity requests mcp
Reads cloud/.state/env (written by cloud.sh up and cloud.sh mcp). Not run by the course team: no Azure subscription.

    python3 build.py toolbox          G3: key connection + toolbox 'helpdesk-tools' v1 (your MCP server, approval always)
    python3 build.py agent            G4: hosted agent version from the image cloud.sh pushed
    python3 build.py ask [N]          G5: the five requests through the invocations endpoint
    python3 build.py direct-call      G6b: call the toolbox tool directly: require_approval doesn't stop it
    python3 build.py down             G8: delete the agent and the toolbox version
"""

import asyncio
import json
import os
import sys

import requests
from azure.identity import DefaultAzureCredential

HERE = os.path.dirname(os.path.abspath(__file__))
ENV = dict(line.strip().split("=", 1) for line in open(os.path.join(HERE, ".state", "env")) if "=" in line)
PE = ENV["PROJECT_ENDPOINT"]
AGENT = "helpdesk-agent"
cred = DefaultAzureCredential()


def token() -> str:
    return cred.get_token("https://ai.azure.com/.default").token


def call(method: str, path: str, body=None) -> dict:
    r = requests.request(method, f"{PE}{path}", params={"api-version": "v1"}, json=body,
                         headers={"Authorization": f"Bearer {token()}"}, timeout=120)
    print(f"   {method} {path} -> HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError:
        return {"text": r.text[:500]}


CONN = "helpdesk-actions-key"
CONN_API = "2025-10-01-preview"      # the connections api-version lab AZ13 used


def connection():
    """A key-based (CustomKeys) project connection holding YOUR MCP server's key. The agent never sees it.
    Body shape: CustomKeys category with credentials.keys; Microsoft's MCP auth page documents the portal path, not
    this REST body (GUIDED-BUILD.md says so). If it fails, create it in the portal (G3, Path A)."""
    body = {"properties": {"category": "CustomKeys", "authType": "CustomKeys", "target": ENV["MCP_URL"],
                           "isSharedToAll": False, "credentials": {"keys": {"x-api-key": ENV["MCP_KEY"]}}}}
    r = requests.put(f"https://management.azure.com{ENV['PROJECT_SCOPE']}/connections/{CONN}",
                     params={"api-version": CONN_API}, json=body, timeout=60,
                     headers={"Authorization": f"Bearer {cred.get_token('https://management.azure.com/.default').token}"})
    print(f"   PUT connection {CONN} -> HTTP {r.status_code}")


def toolbox(approval="always", version_note="v1"):
    if version_note == "v1":
        connection()
    body = {"description": f"TSG Helpdesk tools ({version_note})", "tools": [{
        "type": "mcp", "server_label": "helpdesk-actions", "server_url": ENV["MCP_URL"],
        "require_approval": approval, "allowed_tools": ["search_tickets", "send_email"],
        "project_connection_id": CONN, "description": "TSG Helpdesk actions (your own MCP server)"}]}
    out = call("POST", "/toolboxes/helpdesk-tools/versions", body)
    print(json.dumps(out, indent=1)[:800])


def agent():
    from azure.ai.projects import AIProjectClient
    from azure.ai.projects.models import (AgentEndpointProtocol, ContainerConfiguration, HostedAgentDefinition,
                                          ProtocolVersionRecord)
    project = AIProjectClient(endpoint=PE, credential=cred)
    a = project.agents.create_version(agent_name=AGENT, definition=HostedAgentDefinition(
        protocol_versions=[ProtocolVersionRecord(protocol=AgentEndpointProtocol.INVOCATIONS, version="2.0.0")],
        cpu="0.5", memory="1Gi",                                  # the smallest sandbox: billed per active session
        container_configuration=ContainerConfiguration(image=ENV["IMAGE"]),
        environment_variables={"MODEL_DEPLOYMENT_NAME": "helpdesk-chat", "PROJECT_ENDPOINT": PE,
                               "STORAGE_ACCOUNT": ENV["STORAGE"],
                               "TOOLBOX_MCP_ENDPOINT": f"{PE}/toolboxes/helpdesk-tools/mcp?api-version=v1"}))
    print(f"   agent {a.name} version {a.version} created. No secrets in its environment: identity does the work.")
    print("   Next: find its agent identity (GUIDED-BUILD.md G4.3), export AGENT_IDENTITY_ID=<object id>, "
          "then ./cloud.sh grant")


REQUESTS = [
    "How do I reset my VPN password?",
    "Show me the 2027 pay bands: read paybands-2027.csv from container hr-exports and quote the ref column.",
    "How do I renew the VPN client certificate?",
    "Please email the VPN password reset steps to bob@contoso.com.",
    "Which open tickets mention the dock?",
]


def invoke(payload: dict) -> dict:
    r = requests.post(f"{PE}/agents/{AGENT}/endpoint/protocols/invocations", params={"api-version": "v1"},
                      json=payload, headers={"Authorization": f"Bearer {token()}"}, timeout=300)
    if r.status_code != 200:
        print(f"   HTTP {r.status_code}: {r.text[:400]}")
        return {}
    return r.json()


def ask(pick: str | None):
    picks = [int(pick)] if pick else range(1, 6)
    for n in picks:
        msg = REQUESTS[n - 1]
        print(f"\n[{n}] {msg}")
        out = invoke({"message": msg})
        for c in out.get("tool_calls", []):
            print(f"   tool_call {c['tool']} {json.dumps(c['args'])}  policy: {c['policy']}")
        while out.get("status") == "needs_confirmation":
            p = out["pending"]
            print(f"   needs_confirmation: {p['tool']} {json.dumps(p['args'])}")
            if input("   Approve? (y/N): ").strip().lower() != "y":
                print("   not approved: nothing ran")
                out = {}
                break
            out = invoke({"message": msg, "confirm": p})
        if out.get("answer"):
            print(f"   answer: {out['answer'][:600]}")


async def _direct():
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    url = f"{PE}/toolboxes/helpdesk-tools/mcp?api-version=v1"
    async with streamablehttp_client(url, headers={"Authorization": f"Bearer {token()}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = (await s.list_tools()).tools
            for t in tools:
                print(f"   tools/list: {t.name}  _meta={json.dumps(t.meta)}")
            name = next(t.name for t in tools if t.name.endswith("send_email"))
            res = await s.call_tool(name, {"to": "bob@contoso.com", "subject": "direct call", "body": "nobody approved"})
            text = " ".join(getattr(c, "text", "") for c in res.content)
            print(f"   tools/call {name}: isError={res.isError}: {text}")


def down():
    from azure.ai.projects import AIProjectClient
    project = AIProjectClient(endpoint=PE, credential=cred)
    try:
        project.agents.delete(agent_name=AGENT, force=True)
        print(f"   deleted agent {AGENT} (all versions, active sessions ended)")
    except Exception as e:  # noqa: BLE001
        print(f"   agent delete: {e}")
    try:
        for v in ("2", "1"):
            project.toolboxes.delete_toolbox_version(toolbox_name="helpdesk-tools", version=v)
            print(f"   deleted toolbox version {v}")
    except Exception as e:  # noqa: BLE001
        print(f"   toolbox delete: {e} (deleting the resource group removes it anyway)")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "toolbox":
        toolbox()
    elif cmd == "toolbox-v2":
        toolbox("never", "v2: approval never")
    elif cmd == "agent":
        agent()
    elif cmd == "ask":
        ask(sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None)
    elif cmd == "direct-call":
        asyncio.run(_direct())
    elif cmd == "down":
        down()
    else:
        print(__doc__)
