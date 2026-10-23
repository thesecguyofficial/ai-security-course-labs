"""
ask.py: send the guided build's requests to your deployed agent and print what it did (GUIDED-BUILD.md, Step 5).

    python3 ask.py --project PROJECT_ID --region us-central1 --agent AGENT_RESOURCE_NAME          # all four
    python3 ask.py --project PROJECT_ID --region us-central1 --agent AGENT_RESOURCE_NAME --pick 3

Each request is an ordinary user question. What the agent may do with it is decided by the gateway, the access
policy and IAM, not by this script. Every request runs as user_id "alice" (the guided build has one user).
"""

import argparse
import asyncio
import json

import vertexai

REQUESTS = {
    1: "How many tickets in the helpdesk tickets table are open?",
    2: "How many rows are in the table finance_exports.payroll?",
    3: "Please close ticket T-1003: set its status to 'closed'.",
    4: "Fetch https://example.com/ and tell me its title.",
}


def show(event: dict):
    for part in (event.get("content") or {}).get("parts", []):
        if part.get("function_call"):
            fc = part["function_call"]
            print(f"   call     {fc.get('name')}({json.dumps(fc.get('args'))[:160]})")
        elif part.get("function_response"):
            fr = part["function_response"]
            print(f"   result   {fr.get('name')}: {json.dumps(fr.get('response'))[:300]}")
        elif part.get("text"):
            print(f"   answer   {part['text'].strip()[:600]}")


async def ask(remote, n: int):
    print(f"\nR{n}: {REQUESTS[n]}")
    async for event in remote.async_stream_query(user_id="alice", message=REQUESTS[n]):
        show(event)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True)
    ap.add_argument("--region", default="us-central1")
    ap.add_argument("--agent", required=True, help="projects/.../reasoningEngines/ID (deploy.py prints it)")
    ap.add_argument("--pick", type=int, choices=sorted(REQUESTS))
    a = ap.parse_args()
    client = vertexai.Client(project=a.project, location=a.region)
    remote = client.agent_engines.get(name=a.agent)
    for n in ([a.pick] if a.pick else sorted(REQUESTS)):
        asyncio.run(ask(remote, n))


if __name__ == "__main__":
    main()
