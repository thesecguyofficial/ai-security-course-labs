"""
memory.py: Memory Bank steps of the guided build (GUIDED-BUILD.md, Step 6). Your project only.

    python3 memory.py --project P --region us-central1 --agent NAME ttl --days 30   # set a default TTL
    python3 memory.py --project P --region us-central1 --agent NAME write           # one memory for alice
    python3 memory.py --project P --region us-central1 --agent NAME read --user alice
    python3 memory.py --project P --region us-central1 --agent NAME read --user bob

Calls from Google's Memory Bank pages: client.agent_engines.memories.create / .retrieve with a scope dict, and the
memory_bank_config.ttl_config.default_ttl setting ("<seconds>s"). Newer SDK versions also name these
agentplatform.Client and client.runtimes; the config keys are the same.
"""

import argparse
import json

import vertexai

APP = "tsg_helpdesk_gc14"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True)
    ap.add_argument("--region", default="us-central1")
    ap.add_argument("--agent", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    ttl = sub.add_parser("ttl")
    ttl.add_argument("--days", type=int, required=True)
    sub.add_parser("write")
    read = sub.add_parser("read")
    read.add_argument("--user", required=True)
    a = ap.parse_args()
    client = vertexai.Client(project=a.project, location=a.region)

    if a.cmd == "ttl":
        client.agent_engines.update(name=a.agent, config={
            "context_spec": {"memory_bank_config": {"ttl_config": {"default_ttl": f"{a.days * 86400}s"}}}})
        print(f"default_ttl set to {a.days * 86400}s ({a.days} days) for memories created from now on")
    elif a.cmd == "write":
        op = client.agent_engines.memories.create(
            name=a.agent, fact="Alice prefers replies before 10:00.", scope={"app_name": APP, "user_id": "alice"})
        print(op)
    else:
        got = list(client.agent_engines.memories.retrieve(
            name=a.agent, scope={"app_name": APP, "user_id": a.user}))
        print(f"{len(got)} memories for user_id={a.user}")
        for m in got:
            mem = getattr(m, "memory", m)
            print(json.dumps({"fact": getattr(mem, "fact", None), "scope": getattr(mem, "scope", None),
                              "expireTime": str(getattr(mem, "expire_time", None))}))


if __name__ == "__main__":
    main()
