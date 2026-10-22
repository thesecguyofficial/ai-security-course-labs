"""
hunt.py: what the Helpdesk's own audit log tells you (lesson 13.2, "spot it"). The log is FAKE: 19 October 2026, the
hardened build's first day. Microsoft's MCP guidance: "Log approvals and tool calls for auditing and troubleshooting."
This is that log: one JSON line per retrieve, approval and tool_call, written by the app (fields are the lab's own).

    python3 hunt.py          # make hunt

  H1  knowledge base retrieves WITHOUT the user's token (permission-enabled sources return everything)
  H2  approvals clicked faster than a person can read the arguments (rubber-stamping)
  H3  approved send_email to an address outside contoso.com
  H4  reconstruct(): which retrieved chunk put the arguments into a write call? (CHALLENGE 4)
"""

import collections
import json
import os

import twin

HERE = os.path.dirname(os.path.abspath(__file__))
FAST_MS = 1500


def load_events(path=os.path.join(HERE, "logs", "helpdesk-audit.jsonl")) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def h1_no_token(ev):
    return [e for e in ev if e["event"] == "retrieve" and not e["user_token"]]


def h2_fast_approvers(ev, min_count=5):
    fast = collections.Counter(e["approver"] for e in ev if e["event"] == "approval" and e["approve"]
                               and e["latency_ms"] < FAST_MS)
    return {who: n for who, n in fast.items() if n >= min_count}


def h3_outside_email(ev):
    return [e for e in ev if e["event"] == "tool_call" and e["tool"] == "send_email"
            and not e["args"]["to"].lower().endswith("@contoso.com")]


def reconstruct(ev: list[dict]) -> list[tuple[str, str, str]]:
    """CHALLENGE 4. For every write tool_call, find the retrieved chunk(s) in the SAME turn whose text contains one of
    the call's argument values (a recipient address, a message body...). Return [(turn_id, tool, chunk_id)], sorted.
    Chunk text: {row["chunk_id"]: row["chunk"] for row in twin.build_rows(twin.setup("fixes"))}.
    A value the user never typed but a document did is the fingerprint of indirect injection. Ignore values shorter
    than 6 characters: "VPN" appears in plenty of honest chunks."""
    return []


def main():
    ev = load_events()
    print(f"{len(ev)} events, {ev[0]['ts']} to {ev[-1]['ts']}\n")
    h1 = h1_no_token(ev)
    print(f"H1 retrieves without the user's token: {len(h1)}")
    for e in h1:
        print(f"   {e['ts']} {e['agent']} v{e['agent_version']} user={e['user']} docs={e['docs']}")
    h2 = h2_fast_approvers(ev)
    print(f"\nH2 approvers clicking 'approve' in under {FAST_MS} ms, 5+ times: {h2 or 'none'}")
    h3 = h3_outside_email(ev)
    print(f"\nH3 approved emails outside contoso.com: {len(h3)}")
    for e in h3:
        print(f"   {e['ts']} {e['turn_id']} user={e['user']} to={e['args']['to']}")
    r = reconstruct(ev)
    print(f"\nH4 write calls whose arguments came from a retrieved chunk: {r if r else 'not implemented yet (challenge 4)'}")


if __name__ == "__main__":
    main()
