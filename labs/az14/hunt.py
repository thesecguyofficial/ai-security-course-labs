"""
hunt.py: hunt in one day of the hosted agent's traces (logs/helpdesk-traces.jsonl, FAKE data for 21 Oct 2026).

    python3 hunt.py          # make hunt

Span names (invoke_agent, execute_tool) and the attributes gen_ai.tool.call.arguments / gen_ai.tool.call.result are
the names on Microsoft's tracing page. Everything else in the file (token_oid, x_ms_user_identity, tool, the egress
events) is the lab's own: in real life it comes from your app's log and the egress audit log, joined by conversation.

CHALLENGE 3 (lesson 14.7): chain() links each write call back to the tool RESULT, earlier in the same conversation,
that contained its argument values. That is how you prove "the article told it to", not "the user asked".
"""

import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
WRITE_TOOLS = {"send_email", "create_ticket", "close_ticket", "delete_ticket", "delete_blob", "http_get"}
SECRET = re.compile(r"(KEY|SECRET|PASSWORD|TOKEN)\s*=", re.I)


def load(path=os.path.join(HERE, "logs", "helpdesk-traces.jsonl")) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def h1_outside_email(ev):
    """send_email calls whose recipient domain is not exactly contoso.com."""
    out = []
    for e in ev:
        if e.get("span") == "execute_tool" and e["tool"] == "send_email":
            to = json.loads(e["gen_ai.tool.call.arguments"]).get("to", "")
            if domain(to) != "contoso.com":
                out.append((e["time"], e["gen_ai.conversation.id"], to))
    return out


def h2_egress(ev):
    """Outbound hosts the egress policy denied, or would have denied in Audit mode."""
    return [(e["time"], e["gen_ai.conversation.id"], e["host"], e["action"]) for e in ev
            if e.get("event") == "egress" and e["action"] in ("Deny", "WouldDeny")]


def h3_identity_mismatch(ev):
    """Turns where the session identity (x-ms-user-identity) isn't the signed-in user's own object ID."""
    return [(e["time"], e["gen_ai.conversation.id"], e["token_oid"], e["x_ms_user_identity"]) for e in ev
            if e.get("span") == "invoke_agent" and e["token_oid"] != e["x_ms_user_identity"]]


def h4_secrets(ev):
    """Trace attributes that look like they carry a secret. Microsoft: "Don't store secrets ... in span attributes"."""
    return [(e["time"], e["gen_ai.conversation.id"], e.get("tool")) for e in ev
            if e.get("span") == "execute_tool" and SECRET.search(e.get("gen_ai.tool.call.result", ""))]


def chain(ev) -> list[tuple]:
    """CHALLENGE 3. Return (time, conversation, write tool, matched value, source tool) for each write call whose
    argument value (6+ characters) appeared in an earlier tool result in the same conversation.
    Expected on this log: 2 tuples (the lookalike email and the http_get)."""
    return []


def main():
    ev = load()
    print(f"{len(ev)} events, {ev[0]['time']} to {ev[-1]['time']}\n")
    r = h1_outside_email(ev)
    print(f"H1 send_email outside contoso.com: {len(r)}")
    for x in r:
        print(f"   {x[0]} {x[1]} to={x[2]}")
    r = h2_egress(ev)
    print(f"\nH2 egress denied or would-deny: {len(r)}")
    for x in r:
        print(f"   {x[0]} {x[1]} host={x[2]} action={x[3]}")
    r = h3_identity_mismatch(ev)
    print(f"\nH3 session identity is not the signed-in user: {len(r)}")
    for x in r:
        print(f"   {x[0]} {x[1]} signed_in={x[2]} session_as={x[3]}")
    r = h4_secrets(ev)
    print(f"\nH4 secrets in trace attributes: {len(r)}")
    for x in r:
        print(f"   {x[0]} {x[1]} tool={x[2]}")
    c = chain(ev)
    print(f"\nH5 write calls traced to a tool result: {len(c) if c else 'not implemented yet (challenge 3)'}")
    for x in c:
        print(f"   {x}")


if __name__ == "__main__":
    main()
