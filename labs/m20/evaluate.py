"""
evaluate.py: run every attack and every normal request against one setup, each in a fresh copy of the chain.

    python3 evaluate.py first-draft            # make attack
    python3 evaluate.py hardened               # make hardened
    python3 evaluate.py hardened A4 --trace    # one attack, with every hop printed
    python3 evaluate.py hardened --idp keycloak   # the same suite against Keycloak (README, part B)
"""

from __future__ import annotations

import argparse
import sys

import oauth
from services import AGENT_SECRETS, Chain

TICKET_URL = "/tickets/"


def _aud(chain: Chain, name: str) -> str:
    """The aud:<name> scope, in setups where audiences travel as scopes."""
    return f" aud:{name}" if "aud:" in chain.cfg["signin_scope"] else ""


def _mail_token(chain: Chain) -> str | None:
    """What an attacker who can read the mail agent's traffic or logs walks away with."""
    if chain.debug_log:
        return chain.debug_log[-1]["authorization"][7:]
    return chain.captured.get("mail-agent->mail-api")


def a1_confused_deputy(chain):
    """Bob asks for Alice's ticket. Does the tickets agent fetch it with authority Bob doesn't have?"""
    status, out = chain.ask("bob", "Show me T-4711")
    return "VPN" in out.get("summary", ""), f"bob got: {out.get('summary') or out}"


def a2_passthrough_delete(chain):
    """A planted instruction in a ticket comment makes the mail agent delete the ticket with the token it holds."""
    chain.ask("alice", "Summarise T-4711 and email me the summary")
    return "T-4711" not in chain.tickets, "T-4711 " + ("DELETED" if "T-4711" not in chain.tickets else "still there")


def a3_cross_audience(chain):
    """A token meant for the mail API, taken from the mail agent, is replayed at the tickets API."""
    chain.ask("alice", "Summarise T-4713 and email me the summary")
    stolen = _mail_token(chain)
    status, out = oauth.call("GET", chain.services["tickets-api"].url + TICKET_URL + "T-4713", token=stolen)
    return status == 200, f"tickets-api answered {status} {out.get('error_description', '')}".strip()


def a4_upscope(chain):
    """The tickets agent swaps the token it was handed for one that can DELETE. Will the server add a scope?"""
    chain.ask("alice", "Show me T-4713")
    received = chain.captured.get("orchestrator-agent->tickets-agent") or chain.captured["user"]
    status, out = oauth.token_exchange(chain.meta, "tickets-agent", AGENT_SECRETS["tickets-agent"], received,
                                       audience="tickets-api",
                                       scope="profile tickets:read tickets:delete" + _aud(chain, "tickets-api"))
    if status != 200:
        return False, f"exchange refused: {out.get('error')} {out.get('error_description', '')}"
    status, out = oauth.call("DELETE", chain.services["tickets-api"].url + TICKET_URL + "T-4713", token=out["access_token"])
    return status == 200, f"exchange issued tickets:delete; DELETE answered {status}"


def a5_replay_later(chain):
    """The mail token from a log is replayed ten minutes later."""
    chain.ask("alice", "Summarise T-4713 and email me the summary")
    stolen = _mail_token(chain)
    chain.clock.offset = 600
    status, out = oauth.call("POST", chain.services["mail-api"].url + "/send", token=stolen,
                             body={"to": "alice@example.com", "subject": "Your account is locked", "body": "click here"})
    return status == 200, f"mail-api answered {status} {out.get('error_description', '')}".strip()


def a6_replay_now(chain):
    """The same mail token is sent again straight away: a duplicate 'send', no extra permission needed."""
    chain.ask("alice", "Summarise T-4713 and email me the summary")
    stolen = _mail_token(chain)
    status, out = oauth.call("POST", chain.services["mail-api"].url + "/send", token=stolen,
                             body={"to": "alice@example.com", "subject": "Update on T-4713", "body": "again"})
    return status == 200, f"mail-api answered {status} {out.get('error_description', '')}".strip()


def a7_bystander_agent(chain):
    """A metrics agent that overheard Alice's sign-in token exchanges it for a token that can delete."""
    user_token = chain.sign_in("alice")
    status, out = oauth.token_exchange(chain.meta, "metrics-agent", AGENT_SECRETS["metrics-agent"], user_token,
                                       audience="tickets-api", scope="tickets:read tickets:delete" + _aud(chain, "tickets-api"))
    if status != 200:
        return False, f"exchange refused: {status} {out.get('error')} {out.get('error_description', '')}"
    status, out = oauth.call("DELETE", chain.services["tickets-api"].url + TICKET_URL + "T-4713", token=out["access_token"])
    return status == 200, f"metrics-agent got a token; DELETE answered {status}"


def a8_injected_recipient(chain):
    """The planted instruction also asks for a copy to an outside address. (Challenge 1.)"""
    chain.ask("alice", "Summarise T-4711 and email me the summary")
    leaked = [m for m in chain.outbox if m["to"].endswith("@evil.example")]
    return bool(leaked), f"{len(leaked)} email(s) to evil.example"


def n1_summary_email(chain):
    status, out = chain.ask("alice", "Summarise T-4713 and email me the summary")
    ok = status == 200 and any(m["to"] == "alice@example.com" for m in chain.outbox)
    return ok, f"status {status}, emails to alice: {sum(m['to'] == 'alice@example.com' for m in chain.outbox)}"


def n2_bob_own_ticket(chain):
    status, out = chain.ask("bob", "Show me T-4712")
    return "Printer" in out.get("summary", ""), out.get("summary", str(out))[:60]


def n3_alice_poisoned_ticket(chain):
    status, out = chain.ask("alice", "Summarise T-4711 and email me the summary")
    ok = "VPN" in out.get("summary", "") and any(m["to"] == "alice@example.com" for m in chain.outbox)
    return ok, "summary + email to alice" if ok else str(out)[:80]


ATTACKS = {"A1": a1_confused_deputy, "A2": a2_passthrough_delete, "A3": a3_cross_audience, "A4": a4_upscope,
           "A5": a5_replay_later, "A6": a6_replay_now, "A7": a7_bystander_agent, "A8": a8_injected_recipient}
NORMAL = {"N1": n1_summary_email, "N2": n2_bob_own_ticket, "N3": n3_alice_poisoned_ticket}


def run_one(setup: str, test, idp: str = "local") -> tuple[bool, str, Chain]:
    chain = Chain(setup, idp)
    try:
        ok, evidence = test(chain)
    finally:
        chain.stop()
    return ok, evidence, chain


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("setup", choices=["first-draft", "hardened"])
    p.add_argument("only", nargs="?", help="one test id, e.g. A4 or N1")
    p.add_argument("--idp", choices=["local", "keycloak"], default="local")
    p.add_argument("--trace", action="store_true", help="print every hop")
    args = p.parse_args(argv)
    tests = {**ATTACKS, **NORMAL}
    if args.only:
        tests = {args.only: tests[args.only]}
    worked, normal_ok = [], 0
    for tid, test in tests.items():
        ok, evidence, chain = run_one(args.setup, test, args.idp)
        kind = "attack" if tid.startswith("A") else "normal"
        if kind == "attack":
            verdict = "WORKED " if ok else "blocked"
            worked += [tid] if ok else []
        else:
            verdict = "works  " if ok else "BROKEN "
            normal_ok += ok
        print(f"{tid} {verdict} {(test.__doc__ or test.__name__).strip().splitlines()[0][:70]:<72} {evidence}")
        if args.trace:
            print("\n".join(chain.trace))
    attacks = [t for t in tests if t.startswith("A")]
    normals = [t for t in tests if t.startswith("N")]
    print(f"\nAttacks that worked: {len(worked)} of {len(attacks)}  ({', '.join(worked) or 'none'})"
          f" | normal requests that work: {normal_ok} of {len(normals)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
