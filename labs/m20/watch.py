"""
watch.py: send one request through the agent chain and print every hop, every token and every API decision.

    python3 watch.py hardened alice "Summarise T-4711 and email me the summary"     # make watch
    python3 watch.py first-draft bob "Show me T-4711"
    python3 watch.py hardened alice "Show me T-4713" --idp keycloak

Each exchanged token is shown as {aud, scope, lifetime, act}: the scope list hides openid, profile and the
aud:... scopes so you can see the permissions shrink. The audit rows at the end are what the APIs logged.
"""
import argparse
import sys

from services import Chain


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("setup", choices=["first-draft", "hardened"])
    p.add_argument("user", choices=["alice", "bob"])
    p.add_argument("request")
    p.add_argument("--idp", choices=["local", "keycloak"], default="local")
    args = p.parse_args(argv)
    with Chain(args.setup, args.idp) as chain:
        status, out = chain.ask(args.user, args.request)
        print(f"Setup: {args.setup}   identity provider: {chain.issuer}\n")
        print("\n".join(chain.trace))
        print(f"\nAnswer ({status}): {out.get('summary') or out}")
        print("\nWhat the APIs logged:")
        for r in chain.audit:
            chainlist, node = [], r.get("act")
            while node:
                chainlist.append(node.get("sub") or node.get("client_id"))
                node = node.get("act")
            via = " <- ".join(chainlist) if chainlist else f"azp={r.get('azp')} (no act claim)"
            print(f"   {r['api']:<11} {r['op']:<6} {r.get('ticket') or r.get('to', ''):<20} {r['result']:<8} "
                  f"user={r.get('user')}  via {via}  {r.get('reason', '')}")
        if chain.outbox:
            print("\nOutbox: " + ", ".join(m["to"] for m in chain.outbox))
    return 0


if __name__ == "__main__":
    sys.exit(main())
