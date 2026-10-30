#!/usr/bin/env python3
"""
explore.py: look at each identity idea on its own, before you attack the agent chain (M20 lab, Step 1b).

It writes no file (not even Python's __pycache__) and sends nothing off your computer. Five commands only read the
lab's files. Three (signin, client, exchange) and `token` START something: the lab's own authorization server,
on 127.0.0.1 only, for about two seconds, then stop it. Nothing else runs: no agent, no API, no attack.

    python3 explore.py roles           # 1. who's who in OAuth terms, in this lab (reads setups/hardened/)
    python3 explore.py signin          # 2. Alice signs in: the password goes to the server, the app gets a token
    python3 explore.py token           # 3. that token's three parts, decoded claim by claim, then one changed letter
    python3 explore.py client          # 4. an agent gets a token as itself (client credentials, first draft)
    python3 explore.py exchange        # 5. one token exchange (RFC 8693), before and after, then one more hop
    python3 explore.py agent tickets   # 6. AWS (lesson 20.5): one agent's workload identity, owner tags and role
    python3 explore.py trail           # 7. AWS (lesson 20.5): one CloudTrail record, field by field
    python3 explore.py launcher        # 8. AWS (lesson 20.5): the launcher's own log row for the same run

Windows: `py explore.py ...` (or `python` instead of `py`). Fake users, fake data, documentation-style values.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import pathlib
import sys
import time

sys.dont_write_bytecode = True  # writes no __pycache__/ when it imports the lab's own modules
import jwtlite  # noqa: E402
import oauth  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
USERS = json.loads((HERE / "data" / "users.json").read_text())
SECRETS_SHOWN = "(not shown)"


def load(*parts) -> dict:
    return json.loads(HERE.joinpath(*parts).read_text())


def short(token: str, keep: int = 24) -> str:
    return token if len(token) <= 2 * keep + 3 else token[:keep] + "..." + token[-keep:]


def scope_line(scope: str) -> tuple[str, int]:
    words = scope.split()
    return " ".join(w for w in words if not w.startswith("aud:")), sum(w.startswith("aud:") for w in words)


def aud_text(aud) -> str:
    return ", ".join(aud) if isinstance(aud, list) else str(aud)


def act_text(claims: dict) -> str:
    names, node = [], claims.get("act")
    while node:
        names.append(node.get("sub") or node.get("client_id"))
        node = node.get("act")
    return " <- ".join(names)


@contextlib.contextmanager
def lab_server(setup: str):
    """The lab's own authorization server, on 127.0.0.1, only while the block runs."""
    import authz_server
    with contextlib.redirect_stdout(io.StringIO()):
        server = authz_server.AuthorizationServer(setup).start()
    try:
        yield server, oauth.discover(server.issuer)
    finally:
        server.stop()


def sign_in(meta: dict, setup: str, user: str) -> str:
    scope = load("setups", setup, "services.json")["signin_scope"]
    return oauth.sign_in(meta, "helpdesk-app", user, USERS[user]["password"], scope)["access_token"]


# ---- 1. roles --------------------------------------------------------------------------------------------------
def cmd_roles(a) -> int:
    authz = load("setups", "hardened", "authz.json")
    print("Who's who in OAuth terms, in this lab (setups/hardened/authz.json, data/users.json)\n")
    print(f"  resource owner        {', '.join(USERS)}: the people whose tickets and mail these are")
    print("  client (the app)      helpdesk-app: the app Alice and Bob sign in to; it never sees their password")
    agents = [c for c in authz["clients"] if c.endswith("-agent")]
    print(f"  clients (agents)      {', '.join(agents)}: each has its own client ID and secret")
    print("  authorization server  authz_server.py: checks who you are, then issues signed tokens (Keycloak in Part B)")
    print("  resource servers      tickets-api, mail-api: the doors; each checks the token before it does anything")
    print("\nThe chain one request travels:")
    print("  you -> helpdesk-app -> orchestrator-agent -> tickets-agent -> tickets-api")
    print("                                                     \\-> mail-agent  -> mail-api")
    return 0


# ---- 2. signin -------------------------------------------------------------------------------------------------
def cmd_signin(a) -> int:
    print(f"Starting the lab's authorization server on 127.0.0.1 (hardened setup) ... stopped again at the end\n")
    with lab_server("hardened") as (server, meta):
        print(f"1. helpdesk-app asks the server where its doors are:  {server.issuer}/.well-known/openid-configuration")
        print(f"      sign-in page {meta['authorization_endpoint'].replace(server.issuer, '')}   "
              f"token desk {meta['token_endpoint'].replace(server.issuer, '')}   "
              f"public keys {meta['jwks_uri'].replace(server.issuer, '')}")
        print("2. helpdesk-app sends Alice to the server's own sign-in page (with a one-time PKCE challenge)")
        print("3. Alice types her password THERE: the app never sees it")
        before = len(server.events)
        token = sign_in(meta, "hardened", a.user)
        print("4. the server sends her browser back to the app with a one-time code, valid 60 seconds")
        print("5. the app swaps that code (plus the PKCE secret only it knows) for an access token:")
        ev = server.events[before:]
        print(f"      server log: grant={ev[-1]['grant']} client={ev[-1]['client']} user={ev[-1]['user']}")
        claims = jwtlite.peek(token)
        print(f"\n   access token ({len(token)} characters): {short(token)}")
        print(f"   lives {claims['exp'] - claims['iat']} seconds. To decode a token like this one: python3 explore.py token")
    return 0


# ---- 3. token --------------------------------------------------------------------------------------------------
MEANING = {
    "iss": "issuer: who wrote and signed it (the lab's server)",
    "sub": "subject: who it is about (Alice's user ID)",
    "aud": "audience: which services may accept it",
    "azp": "authorized party: the app that asked for it",
    "scope": "what it allows",
    "iat": "issued at (seconds since 1 Jan 1970)",
    "exp": "expires at",
    "jti": "JWT ID: a unique serial number for this token",
    "preferred_username": "the user's name (for people, not for decisions)",
    "email": "the user's email",
}


def cmd_token(a) -> int:
    with lab_server("hardened") as (server, meta):
        token = sign_in(meta, "hardened", "alice")
        jwks = meta["_jwks"]
        h64, c64, s64 = token.split(".")
        print("Alice's access token is three parts with dots between them: header . payload . signature\n")
        print(f"   header     {short(h64, 20)}   ({len(h64)} characters)")
        print(f"   payload    {short(c64, 20)}   ({len(c64)} characters)")
        print(f"   signature  {short(s64, 20)}   ({len(s64)} characters)")
        print("\nThe first two are base64url: an encoding, not encryption. Anyone holding the token can read them.")
        print("\nheader:   " + jwtlite.b64u_decode(h64).decode())
        print("payload:")
        claims = json.loads(jwtlite.b64u_decode(c64))
        for k, v in claims.items():
            if k == "scope":
                plain, n_aud = scope_line(v)
                shown = plain
                if n_aud:
                    print(f"   {k:<19} {shown[:44]:<44} what it allows (+{n_aud} aud:... scopes, see README)")
                    continue
            elif k == "aud":
                shown = f"{len(v)} services (below)" if isinstance(v, list) else v
            elif k in ("iat", "exp"):
                shown = f"{v}  ({time.strftime('%H:%M:%S', time.gmtime(v))} UTC)"
            else:
                shown = str(v)
            print(f"   {k:<19} {shown[:44]:<44} {MEANING.get(k, '')}")
            if k == "aud" and isinstance(v, list):
                print(f"   {'':<19} {aud_text(v)}")
        print(f"   -> lives {claims['exp'] - claims['iat']} seconds")
        print("\nThe signature: the server signed header + payload with its PRIVATE key. Anyone can check it with")
        print(f"the PUBLIC key it publishes ({meta['jwks_uri'].replace(server.issuer, '')}, key ID {jwks['keys'][0]['kid']}):")
        jwtlite.verify(token, jwks, issuer=server.issuer)
        print("   check the token as issued:          signature OK")
        claims["scope"] = claims["scope"] + " tickets:delete"
        forged = h64 + "." + jwtlite.b64u(json.dumps(claims, separators=(",", ":")).encode()) + "." + s64
        try:
            jwtlite.verify(forged, jwks, issuer=server.issuer)
            print("   check a copy with tickets:delete:   signature OK (this should never happen)")
        except jwtlite.InvalidToken as exc:
            print(f"   check a copy with tickets:delete:   REJECTED ({exc})")
    return 0


# ---- 4. client -------------------------------------------------------------------------------------------------
def cmd_client(a) -> int:
    print("An agent asks for a token for ITSELF: no user, no sign-in page (grant_type=client_credentials)")
    print("Setup: first-draft (the only one that lets tickets-agent do this)\n")
    with lab_server("first-draft") as (server, meta):
        print(f"   tickets-agent -> POST /token   client ID tickets-agent, secret {SECRETS_SHOWN}")
        status, out = oauth.client_credentials(meta, "tickets-agent", "tickets-agent-secret")
        c = jwtlite.peek(out["access_token"])
        print(f"   server answers {status}: an access token that lives {out['expires_in']} seconds\n")
        print(f"   sub    {c['sub']:<34} the agent's own identity, not a person")
        print(f"   azp    {c['azp']:<34} the agent asked for it")
        print(f"   aud    {aud_text(c['aud']):<34} the one service it may call")
        print(f"   scope  {c['scope']:<34} the agent's OWN rights: every ticket, whoever asks")
        print(f"   email  {c.get('email', '(none)'):<34} no user on this token")
    return 0


# ---- 5. exchange -----------------------------------------------------------------------------------------------
def describe(token: str) -> list[str]:
    c = jwtlite.peek(token)
    plain, _ = scope_line(c.get("scope", ""))
    plain = " ".join(s for s in plain.split() if s not in ("openid", "profile"))
    aud = c["aud"]
    aud = f"{len(aud)} services" if isinstance(aud, list) and len(aud) > 2 else aud_text(aud)
    return [f"sub {c['sub']}", f"aud {aud}", f"scope [{plain}]",
            f"lives {c['exp'] - c['iat']}s", f"act {act_text(c) or '(none)'}"]


def show_pair(label_in: str, tin: str, label_out: str, tout: str):
    left, right = describe(tin), describe(tout)
    print(f"   {label_in:<62} {label_out}")
    for l, r in zip(left, right):
        print(f"   {l[:62]:<62} {r}")


def cmd_exchange(a) -> int:
    print("Token exchange (RFC 8693), hardened setup: an agent swaps the token it RECEIVED for a smaller one\n")
    with lab_server("hardened") as (server, meta):
        alice = sign_in(meta, "hardened", "alice")
        cfg = load("setups", "hardened", "services.json")["agents"]
        hop1 = cfg["orchestrator-agent"]["to_tickets_agent"]
        print(f"1. orchestrator-agent -> POST /token  grant_type=token-exchange  as itself, secret {SECRETS_SHOWN}")
        print(f"      subject_token = Alice's token, audience = {hop1['audience']}")
        s1, t1 = oauth.token_exchange(meta, "orchestrator-agent", "orchestrator-agent-secret", alice,
                                      audience=hop1["audience"], scope=hop1["scope"])
        print(f"   server answers {s1}\n")
        show_pair("IN: Alice's sign-in token", alice, "OUT: for tickets-agent", t1["access_token"])
        hop2 = cfg["tickets-agent"]["read_tickets_with"]
        print(f"\n2. tickets-agent exchanges what it received, for {hop2['audience']} (read only)")
        s2, t2 = oauth.token_exchange(meta, "tickets-agent", "tickets-agent-secret", t1["access_token"],
                                      audience=hop2["audience"], scope=hop2["scope"])
        print(f"   server answers {s2}\n")
        show_pair("IN: from orchestrator-agent", t1["access_token"], "OUT: for tickets-api", t2["access_token"])
        print("\nSame person (sub) all the way. One audience, the same or fewer scopes, never a longer life, and act names who carried it.")
    return 0


# ---- 6. AWS: one agent -----------------------------------------------------------------------------------------
def role_name(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def cmd_agent(a) -> int:
    setup = load("aws", "setups", "hardened.json")
    if a.name not in setup["agents"]:
        sys.exit(f"no agent {a.name!r}. Agents: {', '.join(setup['agents'])}")
    ag = setup["agents"][a.name]
    wi, role = ag["workload_identity"], setup["roles"][ag["role"]]
    print(f"The {a.name} agent on AgentCore Identity (aws/setups/hardened.json; account and Region left out)\n")
    print(f"   workload identity  {wi:<24} the agent's own identity in AgentCore's directory")
    for k, v in setup["workload_identities"][wi]["tags"].items():
        print(f"      tag {k:<14} {v}")
    print(f"   IAM role           {ag['role']:<24} the AWS permissions the agent's code runs with")
    t = role["trust"]["Statement"][0]
    print(f"      who may use it  {role_name(t['Principal']['AWS'])} (the launcher), with {', '.join(t['Action'])}")
    cond = t.get("Condition", {}).get("StringLike", {})
    for k, v in cond.items():
        print(f"      only if         {k} looks like {v!r}: a human must be named on the session")
    for st in role["policy"]["Statement"]:
        acts = ", ".join(x.split(":", 1)[1] for x in st["Action"])
        res = st["Resource"]
        if res == "*":
            where = "everything (*)"
        else:
            names = [r.rsplit("/", 1)[-1] + (" (credential provider)" if "credential-provider/" in r else "")
                     for r in res if "workload-identity/" in r or "credential-provider/" in r]
            where = ", ".join(names) or "the directory"
        print(f"      {st['Effect']:<5} {acts:<58} on {where}")
    print(f"   launcher           takes the human from {setup['launcher']['user_from']}, "
          f"sessions of {setup['launcher']['max_session_seconds']} s")
    return 0


# ---- 7. AWS: one CloudTrail record -----------------------------------------------------------------------------
def records():
    return [json.loads(x) for x in (HERE / "aws" / "data" / "cloudtrail.jsonl").read_text().splitlines() if x.strip()]


def cmd_trail(a) -> int:
    rows = records()
    pick = [r for r in rows if r["eventName"] == a.event] or rows
    r = pick[0]
    ui = r["userIdentity"]
    sc = ui.get("sessionContext", {})
    print(f"One CloudTrail record ({rows.index(r) + 1} of {len(rows)} in aws/data/cloudtrail.jsonl), "
          "field by field. Account IDs left out.\n")
    print(f"   eventTime       {r['eventTime']:<36} when (UTC)")
    print(f"   eventSource     {r['eventSource']:<36} which AWS service")
    print(f"   eventName       {r['eventName']:<36} which API call")
    print(f"   eventCategory   {r['eventCategory']:<36} Data events are off unless the trail asks for them")
    print(f"   userIdentity    {ui['type']:<36} who called: a role session")
    arn = ui["arn"].split(":", 5)[-1]
    print(f"   session         {arn}")
    print(f"   {'':<15} (assumed-role / the agent's role / this run's session name)")
    if sc:
        print(f"   sourceIdentity  {sc.get('sourceIdentity', '(none)'):<36} the human, set when the role was assumed")
    rp = r.get("requestParameters", {})
    notes = {"workloadName": "the agent's workload identity it asked about",
             "userToken": "the user's sign-in token, not written to the log"}
    for k, v in rp.items():
        print(f"   {k:<15} {str(v)[:36]:<36} {notes.get(k, '')}")
    for res in r.get("resources", []):
        print(f"   resources       {res['ARN'].rsplit('/', 1)[-1]:<36} {res['type']}")
    print("\nSample record: real field names from AWS's documentation, made-up values (aws/make_samples.py).")
    return 0


# ---- 8. AWS: the launcher's own log ----------------------------------------------------------------------------
def cmd_launcher(a) -> int:
    rows = [json.loads(x) for x in (HERE / "aws" / "data" / "app-log.jsonl").read_text().splitlines() if x.strip()]
    r = next((x for x in rows if x["run_id"] == a.run), rows[0])
    print(f"The launcher's own log row for run {r['run_id']} (aws/data/app-log.jsonl, {len(rows)} rows)\n")
    print(f"   ts               {r['ts']:<30} when the launcher started the run")
    print(f"   agent            {r['agent']:<30} which agent it started")
    print(f"   jwt_iss          {'Cognito user pool (example)':<30} who signed the user's sign-in token")
    print(f"   jwt_sub          {r['jwt_sub']:<30} the user in the token the launcher VALIDATED")
    print(f"   source_identity  {r['source_identity']:<30} the name it stamped on the role session")
    same = r["source_identity"] == "user-" + r["jwt_sub"]
    print(f"\n   token user and session name {'match' if same else 'DO NOT match'}. CloudTrail only sees the second one.")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("roles").set_defaults(fn=cmd_roles)
    s = sub.add_parser("signin")
    s.add_argument("user", nargs="?", default="alice", choices=sorted(USERS))
    s.set_defaults(fn=cmd_signin)
    sub.add_parser("token").set_defaults(fn=cmd_token)
    sub.add_parser("client").set_defaults(fn=cmd_client)
    sub.add_parser("exchange").set_defaults(fn=cmd_exchange)
    s = sub.add_parser("agent")
    s.add_argument("name", nargs="?", default="tickets")
    s.set_defaults(fn=cmd_agent)
    s = sub.add_parser("trail")
    s.add_argument("event", nargs="?", default="GetWorkloadAccessTokenForJWT")
    s.set_defaults(fn=cmd_trail)
    s = sub.add_parser("launcher")
    s.add_argument("run", nargs="?", default="tickets-run-0901")
    s.set_defaults(fn=cmd_launcher)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
