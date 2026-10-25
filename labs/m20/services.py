"""
services.py: the TSG Helpdesk as a chain of three agents and two APIs, each a tiny HTTP service on 127.0.0.1.

    you -> helpdesk-app -> orchestrator-agent -> tickets-agent -> tickets-api
                                                       \\-> mail-agent -> mail-api

Each agent's "model" is a worst-case stand-in (like M7): it follows any instruction it finds inside a ticket,
written as [[assistant: ...]]. So the only thing between an injected instruction and real damage is the token
the agent holds and the checks the APIs make. That is the point of this module.

What each piece does is set in setups/<setup>/services.json. Nothing here knows which setup is "good".
"""

from __future__ import annotations

import copy
import json
import pathlib
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwtlite
import oauth

HERE = pathlib.Path(__file__).resolve().parent
AGENT_SECRETS = {name: name + "-secret" for name in
                 ("orchestrator-agent", "tickets-agent", "mail-agent", "metrics-agent")}


class Clock:
    """Shared clock, so the lab can ask 'what if this token is replayed 10 minutes from now?'"""

    def __init__(self):
        self.offset = 0.0

    def __call__(self) -> float:
        return time.time() + self.offset


def allowed_recipient(claims: dict, to: str) -> bool:
    """CHALLENGE 1 (lesson 20.6): the hardened mail API calls this before it sends anything.

    A token proves WHO the user is and WHICH agent is asking. It does not say where this particular email may go.
    Return True only when `to` is an address this user may send to: in this lab, the user's own address, which
    the authorization server put in the token's `email` claim.
    """
    return True  # TODO: replace with your rule. Until then a planted instruction can mail tickets out (A8).


class Service:
    """A JSON-over-HTTP service on an ephemeral 127.0.0.1 port."""

    name = "service"

    def __init__(self, chain: "Chain", cfg: dict):
        self.chain, self.cfg = chain, cfg
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def say(self, text: str):
        self.chain.trace.append(f"   {self.name:<18} {text}")

    def handle(self, method: str, path: str, token: str | None, body: dict, headers) -> tuple[int, dict]:
        raise NotImplementedError

    def check_token(self, token: str | None, audience: str | None) -> tuple[dict | None, str]:
        """Signature, issuer, expiry always. Audience only if `audience` is given (the first draft passes None)."""
        if not token:
            return None, "no token"
        try:
            claims = jwtlite.verify(token, self.chain.jwks, issuer=self.chain.issuer, now=self.chain.clock())
        except jwtlite.InvalidToken as exc:
            return None, str(exc)
        if audience:
            aud = claims.get("aud")
            if audience not in (aud if isinstance(aud, list) else [aud]):
                return None, f"token is for {aud}, not for {audience}"
        return claims, ""

    def _handler(self):
        service = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _go(self, method):
                length = min(int(self.headers.get("Content-Length") or 0), 64_000)
                raw = self.rfile.read(length).decode() if length else ""
                try:
                    body = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    body = {}
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else None
                try:
                    status, out = service.handle(method, self.path, token, body, self.headers)
                except Exception as exc:  # noqa: BLE001 - a lab service reports, it doesn't crash the chain
                    status, out = 500, {"error": "server_error", "error_description": repr(exc)}
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._go("GET")

            def do_POST(self):
                self._go("POST")

            def do_DELETE(self):
                self._go("DELETE")

        return Handler


# ---- the two APIs -----------------------------------------------------------------------------------------------
class API(Service):
    def audit(self, **row):
        row.update(api=self.name, ts=int(self.chain.clock()))
        self.chain.audit.append(row)

    def authorize(self, token, needed_scope: str, write: bool):
        """Returns (claims, None) or (None, (status, error_body))."""
        claims, why = self.check_token(token, self.name if self.cfg["check_audience"] else None)
        if not claims:
            return None, (401, {"error": "invalid_token", "error_description": why})
        callers = self.cfg.get("allowed_callers")
        if callers and claims.get("azp") not in callers:
            return None, (403, {"error": "forbidden", "error_description":
                                f"{claims.get('azp')} may not call {self.name} (allowed: {', '.join(callers)})"})
        if needed_scope not in claims.get("scope", "").split():
            return None, (403, {"error": "insufficient_scope", "error_description": f"needs {needed_scope}"})
        if write and self.cfg.get("one_time_writes"):
            key = (self.name, claims.get("jti"))
            if key in self.chain.used_jti:
                return None, (401, {"error": "invalid_token", "error_description": "token already used (replay)"})
            self.chain.used_jti.add(key)
        return claims, None


class TicketsAPI(API):
    name = "tickets-api"

    def handle(self, method, path, token, body, headers):
        m = re.fullmatch(r"/tickets/(T-\d+)", urllib.parse.urlsplit(path).path)
        if not m:
            return 404, {"error": "not_found"}
        tid = m.group(1)
        write = method == "DELETE"
        claims, err = self.authorize(token, "tickets:delete" if write else "tickets:read", write)
        peeked = jwtlite.peek(token or "")
        if err:
            self.audit(op=method, ticket=tid, result="refused", reason=err[1]["error_description"],
                       user=peeked.get("preferred_username"), azp=peeked.get("azp"), jti=peeked.get("jti"),
                       aud=peeked.get("aud"), act=peeked.get("act"))
            self.say(f"{method} {tid}: REFUSED ({err[1]['error_description']})")
            return err
        user = claims.get("preferred_username")
        is_service = (claims.get("preferred_username") or claims["sub"]).startswith("service-account-")
        if is_service and self.cfg.get("trust_service_accounts"):
            # "Internal callers are trusted": the agent's service account may read any ticket, and its word
            # about who it acts for goes into the log only. This is the confused deputy.
            user = headers.get("X-On-Behalf-Of")
        ticket = self.chain.tickets.get(tid)
        trusted_internal = is_service and self.cfg.get("trust_service_accounts")
        if not ticket or (ticket["owner"] != user and not trusted_internal):
            self.audit(op=method, ticket=tid, result="refused", reason="not your ticket", user=user,
                       azp=claims.get("azp"), jti=claims.get("jti"), act=claims.get("act"))
            self.say(f"{method} {tid} for {user}: REFUSED (not found for this user)")
            return 404, {"error": "not_found"}
        self.audit(op=method, ticket=tid, result="ok", user=user, azp=claims.get("azp"), jti=claims.get("jti"),
                   act=claims.get("act"), aud=claims.get("aud"))
        if write:
            del self.chain.tickets[tid]
            self.say(f"DELETE {tid} for {user} via {claims.get('azp')}: DONE")
            return 200, {"deleted": tid}
        self.say(f"GET {tid} for {user} via {claims.get('azp')}: ok")
        return 200, dict(ticket, id=tid)


class MailAPI(API):
    name = "mail-api"

    def handle(self, method, path, token, body, headers):
        if method != "POST" or path != "/send":
            return 404, {"error": "not_found"}
        claims, err = self.authorize(token, "mail:send", write=True)
        peeked = jwtlite.peek(token or "")
        to = body.get("to", "")
        if err:
            self.audit(op="send", to=to, result="refused", reason=err[1]["error_description"],
                       user=peeked.get("preferred_username"), azp=peeked.get("azp"), jti=peeked.get("jti"),
                       aud=peeked.get("aud"), act=peeked.get("act"))
            self.say(f"send to {to}: REFUSED ({err[1]['error_description']})")
            return err
        if self.cfg.get("recipient_rule") == "own-address" and not allowed_recipient(claims, to):
            self.audit(op="send", to=to, result="refused", reason="recipient not allowed",
                       user=claims.get("preferred_username"), azp=claims.get("azp"), jti=claims.get("jti"))
            self.say(f"send to {to}: REFUSED (recipient not allowed for {claims.get('preferred_username')})")
            return 403, {"error": "forbidden", "error_description": "recipient not allowed"}
        self.chain.outbox.append({"to": to, "subject": body.get("subject"), "from_user": claims.get("preferred_username")})
        self.audit(op="send", to=to, result="ok", user=claims.get("preferred_username"), azp=claims.get("azp"),
                   jti=claims.get("jti"), act=claims.get("act"), aud=claims.get("aud"))
        self.say(f"send to {to} for {claims.get('preferred_username')} via {claims.get('azp')}: SENT")
        return 200, {"sent": True}


# ---- the three agents -------------------------------------------------------------------------------------------
class Agent(Service):
    def incoming(self, token):
        return self.check_token(token, self.name if self.cfg.get("check_audience") else None)

    def token_for(self, how, received: str, label: str) -> str | None:
        """'passthrough' forwards what we were given. A dict means: RFC 8693 exchange for exactly that."""
        if how == "passthrough":
            self.say(f"-> {label}: forwards the token it was given (passthrough)")
            return received
        status, out = oauth.token_exchange(self.chain.meta, self.name, AGENT_SECRETS[self.name], received,
                                           audience=how.get("audience"), scope=how.get("scope"))
        if status != 200:
            self.say(f"-> {label}: token exchange REFUSED: {out.get('error')} {out.get('error_description', '')}")
            return None
        self.say(f"-> {label}: exchanged for {self.chain.describe(out['access_token'])}")
        self.chain.captured[f"{self.name}->{label}"] = out["access_token"]
        return out["access_token"]


class Orchestrator(Agent):
    name = "orchestrator-agent"

    def handle(self, method, path, token, body, headers):
        claims, why = self.incoming(token)
        if not claims:
            self.say(f"REFUSED incoming token: {why}")
            return 401, {"error": "invalid_token", "error_description": why}
        request = body.get("request", "")
        tid = (re.findall(r"T-\d+", request) or [None])[0]
        self.say(f"plan for {claims.get('preferred_username')}: read {tid}" + (", email a summary" if "email" in request.lower() else ""))
        down = self.token_for(self.cfg["to_tickets_agent"], token, "tickets-agent")
        if not down:
            return 403, {"error": "delegation_refused"}
        return oauth.call("POST", self.chain.services["tickets-agent"].url + "/task", token=down,
                          body={"ticket": tid, "email": "email" in request.lower()})


class TicketsAgent(Agent):
    name = "tickets-agent"

    def handle(self, method, path, token, body, headers):
        claims, why = self.incoming(token)
        if not claims:
            self.say(f"REFUSED incoming token: {why}")
            return 401, {"error": "invalid_token", "error_description": why}
        tid, user = body.get("ticket"), claims.get("preferred_username")
        how = self.cfg["read_tickets_with"]
        if how == "service-account":
            status, out = oauth.client_credentials(self.chain.meta, self.name, AGENT_SECRETS[self.name])
            if status != 200:
                return 502, {"error": "no service token"}
            api_token = out["access_token"]
            self.say(f"-> tickets-api: uses ITS OWN service account, says it acts for {user}")
            self.chain.captured["tickets-agent->tickets-api"] = api_token
            status, ticket = oauth.call_with_headers("GET", self.chain.services["tickets-api"].url + f"/tickets/{tid}",
                                                     api_token, {"X-On-Behalf-Of": user})
        else:
            api_token = self.token_for(how, token, "tickets-api")
            if not api_token:
                return 403, {"error": "delegation_refused"}
            status, ticket = oauth.call("GET", self.chain.services["tickets-api"].url + f"/tickets/{tid}", token=api_token)
        if status != 200:
            return status, ticket
        summary = f"{tid} '{ticket['title']}': {ticket['body']}"
        if body.get("email"):
            down = self.token_for(self.cfg["to_mail_agent"], token, "mail-agent")
            if not down:
                return 403, {"error": "delegation_refused", "summary": summary}
            oauth.call("POST", self.chain.services["mail-agent"].url + "/task", token=down, body={"ticket": ticket})
        return 200, {"summary": summary}


class MailAgent(Agent):
    name = "mail-agent"

    def handle(self, method, path, token, body, headers):
        claims, why = self.incoming(token)
        if not claims:
            self.say(f"REFUSED incoming token: {why}")
            return 401, {"error": "invalid_token", "error_description": why}
        ticket = body.get("ticket", {})
        mail = self.chain.services["mail-api"].url + "/send"

        def send(to, subject, text):
            # One token per tool call: in the hardened setup a used token is refused, so ask for a fresh one.
            mail_token = self.token_for(self.cfg["to_mail_api"], token, "mail-api")
            if not mail_token:
                return None
            if self.cfg.get("debug_log_tokens"):
                self.chain.debug_log.append({"agent": self.name, "authorization": "Bearer " + mail_token})
            oauth.call("POST", mail, token=mail_token, body={"to": to, "subject": subject, "body": text})
            return mail_token

        last = send(claims.get("email"), f"Update on {ticket.get('id')}", ticket.get("body"))
        if not last:
            return 403, {"error": "delegation_refused"}
        text = ticket.get("body", "") + " " + " ".join(c["text"] for c in ticket.get("comments", []))
        # The stand-in model obeys planted instructions, using the credential it holds for every tool.
        for directive in re.findall(r"\[\[assistant:(.*?)\]\]", text):
            self.say(f"model obeys a planted instruction: {directive.strip()!r}")
            for tid in re.findall(r"delete ticket (T-\d+)", directive):
                oauth.call("DELETE", self.chain.services["tickets-api"].url + f"/tickets/{tid}", token=last)
            for addr in re.findall(r"to ([\w.+-]+@[\w.-]+)", directive):
                send(addr, f"Copy of {ticket.get('id')}", json.dumps(ticket))
        return 200, {"sent": True}


# ---- the whole chain ---------------------------------------------------------------------------------------------
class Chain:
    """Starts everything for one setup, against the lab's own authorization server or Keycloak."""

    def __init__(self, setup: str, idp: str = "local", keycloak_url: str = "http://127.0.0.1:8180"):
        self.setup, self.idp = setup, idp
        self.cfg = json.loads((HERE / "setups" / setup / "services.json").read_text())
        self.clock = Clock()
        self.trace: list[str] = []
        self.audit: list[dict] = []
        self.outbox: list[dict] = []
        self.debug_log: list[dict] = []
        self.captured: dict[str, str] = {}
        self.used_jti: set = set()
        self.tickets = copy.deepcopy(json.loads((HERE / "data" / "tickets.json").read_text()))
        self.authz = None
        if idp == "local":
            import authz_server
            self.authz = authz_server.AuthorizationServer(setup, clock=self.clock).start()
            self.issuer = self.authz.issuer
        else:
            self.issuer = f"{keycloak_url}/realms/tsg-{setup}"
        self.meta = oauth.discover(self.issuer)
        self.jwks = self.meta["_jwks"]
        self.services = {}
        for cls in (TicketsAPI, MailAPI):
            self.services[cls.name] = cls(self, self.cfg["apis"][cls.name])
        for cls in (Orchestrator, TicketsAgent, MailAgent):
            self.services[cls.name] = cls(self, self.cfg["agents"][cls.name])

    def stop(self):
        for s in self.services.values():
            s.stop()
        if self.authz:
            self.authz.stop()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()

    @staticmethod
    def describe(token: str) -> str:
        c = jwtlite.peek(token)
        scope = " ".join(s for s in c.get("scope", "").split() if not s.startswith("aud:") and s not in ("openid", "profile"))
        act = []
        node = c.get("act")
        while node:
            act.append(node.get("sub") or node.get("client_id"))
            node = node.get("act")
        parts = [f"aud={c.get('aud')}", f"scope=[{scope}]", f"lives {int(c.get('exp', 0) - c.get('iat', 0))}s"]
        if act:
            parts.append("act=" + " <- ".join(act))
        return "{" + ", ".join(parts) + "}"

    def sign_in(self, user: str) -> str:
        import authz_server  # noqa: F401  (users.json lives next to it)
        users = json.loads((HERE / "data" / "users.json").read_text())
        tokens = oauth.sign_in(self.meta, "helpdesk-app", user, users[user]["password"], self.cfg["signin_scope"])
        self.trace.append(f"   {'helpdesk-app':<18} {user} signed in (code + PKCE): {self.describe(tokens['access_token'])}")
        self.captured["user"] = tokens["access_token"]
        return tokens["access_token"]

    def ask(self, user: str, request: str) -> tuple[int, dict]:
        token = self.sign_in(user)
        self.trace.append(f"   {'helpdesk-app':<18} {user} asks: {request!r}")
        return oauth.call("POST", self.services["orchestrator-agent"].url + "/task", token=token,
                          body={"request": request})
