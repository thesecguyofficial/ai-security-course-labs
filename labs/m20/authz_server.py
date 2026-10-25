"""
authz_server.py: the lab's own OAuth 2.0 authorization server, on 127.0.0.1 only. LAB ONLY.

Standard library, no install. It does four things, the same way Keycloak does them (lesson 20.6):
  - OpenID discovery + JWKS          /.well-known/openid-configuration, /jwks
  - sign-in: authorization code + PKCE  /authorize (login form), /token grant_type=authorization_code
  - client credentials (an agent acting as itself)  /token grant_type=client_credentials
  - token exchange, RFC 8693         /token grant_type=urn:ietf:params:oauth:grant-type:token-exchange

What changes between the setups is policy, read from setups/<setup>/authz.json:
  - which audiences and scopes each client may ask for, and how long tokens live
  - downscope_only: a token exchange may only keep or drop scopes, never add them (RFC 8707 "downscope")
  - audience_scopes: an audience X is only reachable while the scope "aud:X" is still in the token
    (that is how Keycloak's downscope enforcer shrinks audiences too; see README "Why aud:... scopes")
  - record_actor: write the RFC 8693 "act" claim, nested one level per hop
  - max_actors: refuse chains longer than this

Run it on its own to poke at it with curl:  python3 authz_server.py hardened   (Ctrl+C to stop)
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import pathlib
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwtlite

HERE = pathlib.Path(__file__).resolve().parent
USERS = json.loads((HERE / "data" / "users.json").read_text())
_KEY = None
_KEY_LOCK = threading.Lock()


def signing_key() -> jwtlite.RSAKey:
    """One RSA key per Python process (making one takes about a second)."""
    global _KEY
    with _KEY_LOCK:
        if _KEY is None:
            _KEY = jwtlite.RSAKey(kid="tsg-lab-1")
        return _KEY


def load_policy(setup: str) -> dict:
    path = HERE / "setups" / setup / "authz.json"
    if not path.exists():
        raise SystemExit(f"No setup called {setup!r} (looked for {path})")
    return json.loads(path.read_text())


class AuthorizationServer:
    def __init__(self, setup: str, port: int = 0, clock=time.time):
        self.setup = setup
        self.policy = load_policy(setup)
        self.clock = clock
        self.codes: dict[str, dict] = {}
        self.events: list[dict] = []
        self.key = signing_key()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), self._handler())
        self.issuer = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    # ---- lifecycle -------------------------------------------------------------------------------------------
    def start(self) -> "AuthorizationServer":
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def log(self, **event):
        event["ts"] = int(self.clock())
        self.events.append(event)

    # ---- token minting ---------------------------------------------------------------------------------------
    def mint(self, *, sub: str, aud: list[str], azp: str, scope: list[str], lifetime: int,
             user: dict | None = None, act: dict | None = None) -> str:
        now = int(self.clock())
        claims = {"iss": self.issuer, "sub": sub, "aud": aud[0] if len(aud) == 1 else aud, "azp": azp,
                  "scope": " ".join(scope), "iat": now, "exp": now + lifetime, "jti": secrets.token_urlsafe(12)}
        if user:
            claims["preferred_username"] = user["username"]
            claims["email"] = user["email"]
        if act:
            claims["act"] = act
        return jwtlite.encode(claims, self.key, typ="at+jwt")

    def _audiences_from(self, client: dict, scopes: list[str]) -> list[str]:
        auds = list(client.get("audience", []))
        if self.policy.get("audience_scopes"):
            auds += [s[4:] for s in scopes if s.startswith("aud:")]
        return list(dict.fromkeys(auds))

    # ---- grants ----------------------------------------------------------------------------------------------
    def authenticate(self, headers, form) -> tuple[str | None, dict | None]:
        cid, secret = None, None
        auth = headers.get("Authorization", "")
        if auth.startswith("Basic "):
            raw = base64.b64decode(auth[6:]).decode()
            cid, _, secret = raw.partition(":")
            cid, secret = urllib.parse.unquote(cid), urllib.parse.unquote(secret)
        else:
            cid, secret = form.get("client_id"), form.get("client_secret")
        client = self.policy["clients"].get(cid or "")
        if not client:
            return None, None
        if client.get("public"):
            return cid, client
        if not secret or not secrets.compare_digest(secret, client.get("secret", "")):
            return None, None
        return cid, client

    def grant_code(self, cid, client, form):
        record = self.codes.pop(form.get("code", ""), None)
        if not record or record["client_id"] != cid or record["redirect_uri"] != form.get("redirect_uri"):
            return 400, {"error": "invalid_grant", "error_description": "unknown, used or mismatched code"}
        if record["expires"] < self.clock():
            return 400, {"error": "invalid_grant", "error_description": "code expired"}
        verifier = form.get("code_verifier", "")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        if not secrets.compare_digest(challenge, record["code_challenge"]):
            return 400, {"error": "invalid_grant", "error_description": "PKCE verifier does not match"}
        user = USERS[record["username"]]
        scope = [s for s in record["scope"] if s in client.get("scopes", []) or s == "openid"]
        lifetime = client.get("lifetime", self.policy["default_lifetime"])
        token = self.mint(sub=user["sub"], aud=self._audiences_from(client, scope), azp=cid, scope=scope,
                          lifetime=lifetime, user=user)
        self.log(grant="authorization_code", client=cid, user=user["username"], scope=scope)
        return 200, {"access_token": token, "token_type": "Bearer", "expires_in": lifetime, "scope": " ".join(scope)}

    def grant_client_credentials(self, cid, client, form):
        if not client.get("client_credentials"):
            return 400, {"error": "unauthorized_client", "error_description": "client credentials not allowed"}
        scope = client.get("service_scopes", [])
        lifetime = client.get("lifetime", self.policy["default_lifetime"])
        token = self.mint(sub="service-account-" + cid, aud=client.get("service_audience", []), azp=cid,
                          scope=scope, lifetime=lifetime)
        self.log(grant="client_credentials", client=cid, scope=scope)
        return 200, {"access_token": token, "token_type": "Bearer", "expires_in": lifetime, "scope": " ".join(scope)}

    def grant_exchange(self, cid, client, form):
        def refuse(status, error, why):
            self.log(grant="token_exchange", client=cid, result="refused", error=error, why=why)
            return status, {"error": error, "error_description": why}

        if not client.get("exchange"):
            return refuse(400, "unauthorized_client", "token exchange is not enabled for this client")
        if form.get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token":
            return refuse(400, "invalid_request", "subject_token_type must be an access token")
        try:
            subject = jwtlite.verify(form.get("subject_token", ""), {"keys": [self.key.public_jwk()]},
                                     issuer=self.issuer, now=self.clock())
        except jwtlite.InvalidToken as exc:
            return refuse(400, "invalid_request", f"subject token rejected: {exc}")
        subject_aud = subject["aud"] if isinstance(subject["aud"], list) else [subject["aud"]]
        if cid not in subject_aud:
            # Same rule and wording as Keycloak's standard token exchange: you may only exchange a token
            # that was issued TO you. Stops a bystander agent from cashing in a token it overheard.
            return refuse(403, "access_denied", "Client is not within the token audience")
        if form.get("actor_token"):
            return refuse(400, "invalid_request", "this lab derives the actor from client authentication")

        subject_scope = subject.get("scope", "").split()
        allowed = client.get("scopes", [])
        if "scope" in form:
            requested = form["scope"].split()
        elif self.policy.get("downscope_only"):
            requested = [s for s in subject_scope if s in allowed]
        else:
            requested = list(allowed)   # first draft: you get everything the client may have
        not_allowed = [s for s in requested if s not in allowed]
        if not_allowed:
            return refuse(400, "invalid_scope", f"Scopes {not_allowed} are not allowed for client {cid}")
        if self.policy.get("downscope_only"):
            extra = [s for s in requested if s not in subject_scope]
            if extra:
                return refuse(400, "invalid_scope",
                              f"Scopes {extra} not present in the initial access token {subject_scope}")

        possible = self._audiences_from({"audience": client.get("targets", [])}, requested) \
            if not self.policy.get("audience_scopes") else [s[4:] for s in requested if s.startswith("aud:")]
        if form.get("audience"):
            wanted = form["audience"].split()
            missing = [a for a in wanted if a not in possible]
            if missing:
                return refuse(400, "invalid_request", f"Requested audience not available: {', '.join(missing)}")
            aud = wanted
        else:
            aud = possible
        if not aud:
            return refuse(400, "invalid_request", "no audience for the new token")

        act = None
        if self.policy.get("record_actor"):
            act = {"sub": cid}
            if subject.get("act"):
                act["act"] = subject["act"]
            depth, node = 0, act
            while node:
                depth, node = depth + 1, node.get("act")
            if depth > self.policy.get("max_actors", 99):
                return refuse(400, "invalid_request", f"delegation chain longer than {self.policy['max_actors']}")

        user = next((u for u in USERS.values() if u["sub"] == subject["sub"]), None)
        lifetime = min(client.get("lifetime", self.policy["default_lifetime"]),
                       max(1, subject["exp"] - int(self.clock()))) if self.policy.get("never_outlive_subject") \
            else client.get("lifetime", self.policy["default_lifetime"])
        token = self.mint(sub=subject["sub"], aud=aud, azp=cid, scope=requested, lifetime=lifetime,
                          user=user, act=act)
        self.log(grant="token_exchange", client=cid, result="issued", user=subject.get("preferred_username"),
                 aud=aud, scope=requested, lifetime=lifetime)
        return 200, {"access_token": token, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                     "token_type": "Bearer", "expires_in": lifetime, "scope": " ".join(requested)}

    # ---- HTTP ------------------------------------------------------------------------------------------------
    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet: the lab prints its own story
                pass

            def send(self, status, body, ctype="application/json", headers=None):
                data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "no-store")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def form(self):
                length = min(int(self.headers.get("Content-Length") or 0), 64_000)
                return dict(urllib.parse.parse_qsl(self.rfile.read(length).decode()))

            def do_GET(self):
                url = urllib.parse.urlsplit(self.path)
                if url.path == "/.well-known/openid-configuration":
                    i = server.issuer
                    return self.send(200, {
                        "issuer": i, "authorization_endpoint": i + "/authorize", "token_endpoint": i + "/token",
                        "jwks_uri": i + "/jwks", "response_types_supported": ["code"],
                        "grant_types_supported": ["authorization_code", "client_credentials",
                                                  "urn:ietf:params:oauth:grant-type:token-exchange"],
                        "code_challenge_methods_supported": ["S256"],
                        "authorization_response_iss_parameter_supported": True})
                if url.path == "/jwks":
                    return self.send(200, {"keys": [server.key.public_jwk()]})
                if url.path == "/authorize":
                    q = dict(urllib.parse.parse_qsl(url.query))
                    client = server.policy["clients"].get(q.get("client_id", ""))
                    if not client or q.get("redirect_uri") not in client.get("redirect_uris", []):
                        return self.send(400, "<p>Unknown client or redirect URI.</p>", "text/html")
                    if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
                        return self.send(400, "<p>PKCE (S256) is required.</p>", "text/html")
                    hidden = "".join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
                                     for k, v in q.items())
                    page = ('<!doctype html><title>TSG lab sign-in</title><form method="post" action="/login">'
                            f'{hidden}<label>Username <input name="username"></label>'
                            '<label>Password <input name="password" type="password"></label>'
                            '<button>Sign in</button></form>')
                    return self.send(200, page, "text/html; charset=utf-8")
                return self.send(404, {"error": "not_found"})

            def do_POST(self):
                form = self.form()
                if self.path == "/login":
                    user = USERS.get(form.get("username", ""))
                    if not user or not secrets.compare_digest(form.get("password", ""), user["password"]):
                        return self.send(401, "<p>Wrong username or password.</p>", "text/html")
                    code = secrets.token_urlsafe(24)
                    server.codes[code] = {"client_id": form.get("client_id"), "redirect_uri": form.get("redirect_uri"),
                                          "code_challenge": form.get("code_challenge"), "username": user["username"],
                                          "scope": form.get("scope", "").split(), "expires": server.clock() + 60}
                    loc = form["redirect_uri"] + "?" + urllib.parse.urlencode(
                        {"code": code, "state": form.get("state", ""), "iss": server.issuer})
                    return self.send(302, "", "text/plain", {"Location": loc})
                if self.path == "/token":
                    cid, client = server.authenticate(self.headers, form)
                    if not client:
                        return self.send(401, {"error": "invalid_client"})
                    grant = form.get("grant_type")
                    if grant == "authorization_code":
                        return self.send(*server.grant_code(cid, client, form))
                    if grant == "client_credentials":
                        return self.send(*server.grant_client_credentials(cid, client, form))
                    if grant == "urn:ietf:params:oauth:grant-type:token-exchange":
                        return self.send(*server.grant_exchange(cid, client, form))
                    return self.send(400, {"error": "unsupported_grant_type"})
                return self.send(404, {"error": "not_found"})

        return Handler


if __name__ == "__main__":
    setup = sys.argv[1] if len(sys.argv) > 1 else "hardened"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8730
    s = AuthorizationServer(setup, port)
    print(f"Lab authorization server ({setup}) on {s.issuer}  (Ctrl+C to stop)")
    try:
        s.httpd.serve_forever()
    except KeyboardInterrupt:
        pass
