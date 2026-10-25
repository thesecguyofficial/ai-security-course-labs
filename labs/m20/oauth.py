"""
oauth.py: the OAuth client side of the lab (standard library only).

Works the same against the lab's own authorization server (authz_server.py) and against Keycloak:
  - discover()            OpenID Connect discovery (/.well-known/openid-configuration)
  - sign_in()             authorization code + PKCE (RFC 7636): the script fills in the login form for you
  - client_credentials()  an agent's token for itself (no user)
  - token_exchange()      RFC 8693: swap the token you received for a smaller one for the next hop
"""

from __future__ import annotations

import base64
import hashlib
import html.parser
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

REDIRECT_URI = "http://127.0.0.1:8799/callback"   # registered for helpdesk-app; nothing listens there
GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # we want to SEE the Location header, not follow it
        return None


class _Session:
    """A tiny browser: keeps cookies, never follows redirects, never uses a proxy (everything is 127.0.0.1)."""

    def __init__(self):
        # Cookies by hand: login pages mark them Secure even on http://127.0.0.1, and Python's cookie jar then
        # refuses to send them back. This "browser" only ever talks to one local server, so we keep it simple.
        self.cookies: dict[str, str] = {}
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def request(self, method: str, url: str, form: dict | None = None, headers: dict | None = None):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
        if form is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if self.cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        try:
            resp = self.opener.open(req, timeout=20)
        except urllib.error.HTTPError as err:
            resp = err
        with resp:
            for raw in resp.headers.get_all("Set-Cookie") or []:
                name, _, rest = raw.partition("=")
                self.cookies[name.strip()] = rest.split(";", 1)[0]
            return resp.status if hasattr(resp, "status") else resp.code, dict(resp.headers), resp.read().decode()


_direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(method: str, url: str, *, form: dict | None = None, body: dict | None = None,
         token: str | None = None, auth: tuple[str, str] | None = None) -> tuple[int, dict]:
    """One HTTP call to a 127.0.0.1 service. Returns (status, parsed JSON or {"raw": text})."""
    headers = {}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    if auth:
        cred = base64.b64encode(f"{urllib.parse.quote(auth[0])}:{urllib.parse.quote(auth[1])}".encode()).decode()
        headers["Authorization"] = "Basic " + cred
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _direct.open(req, timeout=20) as resp:
            text, status = resp.read().decode(), resp.status
    except urllib.error.HTTPError as err:
        text, status = err.read().decode(), err.code
    except urllib.error.URLError as err:
        return 0, {"error": "connection_failed", "error_description": str(err.reason)}
    try:
        return status, json.loads(text) if text else {}
    except json.JSONDecodeError:
        return status, {"raw": text[:300]}


def call_with_headers(method: str, url: str, token: str, extra: dict) -> tuple[int, dict]:
    """Like call(), with extra request headers (the first draft's X-On-Behalf-Of)."""
    req = urllib.request.Request(url, method=method, headers=dict(extra, Authorization="Bearer " + token))
    try:
        with _direct.open(req, timeout=20) as resp:
            text, status = resp.read().decode(), resp.status
    except urllib.error.HTTPError as err:
        text, status = err.read().decode(), err.code
    return status, json.loads(text) if text else {}


def discover(issuer: str) -> dict:
    status, meta = call("GET", issuer.rstrip("/") + "/.well-known/openid-configuration")
    if status != 200:
        raise SystemExit(f"Can't read {issuer}/.well-known/openid-configuration (HTTP {status}). Is the server running?")
    status, jwks = call("GET", meta["jwks_uri"])
    meta["_jwks"] = jwks
    return meta


class _FormParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.action, self.fields = None, {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and self.action is None:
            self.action = a.get("action")
        if tag == "input" and a.get("name"):
            self.fields[a["name"]] = a.get("value") or ""


def sign_in(meta: dict, client_id: str, username: str, password: str, scope: str) -> dict:
    """Authorization code + PKCE, like a browser would do it. Returns the token response.

    The user's password goes only to the authorization server's own login page, never to the app: that is the
    point of OAuth. The script types it for you so the lab needs no browser.
    """
    browser = _Session()
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    query = urllib.parse.urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT_URI, "scope": scope,
        "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
    status, headers, page = browser.request("GET", meta["authorization_endpoint"] + "?" + query)
    if status != 200:
        raise SystemExit(f"Login page did not load (HTTP {status}): {page[:200]}")
    form = _FormParser()
    form.feed(page)
    if not form.action:
        raise SystemExit("No login form found on the authorization server's page.")
    fields = dict(form.fields, username=username, password=password)
    action = urllib.parse.urljoin(meta["authorization_endpoint"], html.unescape(form.action))
    status, headers, page = browser.request("POST", action, form=fields)
    location = headers.get("Location") or headers.get("location") or ""
    params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))
    if "code" not in params:
        raise SystemExit(f"Sign-in failed for {username} (HTTP {status}). Wrong password, or the client is not set up.")
    if params.get("state") != state:
        raise SystemExit("state mismatch: refusing the code (CSRF protection)")
    if "iss" in params and params["iss"] != meta["issuer"]:
        raise SystemExit("iss mismatch: refusing the code (RFC 9207 mix-up protection)")
    status, tokens = call("POST", meta["token_endpoint"], form={
        "grant_type": "authorization_code", "code": params["code"], "redirect_uri": REDIRECT_URI,
        "client_id": client_id, "code_verifier": verifier})
    if status != 200:
        raise SystemExit(f"Code exchange failed (HTTP {status}): {tokens}")
    return tokens


def client_credentials(meta: dict, client_id: str, secret: str, scope: str | None = None) -> tuple[int, dict]:
    form = {"grant_type": "client_credentials"}
    if scope:
        form["scope"] = scope
    return call("POST", meta["token_endpoint"], form=form, auth=(client_id, secret))


def token_exchange(meta: dict, client_id: str, secret: str, subject_token: str, *, audience: str | None = None,
                   scope: str | None = None, actor_token: str | None = None) -> tuple[int, dict]:
    """RFC 8693 section 2.1. The requesting agent authenticates as itself (client_id + secret)."""
    form = {"grant_type": GRANT_TOKEN_EXCHANGE, "subject_token": subject_token,
            "subject_token_type": TYPE_ACCESS_TOKEN, "requested_token_type": TYPE_ACCESS_TOKEN}
    if audience:
        form["audience"] = audience
    if scope:
        form["scope"] = scope
    if actor_token:
        form["actor_token"] = actor_token
        form["actor_token_type"] = TYPE_ACCESS_TOKEN
    return call("POST", meta["token_endpoint"], form=form, auth=(client_id, secret))
