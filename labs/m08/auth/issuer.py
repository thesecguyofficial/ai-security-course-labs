"""
issuer.py: a MINIMAL FAKE authorization server for the lab. LAB ONLY. Not an OAuth server.

A real MCP client gets a token through the OAuth 2.1 flow in lesson 8.4 (Protected Resource Metadata ->
authorization server discovery -> PKCE -> a token carrying the `resource` as its audience). That needs a
browser and a running authorization server. To keep the lab offline and on 127.0.0.1, this file skips the
flow and just MINTS the kind of token that flow would produce: a signed JWT with `iss` (who issued it) and
`aud` (which resource it is for, i.e. the RFC 8707 resource indicator). The lab shares one HMAC secret so
you can sign and verify locally; a real deployment verifies the issuer's public key instead.

The security lesson (8.3, 8.4) does not depend on the signature algorithm. It depends on the server
checking that `aud` is itself, and refusing anything else. That check is in secure_http_server.py.
"""

import time

import jwt  # PyJWT, installed with the mcp package

# Lab-only shared secret. A real authorization server signs with a private key; clients and resource
# servers verify with its published public key. Never ship a shared HMAC secret like this in production.
LAB_SECRET = "lab-only-hs256-secret-not-for-real-use"
ISSUER = "https://issuer.lab.invalid/"  # .invalid never resolves. Trailing slash on purpose: the server metadata
# (pydantic AnyHttpUrl) publishes it with one, and OAuth compares issuer strings exactly, with no normalisation.


def mint(subject: str, audience: str, scopes: list[str], *, ttl_seconds: int = 300, expired: bool = False) -> str:
    """Mint a lab JWT for `audience` (the resource the token is FOR)."""
    now = int(time.time())
    iat = now - 3600 if expired else now
    claims = {
        "iss": ISSUER,
        "sub": subject,
        "aud": audience,
        "scope": " ".join(scopes),
        "iat": iat,
        "exp": iat + ttl_seconds,
    }
    return jwt.encode(claims, LAB_SECRET, algorithm="HS256")
