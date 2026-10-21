"""
secure_http_server.py: a SECURE remote MCP server over Streamable HTTP (lesson 8.4). LAB ONLY, 127.0.0.1.

This is the "done right" end of the module. It is an OAuth 2.1 resource server that:

  - binds only to 127.0.0.1 (the spec: local servers SHOULD bind to localhost, not 0.0.0.0);
  - keeps DNS-rebinding protection on (the SDK turns it on for a localhost bind), so a browser on
    another origin cannot drive it;
  - requires a bearer token on every request (no token -> HTTP 401);
  - VALIDATES THE AUDIENCE: it only accepts a token whose `aud` is this server's own resource URL
    (RFC 8707), and rejects a token minted for any other resource. The spec: a server "MUST validate
    that access tokens were issued specifically for them as the intended audience" and token
    passthrough is "explicitly forbidden";
  - REFUSES PASSTHROUGH: if it needs an upstream API it uses its OWN credential, never the caller's
    token (demonstrated by the `whoami` tool, which reports the verified principal but never forwards
    the token anywhere).

The authorization server here is the minimal fake issuer in auth/issuer.py. In a real deployment the
token arrives from the OAuth flow in the lesson; the server-side check below is identical either way.

Run:  python3 servers/secure_http_server.py        # serves on http://127.0.0.1:8808/mcp
Tests drive it automatically (see run_tests.py / test_auth.py).
"""

import sys
from pathlib import Path

import jwt
from pydantic import AnyHttpUrl

from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.auth.middleware.auth_context import get_access_token

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auth import issuer  # noqa: E402

HOST = "127.0.0.1"
PORT = 8808
RESOURCE_URL = f"http://{HOST}:{PORT}/mcp"  # this server's canonical URI = the audience tokens must carry


class LabAudienceVerifier(TokenVerifier):
    """Verify a lab JWT and, crucially, that it was issued for THIS resource.

    PyJWT does the audience check for us: passing audience=RESOURCE_URL makes decode() raise if the
    token's `aud` is anything else. That single argument is the whole defence against token passthrough
    and cross-resource reuse.
    """

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = jwt.decode(
                token,
                issuer.LAB_SECRET,
                algorithms=["HS256"],
                audience=RESOURCE_URL,        # reject tokens minted for any other resource (RFC 8707)
                issuer=issuer.ISSUER,         # reject tokens from any other issuer
                options={"require": ["exp", "aud", "iss"]},
            )
        except jwt.InvalidTokenError:
            return None  # bad signature, wrong audience, wrong issuer, or expired -> 401
        return AccessToken(
            token=token,
            client_id=claims.get("sub", "unknown"),
            scopes=claims.get("scope", "").split(),
            expires_at=claims.get("exp"),
            resource=claims.get("aud"),
            subject=claims.get("sub"),
        )


mcp = MCPServer(
    "secure-notes",
    version="1.0.0",
    token_verifier=LabAudienceVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(issuer.ISSUER),
        resource_server_url=AnyHttpUrl(RESOURCE_URL),
        # Our verifier already checks `aud` itself, so we set this False (the SDK would otherwise also
        # compare AccessToken.resource to resource_server_url). Either belt or braces is fine; here the
        # verifier is the source of truth.
        validate_token_resource=False,
        required_scopes=["notes:read"],
    ),
)


@mcp.tool()
def whoami() -> str:
    """Report the verified caller. Proves the token reached us and was accepted for THIS resource."""
    tok = get_access_token()
    if tok is None:  # pragma: no cover - middleware guarantees a token here
        return "no token"
    # Note what we do NOT do: we never forward `tok.token` to any upstream service. If this tool called
    # an upstream API it would use its own credential (no passthrough).
    return f"subject={tok.subject} scopes={tok.scopes} audience-ok"


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host=HOST, port=PORT)
