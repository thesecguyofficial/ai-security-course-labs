"""
server.py: the Helpdesk's own MCP "actions" server (AZ14 guided build). Runs in YOUR subscription on Azure Container
Apps. Two tools: search_tickets (read) and send_email (write, SIMULATED: nothing is ever sent; the call is printed
to the container log so you can see exactly what ran).

Callers must send the header x-api-key. The Foundry toolbox injects it from a project connection, so neither the
model nor your agent code ever sees the key (Microsoft: "The agent never sees the secret.").
Not run by the course team (no Azure subscription in the build).
"""

import hmac
import json
import os

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse

KEY = os.environ["MCP_API_KEY"]          # from a Container Apps secret (secretref), never baked into the image

# DNS-rebinding protection: recent MCP SDK 1.x releases accept only localhost Host headers by default, so behind
# Container Apps every call got "421 Invalid Host header" (seen 9 Nov 2026). Keep the protection ON and allow only
# this app's own hostname: Container Apps sets CONTAINER_APP_NAME and CONTAINER_APP_ENV_DNS_SUFFIX in every replica.
HOSTS = [h for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h]
if os.environ.get("CONTAINER_APP_NAME") and os.environ.get("CONTAINER_APP_ENV_DNS_SUFFIX"):
    HOSTS.append(f"{os.environ['CONTAINER_APP_NAME']}.{os.environ['CONTAINER_APP_ENV_DNS_SUFFIX']}")
HOSTS += [f"{h}:*" for h in HOSTS] + ["localhost", "localhost:*", "127.0.0.1:*"]
try:
    from mcp.server.transport_security import TransportSecuritySettings
    SECURITY = {"transport_security": TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=HOSTS)}
except ImportError:                       # older SDKs have no Host check at all
    SECURITY = {}
mcp = FastMCP("helpdesk-actions", stateless_http=True, **SECURITY)
TICKETS = {"4471": "Dock not detected after update (bob)", "4480": "Outlook keeps prompting (priya)"}


@mcp.tool()
def search_tickets(query: str) -> str:
    """Search open helpdesk tickets by keyword."""
    return json.dumps({k: v for k, v in TICKETS.items() if query.lower() in v.lower()} or TICKETS)


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email from the helpdesk mailbox. SIMULATED in this lab."""
    print(json.dumps({"event": "send_email", "to": to, "subject": subject}), flush=True)
    return f"Email to {to} sent (simulated)."


app = mcp.streamable_http_app()


async def require_key(scope, receive, send):
    if scope["type"] == "http":
        headers = dict(scope.get("headers") or [])
        if not hmac.compare_digest(headers.get(b"x-api-key", b"").decode(), KEY):
            await JSONResponse({"error": "missing or wrong x-api-key"}, status_code=401)(scope, receive, send)
            return
    await app(scope, receive, send)


if __name__ == "__main__":
    uvicorn.run(require_key, host="0.0.0.0", port=8000, lifespan="on")
