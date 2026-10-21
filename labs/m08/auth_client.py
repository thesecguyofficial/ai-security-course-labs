"""
auth_client.py: drive the secure Streamable HTTP server (lesson 8.4) with three tokens.

  1. a token minted for THIS server's resource URL  -> accepted (whoami works)
  2. a token minted for a DIFFERENT resource         -> refused with 401 (wrong audience)
  3. no token at all                                 -> refused with 401

Run the server first (python3 servers/secure_http_server.py) in another terminal, or let the Makefile /
tests start it for you. Everything is on 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import logging

import httpx2

logging.disable(logging.CRITICAL)  # quiet httpx2's per-request INFO lines

from mcp import Client

from auth import issuer
from servers.secure_http_server import RESOURCE_URL

OTHER_RESOURCE = "http://127.0.0.1:9999/other-api"  # some unrelated service's URL


async def _call(token: str | None) -> tuple[bool, str]:
    # An explicit httpx2 client lets us set the Authorization header the server will check.
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx2.AsyncClient(headers=headers, timeout=10) as http_client:
        from mcp.client.streamable_http import streamable_http_client

        async with Client(streamable_http_client(RESOURCE_URL, http_client=http_client), cache=None) as client:
            res = await client.call_tool("whoami", {})
            text = "\n".join(c.text for c in (res.content or []) if getattr(c, "text", None))
            return True, text


def _unwrap(exc: BaseException) -> str:
    """Pull a readable reason out of a (possibly grouped) transport exception."""
    seen = str(exc)
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
        seen = str(exc)
    return "HTTP 401 Unauthorized" if "401" in seen else f"{type(exc).__name__}: {seen[:80]}"


async def try_token(label: str, token: str | None) -> dict:
    try:
        ok, text = await _call(token)
        return {"label": label, "accepted": ok, "detail": text}
    except BaseException as exc:  # 401 surfaces as an exception from the transport
        return {"label": label, "accepted": False, "detail": _unwrap(exc)}


async def collect() -> list[dict]:
    """Send the three tokens and return the results, without printing."""
    good = issuer.mint("alice", RESOURCE_URL, ["notes:read"])
    wrong_aud = issuer.mint("alice", OTHER_RESOURCE, ["notes:read"])
    return [
        await try_token("token for THIS resource", good),
        await try_token("token for ANOTHER resource", wrong_aud),
        await try_token("no token", None),
    ]


async def main() -> list[dict]:
    results = await collect()
    for r in results:
        verdict = "ACCEPTED" if r["accepted"] else "REFUSED"
        print(f"[{verdict}] {r['label']}: {r['detail']}")
    return results


if __name__ == "__main__":
    asyncio.run(main())
