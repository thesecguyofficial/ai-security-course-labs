"""
review.py: read an MCP server's tool definitions WITHOUT a model in the loop, and scan them.

This is the manual review step from lesson 8.5, in code: connect to a server, print every tool's full
definition (name, description, input schema), and flag any that carry a hidden-directive marker. The
real-world equivalents are the MCP Inspector (`npx @modelcontextprotocol/inspector`) and Snyk Agent Scan
(`snyk-agent-scan inspect`), which list a server's tools so you can read the descriptions before you ever let a model see them.

Run it:
    python3 review.py facts        # review the (possibly poisoned) facts server
    python3 review.py notes        # review the honest server

The CHALLENGE (make challenge) lives in full_definition_text() below.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import Client, StdioServerParameters

import stand_in_model

LAB = Path(__file__).resolve().parent
SERVERS = {"notes": "servers/notes_server.py", "facts": "servers/facts_server.py"}


async def _list(server: str) -> list[dict]:
    params = StdioServerParameters(command=sys.executable, args=[str(LAB / SERVERS[server])], env={})
    async with Client(params, cache=None) as client:
        listed = await client.list_tools()
        return [
            {"server": server, "name": t.name, "description": t.description or "", "input_schema": t.input_schema or {}}
            for t in listed.tools
        ]


def list_tools(server: str) -> list[dict]:
    return asyncio.run(_list(server))


def one_tool(server: str, name: str) -> dict:
    for t in list_tools(server):
        if t["name"] == name:
            return t
    raise KeyError(name)


def full_definition_text(tool: dict) -> str:
    """Everything a scan should read for one tool: name, description and input schema.

    A model reads all three, so a hidden directive can sit in any of them and a scan must cover all of
    them.
    """
    # ===== YOUR TURN (make challenge) =====
    # Right now this returns only the name and the one-line description, so a directive hidden in the
    # input schema (the facts server's 2.0.0 release) slips through. Add the input schema to the text
    # returned below so the scan reads the WHOLE definition.
    # Hint: json.dumps(tool["input_schema"]) turns the schema into searchable text.
    return "\n".join([tool["name"], tool["description"]])
    # ===== END YOUR TURN =====


def scan(server: str) -> int:
    tools = list_tools(server)
    flagged = 0
    for t in tools:
        text = full_definition_text(t)
        bad = stand_in_model.TOKEN in text
        flagged += bad
        print("-" * 68)
        print(f"{t['server']}:{t['name']}")
        print(f"  description: {t['description']!r}")
        print(f"  input schema: {json.dumps(t['input_schema'])}")
        print(f"  VERDICT: {'HIDDEN DIRECTIVE FOUND -> do not use' if bad else 'looks clean'}")
    print("-" * 68)
    print(f"{flagged} of {len(tools)} tool(s) flagged on {server}.")
    return flagged


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "facts"
    raise SystemExit(1 if scan(which) else 0)
