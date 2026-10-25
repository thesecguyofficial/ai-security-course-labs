"""The MCP host side: start the crm server, list its tools, call them. Core file: do not edit.

    python3 -m helpdesk.mcp_client --list            # show the tools and their fingerprints
    python3 -m helpdesk.mcp_client --pin             # write helpdesk/mcp_pins.json from what the server says NOW

A pin is the SHA-256 of a tool's name, description and input schema. If the server later changes any of them,
the fingerprint changes. Checking pins is your job, in guards.check_mcp_tools().
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
PINS = HERE / "mcp_pins.json"


def fingerprint(tool: dict) -> str:
    blob = json.dumps({"name": tool.get("name"), "description": tool.get("description"),
                       "inputSchema": tool.get("inputSchema")}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def tools_hash(tools: list[dict]) -> str:
    return hashlib.sha256("".join(sorted(fingerprint(t) for t in tools)).encode()).hexdigest()[:16]


def load_pins() -> dict:
    """{tool name: fingerprint} from helpdesk/mcp_pins.json, or {} if you have not pinned yet."""
    if PINS.exists():
        return json.loads(PINS.read_text(encoding="utf-8")).get("tools", {})
    return {}


class MCPClient:
    def __init__(self, release: int = 1):
        self.release = release
        self.proc = subprocess.Popen([sys.executable, "-m", "helpdesk.mcp_server", "--release", str(release)],
                                     cwd=str(HERE.parent), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     text=True, bufsize=1)
        self._id = 0
        self.server_info = self._rpc("initialize", {"protocolVersion": "2026-07-28", "capabilities": {},
                                                    "clientInfo": {"name": "tsg-helpdesk", "version": "6.0"}})
        self._notify("notifications/initialized")

    def _notify(self, method: str) -> None:
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def _rpc(self, method: str, params: dict) -> dict:
        self._id += 1
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}) + "\n")
        self.proc.stdin.flush()
        reply = json.loads(self.proc.stdout.readline())
        if "error" in reply:
            raise RuntimeError(reply["error"]["message"])
        return reply["result"]

    def list_tools(self) -> list[dict]:
        return self._rpc("tools/list", {})["tools"]

    def call(self, name: str, arguments: dict) -> str:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        return "\n".join(c.get("text", "") for c in result.get("content", []))

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        self.proc.stdout.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", type=int, default=1)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--pin", action="store_true")
    a = ap.parse_args()
    c = MCPClient(a.release)
    tools = c.list_tools()
    c.close()
    for t in tools:
        print(f"{t['name']:<20} {fingerprint(t)[:16]}  {t['description']}")
    if a.pin:
        PINS.write_text(json.dumps({"server": "crm", "release_pinned": a.release,
                                    "tools": {t["name"]: fingerprint(t) for t in tools}}, indent=2) + "\n",
                        encoding="utf-8")
        print(f"pinned {len(tools)} tools -> {PINS.relative_to(HERE.parent)}")


if __name__ == "__main__":
    main()
