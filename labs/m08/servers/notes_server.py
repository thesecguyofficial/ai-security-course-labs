"""
notes_server.py: the HONEST MCP server in this lab (stdio transport).

It gives an agent three tools over a folder of FAKE notes:
  list_notes()                  names of the notes in data/workspace/
  read_note(name)               the text of one note
  send_email(to, subject, body) "sends" an email: it only appends a line to state/outbox.jsonl.
                                Nothing leaves your computer.

Nothing in this file is malicious. It is still risky in the way real servers are risky: read_note can
read every file in its folder (including the fake .env), and send_email will write to any address it
is given. Whatever steers the agent can steer these tools. That is the point of lesson 8.2.

The host launches this file as a child process (stdio). You never run it by hand.
"""

import json
import time
from pathlib import Path

from mcp.server import MCPServer

LAB = Path(__file__).resolve().parent.parent
WORKSPACE = LAB / "data" / "workspace"
STATE = LAB / "state"

mcp = MCPServer("notes", version="1.0.0")


@mcp.tool()
def list_notes() -> str:
    """List the notes in the team workspace."""
    return "\n".join(sorted(p.name for p in WORKSPACE.iterdir() if p.is_file()))


@mcp.tool()
def read_note(name: str) -> str:
    """Read one note from the team workspace by its file name, for example meeting-notes.md."""
    path = (WORKSPACE / name).resolve()
    # The honest server does stop path traversal: only files inside the workspace folder.
    if WORKSPACE.resolve() not in path.parents or not path.is_file():
        return f"No note called {name!r}."
    return path.read_text(encoding="utf-8")


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a colleague. (Lab: writes to state/outbox.jsonl; nothing is sent.)"""
    STATE.mkdir(exist_ok=True)
    record = {"time": time.strftime("%H:%M:%S"), "to": to, "subject": subject, "body": body}
    with open(STATE / "outbox.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return f"Email to {to} queued."


if __name__ == "__main__":
    mcp.run()  # stdio: JSON-RPC messages on stdin/stdout
