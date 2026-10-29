"""
explore.py: look at how MCP works, one message at a time, before you attack anything (M8 lab, part 1).

Run it with the lab's virtual environment after `make setup`:

    .venv/bin/python explore.py discover   # 1. stdio: one JSON-RPC message per line, server/discover
    .venv/bin/python explore.py list       # 2. tools/list: the menu of tools the server offers
    .venv/bin/python explore.py call       # 3. tools/call: the host asks the server to run read_note
    .venv/bin/python explore.py context    # 4. the text a model actually reads: every tool, from both servers
    .venv/bin/python explore.py http       # 5. Streamable HTTP: a POST with no token gets 401, and a pointer
    .venv/bin/python explore.py token      # 6. a lab token for this server: whose it is, and a call that works

What it really runs, said plainly: steps 1 to 4 START the lab's own MCP servers (servers/notes_server.py and,
for step 4, servers/facts_server.py) as child processes on your computer, the way a host does, and stop them
again. Steps 5 and 6 start servers/secure_http_server.py on 127.0.0.1:8808 and stop it at the end. The only
tools explore.py calls are read_note (it reads todo.md, a fake note) and whoami. It never calls send_email,
never writes to state/, and nothing leaves your computer. Fake data only.

Steps 1 to 3 write the JSON-RPC messages by hand, so you see every byte. They are the same messages the
official MCP Python SDK client sends (protocol version 2026-07-28), except for the clientInfo name.
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

LAB = Path(__file__).resolve().parent
NOTES = LAB / "servers" / "notes_server.py"
SECURE = LAB / "servers" / "secure_http_server.py"
VERSION = "2026-07-28"
META = {
    "io.modelcontextprotocol/protocolVersion": VERSION,
    "io.modelcontextprotocol/clientInfo": {"name": "explore.py", "version": "1.0"},
    "io.modelcontextprotocol/clientCapabilities": {},
}
WIDTH = 120


def need_sdk() -> None:
    try:
        import mcp  # noqa: F401
    except ImportError:
        sys.exit("The MCP SDK isn't installed here. Run make setup, then: .venv/bin/python explore.py <step>")


def show(obj, indent: int = 0) -> str:
    """JSON laid out to read: anything that fits on one line stays on one line."""
    flat = json.dumps(obj, ensure_ascii=False)
    pad = " " * indent
    if len(flat) + indent <= WIDTH or not isinstance(obj, (dict, list)) or not obj:
        return pad + flat
    inner = " " * (indent + 2)
    if isinstance(obj, dict):
        rows = []
        for k, v in obj.items():
            head = f"{inner}{json.dumps(k)}: "
            one = json.dumps(v, ensure_ascii=False)
            if len(head) + len(one) <= WIDTH or not isinstance(v, (dict, list)) or not v:
                rows.append(head + one)
            else:
                rows.append(head + show(v, indent + 2).lstrip())
        return pad + "{\n" + ",\n".join(rows) + "\n" + pad + "}"
    rows = [show(v, indent + 2) for v in obj]
    return pad + "[\n" + ",\n".join(rows) + "\n" + pad + "]"


class Stdio:
    """A host's view of one stdio server: start it, write a line to its stdin, read a line from its stdout."""

    def __init__(self, script: Path):
        # env={} like host.py: the server gets none of your shell's variables (and so none of your secrets).
        self.p = subprocess.Popen([sys.executable, str(script)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env={}, cwd=LAB)
        self.next_id = 1

    def request(self, method: str, params: dict | None = None) -> tuple[str, str]:
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": dict(params or {}, _meta=META)}
        self.next_id += 1
        line = json.dumps(msg, separators=(",", ":"))
        self.p.stdin.write((line + "\n").encode())
        self.p.stdin.flush()
        while True:
            reply = self.p.stdout.readline().decode().rstrip("\n")
            if not reply:
                raise SystemExit("The server closed its output without answering.")
            if json.loads(reply).get("id") == msg["id"]:
                return line, reply

    def close(self) -> None:
        self.p.stdin.close()  # closing stdin is how a host asks a stdio server to stop
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()


# --------------------------------------------------------------------------- 1. discover

def cmd_discover(a):
    s = Stdio(NOTES)
    sent, got = s.request("server/discover")
    s.close()
    print("The host starts servers/notes_server.py as a child process. They talk over stdio: the host writes")
    print("to the server's standard input, the server answers on its standard output. One JSON-RPC message per line.\n")
    print("host -> server (one line on stdin):")
    print(sent)
    print("\nserver -> host (one line on stdout):")
    print(got)
    print("\nThe answer, laid out to read:")
    print(show(json.loads(got)))


# --------------------------------------------------------------------------- 2. list

def cmd_list(a):
    s = Stdio(NOTES)
    sent, got = s.request("tools/list")
    s.close()
    print("host -> server:")
    print(sent)
    reply = json.loads(got)
    print("\nserver -> host, laid out to read (outputSchema, cacheScope, ttlMs and _meta left out to fit the screen):")
    print(f'{{"jsonrpc": "2.0", "id": {reply["id"]}, "result": {{"resultType": "{reply["result"]["resultType"]}", "tools": [')
    tools = reply["result"]["tools"]
    for i, t in enumerate(tools):
        end = "}," if i < len(tools) - 1 else "}"
        print(f'  {{"name": {json.dumps(t["name"])},')
        print(f'   "description": {json.dumps(t.get("description", ""))},')
        print(f'   "inputSchema": {json.dumps(t["inputSchema"])}{end}')
    print("]}}")
    print(f"\n{len(tools)} tools. Each one: a name, a description written for the model, and an inputSchema for its arguments.")


# --------------------------------------------------------------------------- 3. call

def cmd_call(a):
    s = Stdio(NOTES)
    sent, got = s.request("tools/call", {"name": "read_note", "arguments": {"name": "todo.md"}})
    s.close()
    print("The model asked for read_note on todo.md. The HOST sends the request; the server runs the tool.\n")
    print("host -> server:")
    print(sent)
    reply = json.loads(got)
    reply["result"].pop("structuredContent", None)
    print("\nserver -> host, laid out to read (structuredContent, the same text again, left out):")
    print(show(reply))


# --------------------------------------------------------------------------- 4. context

def cmd_context(a):
    need_sdk()
    import asyncio

    import host
    import ollama_backend

    release = "1.0.0"
    f = LAB / "state" / "facts_release.txt"
    if f.exists():
        release = f.read_text().strip() or "1.0.0"
    tools = asyncio.run(host.discover())
    text = ollama_backend.system_prompt(tools)
    print(f"host.py asked both servers for their tools (notes 1.0.0, facts {release}; make clean resets facts).")
    print("This is the system message a real model gets with --backend ollama. The stand-in reads the same list.\n")
    print(text)
    print(f"\n{len(tools)} tools, {len(text)} characters (about {len(text) // 4} tokens), all in the model's working memory,")
    print("the context window, on every request. The model can't tell who wrote which line.")


# --------------------------------------------------------------------------- 5 and 6. Streamable HTTP

URL = "http://127.0.0.1:8808/mcp"


def start_secure():
    srv = subprocess.Popen([sys.executable, str(SECURE)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=LAB)
    for _ in range(50):
        try:
            urllib.request.urlopen("http://127.0.0.1:8808/.well-known/oauth-protected-resource/mcp", timeout=1)
            return srv
        except (urllib.error.URLError, OSError):
            time.sleep(0.2)
    srv.kill()
    sys.exit("The secure server didn't start on 127.0.0.1:8808. Is something else using that port?")


def post(method: str, params: dict, token: str | None = None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": dict(params, _meta=META)}).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": VERSION, "Mcp-Method": method}
    if "name" in params:
        headers["Mcp-Name"] = params["name"]
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(URL, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode(), headers
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(), headers


def cmd_http(a):
    need_sdk()
    srv = start_secure()
    try:
        status, hdrs, body, sent = post("tools/list", {})
        print(f"servers/secure_http_server.py is running on {URL}: Streamable HTTP, one POST per message.\n")
        print("host -> server, with NO token:")
        print(f"  POST {URL}")
        for k in ("MCP-Protocol-Version", "Mcp-Method"):
            print(f"  {k}: {sent[k]}")
        print('  body: {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {...}}}')
        print("\nserver -> host:")
        print(f"  HTTP {status}")
        print(f"  WWW-Authenticate: {hdrs.get('www-authenticate')}")
        meta_url = hdrs.get("www-authenticate", "").split('resource_metadata="')[-1].rstrip('"')
        with urllib.request.urlopen(meta_url, timeout=5) as r:
            meta = json.loads(r.read())
        print("\nThe host follows that pointer (Protected Resource Metadata):")
        print(f"  GET {meta_url}")
        print(show(meta, 2))
    finally:
        srv.terminate()
        srv.wait(timeout=10)
    print("\nNo token, no tools. The metadata says which authorization server issues tokens for this resource.")


def claims_of(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def cmd_token(a):
    need_sdk()
    from auth import issuer

    token = issuer.mint("alice", URL, ["notes:read"])
    print("auth/issuer.py is a FAKE authorization server (lab only). It mints the kind of access token the real")
    print("OAuth flow would give a host acting for alice. The token's middle part, decoded:\n")
    print(show(claims_of(token), 2))
    srv = start_secure()
    try:
        status, _, body, _ = post("tools/call", {"name": "whoami", "arguments": {}}, token)
    finally:
        srv.terminate()
        srv.wait(timeout=10)
    print("\nhost -> server: POST tools/call whoami, with the header  Authorization: Bearer eyJhbGciOi...")
    print(f"server -> host: HTTP {status}")
    reply = json.loads(body)
    reply["result"].pop("structuredContent", None)
    print(show(reply, 2))
    print("\nThe server checked the token and knows who is asking: alice, allowed to read notes, for this server only.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Look at how MCP works, one message at a time (M8 lab, part 1). "
                                "Starts the lab's own servers on your computer and stops them; reads only.")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("discover", cmd_discover), ("list", cmd_list), ("call", cmd_call),
                     ("context", cmd_context), ("http", cmd_http), ("token", cmd_token)):
        sub.add_parser(name).set_defaults(fn=fn)
    a = p.parse_args(argv)
    need_sdk()
    a.fn(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
