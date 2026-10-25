"""The Helpdesk web app and command line. Core file: do not edit.

    python3 -m helpdesk.app                                         # http://127.0.0.1:8719 (make run)
    python3 -m helpdesk.app --ask alice@acme.example "How do I get a refund?"   # one turn, printed (make ask)

The sign-in is simulated: the page lets you pick a user from data/users.json. Authentication is out of scope
for the capstone (README, "Scope"); everything after "who is asking" is in scope.
The server listens on config.HOST (127.0.0.1). It refuses to start on any other address.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from helpdesk import config
from helpdesk.core import Helpdesk

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>TSG Helpdesk (capstone)</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="/app.css"></head><body>
<h1>TSG Helpdesk</h1><p>Lab app on 127.0.0.1. Fake data only.</p>
<form id="f"><select id="u">USERS</select> <input id="m" size="50" placeholder="Ask the helpdesk" required>
<button>Send</button></form><div id="log"></div><script src="/app.js"></script></body></html>"""

CSS = """body{font:16px system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;background:#F6F2E9;color:#0A1020}
#log div{background:#FFFDF8;border:1px solid #D6CCB8;border-radius:8px;padding:.7rem;margin:.6rem 0}
.me{border-color:#8A4F00!important}input,select,button{font:inherit;padding:.4rem}"""

# Served as its own file (not inline) so that a strict Content-Security-Policy (script-src 'self') can work.
JS = """document.getElementById('f').onsubmit = async (e) => {
  e.preventDefault();
  const user = document.getElementById('u').value, message = document.getElementById('m').value;
  const me = document.createElement('div'); me.className = 'me'; me.textContent = user + ': ' + message;
  document.getElementById('log').prepend(me);
  const r = await fetch('/api/chat', {method: 'POST', headers: {'Content-Type': 'application/json'},
                                      body: JSON.stringify({user, message})});
  const data = await r.json();
  const bot = document.createElement('div');
  bot.innerHTML = data.reply_html;          // the sink: whatever render_html() returns becomes live HTML
  me.after(bot);
};"""


class Handler(BaseHTTPRequestHandler):
    helpdesk: Helpdesk = None  # set in serve()
    lock = threading.Lock()

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in self.helpdesk.guards.response_headers().items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, b'{"ok": true}', "application/json")
        if self.path == "/app.js":
            return self._send(200, JS.encode(), "text/javascript; charset=utf-8")
        if self.path == "/app.css":
            return self._send(200, CSS.encode(), "text/css; charset=utf-8")
        if self.path in ("/", "/index.html"):
            opts = "".join(f'<option>{u}</option>' for u in self.helpdesk.users["users"])
            return self._send(200, PAGE.replace("USERS", opts).encode(), "text/html; charset=utf-8")
        return self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path != "/api/chat":
            return self._send(404, b"not found", "text/plain")
        size = int(self.headers.get("Content-Length") or 0)
        if size > 1_000_000:
            return self._send(413, b'{"error": "too large"}', "application/json")
        try:
            body = json.loads(self.rfile.read(size) or b"{}")
            with self.lock:
                r = self.helpdesk.handle(str(body.get("user", "")), str(body.get("message", "")),
                                         ip=self.client_address[0])
            out = {"reply": r.reply, "reply_html": r.reply_html, "request_id": r.request_id, "blocked": r.blocked}
            return self._send(200, json.dumps(out).encode(), "application/json")
        except KeyError as e:
            return self._send(403, json.dumps({"error": str(e)}).encode(), "application/json")
        except (ValueError, TypeError):
            return self._send(400, b'{"error": "bad request"}', "application/json")

    def log_message(self, fmt, *args):  # quiet: the app log is the record
        pass


def serve(host: str = config.HOST, port: int = config.PORT) -> None:
    if host not in ("127.0.0.1", "localhost", "::1"):
        sys.exit(f"refusing to listen on {host}: this app is deliberately vulnerable, keep it on 127.0.0.1")
    Handler.helpdesk = Helpdesk()
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"TSG Helpdesk on http://{host}:{port}  (Ctrl+C to stop; app log: state/app-log.jsonl)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        Handler.helpdesk.close()


def ask(user: str, message: str) -> None:
    with Helpdesk() as hd:
        r = hd.handle(user, message)
    for c in r.calls:
        mark = "ALLOW" if c["allowed"] else "DENY "
        args = ", ".join(f"{k}={str(v)[:40]!r}" for k, v in c["args"].items())
        print(f"  tool  {mark} {c['tool']}({args})  {c['reason']}  <- {c['why']}")
    if r.blocked:
        print(f"  BLOCKED: {r.blocked}")
    print(f"  docs  {', '.join(r.docs) or '-'}")
    print("REPLY:\n" + r.reply)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ask", nargs=2, metavar=("USER", "MESSAGE"))
    ap.add_argument("--port", type=int, default=config.PORT)
    a = ap.parse_args()
    if a.ask:
        ask(*a.ask)
    else:
        serve(config.HOST, a.port)


if __name__ == "__main__":
    main()
