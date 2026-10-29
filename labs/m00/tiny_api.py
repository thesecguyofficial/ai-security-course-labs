"""
tiny_api.py: a tiny web server with an API, on your own computer only (M0, lesson 0.3b "How apps talk").

It shows the ideas from the tech basics videos with real requests you can send with curl:

    python3 tiny_api.py &                       # start it in the background (Windows: py tiny_api.py, in its own window)
    curl -i http://127.0.0.1:8080/                                        # a web page (HTML)
    curl -i http://127.0.0.1:8080/api/orders/1001                         # an API endpoint, no key -> 401
    curl -i -H "Authorization: Bearer demo-key-123" http://127.0.0.1:8080/api/orders/1001   # with the key -> 200, JSON
    curl -i -X POST -H "Authorization: Bearer demo-key-123" -H "Content-Type: application/json" \
         -d '{"item": "tent", "qty": 1}' http://127.0.0.1:8080/api/orders                 # create one -> 201
    kill %1                                     # stop it (or Ctrl+C if it runs in the front)

It listens on 127.0.0.1 only, so nothing else on your network can reach it. The data and the key are fake.
Standard library only: no packages to install.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_KEY = "demo-key-123"  # fake, printed in the lesson on purpose
ORDERS = {1001: {"id": 1001, "item": "sleeping bag", "qty": 2, "status": "shipped"}}
PAGE = """<!doctype html>
<html>
  <head><title>Demo shop</title></head>
  <body>
    <h1>Demo shop</h1>
    <p>This page came from tiny_api.py on <b>your own computer</b>.</p>
    <a href="/api/orders/1001">Order 1001 (needs an API key)</a>
  </body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "tiny_api/1.0"
    protocol_version = "HTTP/1.1"

    def version_string(self):
        return self.server_version

    def log_message(self, *args):  # quiet: the terminal shows only what curl prints
        pass

    def send(self, code: int, body, kind: str = "application/json"):
        data = (body if isinstance(body, str) else json.dumps(body) + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorised(self) -> bool:
        if self.headers.get("Authorization", "") == f"Bearer {API_KEY}":
            return True
        self.send(401, {"error": "missing or wrong API key"})
        return False

    def do_GET(self):
        if self.path == "/":
            return self.send(200, PAGE, "text/html; charset=utf-8")
        if self.path.startswith("/api/orders/"):
            if not self.authorised():
                return
            oid = self.path.rsplit("/", 1)[-1]
            order = ORDERS.get(int(oid)) if oid.isdigit() else None
            return self.send(200, order) if order else self.send(404, {"error": f"no order {oid}"})
        self.send(404, {"error": "no such endpoint"})

    def do_POST(self):
        if self.path != "/api/orders":
            return self.send(404, {"error": "no such endpoint"})
        if not self.authorised():
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            new = json.loads(self.rfile.read(min(n, 10_000)) or b"{}")
            item, qty = str(new["item"]), int(new["qty"])
        except (ValueError, KeyError, TypeError):
            return self.send(400, {"error": "send JSON like {\"item\": \"tent\", \"qty\": 1}"})
        oid = max(ORDERS) + 1
        ORDERS[oid] = {"id": oid, "item": item, "qty": qty, "status": "new"}
        self.send(201, ORDERS[oid])


def main(argv=None):
    ap = argparse.ArgumentParser(description="A tiny local API for the tech basics videos (127.0.0.1 only).")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args(argv)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print(f"tiny_api: listening on http://127.0.0.1:{a.port} (this computer only). Fake data, fake key.", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
