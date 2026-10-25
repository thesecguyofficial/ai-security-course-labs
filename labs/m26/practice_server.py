"""
practice_server.py: a practice inference server for the M26 lab. It imitates the SHAPE of an Ollama server and a
vLLM OpenAI-compatible server (paths and status codes), so probe.py has something real to knock on. There is no
model behind it: answers are canned, and management calls change nothing and download nothing.

It only ever binds to 127.0.0.1. Three profiles:

    first-draft  no login anywhere, every path open (the exposed server from lesson 26.0)
    key-only     vLLM started with --api-key and no gateway: /v1 paths need the key, the rest of the server
                 does not (the split vLLM's security guide documents)
    hardened     the gateway in front: a key on every path, and only the allow-listed paths exist

Run it by hand if you like (Ctrl+C stops it):  python3 practice_server.py first-draft 8765
"""

import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
LAB_KEY = "lab-key-acme"          # a lab placeholder, accepted by every profile that wants a key
VLLM_PROTECTED_PREFIXES = ("/v1", "/v2", "/inference", "/cohere")   # what --api-key covers (vLLM security guide)

# path -> (method, kind, canned response). Management and ops calls are no-ops in the lab.
ROUTES = {
    "/v1/models": ("GET", "inference", {"object": "list", "data": [{"id": "lab-model"}]}),
    "/v1/chat/completions": ("POST", "inference", {"choices": [{"message": {"role": "assistant", "content": "lab answer"}}]}),
    "/health": ("GET", "health", {}),
    "/version": ("GET", "info", {"version": "0.10.2"}),
    "/metrics": ("GET", "info", {"lab": "metrics text would be here"}),
    "/tokenize": ("POST", "info", {"tokens": [1, 2, 3]}),
    "/pause": ("POST", "ops", {"lab": "nothing was paused"}),
    "/update_weights": ("POST", "ops", {"lab": "no weights were changed"}),
    "/collective_rpc": ("POST", "dev", {"lab": "development endpoint (VLLM_SERVER_DEV_MODE=1)"}),
    "/api/tags": ("GET", "inference", {"models": [{"name": "lab-model"}]}),
    "/api/pull": ("POST", "management", {"status": "success", "lab": "nothing was downloaded"}),
    "/api/delete": ("DELETE", "management", {"lab": "nothing was deleted"}),
}


def gateway_config(profile):
    stack = "hardened" if profile == "hardened" else "first-draft"
    return json.loads((HERE / "stacks" / stack / "gateway.json").read_text(encoding="utf-8"))


def decide(profile, method, path, auth_header):
    """Return (status, body) for one request under a profile. Pure function, used by the server and the tests."""
    route = ROUTES.get(path)
    has_key = auth_header == f"Bearer {LAB_KEY}"
    if profile == "hardened":
        gw = gateway_config(profile)
        if gw.get("require_auth") and not has_key:
            return 401, {"error": "missing or wrong key"}
        if path not in gw["allow_paths"]:
            return 404, {"error": "not found"}
    elif profile == "key-only":
        if path.startswith(VLLM_PROTECTED_PREFIXES) and not has_key:
            return 401, {"error": "Unauthorized"}
        if path.startswith("/api/") or ROUTES.get(path, ("", ""))[1] == "dev":
            return 404, {"error": "not found"}      # a single vLLM server: no Ollama, dev mode off
    elif profile != "first-draft":
        raise ValueError(f"unknown profile {profile!r}")
    if route is None:
        return 404, {"error": "not found"}
    if method != route[0]:
        return 405, {"error": "method not allowed"}
    return 200, route[2]


class Handler(BaseHTTPRequestHandler):
    profile = "first-draft"

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(min(length, 65536))
        status, body = decide(self.profile, self.command, self.path.split("?")[0], self.headers.get("Authorization"))
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_DELETE = _answer

    def log_message(self, *args):   # keep the lab output readable
        pass


def start(profile, port=0):
    """Start the server on 127.0.0.1 in a background thread. Returns (server, port)."""
    handler = type("LabHandler", (Handler,), {"profile": profile})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


if __name__ == "__main__":
    prof = sys.argv[1] if len(sys.argv) > 1 else "first-draft"
    srv, p = start(prof, int(sys.argv[2]) if len(sys.argv) > 2 else 8765)
    print(f"practice server ({prof}) on http://127.0.0.1:{p}  (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
