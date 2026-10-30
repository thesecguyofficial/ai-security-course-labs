#!/usr/bin/env python3
"""
explore.py: look at each idea of model serving on its own, before you scan and lock down the stack (M26 lab,
"Understand the lab").

What it does, said plainly: it reads the lab's files and, for `server`, starts the lab's own practice server on
127.0.0.1 for a few seconds, sends it two real HTTP requests and stops it. Nothing else runs. It starts no
container, loads no model, imports none of the model code in models/, opens no connection to any other address and
writes no file (not even Python's __pycache__).

Run it with the lab's own Python, .venv/bin/python (where PyYAML is):

    server                1. a model server is a web server: start the practice server, send two requests, stop it
    endpoints             2. its 12 paths: which ones apps call, and which ones only operators should
    tokens ["text"]       3. a prompt becomes tokens, and the tokens are grouped into blocks
    cache [--salt]        4. the prefix cache: a miss, a hit, and another tenant's hit (--salt: one cache per tenant)
    container [stack]     5. the compose file: which containers, which images, which ports reach the host
    node [stack]          6. the GPU node: machine type, image, toolkit, GPU sharing, metadata settings
    measure               7. attestation in one picture: a measurement is a hash of exactly what is loaded

    e.g. .venv/bin/python explore.py cache --salt

Windows: `.venv\\Scripts\\python explore.py ...`. Fake data only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import socket
import sys

sys.dont_write_bytecode = True  # read-only: importing the lab's modules must not write __pycache__/
import cache_engine  # noqa: E402  (a toy prefix cache; nothing runs on import)
import practice_server  # noqa: E402  (nothing starts on import)

HERE = pathlib.Path(__file__).resolve().parent
ACME_SYSTEM = "You are the ACME helpdesk bot . Internal code ACME-LAB-0042 is secret . Answer in English ."
# The reviewed measurement of models/approved-model (computed on 30 Oct 2026 and pinned here, the way a key policy
# pins the measurements you reviewed). Change one byte of that folder and `measure` says NO MATCH.
REVIEWED = "932d715fe8fcdb87863a5027a93da210140006c73633127aac1f9b6f0942c250"

ENGINE = {"/api/": "Ollama"}
DOES = {
    "/v1/models": "lists the models it serves",
    "/v1/chat/completions": "answers a chat (the OpenAI-style request)",
    "/health": "answers 'I am up'",
    "/version": "tells the engine version",
    "/metrics": "counters for monitoring, incl. the KV cache",
    "/tokenize": "turns text into tokens",
    "/pause": "pauses generation",
    "/update_weights": "loads new model weights",
    "/collective_rpc": "runs methods on the engine (dev mode)",
    "/api/tags": "lists the models on disk",
    "/api/pull": "downloads a model",
    "/api/delete": "deletes a model",
}


def _short(h: bytes | str) -> str:
    return (h.hex() if isinstance(h, bytes) else h)[:12]


# ------------------------------------------------------------------------------------------------ 1. server
def _raw(port: int, method: str, path: str, body: dict | None = None) -> tuple[list[str], str, str]:
    """Send one HTTP request with a plain socket, so what is printed is exactly what was sent."""
    data = json.dumps(body) if body is not None else ""
    lines = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1:{port}"]
    if body is not None:
        lines += ["Content-Type: application/json", f"Content-Length: {len(data)}"]
    lines.append("Connection: close")
    wire = ("\r\n".join(lines) + "\r\n\r\n" + data).encode()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(wire)
        got = b""
        while chunk := s.recv(65536):
            got += chunk
    head, _, rest = got.decode().partition("\r\n\r\n")
    shown = [ln for ln in lines if not ln.startswith(("Content-Length", "Connection"))]
    return shown + ([data] if data else []), head.splitlines()[0], rest


def cmd_server(_a) -> None:
    try:
        srv, port = practice_server.start("first-draft", 8765)
    except OSError:  # 8765 is busy: let the system pick a free port
        srv, port = practice_server.start("first-draft", 0)
    try:
        print(f"Started the lab's practice server on 127.0.0.1, port {port}")
        print("  127.0.0.1 = loopback: only this computer can reach it (0.0.0.0 would mean every network address)")
        print("  real defaults: Ollama 127.0.0.1:11434, vLLM port 8000. No model here: answers are canned.\n")
        asks = [("GET", "/v1/models", None, "which models do you serve?"),
                ("POST", "/v1/chat/completions",
                 {"model": "lab-model", "messages": [{"role": "user", "content": "What is a GPU?"}]},
                 "the chat request an app sends")]
        for i, (method, path, body, why) in enumerate(asks, 1):
            sent, status, reply = _raw(port, method, path, body)
            print(f"{i}. {method} {path}   ({why})")
            print("   sent:     " + sent[0])
            for ln in sent[1:]:
                print("             " + ln)
            print(f"   received: {status}")
            print(f"             {reply}\n")
    finally:
        srv.shutdown()
        srv.server_close()
    print(f"Server stopped. Port {port} is closed again.")


# --------------------------------------------------------------------------------------------- 2. endpoints
def cmd_endpoints(_a) -> None:
    print("The practice server's 12 paths: the same paths a real Ollama or vLLM server has (method + path = endpoint)")
    print(f"  {'method':<7}{'path':<22}{'engine':<8}{'kind':<12}what it does on a real server")
    for path, (method, kind, _) in practice_server.ROUTES.items():
        engine = "Ollama" if path.startswith("/api/") else "vLLM"
        print(f"  {method:<7}{path:<22}{engine:<8}{kind:<12}{DOES.get(path, '')}")
    kinds = [k for _, k, _ in practice_server.ROUTES.values()]
    ops = len(kinds) - kinds.count("inference") - kinds.count("health")
    print(f"{kinds.count('inference')} paths are 'inference': what apps call. {kinds.count('health')} is a health check. "
          f"The other {ops} are for operators (info, ops, dev, management).")
    print("All 12 share ONE address and port. Nothing in HTTP itself says which callers may use which path.")


# ------------------------------------------------------------------------------------------------ 3. tokens
def cmd_tokens(a) -> None:
    text = a.text or ACME_SYSTEM + " where is my order"
    tokens = text.split()
    n = cache_engine.BLOCK_SIZE
    print(f'Text ({len(text)} characters): "{text}"\n')
    print("Step 1  tokens. The lab splits on spaces: one token per word or mark (a stand-in).")
    print("        Real tokenizers cut text into word pieces, about 4 characters of English per token.")
    shown = [f"[{i}]{t}" for i, t in enumerate(tokens)]
    for i in range(0, len(shown), 11):
        print("        " + " ".join(shown[i:i + 11]))
    print(f"\nStep 2  blocks of {n} tokens. The server keeps its work per block (vLLM's design doc uses 16 in its example).")
    full = len(tokens) - len(tokens) % n
    for i in range(0, len(tokens), n):
        part = tokens[i:i + n]
        tag = "" if i < full else "   <- not full: never cached"
        print(f"        block {i // n}: {' '.join(part)}{tag}")
    print(f"\n{len(tokens)} tokens = {full // n} full blocks. The model reads all {len(tokens)} at once (prefill),")
    print("then writes its answer one new token at a time (decode).")


# ------------------------------------------------------------------------------------------------- 4. cache
def _serve(engine, tenant: str, question: str, salt: str | None) -> None:
    prompt = f"{ACME_SYSTEM} {question}"
    tokens = prompt.split()
    hashes = cache_engine.block_hashes(tokens, salt)
    known = [h in engine.blocks for h in hashes]
    hit = 0
    for k in known:
        if not k:
            break
        hit += 1
    r = engine.serve(prompt, salt=salt, writer=tenant)
    marks = " ".join(f"{_short(h)}:{'HIT' if i < hit else 'miss'}" for i, h in enumerate(hashes))
    owners = f"   from {', '.join(r['block_owners'])}'s blocks" if r["block_owners"] else ""
    print(f"  {tenant:<7}...system prompt + \"{question}\"  ({r['prompt_tokens']} tokens)")
    print(f"          blocks {marks}")
    print(f"          cached tokens {r['cached_tokens']:>2}   time to first token {r['ttft_ms']:>3} ms{owners}")


def cmd_cache(a) -> None:
    engine = cache_engine.PrefixCacheEngine()
    print("A prefix cache: ONE engine, empty at the start. Each full block is named by a SHA-256 hash of the block")
    print("before it and its own tokens, so the same opening gives the same hashes.")
    print("Time to first token comes from the lab's cost model: 20 ms + 2 ms per token NOT found in the cache.")
    if a.salt:
        print("--salt: the gateway mixes a per-tenant salt into block 0, so each tenant gets its own hashes.\n")
    else:
        print("No salt: every tenant shares one cache.\n")

    def salt(t):
        return hashlib.sha256(f"lab-salt/{t}".encode()).hexdigest()[:16] if a.salt else None

    _serve(engine, "acme", "where is my order", salt("acme"))
    _serve(engine, "acme", "reset my password", salt("acme"))
    _serve(engine, "globex", "what is the weather", salt("globex"))
    if a.salt:
        print("\nglobex sent the same opening and got 0 cached tokens: no answer came back faster.")
    else:
        print("\nglobex never sent that opening before, yet 16 tokens came from acme's blocks and its answer started")
        print("faster. Faster tells the caller: someone already sent this. That is a timing side channel.")


# --------------------------------------------------------------------------------------------- 5. container
def _reach(port: str) -> str:
    parts = str(port).split(":")
    if len(parts) == 2:
        return "every host address (0.0.0.0, [::])"
    return f"{parts[0]} only (this host)" if parts[0] in ("127.0.0.1", "::1") else f"{parts[0]} only"


def cmd_container(a) -> None:
    import yaml  # PyYAML, from .venv (make setup)
    path = HERE / "stacks" / a.stack / "docker-compose.yml"
    services = yaml.safe_load(path.read_text(encoding="utf-8"))["services"]
    print(f"stacks/{a.stack}/docker-compose.yml: {len(services)} containers (read only, nothing is started)")
    print("A container = one program and the files it needs, run as an isolated process on this host.\n")
    print(f"  {'service':<10}{'image (name:version)':<41}{'ports':<22}who can reach it")
    for name, svc in services.items():
        ports = svc.get("ports") or []
        if ports:
            for p in ports:
                host_side = str(p).rsplit(":", 1)[0]
                print(f"  {name:<10}{svc['image']:<41}{p:<22}host port {host_side.split(':')[-1]}: {_reach(p)}")
        else:
            exp = ", ".join(str(x) for x in svc.get("expose", [])) or "-"
            print(f"  {name:<10}{svc['image']:<41}{'expose ' + exp:<22}other containers only: no host port")
    print('\n"8000:8000" = host port 8000 -> container port 8000 on every host address.')
    print('"127.0.0.1:8443:8443" = the same, for this host only.  "expose" = no port on the host at all.')


# -------------------------------------------------------------------------------------------------- 6. node
def cmd_node(a) -> None:
    import yaml  # PyYAML, from .venv (make setup)
    base = HERE / "stacks" / a.stack
    cluster = yaml.safe_load((base / "cluster.yaml").read_text(encoding="utf-8"))
    nodes = json.loads((base / "nodes.json").read_text(encoding="utf-8"))["nodes"]
    print(f"stacks/{a.stack}: the cluster and its GPU nodes (lab data, read only)\n")
    print(f"cluster.yaml (eksctl): cluster {cluster['metadata']['name']} in {cluster['metadata']['region']}")
    for g in cluster.get("managedNodeGroups", []):
        taints = ", ".join(t["key"] for t in g.get("taints", [])) or "none"
        print(f"  node group {g['name']:<8} machine {g['instanceType']:<13} image family {g.get('amiFamily', '-'):<26}"
              f"taints: {taints}")
    print("\nnodes.json: what is installed on each GPU node")
    explain = {
        "ami": "the disk image the machine started from",
        "nvidia_container_toolkit": "hands the GPU to containers",
        "gpu_sharing": "how tenants share one GPU",
        "tenants": "whose containers run here",
        "imds_http_tokens": "metadata service: token required?",
        "imds_hop_limit": "how far metadata answers travel",
    }
    for n in nodes:
        print(f"  {n['name']}")
        for k, why in explain.items():
            v = ", ".join(n[k]) if isinstance(n[k], list) else n[k]
            print(f"    {k:<26}{str(v):<30}{why}")


# ----------------------------------------------------------------------------------------------- 7. measure
def _measure(files: dict[str, bytes]) -> tuple[str, dict[str, str]]:
    # .json is text: Windows checkouts may turn \n into \r\n, so hash it with \n line ends
    each = {name: hashlib.sha256(data.replace(b"\r\n", b"\n") if name.endswith(".json") else data).hexdigest()
            for name, data in sorted(files.items())}
    whole = hashlib.sha256("".join(f"{n}={h}\n" for n, h in each.items()).encode()).hexdigest()
    return whole, each


def _folder(name: str) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted((HERE / "models" / name).iterdir()) if p.is_file()}


def cmd_measure(_a) -> None:
    print("A measurement = a hash of exactly what is loaded. A TEE reports its measurements in a signed")
    print("attestation; a key service releases a key only if they match the values you reviewed.")
    print("Lab stand-in: SHA-256 of each file in a model folder, then one hash over those hashes.\n")
    files = _folder("approved-model")
    whole, each = _measure(files)
    print("models/approved-model")
    for n, h in each.items():
        print(f"  {n:<20}{h[:24]}...")
    print(f"  measurement         {whole[:24]}...")
    print(f"  reviewed value      {REVIEWED[:24]}...   (pinned in explore.py)")
    verdict = "MATCH: the key would be released" if whole == REVIEWED else "NO MATCH: the key stays locked"
    print(f"  -> {verdict}\n")
    changed = dict(files)
    w = bytearray(changed["model.safetensors"])
    w[-1] ^= 1
    changed["model.safetensors"] = bytes(w)
    whole2, _ = _measure(changed)
    print("the same folder with ONE bit of model.safetensors flipped (in memory only; the file is unchanged)")
    print(f"  measurement         {whole2[:24]}...   -> "
          f"{'MATCH' if whole2 == REVIEWED else 'NO MATCH: the key stays locked'}")
    whole3, _ = _measure(_folder("suspicious-model"))
    print("models/suspicious-model (other files, other code)")
    print(f"  measurement         {whole3[:24]}...   -> "
          f"{'MATCH' if whole3 == REVIEWED else 'NO MATCH: the key stays locked'}")
    print("\nA match proves WHICH files are loaded. It does not prove they are safe: that is what your review is for.")


def main() -> None:
    p = argparse.ArgumentParser(description="Look at each idea of model serving on its own (read-only).")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("server", help="start the practice server on 127.0.0.1, send two requests, stop it")
    sub.add_parser("endpoints", help="the practice server's 12 paths and what each is for")
    t = sub.add_parser("tokens", help="a prompt becomes tokens, then blocks")
    t.add_argument("text", nargs="?")
    c = sub.add_parser("cache", help="a prefix cache: miss, hit, and another tenant's hit")
    c.add_argument("--salt", action="store_true", help="one cache per tenant (salted block hashes)")
    for name in ("container", "node"):
        s = sub.add_parser(name)
        s.add_argument("stack", nargs="?", default="first-draft", choices=["first-draft", "hardened"])
    sub.add_parser("measure", help="a measurement is a hash of exactly what is loaded")
    a = p.parse_args()
    {"server": cmd_server, "endpoints": cmd_endpoints, "tokens": cmd_tokens, "cache": cmd_cache,
     "container": cmd_container, "node": cmd_node, "measure": cmd_measure}[a.cmd](a)


if __name__ == "__main__":
    main()
