"""
explore.py: look at Ollama and your first model, one step at a time (M0, lesson 0.4 "Lab, part 1").

Nothing here changes anything. Each command asks Ollama, on your own computer, one question and explains the answer:

    python3 explore.py server                 # 1. is Ollama answering, and only on this computer (127.0.0.1)?
    python3 explore.py models                 # 2. the models you downloaded: size, parameters, quantization
    python3 explore.py template gemma3:1b     # 3. how the app's note and your question become ONE text
    python3 explore.py chat gemma3:1b --system "You are the help desk bot for a demo shop." "What are your opening hours?"
                                              # 4. the exact request a chat app sends, and the reply

Windows: use `py` instead of `python3`. Standard library only: no packages to install.
It only talks to Ollama on 127.0.0.1:11434 (or OLLAMA_HOST if you set it to a 127.0.0.1 address).
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.request

PORT = 11434


def base_url() -> str:
    host = os.environ.get("OLLAMA_HOST", "").strip()
    if host and (host.startswith("127.0.0.1") or host.startswith("localhost") or host.startswith("http://127.0.0.1")):
        return host if host.startswith("http") else f"http://{host}"
    return f"http://127.0.0.1:{PORT}"


def call(path: str, body: dict | None = None, url: str | None = None, timeout: float = 300):
    req = urllib.request.Request((url or base_url()) + path,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="GET" if body is None else "POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def no_server():
    print(f"Ollama is not answering on {base_url()}.")
    print("  Start it: open the Ollama app (Mac, Windows), or run: sudo systemctl start ollama (Linux).")
    print("  Not installed yet? Lesson 0.4, part 1 shows how.")
    sys.exit(1)


def network_address() -> str | None:
    """This computer's address on its network (no packet is sent: a UDP 'connect' only picks a route)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # TEST-NET address from RFC 5737: never routed anywhere real
        ip = s.getsockname()[0]
        s.close()
        return None if ip.startswith("127.") else ip
    except OSError:
        return None


def answers(host: str) -> bool:
    try:
        with socket.create_connection((host, PORT), timeout=2):
            return True
    except OSError:
        return False


def cmd_server(_a):
    try:
        v = call("/api/version", timeout=5)["version"]
    except (urllib.error.URLError, OSError):
        no_server()
    print(f"Ollama {v} is answering at {base_url()}")
    print("  127.0.0.1 (also called localhost) means: this computer only.\n")
    ip = network_address()
    if ip is None:
        print("This computer has no network address right now, so nothing else can reach it.")
        return
    if answers(ip):
        print(f"!! Port {PORT} ALSO answers on this computer's network address, {ip}.")
        print("   Other devices on your network can use your models. Remove OLLAMA_HOST and restart Ollama (lesson 0.6).")
    else:
        print(f"Port {PORT} on this computer's network address ({ip}): no answer.")
        print("  Good: other devices on your network can't reach Ollama. It is private to this computer.")


def gb(n: int) -> str:
    return f"{n / 1e9:.1f} GB"


def cmd_models(_a):
    try:
        models = call("/api/tags", timeout=10).get("models", [])
    except (urllib.error.URLError, OSError):
        no_server()
    if not models:
        print("No models yet. Download the small one: ollama pull gemma3:1b")
        return
    print(f"{len(models)} model(s) on this computer:\n")
    for m in models:
        d = m.get("details", {})
        print(f"  {m['name']}")
        print(f"     file size     {gb(m.get('size', 0))}")
        print(f"     parameters    {d.get('parameter_size', '?'):<10} the numbers the model learned in training")
        print(f"     quantization  {d.get('quantization_level', '?'):<10} how many bits store each number (Q4 = about 4)")
        print(f"     family        {d.get('family', '?')}")
    print("\nA model file is mostly those numbers. Ollama loads it into memory and runs it; nothing leaves this computer.")


def cmd_template(a):
    try:
        info = call("/api/show", {"model": a.model}, timeout=30)
    except urllib.error.HTTPError:
        print(f"No model called {a.model}. See your models with: python3 explore.py models")
        sys.exit(1)
    except (urllib.error.URLError, OSError):
        no_server()
    tpl = info.get("template", "")
    print(f"=== the chat template of {a.model} (from Ollama, unchanged) ===")
    print(tpl.strip())
    print("=== end ===\n")
    print("A model reads ONE text. Before every reply, Ollama fills this template with the messages:")
    print("the app's note (role \"system\") and your question (role \"user\") end up side by side in that text.")
    sys_lines = [ln.strip() for ln in tpl.splitlines() if '"system"' in ln or ".System" in ln]
    if sys_lines:
        print("\nLines of this template that place the system note:")
        for ln in sys_lines:
            print(f"   {ln}")


def cmd_chat(a):
    msgs = []
    if a.system:
        msgs.append({"role": "system", "content": a.system})
    msgs.append({"role": "user", "content": a.question})
    body = {"model": a.model, "messages": msgs, "stream": False, "options": {"seed": 7}}
    print(f"=== request: POST {base_url()}/api/chat ===")
    print(json.dumps(body, indent=2))
    try:
        r = call("/api/chat", body)
    except urllib.error.HTTPError as e:
        print(f"Ollama answered {e.code}: {e.read().decode()[:200]}")
        sys.exit(1)
    except (urllib.error.URLError, OSError):
        no_server()
    print("\n=== reply ===")
    print(r.get("message", {}).get("content", "").strip())
    print("\n=== what the model read and wrote ===")
    print(f"  {r.get('prompt_eval_count', '?')} tokens in: the note and the question, read as one text")
    print(f"  {r.get('eval_count', '?')} tokens out: the reply, one token at a time")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Look at Ollama and your first model, one step at a time (read-only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("server", help="is Ollama answering, and only on this computer?").set_defaults(fn=cmd_server)
    sub.add_parser("models", help="the models you downloaded").set_defaults(fn=cmd_models)
    t = sub.add_parser("template", help="how the messages become one text")
    t.add_argument("model")
    t.set_defaults(fn=cmd_template)
    c = sub.add_parser("chat", help="the exact request a chat app sends, and the reply")
    c.add_argument("model")
    c.add_argument("question")
    c.add_argument("--system", default="", help="the app's note to the model (system prompt)")
    c.set_defaults(fn=cmd_chat)
    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
