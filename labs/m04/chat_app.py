#!/usr/bin/env python3
"""
M4.6 lab: a tiny local "support chat" app that logs every turn, like most real apps do.

Run it two ways and compare the log files:

    python3 chat_app.py --script conversation.txt            # NO redaction: watch PII land in logs/
    python3 chat_app.py --script conversation.txt --redact   # redaction in AND out, plus a log filter

Or chat by hand (type 'quit' to stop):

    python3 chat_app.py --redact

Where things go:
    logs/app.log       your application's log (what your company keeps)
    logs/provider.log  what the AI model's provider received (what left your company)

Optional, a real local model instead of the stand-in (needs Ollama from lesson 0.6 and a pulled model):
    python3 chat_app.py --backend ollama --model gemma3:1b --redact

Safety: the only network address this script ever calls is http://localhost:11434 (Ollama on YOUR computer),
and only with --backend ollama. All "personal data" in this lab is fake, reserved test data.
"""

import argparse
import json
import logging
import pathlib
import sys
import urllib.error
import urllib.request

from stub_llm import stub_llm

HERE = pathlib.Path(__file__).resolve().parent
LOG_DIR = HERE / "logs"
OLLAMA_URL = "http://localhost:11434/v1/chat/completions"  # OpenAI-compatible API (lesson 1.8)
SYSTEM_PROMPT = "You are a helpful support assistant. Keep answers short."

log = logging.getLogger("app")


def setup_app_log(redact_logs: bool):
    """Write the app's log to logs/app.log. With redaction on, attach the safety-net filter."""
    LOG_DIR.mkdir(exist_ok=True)
    handler = logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    if redact_logs:
        from redactor import RedactingLogFilter
        # Filters on a HANDLER run for every record written through it, whichever code logged it.
        handler.addFilter(RedactingLogFilter())
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)


def ollama_llm(messages: list[dict], model: str) -> str:
    """Call a real model through Ollama's OpenAI-compatible API on localhost."""
    body = json.dumps({"model": model, "messages": messages, "temperature": 0}).encode("utf-8")
    req = urllib.request.Request(OLLAMA_URL, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read().decode("utf-8"))["choices"][0]["message"]["content"]
    except urllib.error.URLError as e:
        sys.exit(f"Could not reach Ollama at {OLLAMA_URL} ({e}).\n"
                 f"Tip: start Ollama (lesson 0.6) and run: ollama pull {model}")


def handle_turn(user_text: str, history: list[dict], args) -> str:
    """One chat turn: (redact in) -> model -> (redact out) -> log -> return the reply."""
    # A careless debug line, the kind that ends up in real code. Without the log filter it leaks raw input.
    log.debug("raw request received: %s", user_text)

    # ---- 1. REDACT IN: clean the user's text BEFORE it leaves for the model provider.
    if args.redact:
        from redactor import redact
        to_model = redact(user_text)
    else:
        to_model = user_text
    history.append({"role": "user", "content": to_model})

    # ---- 2. call the model (the stand-in, or a real one through Ollama)
    if args.backend == "ollama":
        reply = ollama_llm(history, args.model)
    else:
        reply = stub_llm(history)

    # ---- 3. REDACT OUT: the model's answer may contain PII it saw elsewhere (RAG, tools, training data).
    if args.redact:
        reply = redact(reply)
    history.append({"role": "assistant", "content": reply})

    # ---- 4. log the turn. These are the lines your company keeps (and ships to the SIEM, the vendor...).
    log.info("user: %s", to_model)
    log.info("assistant: %s", reply)
    return reply


def main():
    p = argparse.ArgumentParser(description="M4.6 lab chat app")
    p.add_argument("--redact", action="store_true", help="turn on redaction in, out and in the logs")
    p.add_argument("--script", help="read user messages from this file (one per line) instead of typing")
    p.add_argument("--backend", choices=["stub", "ollama"], default="stub",
                   help="stub = the stand-in model (default); ollama = a real local model")
    p.add_argument("--model", default="gemma3:1b", help="Ollama model name (only with --backend ollama)")
    p.add_argument("--fresh", action="store_true", help="delete old log files first")
    args = p.parse_args()

    if args.fresh:
        for f in ("app.log", "provider.log"):
            (LOG_DIR / f).unlink(missing_ok=True)
    setup_app_log(redact_logs=args.redact)
    mode = "REDACTION ON" if args.redact else "NO REDACTION"
    model = "stand-in model (stub_llm.py)" if args.backend == "stub" else f"Ollama: {args.model}"
    print(f"--- support chat · {mode} · {model} ---")

    history = [{"role": "system", "content": SYSTEM_PROMPT}]
    if args.script:
        lines = [ln.strip() for ln in (HERE / args.script).read_text(encoding="utf-8").splitlines()]
        for user_text in [ln for ln in lines if ln and not ln.startswith("#")]:
            print(f"\nyou> {user_text}")
            print(f"bot> {handle_turn(user_text, history, args)}")
    else:
        while True:
            try:
                user_text = input("\nyou> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if user_text.lower() in {"quit", "exit"}:
                break
            if user_text:
                print(f"bot> {handle_turn(user_text, history, args)}")
    if args.backend == "stub":
        print("\nLogs written to logs/app.log and logs/provider.log")
    else:
        # With Ollama the "provider" is your own laptop, so there is no provider.log; check_logs.py still
        # checks logs/app.log. With a cloud API, the provider's copy is outside your control.
        print("\nLog written to logs/app.log")


if __name__ == "__main__":
    main()
