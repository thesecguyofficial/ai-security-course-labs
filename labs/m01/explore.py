#!/usr/bin/env python3
"""
explore.py: look inside a local model before the exercises (M1 lab, part 1 "Understand it").

Nothing here changes anything. Each command shows one idea from the first two videos of Module 1:

    python3 explore.py model                               # 1. what a model file is: parameters, quantization, size
    python3 explore.py next "The capital of France is"     # 2. next-token prediction, one token at a time
    python3 explore.py history                             # 3. the model forgets between requests; the app re-sends
    python3 explore.py --model llama3.2:1b model           #    another model: --model goes BEFORE the command

You need Ollama running (lesson 0.6) and a model pulled: ollama pull gemma3:1b
Python standard library only, nothing to install. Talks only to Ollama on localhost (this computer).
"""

import argparse
import json
import math
import sys
import urllib.error
import urllib.request

OLLAMA = "http://localhost:11434"  # localhost = this computer; 11434 = the port (door number) Ollama listens on
DEFAULT_MODEL = "gemma3:1b"


def call(path, payload=None):
    """GET (no payload) or POST JSON to Ollama's API and return the JSON answer as a Python dictionary."""
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(OLLAMA + path, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        sys.exit(f"Ollama answered with an error {e.code}: {e.read().decode('utf-8', 'replace')}\n"
                 f"Tip: did you pull the model? Try: ollama pull {DEFAULT_MODEL}")
    except urllib.error.URLError:
        sys.exit("Could not reach Ollama at http://localhost:11434.\n"
                 "Tip: start the Ollama app (Mac/Windows) or run `ollama serve` (Linux), then try again.")


# ---------------------------------------------------------------- 1. the model file
def cmd_model(a):
    show = call("/api/show", {"model": a.model})           # Ollama's description of the model
    tags = call("/api/tags")                               # the downloaded models, with their size on disk
    size = next((m["size"] for m in tags.get("models", []) if m["name"] == a.model), 0)
    info, details = show.get("model_info", {}), show.get("details", {})
    params = info.get("general.parameter_count", 0)
    arch = info.get("general.architecture", details.get("family", "?"))
    ctx = info.get(f"{arch}.context_length")
    quant = details.get("quantization_level", "?")
    print(f"model:          {a.model}  (family {details.get('family', '?')}, file format {details.get('format', '?')})")
    print(f"parameters:     {params:,}  = about {params / 1e9:.1f} billion numbers learned in training (the weights)")
    print(f"quantization:   {quant}  = the numbers are rounded and stored in fewer bits, so the file is smaller")
    if params and size:
        print(f"file size:      {size / 1e6:,.0f} MB  = about {size * 8 / params:.1f} bits per number on average"
              f"  (at 16 bits each it would be about {params * 2 / 1e9:.1f} GB)")
    if ctx:
        print(f"context length: {ctx:,} tokens = the most this model was built to read at once"
              f" (Ollama uses a smaller window unless you ask)")
    print("\nThe model file is mostly those numbers. No rules, no database of facts: what it 'knows' is spread")
    print("across all of them. Running it (inference) reads the numbers; it never changes them.")


# ---------------------------------------------------------------- 2. next-token prediction
def cmd_next(a):
    r = call("/api/generate", {
        "model": a.model, "prompt": a.text, "stream": False,
        "raw": True,                       # no chat template: continue exactly this text
        "logprobs": True, "top_logprobs": 3,  # also return the top 3 guesses at every step
        "options": {"num_predict": a.tokens, "temperature": 0},
    })
    steps = r.get("logprobs") or []
    print(f'text so far: "{a.text}"')
    print(f"The model reads all of it, scores every token it knows, and the top guess is added. Then again.\n")
    if not steps:  # an older Ollama without logprobs: still show the continuation
        print(f'continuation: "{r.get("response", "")}"')
        return
    so_far = a.text
    for i, s in enumerate(steps, 1):
        guesses = "  ".join(f"{t['token']!r} {math.exp(t['logprob']) * 100:4.1f}%" for t in s.get("top_logprobs", []))
        print(f"step {i}: picks {s['token']!r:<12} top 3 guesses: {guesses}")
        so_far += s["token"]
    print(f'\nresult: "{so_far}"')
    print(f"({len(steps)} tokens, one per step. temperature 0 = always take the top guess.)")


# ---------------------------------------------------------------- 3. stateless model, app re-sends history
SYSTEM = {"role": "system", "content": "You are a helpful assistant. Answer in one short sentence."}


def show_request(model, title, messages):
    r = call("/api/chat", {"model": model, "messages": messages,
                           "stream": False, "options": {"temperature": 0, "num_predict": 40}})
    print(f"== {title}: the app sends {len(messages)} messages ({r.get('prompt_eval_count')} tokens) ==")
    for m in messages:
        print(f"   {m['role']:<9} {m['content']}")
    reply = r["message"]["content"].strip()
    print(f"   -> model: {reply}\n")
    return reply


def cmd_history(a):
    first = {"role": "user", "content": "Hi! My name is Asha and my favourite colour is green."}
    reply = show_request(a.model, "Request 1", [SYSTEM, first])
    question = {"role": "user", "content": "What is my name?"}
    show_request(a.model, "Request 2, a new request without the history", [SYSTEM, question])
    show_request(a.model, "Request 3, the app re-sends the history", [SYSTEM, first, {"role": "assistant", "content": reply}, question])
    print("The model keeps nothing between requests. A chat 'remembers' only because the app sends the earlier")
    print("messages again, every time, inside the context window (working memory).")



def main(argv=None):
    p = argparse.ArgumentParser(description="Look inside a local model (M1 lab, part 1). Changes nothing.")
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"model name (default {DEFAULT_MODEL})")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("model", help="what the model file is").set_defaults(fn=cmd_model)
    n = sub.add_parser("next", help="next-token prediction, step by step")
    n.add_argument("text"); n.add_argument("--tokens", type=int, default=6); n.set_defaults(fn=cmd_next)
    sub.add_parser("history", help="the app re-sends the chat history").set_defaults(fn=cmd_history)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
