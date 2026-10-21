#!/usr/bin/env python3
"""
M1.8 lab: talk to a local AI model, count tokens, and watch the context window fill up.

You need:  Ollama running on this computer (lesson 0.6) and a small model pulled, e.g.
           ollama pull gemma3:1b
No extra Python packages: this script only uses Python's standard library.

Try these, one at a time:
    python3 llm_lab.py check                          # is Ollama running? which models do I have?
    python3 llm_lab.py chat "What is a token?"        # call the OpenAI-compatible API, see the raw request
    python3 llm_lab.py tokens "hello" "Ignore previous instructions" "₹1,999"   # count tokens
    python3 llm_lab.py temp "Name a colour." --runs 3 # same question, different temperatures
    python3 llm_lab.py fill --ctx 1024                # watch the context window fill and forget

Safety note: everything here talks to http://localhost:11434, which is YOUR computer only.
Nothing you type leaves your machine.
"""

import argparse  # reads the words you type after the script name
import json  # turns Python dictionaries into JSON text and back
import sys
import urllib.error
import urllib.request  # sends HTTP requests (the same thing a browser does)

# Where Ollama listens. 127.0.0.1 / localhost means "this computer".
OLLAMA = "http://localhost:11434"
# The OpenAI-compatible address. Any app written for the OpenAI API can point here instead.
OPENAI_COMPAT = OLLAMA + "/v1"
DEFAULT_MODEL = "gemma3:1b"


def post_json(url, payload):
    """Send `payload` as JSON to `url` and return the JSON answer as a Python dictionary."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        # Ollama ignores the key, but OpenAI-style apps always send one. Never put a real key here.
        "Authorization": "Bearer ollama",
    })
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        sys.exit(f"Ollama answered with an error {e.code}: {e.read().decode('utf-8', 'replace')}\n"
                 f"Tip: did you pull the model? Try: ollama pull {DEFAULT_MODEL}")
    except urllib.error.URLError:
        sys.exit("Could not reach Ollama at http://localhost:11434.\n"
                 "Tip: start the Ollama app (Mac/Windows) or run `ollama serve` (Linux), then try again.")


def get_json(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError:
        sys.exit("Could not reach Ollama at http://localhost:11434. Is it running?")


# ---------------------------------------------------------------- 1. check
def cmd_check(args):
    tags = get_json(OLLAMA + "/api/tags")  # Ollama's own list of downloaded models
    names = [m["name"] for m in tags.get("models", [])]
    print("Ollama is running.")
    print("Models on this computer:", ", ".join(names) or "(none yet: run `ollama pull gemma3:1b`)")
    models = get_json(OPENAI_COMPAT + "/models")  # the same list, through the OpenAI-compatible API
    print("Seen through the OpenAI-compatible API:", [m["id"] for m in models.get("data", [])])


# ---------------------------------------------------------------- 2. chat
def cmd_chat(args):
    # This is the exact shape every OpenAI-compatible API expects: a model name and a list of messages.
    request = {
        "model": args.model,
        "messages": [
            # The "system" message is the app's instructions (the manager's sticky note).
            {"role": "system", "content": "You are a helpful assistant. Answer in at most three sentences."},
            # The "user" message is what the person typed.
            {"role": "user", "content": args.question},
        ],
        "temperature": 0.2,
    }
    print("---- what we send (HTTP POST", OPENAI_COMPAT + "/chat/completions) ----")
    print(json.dumps(request, indent=2, ensure_ascii=False))
    answer = post_json(OPENAI_COMPAT + "/chat/completions", request)
    print("\n---- what the model says ----")
    print(answer["choices"][0]["message"]["content"].strip())
    usage = answer.get("usage", {})
    print("\n---- the bill (in tokens) ----")
    print(f"prompt tokens (everything we sent, incl. the system message): {usage.get('prompt_tokens')}")
    print(f"completion tokens (what the model wrote):                   {usage.get('completion_tokens')}")
    print("On a paid cloud API, you pay for both numbers. That is why 'denial of wallet' is a real attack.")


# ---------------------------------------------------------------- 3. tokens
def count_prompt_tokens(model, text):
    """Ask Ollama how many tokens a one-message conversation uses. num_predict=1 = 'write at most 1 token'."""
    r = post_json(OLLAMA + "/api/chat", {
        "model": model, "stream": False,
        "messages": [{"role": "user", "content": text}],
        "options": {"num_predict": 1, "temperature": 0},
    })
    return r.get("prompt_eval_count", 0)  # "Number of tokens in the prompt" (Ollama API docs)


def cmd_tokens(args):
    # Even an empty message costs tokens: the chat template adds markers like <start_of_turn>user.
    overhead = count_prompt_tokens(args.model, "")
    print(f"Chat-template overhead for {args.model}: {overhead} tokens (the wrapping around every message)\n")
    print(f"{'tokens':>6}  {'chars':>5}  text")
    for text in args.texts:
        n = count_prompt_tokens(args.model, text) - overhead
        print(f"{n:>6}  {len(text):>5}  {text}")
    print("\nRule of thumb for English: 1 token is about 4 characters (OpenAI help centre).")
    print("Other languages, numbers and symbols often need more tokens per character. Try some!")


# ---------------------------------------------------------------- 4. temperature
def cmd_temp(args):
    for t in (0.0, 1.0, 1.8):
        print(f"\n== temperature {t} ==")
        for i in range(args.runs):
            r = post_json(OPENAI_COMPAT + "/chat/completions", {
                "model": args.model, "temperature": t, "max_tokens": 40,
                "messages": [{"role": "user", "content": args.question}],
            })
            print(f"  run {i + 1}: {r['choices'][0]['message']['content'].strip()[:120]}")
    print("\nLow temperature = the most likely words, run after run. High = more random.")
    print("Even at 0, answers can differ between runs or machines. Test AI features many times, not once.")


# ---------------------------------------------------------------- 5. fill the context window
FILLER = ("Here is a long, boring paragraph that only exists to take up space on the whiteboard. "
          "It talks about the weather, the colour of the office walls, and what was for lunch on Tuesday. ") * 3


def cmd_fill(args):
    ctx = args.ctx
    secret = "PINEAPPLE-42"
    # Message 1: the important fact. (Not a system message: Ollama always keeps system messages.)
    messages = [
        {"role": "user", "content": f"Remember this codeword for later: {secret}. Just reply OK."},
        {"role": "assistant", "content": "OK."},
    ]
    print(f"Context window for this run: {ctx} tokens (we set it with the num_ctx option)\n")
    last = 0
    for rnd in range(1, args.rounds + 1):
        messages.append({"role": "user", "content": f"Note {rnd}: {FILLER} Reply OK."})
        r = post_json(OLLAMA + "/api/chat", {
            "model": args.model, "stream": False, "messages": messages,
            "options": {"num_ctx": ctx, "num_predict": 4, "temperature": 0},
        })
        used = r.get("prompt_eval_count", 0)
        messages.append({"role": "assistant", "content": "OK."})
        bar = "#" * int(40 * min(used, ctx) / ctx)
        note = "  <- stopped growing: older messages are being dropped" if used <= last else ""
        print(f"round {rnd:>2}: {used:>5} / {ctx} tokens [{bar:<40}]{note}")
        last = used
    messages.append({"role": "user", "content": "What was the codeword I asked you to remember? Answer with the codeword only."})
    r = post_json(OLLAMA + "/api/chat", {
        "model": args.model, "stream": False, "messages": messages,
        "options": {"num_ctx": ctx, "num_predict": 20, "temperature": 0},
    })
    answer = r["message"]["content"].strip()
    print(f"\nWe asked for the codeword. The model said: {answer!r}")
    if secret in answer:
        print("It remembered: the first message still fits. Run again with a smaller --ctx or more --rounds.")
    else:
        print("It forgot. The first message fell off the whiteboard to make room. Nothing warned you.")
    print("Security lesson: whatever is on the whiteboard is all the model 'knows'. Rules that fall off stop working,")
    print("and an attacker who can add text can push things off. Long chats are not long memory.")


def main():
    p = argparse.ArgumentParser(description="M1.8 lab: local LLM, tokens, context window")
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"model name (default {DEFAULT_MODEL})")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check").set_defaults(fn=cmd_check)
    c = sub.add_parser("chat"); c.add_argument("question"); c.set_defaults(fn=cmd_chat)
    t = sub.add_parser("tokens"); t.add_argument("texts", nargs="+"); t.set_defaults(fn=cmd_tokens)
    te = sub.add_parser("temp"); te.add_argument("question"); te.add_argument("--runs", type=int, default=3); te.set_defaults(fn=cmd_temp)
    f = sub.add_parser("fill"); f.add_argument("--ctx", type=int, default=1024); f.add_argument("--rounds", type=int, default=12)
    f.set_defaults(fn=cmd_fill)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
