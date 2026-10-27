#!/usr/bin/env python3
"""Course video demo (M5, lesson 5.2): a short request can cost a long answer, and max_tokens is the brake.

Sends the same one-line request to a real local model (Ollama, http://localhost:11434) twice: once with a small
max_tokens, once with a large one, and prints the token counts the server reports. Nothing leaves your machine.

    python3 demos/m05/cost_asymmetry.py
"""
import json
import time
import urllib.request

URL = "http://localhost:11434/v1/chat/completions"
PROMPT = "Write a detailed 1,500-word history of the printing press."


def run(model: str, max_tokens: int):
    body = json.dumps({"model": model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": PROMPT}]})
    req = urllib.request.Request(URL, data=body.encode(), headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=900) as r:
        usage = json.load(r)["usage"]
    return usage["prompt_tokens"], usage["completion_tokens"], time.time() - t0


def main():
    model = "gemma3:1b"
    print(f"request: {PROMPT!r}\nmodel:   {model} (local)\n")
    print(f"{'max_tokens':>10}  {'input tokens':>12}  {'output tokens':>13}  {'output/input':>12}  {'seconds':>7}")
    for cap in (100, 2000):
        i, o, s = run(model, cap)
        print(f"{cap:>10}  {i:>12}  {o:>13}  {o / i:>11.0f}x  {s:>7.1f}")
    print("\nOn a paid API you pay per token, and output tokens usually cost more than input tokens.")


if __name__ == "__main__":
    main()
