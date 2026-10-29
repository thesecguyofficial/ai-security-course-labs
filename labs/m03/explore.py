#!/usr/bin/env python3
"""
explore.py: look at each step of SupportBot on its own, before you attack it (M3 lab, part 1 "Understand the lab").

Nothing here changes the lab: no tickets, no logs, no state files. Each command shows one step of what
support_bot.py does with an email:

    python3 explore.py request data/emails/01_normal.txt     # 1. the exact JSON request the app sends a model
    python3 explore.py send    data/emails/01_normal.txt     # 2. send it to a real local model (Ollama), show the reply
    python3 explore.py stream  data/emails/01_normal.txt     # 3. the same request as ONE stream of text, the way the
                                                             #    model reads it (Gemma 3's chat format), checked
                                                             #    against Ollama (add --no-check to skip the model)
    python3 explore.py standin data/emails/03_planted_note.txt   # 4. the stand-in model's raw reply, line by line,
                                                                 #    and what the weak app does with each line

Fake data only. `send` and `stream` talk only to Ollama on 127.0.0.1 (your own computer); the other two need no
model at all. Ollama: lessons 0.6 and 1.8, then `ollama pull gemma3:1b`.
"""

import argparse
import json
import pathlib
import sys
import tempfile
import urllib.error
import urllib.request

import support_bot
from stand_in_model import stand_in_model

OLLAMA = "http://127.0.0.1:11434"


def capture_request(email_file: str, fixes: str, model: str) -> dict:
    """Run support_bot.handle_email with the model call swapped for a recorder, so the messages shown are EXACTLY
    the ones the app builds. State and logs go to a temporary folder that is deleted at the end."""
    email = pathlib.Path(email_file).read_text(encoding="utf-8")
    seen = {}

    def recorder(messages, backend, model_name):
        seen["messages"] = messages
        return stand_in_model(messages)

    real_call, real_state, real_log = support_bot.call_model, support_bot.STATE_DIR, support_bot.LOG_FILE
    with tempfile.TemporaryDirectory() as tmp:
        support_bot.call_model = recorder
        support_bot.STATE_DIR = pathlib.Path(tmp) / "state"
        support_bot.LOG_FILE = pathlib.Path(tmp) / "logs" / "events.jsonl"
        try:
            support_bot.handle_email(email, "summarise", support_bot.parse_fixes(fixes), "ollama", model)
        finally:
            support_bot.call_model, support_bot.STATE_DIR, support_bot.LOG_FILE = real_call, real_state, real_log
    # The same body support_bot.call_model() sends with --backend ollama.
    return {"model": model, "messages": seen["messages"], "temperature": 0}


def post(url: str, body: dict, timeout: int = 300) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        sys.exit(f"Ollama answered {e.code}: {e.read().decode('utf-8', 'replace')[:300]}")
    except urllib.error.URLError as e:
        sys.exit(f"Could not reach Ollama at {OLLAMA} ({e.reason}).\n"
                 f"Tip: start Ollama (lesson 0.6) and run: ollama pull {body.get('model')}")


def gemma_stream(messages: list[dict]) -> str:
    """Write the messages as one stream of text in Gemma 3's chat format (Google's guide:
    https://ai.google.dev/gemma/docs/core/prompt-structure). Gemma has only two roles, user and model: Ollama
    sends a system message as a user turn of its own. `stream` checks this against Ollama itself. Every turn opens with <start_of_turn> and closes with <end_of_turn>, and the
    stream ends with an open model turn: the model's job is to continue the text from there."""
    out = []
    for i, m in enumerate(messages):
        last = i == len(messages) - 1
        if m["role"] in ("user", "system"):
            out.append(f"<start_of_turn>user\n{m['content']}<end_of_turn>\n")
            if last:
                out.append("<start_of_turn>model\n")
        elif m["role"] == "assistant":
            out.append(f"<start_of_turn>model\n{m['content']}" + ("" if last else "<end_of_turn>\n"))
    return "".join(out)


def cmd_request(a):
    body = capture_request(a.email_file, a.fixes, a.model)
    print(f"POST {OLLAMA}/v1/chat/completions   (the OpenAI-compatible chat API; fixes: {a.fixes})\n")
    print(json.dumps(body, indent=2, ensure_ascii=False))


def cmd_send(a):
    body = capture_request(a.email_file, a.fixes, a.model)
    print(f"Sending the request above to {OLLAMA}/v1/chat/completions ...\n")
    reply = post(f"{OLLAMA}/v1/chat/completions", body)
    print(json.dumps(reply, indent=2, ensure_ascii=False))


def cmd_stream(a):
    body = capture_request(a.email_file, a.fixes, a.model)
    tape = gemma_stream(body["messages"])
    print(f"The request as ONE stream of text ({a.model}'s chat format). <start_of_turn> and <end_of_turn> are")
    print("special marker tokens. The model reads all of it, then continues after the last line:\n")
    print(tape, end="")
    print("[the model writes its reply here]\n")
    if a.no_check:
        return
    # Proof: send the messages through the chat API, then send the stream we built as raw text (raw = Ollama
    # adds no template). keep_alive 0 unloads the model after each call, so neither answer reuses the other's work.
    opts = {"temperature": 0, "seed": 1}
    chat = post(f"{OLLAMA}/api/chat", {"model": a.model, "messages": body["messages"], "stream": False,
                                       "options": opts, "keep_alive": 0})
    raw = post(f"{OLLAMA}/api/generate", {"model": a.model, "prompt": tape, "raw": True, "stream": False,
                                          "options": opts, "keep_alive": 0})
    c_reply, r_reply = chat["message"]["content"].strip(), raw["response"].strip()
    print("Check with Ollama, temperature 0:")
    print(f"  messages with roles (chat API): {chat.get('prompt_eval_count')} prompt tokens -> {c_reply[:70]!r}...")
    print(f"  our stream as raw text:         {raw.get('prompt_eval_count')} prompt tokens -> {r_reply[:70]!r}...")
    same = chat.get("prompt_eval_count") == raw.get("prompt_eval_count") and c_reply == r_reply
    print("  same tokens, same reply: the roles arrived as marker tokens in one stream" if same else
          "  they differ: this stream only follows Gemma 3's format; other models use other markers")


def cmd_standin(a):
    body = capture_request(a.email_file, a.fixes, a.model)
    reply = stand_in_model(body["messages"])
    print("The stand-in model's raw reply (plain Python, NOT AI), before the app touches it:\n")
    for n, line in enumerate(reply.splitlines(), 1):
        print(f"  {n}| {line}")
    print("\nWhat the WEAK app (no fixes) does with each line:")
    for n, line in enumerate(reply.splitlines(), 1):
        m = support_bot.ACTION_LINE.match(line)
        if m:
            print(f"  {n}  ACTION line: the app runs create_ticket('{m.group(1)}', {m.group(2)}). Nobody asked for it.")
        elif "](" in line:
            print(f"  {n}  markdown link: shown to the agent as a clickable link to {line.split('](')[1].split('/')[2]}")
        elif support_bot.CANARY in line:
            print(f"  {n}  the system prompt's internal reference: shown to the agent")
        else:
            print(f"  {n}  summary text: shown to the agent")


def main(argv=None):
    p = argparse.ArgumentParser(description="Look at each SupportBot step on its own (M3 lab). Changes nothing.")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("request", cmd_request), ("send", cmd_send), ("stream", cmd_stream), ("standin", cmd_standin)):
        s = sub.add_parser(name)
        s.add_argument("email_file")
        s.add_argument("--fixes", default="none", help="none (default), all, or e.g. label,plan")
        s.add_argument("--model", default="gemma3:1b")
        if name == "stream":
            s.add_argument("--no-check", action="store_true", help="only print the stream, don't ask Ollama")
        s.set_defaults(fn=fn)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
