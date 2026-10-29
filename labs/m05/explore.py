"""
explore.py: look at each step of the helpdesk app on its own, before you attack it (M5 lab, "Understand the lab").

Nothing here changes the app. But `shell` (without --safe) really runs the command line it builds, like the
vulnerable app does, so only try harmless commands such as echo. Each command shows one thing that happens to a model's output after
the model has written it, in the order the app does it:

    python3 explore.py data                                   # 0. the fake data the app uses
    python3 explore.py plan "search my tickets for VPN"       # 1. the model's raw output: a JSON "plan"
    python3 explore.py page "search my tickets for <b>VPN</b>" # 2. the HTML the app builds, and how a browser reads it
    python3 explore.py markdown "See **this**: [guide](https://it.example/vpn)"
                                                              # 3. Markdown -> HTML, as chat apps do it
    python3 explore.py markdown --ollama "How do I reconnect to the office Wi-Fi?"
                                                              #    the same with a real model's raw answer (optional)
    python3 explore.py sql "VPN"                              # 4. the SQL text the app sends to the database
    python3 explore.py shell "vpn"                            # 5. the command the app hands to the shell

Add --safe to page, sql or shell to see what the fixed app does instead.
Fake data only. The optional --ollama flag talks only to Ollama on 127.0.0.1 (your own computer).
"""

import argparse
import html
import json
import logging
import re
import shlex
import sys
import urllib.error
import urllib.request
from html.parser import HTMLParser

import helpdesk_app as app

WHERE = {
    "answer": "the web page (HTML)",
    "search_term": "a database query (SQL)",
    "service": "a helper program (a shell command)",
    "filename": "a file name on disk (the challenge)",
}


# ------------------------------------------------------------------------------------------------------------
# How a browser reads HTML, explained with Python's own HTML parser. No browser runs here.
# ------------------------------------------------------------------------------------------------------------
class BrowserView(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.lines = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "img":
            self.lines.append(f"element <img>: fetches {a.get('src')!r} straight away, no click needed")
        elif tag == "a":
            self.lines.append(f"element <a>: a link to {a.get('href')!r}, opened only if someone clicks it")
        elif tag == "script":
            self.lines.append("element <script>: runs as JavaScript as soon as the page loads")
        else:
            what = {"b": "bold text", "strong": "bold text", "em": "slanted (italic) text", "p": "a paragraph", "code": "code-style text",
                    "li": "a list item", "ol": "a numbered list", "ul": "a bullet list",
                    "h1": "a heading", "h2": "a heading", "h3": "a heading"}.get(tag, "formatting")
            self.lines.append(f"element <{tag}>: {what}")
        for k, v in attrs:
            if k.startswith("on"):
                when = {"onerror": "if loading fails", "onload": "when it loads", "onclick": "on a click"}.get(k, k)
                self.lines.append(f"   attribute {k}: runs {v!r} as JavaScript {when}")

    def handle_data(self, data):
        if data.strip():
            self.lines.append(f"text: {data.strip()!r}")


def show_browser_view(page_html: str, compact: bool = False):
    v = BrowserView()
    v.feed(page_html)
    print("how a browser reads it (explained by Python's html.parser; no browser runs here):")
    if compact:  # a real model's answer can be long: count the elements instead of listing them
        tags = re.findall(r"^element <(\w+)>", "\n".join(v.lines), re.M)
        print("   elements: " + ", ".join(f"<{t}> x{tags.count(t)}" for t in dict.fromkeys(tags)))
        fetch = [ln for ln in v.lines if ln.startswith(("element <img>", "element <script>")) or "attribute on" in ln]
        for ln in fetch or ["nothing here is fetched or run: only text and formatting"]:
            print("   " + ln)
        return
    for ln in v.lines:
        print("   " + ln)


# ------------------------------------------------------------------------------------------------------------
# A tiny Markdown renderer, like the ones chat apps use (much simpler). Raw HTML passes through unchanged,
# as the CommonMark spec says it does.
# ------------------------------------------------------------------------------------------------------------
def md_inline(s: str) -> str:
    s = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)\)", r'<img src="\2" alt="\1">', s)
    s = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<![*\w])\*([^*\s][^*]*)\*(?!\*)", r"<em>\1</em>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s


def markdown_to_html(md: str) -> str:
    out, items, kind = [], [], None
    for line in md.strip().splitlines() + [""]:
        m = re.match(r"\s*(?:(\d+)\.|[*-])\s+(.*)", line)
        if m:
            kind = kind or ("ol" if m.group(1) else "ul")
            items.append(f"<li>{md_inline(m.group(2))}</li>")
            continue
        if items:
            out.append(f"<{kind}>" + "".join(items) + f"</{kind}>")
            items, kind = [], None
        h = re.match(r"(#{1,6})\s+(.*)", line)
        if h:
            out.append(f"<h{len(h.group(1))}>{md_inline(h.group(2))}</h{len(h.group(1))}>")
        elif line.strip():
            out.append(f"<p>{md_inline(line.strip())}</p>")
    return "\n".join(out)


def ollama_text(prompt: str, model: str) -> str:
    body = json.dumps({"model": model, "prompt": prompt, "stream": False,
                       "options": {"temperature": 0, "seed": 7, "num_predict": 120}}).encode()
    req = urllib.request.Request("http://127.0.0.1:11434/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            return json.load(r)["response"]
    except urllib.error.URLError as e:
        raise SystemExit(f"Could not reach Ollama on 127.0.0.1:11434 ({e}). Start it, then: ollama pull {model}")


# ------------------------------------------------------------------------------------------------------------
# The commands
# ------------------------------------------------------------------------------------------------------------
def cmd_data(a):
    print("the tickets table (lives in memory, rebuilt every time the app starts; all fake):")
    print(f"   {'id':<3} {'owner':<6} title")
    for t in app.TICKETS:
        print(f"   {t[0]:<3} {t[1]:<6} {t[2]}")
    print(f"\nsigned in as: {app.CURRENT_USER}   (set by the app, never by the model)")
    print("data/fake_secrets.env: fake keys the app must never show (nothing in it works anywhere)")
    print(f"helper program: tools/service_status.py knows: {', '.join(sorted(app.ALLOWED_SERVICES))}")


def cmd_plan(a):
    p = app.get_plan(a.question)
    print(f'question: "{a.question}"\n')
    print("the model's raw output (stand-in model, not AI): one JSON object")
    print("   " + json.dumps(p))
    print("\nwhere the app sends each field next:")
    for k, v in p.items():
        print(f"   {k:<12} {json.dumps(v):<38} -> {WHERE[k]}{'' if v else ' (empty: skipped)'}")


def cmd_page(a):
    p = app.get_plan(a.question)
    print(f"the model's answer (plain text):\n   {p['answer']}\n")
    page = (app.render_answer_safe if a.safe else app.render_answer_vulnerable)(p["answer"])
    print(f"the HTML the {'SAFE' if a.safe else 'vulnerable'} app puts in the page:\n   {page}\n")
    show_browser_view(page)


def cmd_markdown(a):
    if a.ollama:
        text = ollama_text(a.text, a.model)
        print(f"the real model's raw answer ({a.model} through Ollama, on this machine):")
    else:
        text = a.text
        print("the model's raw answer (Markdown):")
    for ln in text.strip().splitlines():
        print(("   " + ln).rstrip())
    page = markdown_to_html(text)
    print("\nthe HTML a chat app makes from it (this file's tiny Markdown renderer):")
    for ln in page.splitlines():
        print("   " + ln)
    print()
    show_browser_view(page, compact=a.ollama)


def cmd_sql(a):
    logging.basicConfig(level=logging.INFO, format="   app log: %(message)s", stream=sys.stdout)
    print(f"the model's search_term: {a.term!r}\n")
    print("the app sends this to the database:")
    try:
        rows = (app.search_tickets_safe if a.safe else app.search_tickets_vulnerable)(app.CURRENT_USER, a.term)
    except Exception as e:  # sqlite3.OperationalError for broken SQL
        print(f"\nthe database refused the query: {type(e).__name__}: {e}")
        return
    print(f"\nrows that came back ({len(rows)}):")
    for r in rows:
        print(f"   ticket {r[0]}  owner={r[1]:<5}  {r[2]}")


def cmd_shell(a):
    logging.basicConfig(level=logging.INFO, format="   app log: %(message)s", stream=sys.stdout)
    print(f"the model's service: {a.service!r}\n")
    if a.safe:
        print("the SAFE app checks the allow-list, then runs the helper with no shell:")
        print(f"   output: {app.service_status_safe(a.service)}")
        return
    cmd = f'"{sys.executable}" tools/service_status.py {a.service}'
    print(f"the app hands ONE string to the shell (/bin/sh):\n   {cmd}\n")
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|")
    commands, cur = [], []
    for tok in lex:
        if tok in (";", "&", "&&", "|", "||"):
            commands.append(cur); cur = []
        else:
            cur.append(tok)
    commands.append(cur)
    print("how the shell reads it (';' means: then run the next command):")
    for i, c in enumerate([c for c in commands if c], 1):
        print(f"   command {i}: program {c[0]}  arguments {c[1:]}")
    print("\nwhat came back:")
    for ln in app.service_status_vulnerable(a.service).splitlines():
        print("   " + ln)


def main(argv=None):
    p = argparse.ArgumentParser(description="Look at each step of the M5 helpdesk app on its own.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("data"); s.set_defaults(fn=cmd_data)
    s = sub.add_parser("plan"); s.add_argument("question"); s.set_defaults(fn=cmd_plan)
    s = sub.add_parser("page"); s.add_argument("question"); s.add_argument("--safe", action="store_true")
    s.set_defaults(fn=cmd_page)
    s = sub.add_parser("markdown"); s.add_argument("text")
    s.add_argument("--ollama", action="store_true", help="ask a real local model through Ollama for the text")
    s.add_argument("--model", default="gemma3:1b"); s.set_defaults(fn=cmd_markdown)
    s = sub.add_parser("sql"); s.add_argument("term"); s.add_argument("--safe", action="store_true")
    s.set_defaults(fn=cmd_sql)
    s = sub.add_parser("shell"); s.add_argument("service"); s.add_argument("--safe", action="store_true")
    s.set_defaults(fn=cmd_shell)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
