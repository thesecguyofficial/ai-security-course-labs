"""
helpdesk_app.py: a tiny IT-helpdesk web app with an AI assistant. Lab for lesson 5.6.

The assistant (a model) turns your question into a "plan" (see stand_in_model.py). The app then does three
things with the model's output, the same three things real AI apps do:

    1. shows the answer in a web page            (HTML)   -> risk: cross-site scripting (XSS)
    2. searches the tickets database with it     (SQL)    -> risk: SQL injection
    3. passes it to a helper program             (shell)  -> risk: command injection

Every one of these has two versions in this file:

    --mode vulnerable   trusts the model's output (what too many apps do)
    --mode safe         treats the model's output like any other untrusted input

Run it:
    python3 helpdesk_app.py                      # vulnerable mode, http://127.0.0.1:8055
    python3 helpdesk_app.py --mode safe          # the fixed version
    python3 helpdesk_app.py --backend ollama     # optional: a real local model instead of the stand-in

Safety: the web server only ever listens on 127.0.0.1 (your own computer). All data is fake. The only other
address this file can call is Ollama on 127.0.0.1:11434, and only with --backend ollama.
"""

import argparse
import html
import json
import logging
import os
import sqlite3
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import stand_in_model

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(LAB_DIR, "tools", "service_status.py")
EXPORT_DIR = os.path.join(LAB_DIR, "exports")
HOST = "127.0.0.1"                         # loopback only: nobody else on your network can reach the app
DEFAULT_PORT = 8055
OLLAMA_URL = "http://127.0.0.1:11434/v1/chat/completions"   # Ollama's OpenAI-compatible API (lesson 1.8)

# Who is signed in. In a real app this comes from the login session (lesson 5.4), NEVER from the model.
CURRENT_USER = "alice"

# The fixes use these two limits.
ALLOWED_SERVICES = {"vpn", "email", "printer", "wifi"}  # allow-list: the ONLY values the helper may receive
MAX_ANSWER_CHARS = 2000                                  # cap on how much model output we render (lesson 5.2)

log = logging.getLogger("helpdesk")


# ---------------------------------------------------------------------------------------------------------
# The fake database. Ticket 3 was opened by an outsider; its text contains an HTML payload.
# Tickets 4 and 5 belong to bob: alice must never see them.
# ---------------------------------------------------------------------------------------------------------
TICKETS = [
    (1, "alice", "VPN drops every hour", "Laptop VPN disconnects about once an hour."),
    (2, "alice", "Printer on floor 3 out of paper", "Printer shows error 41."),
    (3, "alice", "Password reset please",
     "Hi, please reset my password. "
     "<img src=x onerror=\"alert('Model output just ran as code in your browser')\">"),
    (4, "bob", "CONFIDENTIAL payroll export", "March payroll file is on the finance share (fake)."),
    (5, "bob", "CONFIDENTIAL laptop rebuild for the CFO", "Rebuild booked for Friday (fake)."),
]


def make_db() -> sqlite3.Connection:
    """Create the fake tickets database in memory (nothing is written to disk)."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE tickets (id INTEGER PRIMARY KEY, assignee TEXT, title TEXT, body TEXT)")
    db.executemany("INSERT INTO tickets VALUES (?, ?, ?, ?)", TICKETS)
    db.commit()
    return db


DB = make_db()


def latest_ticket_text(user: str) -> str:
    row = DB.execute("SELECT body FROM tickets WHERE assignee = ? ORDER BY id DESC LIMIT 1", (user,)).fetchone()
    return row[0] if row else ""


# ---------------------------------------------------------------------------------------------------------
# The model. Default: the deterministic stand-in (not AI). Optional: a real local model through Ollama.
# ---------------------------------------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "You are an IT helpdesk assistant. Reply ONLY with a JSON object with four string fields: "
    "answer (what to tell the user), search_term (words to search the user's tickets for, or empty), "
    "service (one service name to check the status of, or empty), filename (a file name to save a summary as, "
    "or empty). Copy the user's words exactly into the field they belong to."
)


def ollama_plan(question: str, ticket_text: str, model: str) -> dict:
    """Ask a real local model (Ollama) for the same plan. Optional; the lab does not need it."""
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"My latest ticket says: {ticket_text}\n\nMy question: {question}"},
        ],
        "temperature": 0,
        "seed": 7,
        "response_format": {"type": "json_object"},
    }).encode()
    req = urllib.request.Request(OLLAMA_URL, data=body, headers={"Content-Type": "application/json",
                                                                 "Authorization": "Bearer ollama"})
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            text = json.load(resp)["choices"][0]["message"]["content"]
    except urllib.error.URLError as e:
        raise SystemExit(f"Could not reach Ollama at {OLLAMA_URL} ({e}). "
                         f"Start Ollama (lesson 0.6) and run: ollama pull {model}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = {"answer": text}
    # Whatever the model sent, keep only the four fields we expect, as strings.
    return {k: str(data.get(k, "") or "") for k in ("answer", "search_term", "service", "filename")}


def get_plan(question: str, backend: str = "stand-in", model: str = "gemma3:1b") -> dict:
    ticket = latest_ticket_text(CURRENT_USER)
    if backend == "ollama":
        return ollama_plan(question, ticket, model)
    return stand_in_model.plan(question, ticket)


# ---------------------------------------------------------------------------------------------------------
# 1. HTML: showing the model's answer in a web page
# ---------------------------------------------------------------------------------------------------------
def render_answer_vulnerable(answer: str) -> str:
    # BAD: the model's text is pasted into the page as HTML. If it contains <img onerror=...> or <script>,
    # the browser runs it. Same kind of bug as CVE-2026-32626 (lesson 5.1).
    return f"<p class='answer'>{answer}</p>"


def render_answer_safe(answer: str) -> str:
    # GOOD: cap the length, then HTML-encode (& < > " ' become &amp; &lt; &gt; &quot; &#x27;).
    # The browser now SHOWS the characters instead of running them. This encoding is right for HTML text and
    # quoted attributes, which is where this answer goes. Inside <script>, a URL or CSS you'd need that context's
    # own encoding (OWASP XSS Prevention Cheat Sheet; OWASP LLM10:2026).
    answer = answer[:MAX_ANSWER_CHARS]
    return f"<p class='answer'>{html.escape(answer, quote=True)}</p>"


# ---------------------------------------------------------------------------------------------------------
# 2. SQL: searching the tickets table with the model's search term
# ---------------------------------------------------------------------------------------------------------
def search_tickets_vulnerable(user: str, term: str) -> list:
    # BAD: the model's text is glued into the SQL string, so it can change the query itself.
    sql = f"SELECT id, assignee, title FROM tickets WHERE assignee = '{user}' AND title LIKE '%{term}%'"
    log.info("SQL sent: %s", sql)
    return DB.execute(sql).fetchall()


def search_tickets_safe(user: str, term: str) -> list:
    # GOOD: a parameterised query. The SQL text is fixed; the values travel separately (the ? marks),
    # so the database always treats them as data, never as SQL.
    # Extra: escape LIKE's own wildcards (% and _) so the term is matched literally.
    like = "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    sql = "SELECT id, assignee, title FROM tickets WHERE assignee = ? AND title LIKE ? ESCAPE '\\'"
    log.info("SQL sent: %s  params=%r", sql, (user, like))
    # Defence in depth: while the search runs, SQLite refuses CREATE, DELETE, DROP, INSERT and UPDATE on this
    # connection. SQLite says query_only is "not truly read-only" (COMMIT and checkpoints still work), so in
    # production give the AI feature its own read-only database login instead.
    DB.execute("PRAGMA query_only = ON")
    try:
        return DB.execute(sql, (user, like)).fetchall()
    finally:
        DB.execute("PRAGMA query_only = OFF")


# ---------------------------------------------------------------------------------------------------------
# 3. Shell: passing the model's service name to a helper program
# ---------------------------------------------------------------------------------------------------------
def service_status_vulnerable(service: str) -> str:
    # BAD: one string handed to the system shell. Shell characters in the model's output (; & | $( ) `)
    # start extra commands. Same family of bug as CVE-2023-29374 and CVE-2024-5565 (lesson 5.1).
    cmd = f'"{sys.executable}" tools/service_status.py {service}'
    log.info("command run: %s", cmd)
    done = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=LAB_DIR, timeout=10)
    return (done.stdout + done.stderr).strip()


def run_contained(argv: list, timeout: float = 5, max_output: int = 2000) -> str:
    """Run a helper program with as little power as we can easily give it.

    - no shell: argv is a list, so ; & | are just characters inside one argument
    - an almost empty environment: the helper can't read our tokens or keys from environment variables
    - an empty temporary working folder: relative paths like data/fake_secrets.env lead nowhere
    - a timeout and an output cap: a stuck helper is killed, and a chatty one can't flood the page (the cap trims
      what we return; the output is still read into memory first, so it is not a memory limit)
    This is CONTAINMENT, not a full sandbox: the helper still runs as you. Real sandboxes add a container,
    a separate low-privilege user, no network and syscall filtering (lesson 7.5).
    """
    env = {}
    if os.name == "nt":                     # Windows needs SYSTEMROOT for Python to start at all
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
    with tempfile.TemporaryDirectory() as empty_dir:
        try:
            done = subprocess.run(argv, shell=False, capture_output=True, text=True,
                                  cwd=empty_dir, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return f"helper timed out after {timeout}s and was stopped"
    return (done.stdout + done.stderr).strip()[:max_output]


def service_status_safe(service: str) -> str:
    # GOOD, step 1: allow-list. Only four exact values may reach the helper; everything else is refused
    # and logged, which is also how you SPOT an attack attempt.
    name = service.strip().lower()
    if name not in ALLOWED_SERVICES:
        log.warning("BLOCKED service name from model: %r", service)
        return f"Sorry, I can only check: {', '.join(sorted(ALLOWED_SERVICES))}."
    # GOOD, step 2: run it contained: absolute paths, isolated Python (-I), no shell.
    return run_contained([sys.executable, "-I", HELPER, name])


# ---------------------------------------------------------------------------------------------------------
# Challenge (make challenge): the model also chooses a FILE NAME to save a summary under.
# ---------------------------------------------------------------------------------------------------------
def safe_export_path(filename: str) -> str:
    """Return the full path where a summary called `filename` should be saved.

    YOUR TURN: right now this trusts the model's file name, so '../../somewhere' escapes the exports folder
    (path traversal, one of OWASP's improper-output-handling examples). Make it:
      - raise ValueError for any name that would land outside EXPORT_DIR (hint: os.path.realpath, then compare)
      - raise ValueError for empty names and absolute paths
      - still allow ordinary names like 'vpn-notes'
    `make challenge` fails until you do. No solution is included.
    """
    return os.path.join(EXPORT_DIR, filename + ".txt")


def export_summary(filename: str, text: str) -> str:
    path = safe_export_path(filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text[:MAX_ANSWER_CHARS])
    log.info("summary saved to %s", path)
    return path


# ---------------------------------------------------------------------------------------------------------
# Putting it together
# ---------------------------------------------------------------------------------------------------------
def answer_question(question: str, safe: bool, backend: str = "stand-in", model: str = "gemma3:1b") -> dict:
    """Ask the model, then act on its plan. Returns everything the page needs (and the tests check)."""
    p = get_plan(question, backend, model)
    out = {"plan": p, "rows": None, "status": None, "saved": None}
    out["answer_html"] = (render_answer_safe if safe else render_answer_vulnerable)(p["answer"])
    if p["search_term"]:
        out["rows"] = (search_tickets_safe if safe else search_tickets_vulnerable)(CURRENT_USER, p["search_term"])
    if p["service"]:
        out["status"] = (service_status_safe if safe else service_status_vulnerable)(p["service"])
    if p["filename"]:
        try:
            out["saved"] = export_summary(p["filename"], latest_ticket_text(CURRENT_USER))
        except ValueError as e:
            log.warning("BLOCKED file name from model: %r (%s)", p["filename"], e)
            out["saved"] = "refused"
    return out


def render_page(result: dict, safe: bool, question: str = "") -> str:
    enc = html.escape if safe else (lambda s, quote=True: s)   # vulnerable mode doesn't encode anything
    parts = [result["answer_html"]] if result else []
    if result and result["rows"] is not None:
        rows = "".join(f"<tr><td>{r[0]}</td><td>{enc(str(r[1]))}</td><td>{enc(str(r[2]))}</td></tr>"
                       for r in result["rows"])
        parts.append(f"<table><tr><th>#</th><th>Assignee</th><th>Title</th></tr>{rows}</table>")
    if result and result["status"] is not None:
        parts.append(f"<pre>{enc(result['status'])}</pre>")
    if result and result["saved"]:
        parts.append(f"<p>Saved: {enc(result['saved'])}</p>")
    mode = "SAFE" if safe else "VULNERABLE"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>TSG Helpdesk (M5 lab, {mode})</title>
<style>body{{font-family:sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse}}td,th{{border:1px solid #999;padding:.3rem .6rem}}
.answer{{background:#f4f4f4;padding:.8rem}}</style></head>
<body><h1>TSG Helpdesk assistant</h1>
<p>Mode: <b>{mode}</b> &middot; signed in as <b>{CURRENT_USER}</b> (fake) &middot; model: stand-in or local only</p>
<form method="post" action="/ask"><input name="q" size="60" value="{html.escape(question)}" autofocus>
<button>Ask</button></form>
<p>Try: <i>summarise my latest ticket</i> &middot; <i>search my tickets for VPN</i> &middot;
<i>check the status of vpn</i></p>
{''.join(parts)}
</body></html>"""


# Security headers for SAFE mode. The Content-Security-Policy (CSP) is a second layer: even if some
# model output slipped through un-encoded, the browser is told not to run any script on this page.
SAFE_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
}


def make_handler(safe: bool, backend: str, model: str):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, page: str):
            body = page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if safe:
                for k, v in SAFE_HEADERS.items():
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _answer(self, q: str):
            result = answer_question(q, safe, backend, model) if q else None
            self._send(render_page(result, safe, q))

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(url.query).get("q", [""])[0] if url.path == "/ask" else ""
            self._answer(q)

        def do_POST(self):
            length = min(int(self.headers.get("Content-Length", 0)), 4096)   # cap request size
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            self._answer(form.get("q", [""])[0])

        def log_message(self, fmt, *args):
            log.debug("http: " + fmt, *args)
    return Handler


def make_server(safe: bool, port: int = DEFAULT_PORT, host: str = HOST, backend: str = "stand-in",
                model: str = "gemma3:1b") -> HTTPServer:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("This lab app only listens on 127.0.0.1. Refusing to expose it to the network.")
    return HTTPServer((host, port), make_handler(safe, backend, model))


def main():
    ap = argparse.ArgumentParser(description="M5 lab: a helpdesk app that acts on model output.")
    ap.add_argument("--mode", choices=["vulnerable", "safe"], default="vulnerable")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--backend", choices=["stand-in", "ollama"], default="stand-in",
                    help="stand-in = deterministic stand_in_model.py (default, not AI); ollama = a real local model")
    ap.add_argument("--model", default="gemma3:1b", help="Ollama model name (only with --backend ollama)")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    srv = make_server(a.mode == "safe", a.port, HOST, a.backend, a.model)
    print(f"TSG Helpdesk ({a.mode.upper()} mode, model: {a.backend}) on http://{HOST}:{a.port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
