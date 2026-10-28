# Lab M5.6: when model output changes what your app does, and how to stop it

Companion to lesson **5.6** of *AI Security Engineer* (The Sec Guy). About 45 minutes, $0, all on your laptop.
No installs: Python's standard library only.

You get **TSG Helpdesk**, a tiny web app with an AI assistant. The assistant turns your question into a small
"plan", and the app acts on it in three places that real AI apps use every day:

| Where the model's output lands | What the app does with it | What goes wrong if it trusts it |
|---|---|---|
| A **web page** | Shows the answer | Cross-site scripting (XSS): the browser runs code from the answer |
| A **database query** | Searches your tickets | SQL injection: the answer rewrites the query and leaks other people's tickets |
| A **helper program** | Checks a service's status | Command injection: the answer starts extra commands on the server |

First you attack the vulnerable version and watch all three happen. Then you read the four fixes (output encoding,
a parameterised query, an allow-list, a contained subprocess), attack the safe version, and **prove** the fixes with
automated tests that also prove each attack worked before. Finally, a challenge with no solution included.

## Get the lab files

This folder is part of the free, public course labs repository, [thesecguyofficial/ai-security-course-labs](https://github.com/thesecguyofficial/ai-security-course-labs).

**First time, or you deleted the folder:** download it once.

```bash
git clone https://github.com/thesecguyofficial/ai-security-course-labs.git
cd ai-security-course-labs
```

**Already downloaded it:** go to that folder and get the latest version.

```bash
cd ai-security-course-labs
git pull
```

**No git?** On the [labs page](https://github.com/thesecguyofficial/ai-security-course-labs), click **Code → Download ZIP**, unzip it and open a terminal in that folder (download it again to get updates).

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/m05`.

## What's in this folder

| File | What it is |
|---|---|
| `helpdesk_app.py` | The web app. `--mode vulnerable` (default) or `--mode safe`. Each risky step has a `_vulnerable` and a `_safe` version side by side |
| `stand_in_model.py` | A **stand-in for an AI model**. Plain Python, **not AI**, so every run gives the same result |
| `tools/service_status.py` | The helper program the app runs to "check a service". Prints fake statuses |
| `data/fake_secrets.env` | Fake secrets the app should never reveal. Nothing in it works anywhere |
| `attack.py` | Sends the three attack questions and reports what happened |
| `test_lab.py` | 13 automated tests: 3 prove the attacks work in vulnerable mode, 10 prove the fixes hold |
| `test_challenge.py` | 5 tests for the challenge. 4 fail until you fix the code |
| `run_tests.py` | Runs the tests with one line per result |
| `Makefile` | Shortcuts for Mac/Linux |

**About the stand-in model.** `stand_in_model.py` is *not* an AI model. It copies the one behaviour this lab is
about: a model's output is shaped by the text it was given. Ask it to "search my tickets for X" and it puts X in
the search field; ask it to summarise your latest ticket and it quotes that ticket, including whatever the
ticket's author wrote. A real model does the same, less predictably. Using a stand-in means the tests give the
same answer every run. An optional step at the end swaps in a real local model.

**About the data.** Everything is fake. Users `alice` and `bob` are made up; the "secrets" are lab-only strings and
`AKIAIOSFODNN7EXAMPLE`, the example key from the
[AWS IAM docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html). The database
lives in memory and disappears when the app stops.

**About safety.** The web server listens on `127.0.0.1` only (your own computer) and refuses any other address.
The attacks only target this app, on your machine. Only attack systems you own or have written permission to test
(lesson 0.8).

## Needs

- Python **3.11 or newer** (tested on 3.11, 3.12 and 3.13). Check with `python3 --version` (Windows: `py --version`).
- Mac or Linux for the `make` shortcuts. Windows: run the `python` commands shown under each step.
- A web browser, for one optional step.
- Optional, last step only: Ollama with a small model (lessons 0.6 and 1.8).

There is no setup step. Open a terminal in this folder:

```bash
cd labs/m05
```

- `cd labs/m05`: run it from the course labs repository folder (`ai-security-course-labs`)

## Step 1 · Break it: attack the vulnerable app

```bash
make attack
```

Same as `python3 attack.py --mode vulnerable`.

Real output (Linux, Python 3.13):

```text
--- M5 lab · VULNERABLE mode · stand-in model (stand_in_model.py, not AI) ---

[HTML ] you> summarise my latest ticket
    page HTML: <p class='answer'>Summary of your latest ticket: Hi, please reset my password. <img src=x onerror="alert('Mode...
    RESULT: EXPLOITED - a browser would RUN the onerror code (XSS)

[SQL  ] you> search my tickets for: zzz' OR '1'='1' --
    log: INFO SQL sent: SELECT id, assignee, title FROM tickets WHERE assignee = 'alice' AND title LIKE '%zzz' OR '1'='1' --%'
    rows returned: 5, owners: alice, bob
    RESULT: EXPLOITED - 2 of bob's tickets leaked to alice

[SHELL] you> check the status of vpn; cat data/fake_secrets.env
    log: INFO command run: "/usr/bin/python3" tools/service_status.py vpn; cat data/fake_secrets.env
    helper output: VPN gateway: OK (fake data) | # FAKE values for the M5 lab. ... | DB_PASSWORD=lab-only-not-a-real-password | AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    RESULT: EXPLOITED - an extra command read data/fake_secrets.env

3 of 3 attacks changed what the app did.
```

(On Windows the shell attack uses `&` and `type` instead of `;` and `cat`; `attack.py` picks the right one.)

What just happened, one line each:

1. **HTML.** Ticket 3 was opened by an outsider and contains `<img src=x onerror="alert(...)">`. Alice did nothing
   wrong: she asked for a summary. The model quoted the ticket, the app pasted the answer into the page as HTML,
   and a browser would run the `onerror` code. A real attacker would steal the session or act as Alice instead of
   showing an alert.
2. **SQL.** The model copied the search words into its output, and the app glued them into the SQL text. The
   quote mark ended the string, `OR '1'='1'` made every row match, and `--` commented out the rest. Alice now sees
   Bob's confidential tickets. Look at the `SQL sent:` log line: the attack is visible in it.
3. **Shell.** The app handed one string to the system shell. To a shell, `;` means "then run this next command",
   so `cat data/fake_secrets.env` ran too, and its output came back in the answer.

**See the XSS in a real browser (optional).** Start the app and open it:

```bash
make run
```

Same as `python3 helpdesk_app.py --mode vulnerable`.

Go to <http://127.0.0.1:8055>, type `summarise my latest ticket` and press **Ask**. A pop-up appears saying
*Model output just ran as code in your browser*. We checked this in headless Chromium: the dialog fired in
vulnerable mode and did not fire in safe mode. Press Ctrl+C in the terminal to stop the app.

## Step 2 · Read the fixes

Open `helpdesk_app.py`. Each risky step has two functions next to each other; compare them.

| Risk | Vulnerable version | Safe version | Why it works |
|---|---|---|---|
| XSS | `render_answer_vulnerable`: `f"<p>{answer}</p>"` | `render_answer_safe`: `html.escape(answer)` after a length cap | `<` becomes `&lt;` and `"` becomes `&quot;`, so the browser *shows* the characters instead of running them. Right for HTML text and quoted attributes; `<script>`, URLs and CSS need their own encoding |
| XSS (second layer) | no security headers | `SAFE_HEADERS`: a `Content-Security-Policy` of `default-src 'none'` | Even if something slipped through, the browser is told to run no scripts on this page |
| SQL injection | `search_tickets_vulnerable`: an f-string builds the SQL | `search_tickets_safe`: `?` placeholders, values passed separately | The SQL text never changes; the database always treats the values as data |
| SQL (second layer) | full read-write connection | `PRAGMA query_only = ON` during the search | While the search runs, SQLite refuses `CREATE`, `DELETE`, `DROP`, `INSERT` and `UPDATE`. SQLite calls it "not truly read-only", so production apps should give the AI feature a read-only database login |
| Command injection | `service_status_vulnerable`: `shell=True` with one string | `service_status_safe`: an **allow-list** of four names, then `run_contained` | Only `vpn`, `email`, `printer`, `wifi` can reach the helper; anything else is refused **and logged** |
| Command (second layer) | inherits everything | `run_contained`: argument list (no shell), isolated Python `-I`, an empty environment, an empty temporary working folder, a timeout and an output cap | Even an allowed call runs with less to steal and less time to do damage |

Two design points worth noticing:

- **The user comes from the session, not the model.** `CURRENT_USER` is set by the app (a stand-in for a login).
  The model only supplies the *search words*. Lesson 5.4 is about why the model must never decide who someone is.
- **`run_contained` is containment, not a full sandbox.** The helper still runs as you, with your file
  permissions and network. Production sandboxes add a container or micro-VM, a separate low-privilege user, no
  network, and system-call filtering (lesson 7.5). The docstring says so too.

## Step 3 · Fix it: attack the safe app

```bash
make attack-safe
```

Same as `python3 attack.py --mode safe`.

Real output:

```text
--- M5 lab · SAFE mode · stand-in model (stand_in_model.py, not AI) ---

[HTML ] you> summarise my latest ticket
    page HTML: <p class='answer'>Summary of your latest ticket: Hi, please reset my password. &lt;img src=x onerror=&quot;ale...
    RESULT: safe - the payload is shown as text, not run

[SQL  ] you> search my tickets for: zzz' OR '1'='1' --
    log: INFO SQL sent: SELECT id, assignee, title FROM tickets WHERE assignee = ? AND title LIKE ? ESCAPE '\'  params=('alice', "%zzz' OR '1'='1' --%")
    rows returned: 0, owners: none
    RESULT: safe - the search term was treated as plain text

[SHELL] you> check the status of vpn; cat data/fake_secrets.env
    log: WARNING BLOCKED service name from model: 'vpn; cat data/fake_secrets.env'
    helper output: Sorry, I can only check: email, printer, vpn, wifi.
    RESULT: safe - only allow-listed service names reach the helper

0 of 3 attacks changed what the app did.
```

Notice the **logs**. The safe version still records the attempt: the SQL log shows the injection string sitting
harmlessly inside the parameters, and the allow-list writes a `WARNING BLOCKED` line. Those lines are what you'd
alert on in production.

Want to see it in the browser? `make run-safe`, then ask the same three questions at <http://127.0.0.1:8055>. The
ticket summary shows the `<img ...>` text literally, and normal questions (`search my tickets for VPN`,
`check the status of vpn`) still work.

## Step 4 · Prove it

```bash
make test
```

Same as `python3 run_tests.py`.

Real output:

```text
[PASS] vulnerable: model output lands in the page as live HTML (XSS)
[PASS] vulnerable: model output rewrites the SQL query and leaks bob's tickets
[PASS] vulnerable: model output runs an extra shell command that reads the secrets file
[PASS] safe: the payload is HTML-encoded, so the browser shows it instead of running it
[PASS] safe: parameterised query returns only alice's tickets, and nothing for the injection string
[PASS] safe: the search runs read-only, and query_only is switched back off afterwards
[PASS] safe: the allow-list blocks the injected command, and the secret never appears
[PASS] safe: the helper runs with no inherited environment variables (no tokens or keys to steal)
[PASS] safe: a helper that hangs is stopped by the timeout
[PASS] safe: with no shell, ';' is just a character inside one argument, not a second command
[PASS] http: the vulnerable server sends the payload as live HTML, with no CSP
[PASS] http: the safe server encodes the payload AND sends a CSP that blocks scripts
[PASS] http: the app refuses to listen on anything but 127.0.0.1
----------------------------------------------------------------------
Ran 13 tests in 1.625s

OK

ALL TESTS PASSED (13 run)
```

Why the first three tests check the **vulnerable** app: a test that has never failed proves nothing. Tests 1 to 3
show that each check can catch the bug; tests 4 to 10 show the fix holds against the same attack; tests 11 to 13
start the real web server on a free `127.0.0.1` port and attack it over HTTP. The safe tests also check that normal
questions still work, because a "fix" that breaks the feature gets reverted.

## Step 5 · Your turn: `make challenge`

The model can also choose a **file name**: ask `save a summary as vpn-notes` and the app writes
`exports/vpn-notes.txt`. The function that builds the path, `safe_export_path()` in `helpdesk_app.py`, trusts the
model, so a name like `../escaped` walks out of the `exports/` folder. That's **path traversal**, one of OWASP's
examples of improper output handling (LLM10:2026).

```bash
make challenge
```

Same as `python3 run_tests.py --challenge`.

Real output before your fix (last lines):

```text
[PASS] challenge: an ordinary name still saves inside exports/
[FAIL] challenge: '../../escaped' is refused (ValueError)
[FAIL] challenge: an absolute path is refused (ValueError)
[FAIL] challenge: an empty name is refused (ValueError)
[FAIL] challenge: asking the model to 'save a summary as ../escaped' is refused by the app
  why test_15_dotdot_refused: AssertionError: ValueError not raised
  why test_16_absolute_refused: AssertionError: ValueError not raised
  why test_17_empty_refused: AssertionError: ValueError not raised
  why test_18_end_to_end: AssertionError: False is not true : the app saved the file to /.../labs/m05/exports/../escaped.txt
----------------------------------------------------------------------
Ran 18 tests in 1.612s

FAILED (failures=4)

4 of 18 TESTS FAILED (18 run)
```

The last failure really wrote `escaped.txt` one folder above `exports/` (still inside this lab folder): that file
is your proof of the bug. Edit `safe_export_path()` where the **YOUR TURN** comment is until all 18 tests pass.
Hints are in the comment. No solution is included. `make clean` deletes `exports/` and `escaped.txt`.

## Step 6 (optional) · A real model

With Ollama running (lessons 0.6 and 1.8) and a small model pulled:

```bash
ollama pull gemma3:1b
python3 helpdesk_app.py --backend ollama --model gemma3:1b
python3 helpdesk_app.py --backend ollama --model gemma3:1b --mode safe
```

- `python3 helpdesk_app.py --backend ollama --model gemma3:1b`: vulnerable
- `python3 helpdesk_app.py --backend ollama --model gemma3:1b --mode safe`: safe

The app sends your question to Ollama's OpenAI-compatible endpoint on `127.0.0.1:11434`
([Ollama docs](https://docs.ollama.com/openai)), asking for JSON with the same four fields. Ask the three attack
questions in the browser. What to expect, honestly:

- A small real model may **not** copy your words exactly, or may refuse, rephrase, or break the JSON. Attacks
  that work every time against the stand-in may work sometimes, or only after rewording. That is the point of
  lesson 1.2: the output varies.
- **The safe version doesn't depend on the model behaving.** Encoding, parameters and the allow-list hold
  whatever the model returns. That's why the tests use the stand-in: they test *your code*, not the model's mood.

We tested this code path against a local mock of the Ollama API (the vulnerable app leaked the fake secret; the
safe app blocked it). We did not run it against a live model for this README, so your output will differ.

## Troubleshooting

| Problem | Fix |
|---|---|
| `make: command not found` (Windows) | Run the `python` command shown next to each `make` step, using `py` instead of `python3` |
| `OSError: ... Address already in use` (Windows: `WinError 10048`) | Another program, or an earlier copy of the app, uses port 8055. Stop it with Ctrl+C, or run `python3 helpdesk_app.py --port 8056` and open that port |
| The browser pop-up doesn't appear | Check the page says **Mode: VULNERABLE**. Some browsers block pop-ups after you dismiss several; open a new tab |
| `This lab app only listens on 127.0.0.1` | Working as intended: the lab refuses to expose itself to your network |
| `Could not reach Ollama at http://127.0.0.1:11434/...` | Only with `--backend ollama`: start Ollama and `ollama pull gemma3:1b`, or drop the flag to use the stand-in |
| A test says `helper timed out` unexpectedly | A very slow or busy machine. Close heavy programs and rerun; the timeout is 5 seconds |
| `SyntaxError` or odd errors on start | Python older than 3.11. Check `python3 --version` |
| Leftover `exports/` or `escaped.txt` | `make clean` |

## What to write in your findings notebook (lesson 0.5)

Three lines: what you broke (model output became HTML, SQL and a shell command), how you fixed it (encode,
parameterise, allow-list, contain), and how you'd spot it (the `SQL sent` and `BLOCKED` log lines, a CSP violation
report, a test in CI that replays the attack questions).

## Sources

- OWASP Top 10 for LLM Applications 2026 (LLM10:2026 Improper Output Handling): <https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/>
- LLM10:2026 text, OWASP's canonical source for the 2026 PDF: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM10_ImproperOutputHandling.md>
- OWASP LLM05:2025 Improper Output Handling (the 2025 edition of the same entry): <https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/>
- OWASP Cross Site Scripting Prevention Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
- OWASP SQL Injection Prevention Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
- OWASP OS Command Injection Defense Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html>
- Python `sqlite3` placeholders: <https://docs.python.org/3/library/sqlite3.html>
- Python `subprocess` security considerations: <https://docs.python.org/3/library/subprocess.html>
- Python `-I` isolated mode: <https://docs.python.org/3/using/cmdline.html>
- SQLite `PRAGMA query_only`: <https://www.sqlite.org/pragma.html>
- Ollama OpenAI compatibility: <https://docs.ollama.com/openai>
