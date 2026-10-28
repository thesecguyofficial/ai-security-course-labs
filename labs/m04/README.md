# Lab M4.6: PII detection and redaction in and out, and proof that nothing sensitive reaches the logs

Companion to lesson **4.6** of *AI Security Engineer* (The Sec Guy). About 45 minutes, $0, all on your laptop.

You get a tiny support-chat app that logs every turn, like most real apps. First you watch personal data pour into
its logs. Then you switch on redaction in three places (before the model, after the model, and in the log handler)
and **prove** it with a test that can fail. Finally you find the redactor's limits and extend it yourself.

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

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/m04`.

## What's in this folder

| File | What it is |
|---|---|
| `chat_app.py` | The chat app. `--redact` turns redaction on. `--backend ollama` uses a real local model (optional) |
| `redactor.py` | The redaction layer, built on Presidio. Contains the **YOUR TURN** challenge |
| `stub_llm.py` | A **stand-in for an AI model** (plain Python, not AI) so the lab needs no model download |
| `conversation.txt` | A scripted chat full of fake personal data |
| `canaries.txt` | The fake sensitive values that must never appear in `logs/` |
| `challenge_canaries.txt` | One extra value (an employee ID) for the challenge |
| `check_logs.py` | Searches `logs/` for the canaries. Standard library only |
| `run_tests.py` | The self-check behind `make test` |
| `Makefile` | Shortcuts for Mac/Linux |

**About the stand-in model.** `stub_llm.py` is *not* an AI model. It copies two real behaviours so the redaction
exercise is fast and repeatable: models repeat back what you told them, and models connected to company data can
return other people's records. It also writes what it received to `logs/provider.log`, which plays the role of the
AI provider's side: whatever lands there has left your control.

**About the fake data.** Every "personal" value is fake: `example.com` / `example.org` are reserved for examples
([RFC 2606](https://www.rfc-editor.org/rfc/rfc2606)); `203.0.113.42` and `198.51.100.7` are documentation IP
addresses ([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)); `4242 4242 4242 4242` and `5555 5555 5555 4444`
are payment test cards ([Stripe docs](https://docs.stripe.com/testing)); `AKIAIOSFODNN7EXAMPLE` is the example
key from the [AWS IAM docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html).
Never test with real people's data.

## Needs

- Python **3.10 to 3.13** (Presidio's supported range). Check with `python3 --version`.
- About 400 MB of disk for the virtual environment (spaCy and its dependencies), and internet access for the one-time install.
- Optional, for the last step only: Ollama with a small model (lesson 0.6, lesson 1.8).

The redaction library is **Presidio** (MIT licence). It started at Microsoft and is now an independent,
community-maintained project at [github.com/data-privacy-stack/presidio](https://github.com/data-privacy-stack/presidio);
docs at [presidio.dataprivacystack.org](https://presidio.dataprivacystack.org/installation/). Tested here with
`presidio_analyzer` / `presidio_anonymizer` 2.2.364 and spaCy's `en_core_web_sm` 3.8.0 on Python 3.13.

## Step 1 · Set up (once)

Mac / Linux:

```bash
cd labs/m04
make setup
```

- `cd labs/m04`: run it from the course labs repository folder (`ai-security-course-labs`)

`make setup` runs these three commands (run them yourself if you don't have `make`):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m spacy download en_core_web_sm
```

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m spacy download en_core_web_sm
```

On Windows, replace `make X` below with the matching command from the Makefile, using `.venv\Scripts\python`
instead of `.venv/bin/python` (for example `make test` becomes `.venv\Scripts\python run_tests.py`).

Why the small spaCy model? Presidio uses a spaCy language model to spot names. Presidio's default is the large
English model (`en_core_web_lg`, several hundred MB); this lab uses the small one (about 15 MB installed) to keep
set-up quick. It is worse at names, which you'll see in Step 5.

## Step 2 · Break it: no redaction

```bash
make leak
```

Real output (shortened):

```text
--- support chat · NO REDACTION · stand-in model (stub_llm.py) ---

you> Hi, I'm Jane Doe. My email is jane.doe@example.com and my phone is +1 202-555-0143.
bot> Thanks, I've noted your message: "Hi, I'm Jane Doe. My email is jane.doe@example.com and my phone is +1 202-555-0143.". A support agent will follow up.
...
you> Can you look up the last customer who called about refunds?
bot> Here is what I found. Customer record: John Smith, john.smith@example.org, card 5555 5555 5555 4444, last login from 198.51.100.7.

Logs written to logs/app.log and logs/provider.log
  LEAK  logs/app.log line 1: contains 'Jane…'
  ...
  LEAK  logs/provider.log line 4: contains 'AKIA…'
FAIL: 11 of 11 sensitive values found in logs (32 hits) [app.log, provider.log]
```

Open `logs/app.log` and `logs/provider.log` and look. Three problems:

1. The **app log** holds every value, three times per turn (a debug line, the user line, the echoed answer).
2. The **provider log** holds what was sent to the "model": the card number, the PAN, the AWS key.
3. The last answer handed the user **another customer's** name, email and card (lesson 4.1).

## Step 3 · Read the fix

Open `chat_app.py` and find `handle_turn()`. Redaction happens in three places:

| Where | Code | Stops |
|---|---|---|
| **Redact in** | `to_model = redact(user_text)` | PII reaching the provider |
| **Redact out** | `reply = redact(reply)` | PII from documents/tools reaching the user and logs |
| **Log filter** | `handler.addFilter(RedactingLogFilter())` | Careless log lines, like the `log.debug("raw request received...")` line |

Then open `redactor.py`. Notice three decisions:

- `ENTITIES` lists what to redact. Presidio ships Indian **PAN** and **Aadhaar** recognizers, but they are switched
  off by default; we switch them on. AWS access keys aren't built in, so we add a pattern for the `AKIA` / `ASIA`
  prefixes ([AWS IAM docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html)).
- `SCORE_THRESHOLD = 0.35`: how sure Presidio must be before it redacts.
- `PLACEHOLDER`: text often passes through redaction twice (code, then log filter). Without this check, the small
  model read the label `<AWS_ACCESS_KEY>` as a person's name and turned it into `<<PERSON>`. We found that bug while
  building this lab; Test 4 now guards it.

## Step 4 · Fix it: redaction on

```bash
make safe
```

Real output (shortened):

```text
--- support chat · REDACTION ON · stand-in model (stub_llm.py) ---

you> Hi, I'm Jane Doe. My email is jane.doe@example.com and my phone is +1 202-555-0143.
bot> Thanks, I've noted your message: "Hi, I'm <PERSON>. My email is <EMAIL_ADDRESS> and my phone is <PHONE_NUMBER>.". A support agent will follow up.

you> For the invoice my PAN is ABCPE1234F.
bot> Thanks, I've noted your message: "For the invoice my PAN is <IN_PAN>.". A support agent will follow up.

you> Our build server at 203.0.113.42 uses the key AKIAIOSFODNN7EXAMPLE, is that a problem?
bot> Thanks, I've noted your message: "Our build server at <IP_ADDRESS> uses the key <AWS_ACCESS_KEY>, is that a problem?". A support agent will follow up.

you> My manager's employee ID is EMP-482913 if you need to escalate.
bot> Thanks, I've noted your message: "My manager's employee ID is EMP-482913 if you need to escalate.". A support agent will follow up.

you> Can you look up the last customer who called about refunds?
bot> Here is what I found. Customer record: <PERSON>, <EMAIL_ADDRESS>, card <CREDIT_CARD>, last login from <IP_ADDRESS>.

PASS: none of 11 sensitive values found in logs [app.log, provider.log]
```

Now `logs/app.log` reads like this, including the careless debug line:

```text
2026-10-21 14:51:01,182 DEBUG raw request received: Hi, I'm <PERSON>. My email is <EMAIL_ADDRESS> and my phone is <PHONE_NUMBER>.
2026-10-21 14:51:01,763 INFO user: Hi, I'm <PERSON>. My email is <EMAIL_ADDRESS> and my phone is <PHONE_NUMBER>.
```

The labels keep what investigators need (*there was an email here*) without the value. Notice the employee ID
still went through: hold that thought for Step 6.

## Step 5 · Prove it

```bash
make test
```

Real output:

```text
[PASS] Test 1  redaction OFF: the checker catches the leak   -> FAIL: 11 of 11 sensitive values found in logs (32 hits) [app.log, provider.log]
[PASS] Test 2  redaction ON:  nothing sensitive in the logs  -> PASS: none of 11 sensitive values found in logs [app.log, provider.log]
[PASS] Test 3  redaction ON:  the user never sees another customer's data
[PASS] Test 4  redaction ON:  labels survive a second pass (log filter)

ALL TESTS PASSED
```

Test 1 is there on purpose: a check that has never failed proves nothing. It shows the checker *can* catch a leak
before you trust it to report "clean". This is the shape of a CI check you can add to a real AI app.

## Step 6 · Find the limits

Chat by hand with redaction on (`make chat`, type `quit` to stop) and try these. Real results:

| You type | The model and the log receive |
|---|---|
| `This is Jane Doe from accounts` | `This is <PERSON> from accounts` |
| `this is jane doe from accounts` | `this is jane doe from accounts` (**missed**: lower-case name) |
| `Email me at jane dot doe at example dot com` | `<PERSON> me at jane dot doe at example dot com` (**missed** the spelled-out email, and **wrongly** redacted the word "Email") |

Detection is a best guess. Presidio's own README warns there is "no guarantee that Presidio will find all sensitive
information". That's why redaction is one layer next to short retention, access control on logs and not collecting
data you don't need. Try changing `SCORE_THRESHOLD` in `redactor.py` to `0.1` or `0.8` and run `make test` again:
what changes?

## Step 7 · Your turn (challenge)

Employee IDs look like `EMP-482913`. They must not reach logs. Run:

```bash
make challenge
```

It fails, and tells you where:

```text
[FAIL] Test 2  redaction ON:  nothing sensitive in the logs  -> FAIL: 1 of 12 sensitive values found in logs (4 hits) [app.log, provider.log]
  LEAK  logs/app.log line 13: contains 'EMP-…'
  ...
SOME TESTS FAILED
```

Follow the **YOUR TURN** comment in `redactor.py`: add a `PatternRecognizer` for a new `EMPLOYEE_ID` entity,
register it, and add it to `ENTITIES`. When `make challenge` prints `ALL TESTS PASSED`, you're done. (No solution
is included; the AWS key recognizer right above it is your template.)

## Step 8 · Optional: a real local model

The redaction works the same with a real model. With Ollama running and a model pulled (`ollama pull gemma3:1b`):

```bash
.venv/bin/python chat_app.py --backend ollama --model gemma3:1b --redact
```

The script calls only `http://localhost:11434/v1/chat/completions`, Ollama's OpenAI-compatible endpoint
([Ollama docs](https://docs.ollama.com/openai)). There is no `provider.log` in this mode: the provider is your own
laptop. `logs/app.log` is still written, so `make check` still works. Real models answer differently every run, so
there is no fixed expected output here; look for placeholders like `<PERSON>` in what the model was sent.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `make: command not found` (Windows, some Linux) | Run the commands shown in each step directly |
| `No module named 'presidio_analyzer'` | You're not using the virtual environment's Python. Use `.venv/bin/python` (Mac/Linux) or `.venv\Scripts\python` (Windows), or run `make setup` |
| Odd install or runtime errors on Python 3.14 or newer | Presidio's docs list Python 3.10 to 3.13 as supported (the packages install on 3.14, but this lab is untested there). Install 3.12 or 3.13 and recreate `.venv` |
| First run is slow or downloads a model | If you skipped `spacy download`, Presidio downloads the missing spaCy model itself on first use (needs internet). Run `make setup` to do it up front |
| An error mentioning `publicsuffix.org` (offline) | Presidio's email check tries to fetch the public list of domain endings once; it falls back to a built-in copy. Your chat text is never sent. `redactor.py` hides this message |
| `No log files in logs/` | Run `make leak` or `make safe` first |
| `Could not reach Ollama at http://localhost:11434...` | Only for Step 8: start Ollama (lesson 0.6) and pull the model |
| Test 2 fails on the base lab | Did you edit `canaries.txt` or `ENTITIES`? `git diff` shows what changed; `make clean` then `make test` |

## Safety

- Your chat text never leaves your computer. Network use: the one-time install, a one-time fetch of the public
  domain-suffix list by Presidio's email check (no chat text is sent), and in Step 8 only, `localhost`.
- All personal data in this folder is fake. `logs/` is git-ignored; `make clean` deletes it.
- This folder contains no solution to the challenge and no real secrets.

## Tested

Steps 1 to 7 were run end to end from a clean folder on Linux, Python 3.13.16, presidio 2.2.364, spaCy 3.8.16,
`en_core_web_sm` 3.8.0, on 21 Oct 2026; the outputs above are copied from that run (timestamps will differ).
The challenge was confirmed solvable with a one-line pattern (not included). Step 8 was tested against a stand-in
HTTP server that mimics Ollama's `/v1/chat/completions` endpoint, not a real Ollama install: run it once against
real Ollama before publishing.
