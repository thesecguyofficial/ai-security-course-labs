# Module 0 · Start here: tech basics and your first lab

Two small helpers for Module 0. Both use the Python standard library only (nothing to install), both run on
your own computer only (`127.0.0.1`), and the data and keys in them are fake.

## What's in this folder

| File | Job | Used in |
|---|---|---|
| `tiny_api.py` | A tiny web server with an API: a web page, an endpoint that needs an API key, one that creates an order. For trying HTTP, JSON and status codes with `curl`. | Lesson 0.3b, tech basics |
| `explore.py` | Looks at Ollama and your first model one step at a time: is the server private, what's in a model, how the app's note and your question become one text, and the exact request a chat app sends. Read-only. | Lesson 0.4, lab part 1 |
| `README.md` | This guide. | |

### Get the lab files

New here, or deleted the folder? Get the labs once:

```bash
git clone https://github.com/thesecguyofficial/ai-security-course-labs.git
cd ai-security-course-labs/labs/m00
```

Already have them from an earlier lesson? Go into the `ai-security-course-labs` folder and run `git pull` to get the
latest version. No git? On the GitHub page, use **Code → Download ZIP** and unzip it.

Windows: type `py` wherever this guide says `python3`.

## Lesson 0.3b · Try an API on your own computer (about 10 minutes)

Start the server in the background (the `&`), and wait one second for it:

```bash
python3 tiny_api.py & sleep 1
```

Windows: run `py tiny_api.py` in its own PowerShell window and use a second window for the rest. In PowerShell,
type `curl.exe`, not `curl`.

Then send it requests:

```bash
curl -i http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/api/orders/1001
curl -i -H "Authorization: Bearer demo-key-123" http://127.0.0.1:8080/api/orders/1001
```

Stop it with `kill %1` (Windows: Ctrl+C in its window).

## Lesson 0.4 · Step 1b · Look at Ollama and your model before you attack it (about 10 minutes)

You need Ollama and the small model `gemma3:1b`; lesson 0.4, part 1 installs both. `explore.py` changes nothing.

```bash
python3 explore.py server
python3 explore.py models
python3 explore.py template gemma3:1b
python3 explore.py chat gemma3:1b --system "You are the help desk bot for a demo shop." "What are your opening hours?"
```

Now do the lab itself: lesson 0.4, "Do it for real" (part 2).
