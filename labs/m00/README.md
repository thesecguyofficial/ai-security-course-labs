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

Check it listens on this computer only (Mac: `lsof -nP -iTCP:8080 -sTCP:LISTEN`):

```bash
ss -ltn | grep 8080
```

```text
LISTEN 0      5          127.0.0.1:8080      0.0.0.0:*
```

Ask for an order with no key, then with the (fake) key:

```bash
curl -i http://127.0.0.1:8080/api/orders/1001
curl -i -H "Authorization: Bearer demo-key-123" http://127.0.0.1:8080/api/orders/1001
```

```text
HTTP/1.1 401 Unauthorized
Server: tiny_api/1.0
Content-Type: application/json

{"error": "missing or wrong API key"}

HTTP/1.1 200 OK
Server: tiny_api/1.0
Content-Type: application/json

{"id": 1001, "item": "sleeping bag", "qty": 2, "status": "shipped"}
```

Read the first line of each answer: the status code. 401 means "I don't know who you are"; 200 means it worked.
`curl -i http://127.0.0.1:8080/` returns the demo shop's HTML page, and a POST creates an order:

```bash
curl -i -X POST -H "Authorization: Bearer demo-key-123" -H "Content-Type: application/json" -d '{"item": "tent", "qty": 1}' http://127.0.0.1:8080/api/orders
```

```text
HTTP/1.1 201 Created
...
{"id": 1002, "item": "tent", "qty": 1, "status": "new"}
```

Stop it with `kill %1` (Windows: Ctrl+C in its window). Output above is from the lesson's recording on a fresh
Ubuntu computer (dates and lengths trimmed).

## Lesson 0.4 · Part 1 · Install Ollama

Mac and Windows: download the app from <https://ollama.com/download>. Linux: save the official script to a file,
look at it, then run it, and download the small model:

```bash
curl -fsSL https://ollama.com/install.sh -o ollama-install.sh
grep -n "sudo\|systemctl\|useradd" ollama-install.sh
sh ollama-install.sh
ollama pull gemma3:1b
```

In the recording (fresh Ubuntu), the script printed `The Ollama API is now available at 127.0.0.1:11434.`

## Lesson 0.4 · Step 1b · Look at Ollama and your model before you attack it (about 10 minutes)

You need Ollama and the small model `gemma3:1b`; lesson 0.4, part 1 installs both. `explore.py` changes nothing.

**1. Is the server private?**

```bash
python3 explore.py server
```

```text
Ollama 0.40.13 is answering at http://127.0.0.1:11434
  127.0.0.1 (also called localhost) means: this computer only.

Port 11434 on this computer's network address (10.1.0.39): no answer.
  Good: other devices on your network can't reach Ollama. It is private to this computer.
```

If the second part says `!! Port 11434 ALSO answers`, other devices can use your models: lesson 0.6 shows the fix.

**2. What's in a model?**

```bash
python3 explore.py models
```

```text
  gemma3:1b
     file size     0.8 GB
     parameters    999.89M    the numbers the model learned in training
     quantization  Q4_K_M     how many bits store each number (Q4 = about 4)
     family        gemma3
```

About a billion learned numbers (parameters, also called weights), each stored in about 4 bits, in a 0.8 GB file.

**3. How do the app's note and your question reach the model?**

```bash
python3 explore.py template gemma3:1b
```

The chat template is the pattern Ollama uses to turn the messages into the one text the model reads. For
`gemma3:1b`, this line does it:

```text
{{- if or (eq .Role "user") (eq .Role "system") }}<start_of_turn>user
```

A message with the role `system` (the app's note) and one with the role `user` (the customer) go into the same
kind of turn. Nothing marks the note as more trusted. That's what part 2 uses.

**4. The exact request a chat app sends:**

```bash
python3 explore.py chat gemma3:1b --system "You are the help desk bot for a demo shop." "What are your opening hours?"
```

The request is JSON with the model's name and two messages (`"role": "system"` and `"role": "user"`), sent to
`/api/chat`. In the recording the reply invented opening hours ("Monday - Friday from 10:00 AM to 6:00 PM"):
nothing told the model, so it filled the gap. The last lines count tokens, the small pieces of text a model reads
and writes:

```text
  31 tokens in: the note and the question, read as one text
  75 tokens out: the reply, one token at a time
```

Your reply will differ: answers are a little random.

Now do the lab itself: lesson 0.4, "Do it for real" (part 2).

