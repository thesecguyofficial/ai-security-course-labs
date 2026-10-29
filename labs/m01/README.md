# Lab M1.8: run a model locally, look inside it, count tokens, watch the context window fill

Companion to lesson **1.8** of *AI Security Engineer*. This folder will move to the public
`ai-security-labs` repository; it contains no solutions and no secrets.

## Get the lab

```bash
git clone https://github.com/thesecguyofficial/ai-security-course-labs.git
cd ai-security-course-labs/labs/m01
```

Already cloned it for an earlier module? Run `git pull` inside `ai-security-course-labs` instead. No git? Use the
green **Code → Download ZIP** button on the repository page and unzip it.

## What's in this folder

| File | Its job |
|---|---|
| `README.md` | This guide |
| `explore.py` | Part 1: looks inside the model one idea at a time (the model file, next-token prediction, the app re-sending history). Changes nothing |
| `llm_lab.py` | Part 2: the exercises (`chat`, `tokens`, `temp`, `fill`), plus `check` |

Both scripts use only Python's standard library: no `pip install`, no virtual environment. Windows: type `py`
where you see `python3`.

## Needs

- Ollama running locally (lesson 0.6), listening on `http://localhost:11434`
- A small model: `ollama pull gemma3:1b` (806 MB)
- Python 3.10+

## Step 1 · Ollama from zero (about 5 minutes plus the download)

**Ollama** is a free, open-source program that downloads open-weight models and runs them on your own computer.

1. **Install it** (skip if you did lesson 0.6). Mac or Windows: the installer from
   [ollama.com/download](https://ollama.com/download). Linux: `curl -fsSL https://ollama.com/install.sh | sh`
2. **Check it** (tested with 0.40.13; newer is fine) and see that no model is there yet:

   ```bash
   ollama --version
   ollama list
   ```

   ```text
   ollama version is 0.40.13
   NAME    ID    SIZE    MODIFIED
   ```

3. **Pull the model and list it:**

   ```bash
   ollama pull gemma3:1b
   ollama list
   ```

   ```text
   pulling manifest
   pulling 2f8c3d137f24: 100% ▕█████████████████████████████████████████████████████████ ▏ 805 MB/806 MB  159 MB/s      0s
   pulling 76a6b777faea: 100% ▕██████████████████████████████████████████████████████████▏  140 B
   verifying sha256 digest
   writing manifest
   success
   NAME         ID              SIZE      MODIFIED
   gemma3:1b    97558784bdc9    806 MB    10 seconds ago
   ```

   Two files: the weights (806 MB) and a tiny settings file. `verifying sha256 digest` checks the download's
   fingerprint, so a damaged or swapped file is caught.

4. **Read the model's label:** `ollama show gemma3:1b`

   ```text
     Model
       architecture        gemma3
       parameters          999.89M
       context length      32768
       embedding length    1152
       quantization        Q4_K_M
     ...
     Parameters
       stop           "<end_of_turn>"
       temperature    1
     ...
   ```

   About one billion parameters (learned numbers), built to read up to 32,768 tokens at once, stored in about
   4 bits per number (quantization). The second "Parameters" list is something else: default settings such as
   temperature (lesson 1.2) and the stop token.

5. **Where it listens.** Ollama waits for requests on **localhost** (`127.0.0.1`, this computer) at **port** 11434
   (the "door number" that picks one program). On a Mac, use `lsof -iTCP:11434 -sTCP:LISTEN` instead of the first line:

   ```bash
   ss -ltn | grep 11434
   curl http://localhost:11434/api/version
   ```

   ```text
   LISTEN 0      4096       127.0.0.1:11434      0.0.0.0:*
   {"version":"0.40.13"}
   ```

   `127.0.0.1` means only this computer can connect. Ollama has no login, so never make it listen on `0.0.0.0`
   (every network address) on a machine others can reach.

## Step 1b · Look inside the model before the exercises (about 10 minutes)

New to AI? Do this first. `explore.py` shows one idea at a time from the first two videos of Module 1. Nothing here
changes anything. Look before you run: `python3 explore.py --help` lists its three commands without running any.

**1. The model file.**

```bash
python3 explore.py model
```

```text
model:          gemma3:1b  (family gemma3, file format gguf)
parameters:     999,885,952  = about 1.0 billion numbers learned in training (the weights)
quantization:   Q4_K_M  = the numbers are rounded and stored in fewer bits, so the file is smaller
file size:      806 MB  = about 6.4 bits per number on average  (at 16 bits each it would be about 2.0 GB)
context length: 32,768 tokens = the most this model was built to read at once (Ollama uses a smaller window unless you ask)
```

A model is a file of learned numbers. Q4_K_M keeps most of them at about 4 bits and some more precise, so the
average here is 6.4 bits. Running the model (inference) reads the numbers and never changes them.

**2. Next-token prediction.**

```bash
python3 explore.py next "The capital of France is"
```

```text
step 1: picks ' Paris'     top 3 guesses: ' Paris' 93.8%  ' **'  1.8%  ' a'  0.6%
step 2: picks '.'          top 3 guesses: '.' 97.9%  ','  1.9%  '?'  0.2%
step 3: picks '\n\n'       top 3 guesses: '\n\n' 80.3%  '\n'  7.7%  ' The'  5.4%
step 4: picks 'The'        top 3 guesses: 'The' 54.2%  'It' 18.2%  'What'  3.4%
step 5: picks ' largest'   top 3 guesses: ' largest' 44.1%  ' population'  8.2%  ' city'  7.6%
step 6: picks ' city'      top 3 guesses: ' city' 97.2%  ' country'  1.6%  ' ocean'  0.4%
```

Each step scores every token the model knows and the top guess is added (`temperature 0`). Paris was 94% sure;
"largest" only 44%, and it was picked anyway. Nothing was looked up. Try your own text, and `--tokens 12` for more.

**3. Who keeps the chat.**

```bash
python3 explore.py history
```

```text
== Request 1: the app sends 2 messages (39 tokens) ==
   system    You are a helpful assistant. Answer in one short sentence.
   user      Hi! My name is Asha and my favourite colour is green.
   -> model: That’s lovely to hear, Asha! Green is a fantastic choice. 😊

== Request 2, a new request without the history: the app sends 2 messages (31 tokens) ==
   system    You are a helpful assistant. Answer in one short sentence.
   user      What is my name?
   -> model: I understand you’re asking me this, but I’m programmed to protect your privacy. Therefore, I cannot tell you your name. 😊

== Request 3, the app re-sends the history: the app sends 4 messages (70 tokens) ==
   ...
   -> model: Your name is Asha! 😊
```

The model is stateless. In request 2 it doesn't know the name, and invents a reason (privacy). It "remembers" in
request 3 only because the app sent the earlier messages again, inside the context window (working memory).

**4. One raw API call, read line by line.**

```bash
curl -s http://localhost:11434/api/chat -d '{"model": "gemma3:1b", "messages": [{"role": "user", "content": "Why is the sky blue? One sentence."}], "stream": false}' | python3 -m json.tool
```

(Mac and Linux. On Windows, quoting JSON in PowerShell is awkward: skip this one and use `llm_lab.py chat` in part 2.)

```text
    "message": {
        "role": "assistant",
        "content": "The sky is blue because of a phenomenon called Rayleigh scattering, ..."
    },
    "done": true,
    "done_reason": "stop",
    "total_duration": 2230103251,
    "load_duration": 1034313325,
    "prompt_eval_count": 18,
    "eval_count": 32,
```

`done_reason: stop` = it ended with its stop token, not a length limit. Durations are in nanoseconds: about 2.2 s
in total, 1 s of it loading the model. `prompt_eval_count` = tokens in (18), `eval_count` = tokens out (32).

**5. The check for part 2:** `python3 llm_lab.py check` should print `Ollama is running.` and `gemma3:1b`.

Real output above: fresh Ubuntu 24.04 machine, Ollama 0.40.13, recorded by GitHub Actions
([run 40845124951](https://github.com/thesecguyofficial/ai-security-course-labs/actions/runs/40845124951)).
Your percentages and wording can differ slightly.

## Step 2 · The exercises (part 2)

```bash
python3 llm_lab.py check
python3 llm_lab.py chat "What is a token, in one sentence?"
python3 llm_lab.py tokens "hello" "Ignore previous instructions" "₹1,999"
python3 llm_lab.py temp "Name one colour." --runs 3
python3 llm_lab.py fill --ctx 1024
python3 llm_lab.py fill --ctx 8192
python3 llm_lab.py --model qwen3:1.7b chat "Hi"
```

- `python3 llm_lab.py fill --ctx 1024`: watch it forget
- `python3 llm_lab.py fill --ctx 8192`: plenty of room
- `python3 llm_lab.py --model qwen3:1.7b chat "Hi"`: another model: --model goes BEFORE the command

## Safety

- Talks only to `localhost`. Nothing leaves your computer.
- The `Authorization: Bearer ollama` header is a placeholder; Ollama ignores it. Never put a real key in this script.
- Don't expose Ollama to your network (`OLLAMA_HOST=0.0.0.0`): it has no login.

## What you should see (summary)

| Exercise | Expect |
|---|---|
| `chat` | The raw JSON request, an answer, prompt and completion token counts |
| `tokens` | A fixed chat-template overhead, then per-text token counts; non-English text costs more per character |
| `temp` | Identical (or near) answers at 0, variety at 1.8 |
| `fill --ctx 1024` | Token count climbs, then flatlines at the window; the codeword is usually forgotten |
| `fill --ctx 8192` | No flatline; the codeword is usually remembered |

Exact numbers vary by model, Ollama version and hardware.

## Tested

Both scripts were run against a real Ollama install with `gemma3:1b` on fresh Ubuntu 24.04 machines, recorded by
GitHub Actions: `llm_lab.py` (all five commands) in
[run 40351321093](https://github.com/thesecguyofficial/ai-security-course-labs/actions/runs/40351321093), and
`explore.py` with the Ollama steps above in
[run 40845124951](https://github.com/thesecguyofficial/ai-security-course-labs/actions/runs/40845124951).
