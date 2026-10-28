# Lab M1.8: run a model locally, count tokens, watch the context window fill

Companion to lesson **1.8** of *AI Security Engineer*. This folder will move to the public
`ai-security-labs` repository; it contains no solutions and no secrets.

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

Then go to this lab's folder. Every command in this guide runs from there:

```bash
cd labs/m01
```

## Needs

- Ollama running locally (lesson 0.6), listening on `http://localhost:11434`
- A small model: `ollama pull gemma3:1b` (about 806 MB)
- Python 3.10+ (standard library only, nothing to `pip install`)

## Run

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

The script's request and response handling was tested against a stub that mimics the Ollama endpoints it uses
(`/api/tags`, `/api/chat`, `/v1/models`, `/v1/chat/completions`). Before publishing, run all five commands once
against a real Ollama install with `gemma3:1b` and update the table above if anything differs.
