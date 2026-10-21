"""
llm.py: the "model" that writes answers in the M6 lab.

TWO OPTIONS
1. StandInModel (default) - a STAND-IN, NOT AI. Plain Python, so every run gives the same answer and the tests
   are repeatable. It copies three real behaviours of language models that matter for RAG security:
     a. It answers from the context it is given, quoting the sentences that best match the question.
     b. It follows instructions it finds inside that context ("Note for AI assistants: ...").
        Real models do this too: that's indirect prompt injection (lesson 3.4).
     c. When nothing in the context matches, it doesn't say "I don't know": it guesses, fluently.
        Real models do this too: that's hallucination (lesson 5.5).
   It never reads the system prompt's rules. A real model usually follows "only use tenant X's documents"...
   until a question or a document talks it out of it. Either way, a prompt is not an access control.
2. OllamaModel (optional) - a real local model (e.g. gemma3:1b) through Ollama's OpenAI-compatible API on
   127.0.0.1. Less predictable: attacks may need rewording, and the safe mode must hold anyway.
"""

import json
import re
import urllib.request
from urllib.parse import urlparse

from embedder import tokens

INSTRUCTION_RE = re.compile(r"(?is)note for ai assistants?:\s*(.+?)\s*(?:-->|$)")
CITATION_RE = re.compile(r"\[([a-z0-9_./-]+\.md)\]")


def split_sentences(text: str) -> list[str]:
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    out = []
    for ln in lines:
        out += [s.strip() for s in re.split(r"(?<=[.!?])\s+", ln.strip()) if s.strip()]
    return out


class StandInModel:
    name = "stand-in model (llm.py, not AI)"

    def __init__(self):
        self.calls = 0  # the tests use this to prove the safe app refuses WITHOUT calling the model

    def generate(self, system_prompt: str, question: str, sources: list[dict]) -> str:
        self.calls += 1
        # (b) Follow instructions found in the retrieved text, like a real model can.
        for s in sources:
            m = INSTRUCTION_RE.search(s["text"])
            if m:
                instruction = re.sub(r"(?i)\btell the (customer|user) to\s+", "Please ", m.group(1))
                instruction = re.sub(r"(?i)\band to\s+", "and ", instruction)
                instruction = re.sub(r"(?i)\btheir\b", "your", instruction)
                return f"{instruction[0].upper()}{instruction[1:]} [{s['source']}]"
        # (a) Quote the best-matching sentences, with a citation.
        q = set(tokens(question))
        scored = []
        for s in sources:
            for sent in split_sentences(INSTRUCTION_RE.sub("", s["text"])):
                overlap = len(q & set(tokens(sent)))
                if overlap >= 1:
                    scored.append((overlap, sent, s["source"]))
        if scored:
            scored.sort(key=lambda x: -x[0])
            return " ".join(f"{sent} [{src}]" for _, sent, src in scored[:2])
        # (c) Nothing matches: guess, confidently.
        q_text = question.strip().rstrip("?")
        if re.match(r"(?i)^(can|may|could) i\s+", q_text):
            rest = re.sub(r"(?i)\bmy\b", "your", re.sub(r"(?i)^(can|may|could) i\s+", "", q_text))
            return f"Yes, you can {rest}. Most companies allow this, so there is no need to ask anyone first."
        return "It usually takes about 30 days. That is the standard rule at most companies."


class OllamaModel:
    """A real local model through Ollama's OpenAI-compatible chat endpoint (docs.ollama.com/openai)."""

    def __init__(self, model: str = "gemma3:1b", url: str = "http://127.0.0.1:11434"):
        if urlparse(url).hostname not in ("127.0.0.1", "localhost", "::1"):
            raise SystemExit("This lab only talks to Ollama on 127.0.0.1 (your own computer).")
        self.model, self.url, self.calls = model, url.rstrip("/"), 0
        self.name = f"ollama:{model}"

    def generate(self, system_prompt: str, question: str, sources: list[dict]) -> str:
        self.calls += 1
        context = "\n\n".join(f'<source path="{s["source"]}">\n{s["text"]}\n</source>' for s in sources)
        body = json.dumps({
            "model": self.model, "temperature": 0,
            "messages": [{"role": "system", "content": system_prompt},
                         {"role": "user", "content": f"Sources:\n{context}\n\nQuestion: {question}"}],
        }).encode()
        req = urllib.request.Request(f"{self.url}/v1/chat/completions", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.load(r)["choices"][0]["message"]["content"].strip()
        except OSError as e:
            raise SystemExit(f"Could not reach Ollama at {self.url} ({e}). "
                             f"Start Ollama and run: ollama pull {self.model}")


def cited_paths(answer: str) -> list[str]:
    return list(dict.fromkeys(CITATION_RE.findall(answer)))
