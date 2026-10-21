"""
embedder.py: turns text into vectors (lists of numbers) for the M6 lab.

TWO OPTIONS
1. HashingEmbedder (default)  - a STAND-IN, NOT a neural embedding model. Plain Python, no downloads.
   It hashes each word into one of 512 slots ("feature hashing"), so texts that share words get similar
   vectors. It matches WORDS, not MEANING: "refund" and "money back" look unrelated to it. That's fine for
   this lab, because every attack and fix here is about what your code does around the search, not about how
   clever the embedding is. It is deterministic, so the tests give the same result every run.
2. OllamaEmbedder (optional)  - a real embedding model (e.g. embeddinggemma) served by Ollama on 127.0.0.1.
   Its scores are on a different scale, so the refusal threshold must be re-calibrated (see README, Step 7).
"""

import hashlib
import json
import math
import re
import urllib.request
from urllib.parse import urlparse

WORD_RE = re.compile(r"[a-z0-9]+")

# Very common words carry no topic, so they are ignored (a classic search-engine trick).
STOPWORDS = set("""
a an and are as at be by can do does for from get go has have how i if in is it its my no not of on or our
so that the their them they this to us we what when where which who will with you your up out into than then
there these those was were been being any all also just per via within over under about after before must
""".split())


def tokens(text: str) -> list[str]:
    words = WORD_RE.findall(text.lower())
    out = []
    for w in words:
        if w in STOPWORDS:
            continue
        if len(w) > 3 and w.endswith("s") and not w.endswith("ss"):
            w = w[:-1]  # crude plural folding: refunds -> refund
        out.append(w)
    return out


class HashingEmbedder:
    """Deterministic bag-of-words vectors. A stand-in for tests, NOT a real embedding model."""

    name = "hashing-512 (stand-in, not AI)"
    dim = 512
    # Calibrated for THIS embedder and THIS corpus: on-topic questions score about 0.29 to 0.88,
    # off-topic ones 0.15 or less. A real model needs its own number (README, Step 7).
    default_min_score = 0.25

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._one(t) for t in texts]

    def _one(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for w in tokens(text):
            h = hashlib.blake2b(w.encode(), digest_size=8).digest()
            slot = int.from_bytes(h[:4], "big") % self.dim
            sign = 1.0 if h[4] & 1 else -1.0
            vec[slot] += sign
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


class OllamaEmbedder:
    """A real local embedding model through Ollama's /api/embed endpoint (returns unit-length vectors)."""

    default_min_score = 0.5  # a starting guess only: calibrate it on your own questions (README, Step 7)

    def __init__(self, model: str = "embeddinggemma", url: str = "http://127.0.0.1:11434"):
        host = urlparse(url).hostname
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise SystemExit("This lab only talks to Ollama on 127.0.0.1 (your own computer).")
        self.model, self.url = model, url.rstrip("/")
        self.name = f"ollama:{model}"
        self.dim = len(self.embed(["dimension probe"])[0])

    def embed(self, texts: list[str]) -> list[list[float]]:
        body = json.dumps({"model": self.model, "input": texts}).encode()
        req = urllib.request.Request(f"{self.url}/api/embed", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)["embeddings"]
        except OSError as e:
            raise SystemExit(f"Could not reach Ollama at {self.url}/api/embed ({e}). "
                             f"Start Ollama and run: ollama pull {self.model}")


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))  # both vectors are unit length
