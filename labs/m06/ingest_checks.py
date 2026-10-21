"""
ingest_checks.py: what the SAFE ingestion pipeline checks before a document may enter the vector store.

Three cheap, explainable checks. Honest label: they are ONE layer. Each is easy to get past for an attacker who
knows them (rephrase the instruction, use a domain that looks right, hide text in a PDF layer this lab doesn't
parse). The controls that hold up better are about WHO can write to the corpus: allow-listed sources, review of
uploads, and provenance on every chunk so a bad batch can be found and removed (lesson 6.2).
"""

import re
import unicodedata

# 1. Hidden content: text a human reviewer won't see but the model will.
HIDDEN_PATTERNS = {
    "HTML comment (invisible when rendered)": re.compile(r"<!--.*?-->", re.S),
    "zero-width characters": re.compile("[​‌‍⁠﻿]"),
    "bidirectional control characters": re.compile("[‪-‮⁦-⁩]"),
    "white or invisible styled text": re.compile(
        r"(?i)style\s*=\s*['\"][^'\"]*(display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*(#fff\b|#ffffff|white))"),
}

# 2. Instruction-like text: documents describe things; they shouldn't address the AI or give it orders.
INSTRUCTION_PATTERNS = [
    re.compile(r"(?i)\b(note|message|instructions?)\s+(for|to)\s+(the\s+)?(ai|assistants?|chatbots?|models?|llms?)\b"),
    re.compile(r"(?i)\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|messages)"),
    re.compile(r"(?i)\b(tell|ask|instruct)\s+the\s+(customer|user|employee)s?\s+to\b"),
    re.compile(r"(?i)\byou\s+are\s+now\b|\bsystem\s+prompt\b"),
]

# 3. Links must point at the tenant's own domains.
URL_RE = re.compile(r"(?i)\bhttps?://([a-z0-9.-]+)")
TENANT_DOMAINS = {"alpha": ("alpha.example",), "bravo": ("bravo.example",)}


def inspect_document(text: str, tenant: str) -> list[str]:
    """Return a list of reasons to quarantine this document (empty list = passed)."""
    reasons = []
    for label, pattern in HIDDEN_PATTERNS.items():
        if pattern.search(text):
            reasons.append(f"hidden content: {label}")
    for pattern in INSTRUCTION_PATTERNS:
        m = pattern.search(text)
        if m:
            reasons.append(f"instruction-like text: '{m.group(0)}'")
    allowed = TENANT_DOMAINS.get(tenant, ())
    for host in URL_RE.findall(text):
        host = host.lower().rstrip(".")
        if not any(host == d or host.endswith("." + d) for d in allowed):
            reasons.append(f"link to a domain the tenant doesn't own: {host}")
    return reasons


def normalise(text: str) -> str:
    """Applied to documents that PASSED: NFKC-normalise and drop zero-width and control characters."""
    text = unicodedata.normalize("NFKC", text)
    text = HIDDEN_PATTERNS["zero-width characters"].sub("", text)
    text = HIDDEN_PATTERNS["bidirectional control characters"].sub("", text)
    return text
