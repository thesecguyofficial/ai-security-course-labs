"""
detect.py: the sensitive-data detectors that both the Macie stand-in (macie.py) and the redactor (redact.py) use.

Two kinds, named the way Amazon Macie names them:
- MANAGED data identifiers: a small subset of Macie's list, re-implemented for the lab. AWS_CREDENTIALS (an AWS
  secret access key near a keyword), CREDIT_CARD_NUMBER (passes the Luhn check, near a keyword) and
  CREDIT_CARD_NUMBER_(NO_KEYWORD), PHONE_NUMBER (US and Canada format). Macie's list has NO e-mail address identifier
  and no IP address identifier, so neither has this stand-in. Macie's NAME identifier is a trained model; this lab
  doesn't imitate it (the redactor uses your own customer list instead).
- CUSTOM data identifiers, from a setup's identifiers.json: regex, optional keywords (must appear within
  maximumMatchDistance characters before the match, default 50, not case sensitive) and ignore words (exact, case
  sensitive), the same parts and defaults Macie documents.

These are teaching detectors, not production ones. Real detection is a best guess (lesson 4.2), so the lab also
checks results with planted canaries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CATEGORY = {"AWS_CREDENTIALS": "CREDENTIALS", "CREDIT_CARD_NUMBER": "FINANCIAL_INFORMATION",
            "CREDIT_CARD_NUMBER_(NO_KEYWORD)": "FINANCIAL_INFORMATION", "PHONE_NUMBER": "PERSONAL_INFORMATION"}

_SECRET = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
_SECRET_KEYWORDS = ["aws_secret_access_key", "secret access key", "secret_key", "secretaccesskey"]
_CARD = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
_CARD_KEYWORDS = ["card", "credit", "visa", "mastercard", "amex", "payment"]
_PHONE = re.compile(r"(?<!\d)(?:\+1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)")


@dataclass
class Match:
    type: str          # identifier name, e.g. CREDIT_CARD_NUMBER or a custom identifier's name
    category: str      # Macie's SensitiveDataItemCategory, or CUSTOM_IDENTIFIER
    start: int
    end: int
    value: str


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def _near(text: str, start: int, keywords: list[str], distance: int) -> bool:
    window = text[max(0, start - distance):start].lower()
    return any(k.lower() in window for k in keywords)


def managed(text: str) -> list[Match]:
    out: list[Match] = []
    for m in _SECRET.finditer(text):
        if _near(text, m.start(), _SECRET_KEYWORDS, 50):
            out.append(Match("AWS_CREDENTIALS", "CREDENTIALS", m.start(), m.end(), m.group()))
    for m in _CARD.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            t = "CREDIT_CARD_NUMBER" if _near(text, m.start(), _CARD_KEYWORDS, 50) else "CREDIT_CARD_NUMBER_(NO_KEYWORD)"
            out.append(Match(t, CATEGORY[t], m.start(), m.end(), m.group()))
    for m in _PHONE.finditer(text):
        out.append(Match("PHONE_NUMBER", "PERSONAL_INFORMATION", m.start(), m.end(), m.group()))
    return out


def custom(text: str, identifiers: list[dict]) -> list[Match]:
    out: list[Match] = []
    for cdi in identifiers:
        flags = 0 if cdi.get("caseSensitive", False) else re.IGNORECASE
        for m in re.finditer(cdi["regex"], text, flags):
            if any(w in m.group() for w in cdi.get("ignoreWords", [])):
                continue
            kws = cdi.get("keywords", [])
            if kws and not _near(text, m.start(), kws, int(cdi.get("maximumMatchDistance", 50))):
                continue
            out.append(Match(cdi["name"], "CUSTOM_IDENTIFIER", m.start(), m.end(), m.group()))
    return out


def names(text: str, known: list[str]) -> list[Match]:
    """Your own customer list as a detector: exact names, any letter case."""
    out = []
    for n in known:
        for m in re.finditer(re.escape(n), text, re.IGNORECASE):
            out.append(Match("CUSTOMER_NAME", "PERSONAL_INFORMATION", m.start(), m.end(), m.group()))
    return out


def find(text: str, *, use_managed: bool, custom_ids: list[dict], known_names: list[str] | None = None) -> list[Match]:
    found = (managed(text) if use_managed else []) + custom(text, custom_ids) + names(text, known_names or [])
    # Keep the longest match where two overlap (a card number inside a longer digit run, for example).
    found.sort(key=lambda m: (m.start, -(m.end - m.start)))
    kept: list[Match] = []
    for m in found:
        if kept and m.start < kept[-1].end:
            continue
        kept.append(m)
    return kept


def walk_strings(obj, path="$"):
    """Yield (JSONPath, string) for every string value in a JSON document, the way Macie reports `records[].jsonPath`."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def vector_paths(obj, path="$", min_len=32):
    """JSONPaths of long arrays of numbers: what an embedding looks like inside a log record."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from vector_paths(v, f"{path}.{k}", min_len)
    elif isinstance(obj, list):
        if len(obj) >= min_len and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in obj):
            yield path
        else:
            for i, v in enumerate(obj):
                yield from vector_paths(v, f"{path}[{i}]", min_len)
