"""
detectors.py: STAND-IN classifiers for lab AZ12 (plain Python rules, NOT the real Azure models).

Microsoft's guardrails use classification models from Azure AI Content Safety. Those models are not published, and
this lab must run offline at $0, so each detector below is a small, readable rule set that behaves like the real
category it stands in for, including its blind spots. The point of the lab is the MEASUREMENT method (catch rate AND
false positives, per layer), not these rules. Step 9 of the README runs the same suite against the real Content
Safety API; the optional LLM Guard adapter runs it against an open-source ML classifier.

Every detector returns plain dicts shaped like the fields Azure returns, so the rest of the lab reads like the real
API responses (see guardrail_twin.py).
"""

import base64
import binascii
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

# ----------------------------------------------------------------------------- harm categories
# Severity scale as in Azure AI Content Safety "FourSeverityLevels": 0 safe, 2 low, 4 medium, 6 high.
HARM_LEXICON = {
    "Violence": [
        (6, r"\bkill (you|him|her|them|everyone)\b"),
        (4, r"\bhurt (you|him|her|them)\b|\bbeat (you|him|her|them) up\b"),
        (2, r"\bkill\b|\bshoot\b|\bfight\b"),
    ],
    "Hate": [(4, r"\bLAB-HATE-PLACEHOLDER\b")],      # placeholder only: the suite tests the plumbing, not slurs
    "Sexual": [(4, r"\bLAB-SEXUAL-PLACEHOLDER\b")],
    "Selfharm": [(4, r"\bLAB-SELFHARM-PLACEHOLDER\b")],
}
SEVERITY_NAME = {0: "safe", 2: "low", 4: "medium", 6: "high"}
THRESHOLD_MIN = {"Low": 2, "Medium": 4, "High": 6}   # severityThreshold -> lowest severity that is filtered


def harm_severities(text: str) -> dict:
    """{'Violence': 4, 'Hate': 0, ...} like categoriesAnalysis in text:analyze (FourSeverityLevels)."""
    out = {}
    for cat, rules in HARM_LEXICON.items():
        sev = 0
        for level, pattern in rules:
            if re.search(pattern, text, re.IGNORECASE):
                sev = max(sev, level)
        out[cat] = sev
    return out


# ----------------------------------------------------------------------------- Prompt Shields (user prompt attacks)
RULE_CHANGE = r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(instructions|rules|guidelines|system prompt)\b"
ROLE_PLAY = (r"\b(you are now|from now on,? you are|pretend to be|act as)\b[^\n]{0,80}"
             r"\b(no rules|no limitations|unrestricted|without (any )?rules)\b")
MOCKUP = r"(?im)^\s*(user|assistant|system)\s*:"
B64_TOKEN = r"[A-Za-z0-9+/]{24,}={0,2}"


def _decoded_b64(text: str) -> list[str]:
    found = []
    for tok in re.findall(B64_TOKEN, text):
        try:
            found.append(base64.b64decode(tok, validate=True).decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    return found


def user_prompt_attack(text: str) -> dict:
    """Stand-in for Prompt Shields on the user prompt. Four classes, as Microsoft lists them: attempt to change system
    rules, conversation mockup, role-play, encoding attacks. Reads the RAW text: it does not undo invisible characters."""
    reasons = []
    if re.search(RULE_CHANGE, text, re.IGNORECASE):
        reasons.append("attempt to change system rules")
    if re.search(ROLE_PLAY, text, re.IGNORECASE):
        reasons.append("role-play")
    if len(re.findall(MOCKUP, text)) >= 2:
        reasons.append("conversation mockup")
    for plain in _decoded_b64(text):
        if re.search(RULE_CHANGE, plain, re.IGNORECASE) or re.search(ROLE_PLAY, plain, re.IGNORECASE):
            reasons.append("encoding attack (base64)")
    return {"attackDetected": bool(reasons), "classes": reasons}


# ----------------------------------------------------------------------------- Prompt Shields (document attacks)
AI_ADDRESSED = (r"\[\s*system annotation|\bfor the ai assistant\b|"
                r"\b(ai assistant|assistant|copilot|chatbot)\b[^.\n]{0,40}\b(must|should)\b[^.\n]{0,10}\b(call|send|forward|ignore|tell)\b|"
                r"\bdo not tell the user\b")


def document_attack(text: str) -> dict:
    """Stand-in for Prompt Shields on documents (indirect attacks). Catches instructions aimed at the AI.
    Blind spot on purpose: an instruction written as a normal request to a HUMAN reader (EchoLeak style)."""
    reasons = []
    if re.search(AI_ADDRESSED, text, re.IGNORECASE):
        reasons.append("instructions aimed at the AI")
    if re.search(RULE_CHANGE, text, re.IGNORECASE):
        reasons.append("attempt to change system rules")
    return {"attackDetected": bool(reasons), "classes": reasons}


# ----------------------------------------------------------------------------- protected material (text)
def _protected_index() -> list[dict]:
    with open(os.path.join(HERE, "data", "protected.json"), encoding="utf-8") as f:
        return json.load(f)["texts"]


def protected_material_text(text: str, window_words: int = 8) -> dict:
    """Flags output that repeats any run of `window_words` words from the (fictional) protected index."""
    words = re.findall(r"[a-z']+", text.lower())
    grams = {" ".join(words[i:i + window_words]) for i in range(max(0, len(words) - window_words + 1))}
    for item in _protected_index():
        src = re.findall(r"[a-z']+", item["text"].lower())
        for i in range(max(0, len(src) - window_words + 1)):
            if " ".join(src[i:i + window_words]) in grams:
                return {"detected": True, "id": item["id"]}
    return {"detected": False}


# ----------------------------------------------------------------------------- personal data (PII)
PII_PATTERNS = {
    "Email": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
    "PhoneNumber": r"\+?\d{1,3}[-\s]\d{3}[-\s]555[-\s]\d{4}\b",
    "AzureConnectionString": r"AccountKey=[A-Za-z0-9+/=]{20,}",
    "CreditCardNumber": r"\b(?:\d[ -]?){13,16}\b",
}


def pii(text: str) -> dict:
    """{'Email': ['a@b.com'], ...} for every category found."""
    found = {}
    for cat, pattern in PII_PATTERNS.items():
        hits = re.findall(pattern, text)
        if hits:
            found[cat] = [h if isinstance(h, str) else "".join(h) for h in hits]
    return found


# ----------------------------------------------------------------------------- custom blocklists
def blocklist_hits(text: str, items: list[dict]) -> list[str]:
    """items: [{'blockItemId': 'x', 'pattern': 'NIGHTJAR', 'isRegex': false}] (Microsoft: `pattern`, `isRegex`).
    Exact items match as case-sensitive substrings here; Microsoft's troubleshooting notes that patterns are
    case-sensitive by default."""
    hits = []
    for it in items:
        if it.get("isRegex"):
            if re.search(it["pattern"], text):
                hits.append(it["blockItemId"])
        elif it["pattern"] in text:
            hits.append(it["blockItemId"])
    return hits
