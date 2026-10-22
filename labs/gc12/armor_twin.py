"""
armor_twin.py: an OFFLINE teaching stand-in for Model Armor. Not Google's service, not Google's models.

It copies the SHAPE of Model Armor so you can practise with it at $0 and later swap in the real API:
  - templates and floor settings use the field names of the Model Armor REST API (filterConfig, raiSettings,
    piAndJailbreakFilterSettings, maliciousUriFilterSettings, sdpSettings, templateMetadata, ...)
  - sanitize_user_prompt() / sanitize_model_response() return a dict shaped like the API's response:
    {"sanitizationResult": {"filterMatchState", "filterResults", "invocationResult"}}
  - documented behaviours are modelled (sources in README.md):
      * confidence levels HIGH, MEDIUM_AND_ABOVE, LOW_AND_ABOVE ("a lower threshold ... might increase ... false positives")
      * each prompt and response is inspected on its own, single-turn
      * encoded content (Base64 etc.) is not decoded
      * prompt injection and jailbreak: fewer than three words -> NO_MATCH_FOUND
      * 65,536-token limit for prompt injection, responsible AI and CSAM: over it, the filter returns EXECUTION_SKIPPED
      * one token = four characters, white space excluded
      * malicious URLs: only the first 256 URLs are scanned
      * Sensitive Data Protection basic: a small fixed set of info types (inspection only)
      * the CSAM filter always runs and can't be turned off

What it is NOT: the detectors below are a few regular expressions and word lists. Real Model Armor uses trained
classifiers and Google threat intelligence; it will catch things this twin misses and miss things it catches.
Use the twin to learn the mechanics and to build your test suite; measure the real service with the same suite
(run_suite.py --engine model-armor, README Step 8).
"""

from __future__ import annotations

import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent

LEVELS = {"LOW_AND_ABOVE": 1, "MEDIUM_AND_ABOVE": 2, "HIGH": 3}
NAME_OF = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}          # what a detector reports
TOKEN_LIMIT = 65_536        # prompt injection and jailbreak, responsible AI, CSAM
SDP_TOKEN_LIMIT = 130_000   # Sensitive Data Protection
URL_LIMIT = 256

# ---------------------------------------------------------------------------------------------------------------
# Detectors. Deliberately simple and English-only (plus nothing): see the module docstring.
# Each returns a confidence 0 (nothing), 1 LOW, 2 MEDIUM or 3 HIGH.
# ---------------------------------------------------------------------------------------------------------------
PI_RULES = [
    (3, r"\bignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|rules|prompts?)\b"),
    (3, r"\byou are (now )?dan\b"),
    (3, r"\bno restrictions\b"),
    (3, r"\bdeveloper mode\b"),
    (2, r"\b(repeat|print|reveal|show|output)\b.{0,40}\b(hidden|system|internal|initial)\b.{0,20}\b(instructions|prompt)\b"),
    (2, r"\bdebug mode\b"),
    (2, r"\bignore the\b.{0,30}\band (use|do)\b"),
    (1, r"\bnew policy\b"),
    (1, r"\byou may now\b"),
    (1, r"\bact as\b"),
    (1, r"\bpretend\b"),
    (1, r"\bjailbreak"),
    (1, r"\bignore my previous\b"),
]

RAI_RULES = {
    "dangerous": [(3, r"\[lab-placeholder: dangerous"), (3, r"lab-harmful-output"), (1, r"\bkill\b")],
    "harassment": [(2, r"\bworthless idiot\b"), (1, r"\bregret it\b")],
    "hate_speech": [(3, r"\[lab-placeholder: hate")],
    "sexually_explicit": [(3, r"\[lab-placeholder: explicit")],
}
RAI_TYPE_NAMES = {"dangerous": "DANGEROUS", "harassment": "HARASSMENT", "hate_speech": "HATE_SPEECH",
                  "sexually_explicit": "SEXUALLY_EXPLICIT"}

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)

# SDP basic (twin): three of the six documented info types are modelled. Fake values only.
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
US_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
GCP_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def count_tokens(text: str) -> int:
    """Model Armor's documented token definition: four characters per token, white space excluded."""
    return (len(re.sub(r"\s", "", text)) + 3) // 4


def _score(rules, text: str) -> int:
    low = text.lower()
    return max([lvl for lvl, rx in rules if re.search(rx, low)] or [0])


def load_threat_list() -> set[str]:
    path = HERE / "data" / "threat_list.txt"
    return {ln.strip().lower() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")}


THREATS = load_threat_list()


# ---------------------------------------------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------------------------------------------
def pi_settings(cfg: dict) -> tuple[bool, int]:
    s = cfg.get("filterConfig", {}).get("piAndJailbreakFilterSettings", {})
    on = s.get("filterEnforcement") == "ENABLED"
    # Unspecified confidence means LOW_AND_ABOVE in the API (DETECTION_CONFIDENCE_LEVEL_UNSPECIFIED = "Same as LOW_AND_ABOVE").
    return on, LEVELS.get(s.get("confidenceLevel", "LOW_AND_ABOVE"), 1)


def rai_settings(cfg: dict) -> dict[str, int]:
    out = {}
    for f in cfg.get("filterConfig", {}).get("raiSettings", {}).get("raiFilters", []):
        key = {v: k for k, v in RAI_TYPE_NAMES.items()}[f["filterType"]]
        out[key] = LEVELS.get(f.get("confidenceLevel", "MEDIUM_AND_ABOVE"), 2)
    return out


def uri_on(cfg: dict) -> bool:
    return cfg.get("filterConfig", {}).get("maliciousUriFilterSettings", {}).get("filterEnforcement") == "ENABLED"


def sdp_basic_on(cfg: dict) -> bool:
    sdp = cfg.get("filterConfig", {}).get("sdpSettings", {})
    return sdp.get("basicConfig", {}).get("filterEnforcement") == "ENABLED" or "advancedConfig" in sdp


# ---------------------------------------------------------------------------------------------------------------
# Sanitize
# ---------------------------------------------------------------------------------------------------------------
def _match(found: bool) -> str:
    return "MATCH_FOUND" if found else "NO_MATCH_FOUND"


def _skipped() -> dict:
    return {"executionState": "EXECUTION_SKIPPED", "matchState": "NO_MATCH_FOUND",
            "messageItems": [{"messageType": "INFO", "message": "Detection skipped as token limit exceeded."}]}


def sanitize(template: dict, text: str, kind: str = "prompt", available: bool = True) -> dict:
    """Return a Model-Armor-shaped result for one piece of text. kind = 'prompt' or 'response'."""
    if not available:
        raise ConnectionError("Model Armor (twin) is unavailable")
    tokens = count_tokens(text)
    over = tokens > TOKEN_LIMIT
    results: dict = {}
    skipped = 0

    # CSAM: always on, can't be turned off. The twin has no CSAM detector and never matches.
    if over:
        results["csam"] = {"csamFilterFilterResult": _skipped()}
        skipped += 1
    else:
        results["csam"] = {"csamFilterFilterResult": {"executionState": "EXECUTION_SUCCESS", "matchState": "NO_MATCH_FOUND"}}

    on, threshold = pi_settings(template)
    if on:
        if over:
            results["pi_and_jailbreak"] = {"piAndJailbreakFilterResult": _skipped()}
            skipped += 1
        else:
            words = len(text.split())
            level = 0 if words < 3 else _score(PI_RULES, text)   # "fewer than three words" -> NO_MATCH_FOUND
            hit = level >= threshold and level > 0
            r = {"executionState": "EXECUTION_SUCCESS", "matchState": _match(hit)}
            if level:
                r["confidenceLevel"] = NAME_OF[level]
            results["pi_and_jailbreak"] = {"piAndJailbreakFilterResult": r}

    rai = rai_settings(template)
    if rai:
        if over:
            results["rai"] = {"raiFilterResult": _skipped()}
            skipped += 1
        else:
            per, any_hit = {}, False
            for key, thr in rai.items():
                level = _score(RAI_RULES[key], text)
                hit = level >= thr and level > 0
                any_hit |= hit
                per[key] = {"matchState": _match(hit), **({"confidenceLevel": NAME_OF[level]} if level else {})}
            results["rai"] = {"raiFilterResult": {"executionState": "EXECUTION_SUCCESS", "matchState": _match(any_hit),
                                                  "raiFilterTypeResults": per}}

    if uri_on(template):
        urls = URL_RE.findall(text)[:URL_LIMIT]            # only the first 256 URLs are scanned
        bad = [u for u in urls if re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].lower() in THREATS]
        r = {"executionState": "EXECUTION_SUCCESS", "matchState": _match(bool(bad))}
        if bad:
            r["maliciousUriMatchedItems"] = [{"uri": u} for u in bad]
        results["malicious_uris"] = {"maliciousUriFilterResult": r}

    if sdp_basic_on(template):
        findings = []
        if count_tokens(text) <= SDP_TOKEN_LIMIT:
            for m in CARD_RE.finditer(text):
                digits = re.sub(r"\D", "", m.group())
                if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                    findings.append({"infoType": "CREDIT_CARD_NUMBER", "likelihood": "LIKELY"})
            findings += [{"infoType": "US_SOCIAL_SECURITY_NUMBER", "likelihood": "LIKELY"} for _ in US_SSN_RE.finditer(text)]
            findings += [{"infoType": "GCP_API_KEY", "likelihood": "VERY_LIKELY"} for _ in GCP_API_KEY_RE.finditer(text)]
        results["sdp"] = {"sdpFilterResult": {"inspectResult": {"executionState": "EXECUTION_SUCCESS",
                                                                "matchState": _match(bool(findings)),
                                                                **({"findings": findings} if findings else {})}}}

    any_match = any(_inner(v).get("matchState") == "MATCH_FOUND" for v in results.values())
    total = len(results)
    invocation = "SUCCESS" if skipped == 0 else ("FAILURE" if skipped == total else "PARTIAL")
    return {"sanitizationResult": {"filterMatchState": _match(any_match), "filterResults": results,
                                   "invocationResult": invocation}}


def _inner(filter_result: dict) -> dict:
    """{'piAndJailbreakFilterResult': {...}} -> {...}; SDP nests one level deeper."""
    (v,) = filter_result.values()
    return v.get("inspectResult", v) if isinstance(v, dict) else {}


def matched_filters(result: dict) -> list[str]:
    fr = result["sanitizationResult"]["filterResults"]
    return sorted(k for k, v in fr.items() if _inner(v).get("matchState") == "MATCH_FOUND")


def skipped_filters(result: dict) -> list[str]:
    fr = result["sanitizationResult"]["filterResults"]
    return sorted(k for k, v in fr.items() if _inner(v).get("executionState") == "EXECUTION_SKIPPED")


def sanitize_user_prompt(template: dict, text: str, available: bool = True) -> dict:
    return sanitize(template, text, "prompt", available)


def sanitize_model_response(template: dict, text: str, user_prompt: str = "", available: bool = True) -> dict:
    return sanitize(template, text, "response", available)


def load_json(path) -> dict:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Sanitize one prompt with the offline twin and print the result JSON.")
    ap.add_argument("text")
    ap.add_argument("--template", default="twin/hardened/templates.json", help="templates file (uses the first template)")
    ap.add_argument("--response", action="store_true", help="treat the text as a model response")
    a = ap.parse_args()
    tpl = load_json(HERE / a.template)["templates"][0]
    fn = sanitize_model_response if a.response else sanitize_user_prompt
    print(json.dumps(fn(tpl, a.text), indent=2))
