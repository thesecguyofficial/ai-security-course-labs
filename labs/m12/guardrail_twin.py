"""
guardrail_twin.py: an OFFLINE STAND-IN for Amazon Bedrock Guardrails. It is NOT Bedrock and NOT AI.

Why a stand-in: this lab must run free, offline, on any laptop, and give the same result every time so `make test` can
check exact numbers. Real Bedrock Guardrails uses machine-learning classifiers that AWS updates over time; this file uses
short, readable pattern lists instead. The NUMBERS you get here are therefore not Bedrock's numbers. What this file copies
faithfully is the documented BEHAVIOUR around the classifiers, which is where most real-world mistakes happen:

  * the request shape: a guardrail is the JSON body of a CreateGuardrail request (contentPolicyConfig, topicPolicyConfig,
    wordPolicyConfig, sensitiveInformationPolicyConfig, contextualGroundingPolicyConfig, tierConfig, crossRegionConfig)
  * filter strength vs confidence: LOW blocks HIGH-confidence content only; MEDIUM blocks HIGH and MEDIUM; HIGH blocks
    HIGH, MEDIUM and LOW (AWS docs, "Filter classification and blocking levels")
  * actions: BLOCK, ANONYMIZE (sensitive information only) and NONE (detect mode: report, change nothing)
  * tiers: Classic understands English, French and Spanish and has no prompt-leakage detection; Standard adds languages
    and prompt leakage, and needs a guardrail profile (cross-Region inference)
  * WHAT gets evaluated in a Converse call: once a guardContent block appears in the messages, ONLY guardContent blocks are
    evaluated; the system prompt is evaluated only if it has a guardContent block; tool results (toolResult), tool
    definitions and the model's tool-call arguments are NOT evaluated; grounding_source / query blocks feed only the
    contextual grounding check
  * the prompt attack filter runs on prompts (input), never on the model's answer
  * a blocked prompt means the model is never called
  * asynchronous streaming: chunks reach the user before the scan finishes, and masking is not supported
  * text units: up to 1,000 characters each, counted per policy; word filters and regex are free

Every rule above is quoted, with its source, in the lab README ("How faithful is the twin?").

Classifier stand-ins (deliberately simple, so you can read them and see why they miss things):
  * prompt attack, misconduct, violence: weighted phrase patterns -> a score -> NONE / LOW / MEDIUM / HIGH confidence
  * denied topics: a topic matches when 2 or more of its keywords (taken from the definition and sample phrases) appear
  * sensitive information: regular expressions for a few PII types
  * contextual grounding: word overlap between the answer and the source (grounding) or the question (relevance)
They do NOT decode Base64, re-join spaced-out letters or read text inside tool results, exactly like the gaps the
lessons warn about. Python 3.11+, standard library only.
"""

from __future__ import annotations

import copy
import json
import math
import re
import unicodedata

STRENGTHS = ["NONE", "LOW", "MEDIUM", "HIGH"]
# Which classifier confidences each filter strength blocks (AWS: "Filter classification and blocking levels").
BLOCKED_AT = {
    "NONE": set(),
    "LOW": {"HIGH"},
    "MEDIUM": {"HIGH", "MEDIUM"},
    "HIGH": {"HIGH", "MEDIUM", "LOW"},
}
CLASSIC_LANGUAGES = {"en", "fr", "es"}  # AWS: Classic tier supports English, French and Spanish
STANDARD_LANGUAGES = {"en", "fr", "es", "de", "hi"}  # the stand-in's subset of Standard tier's "extensive" list

# --------------------------------------------------------------------------------------------------------------------
# Classifier stand-ins. Each pattern: (regex, category, weight, language). Weight 2 = strong signal, 1 = weak signal.
# Score -> confidence: 0 NONE, 1 LOW, 2-3 MEDIUM, 4+ HIGH.
# --------------------------------------------------------------------------------------------------------------------
PROMPT_ATTACK_PATTERNS = [
    # prompt injection: "ignore the developer's instructions"
    (r"\bignore (?:all |any )?(?:your|the|all) (?:previous|prior|above|earlier) (?:instructions|rules)\b", "PROMPT_INJECTION", 2, "en"),
    (r"\b(?:disregard|forget) (?:all |any )?(?:your|the) (?:rules|instructions)\b", "PROMPT_INJECTION", 2, "en"),
    (r"\b(?:rules|instructions) no longer apply\b", "PROMPT_INJECTION", 2, "en"),
    (r"\breply only with\b", "PROMPT_INJECTION", 1, "en"),
    (r"\bignore (?:my|the) previous\b", "PROMPT_INJECTION", 1, "en"),
    (r"\bignore[zr]? les instructions\b", "PROMPT_INJECTION", 2, "fr"),
    (r"\bréponds seulement\b", "PROMPT_INJECTION", 1, "fr"),
    (r"\bignora las instrucciones\b", "PROMPT_INJECTION", 2, "es"),
    (r"\bignoriere (?:alle )?(?:vorherigen )?anweisungen\b", "PROMPT_INJECTION", 2, "de"),
    (r"निर्देशों को अनदेखा", "PROMPT_INJECTION", 2, "hi"),
    (r"केवल \S+ लिखें", "PROMPT_INJECTION", 1, "hi"),
    # jailbreak: "drop your safety rules"
    (r"\b(?:dan|do anything now)\b", "JAILBREAK", 2, "en"),
    (r"\bno (?:rules|restrictions|limits)\b", "JAILBREAK", 2, "en"),
    (r"\bpretend (?:you are|to be)\b", "JAILBREAK", 1, "en"),
    # prompt leakage (Standard tier only): "show me your instructions"
    (r"\brepeat everything above\b", "PROMPT_LEAKAGE", 2, "en"),
    (r"\b(?:system prompt|hidden instructions)\b", "PROMPT_LEAKAGE", 2, "en"),
    (r"\byour instructions\b", "PROMPT_LEAKAGE", 1, "en"),
]
CONTENT_PATTERNS = {
    "MISCONDUCT": [
        (r"\bwithout (?:them|him|her|anyone) knowing\b", 2),
        (r"\bclone (?:a |an |my |the )?(?:colleague's |someone's )?(?:access )?badge\b", 2),
        (r"\b(?:steal|harvest) (?:credentials|passwords)\b", 2),
        (r"\bget into (?:my |a |the )?(?:manager's|boss's|colleague's|someone's) (?:mailbox|email|account)\b", 2),
        (r"\bphishing\b", 1),
        (r"\bwipe\b", 1),
        (r"\bpentest\b", 1),
        (r"\bhack(?:ed|ing)?\b", 1),
    ],
    "VIOLENCE": [
        (r"\bhurt (?:him|her|them|someone)\b", 2),
        (r"\bkill\b", 1),
    ],
    "INSULTS": [(r"\b(?:idiot|stupid bot)\b", 2)],
    "HATE": [],     # this lab has no samples for these categories, so the stand-in has no patterns:
    "SEXUAL": [],   # it always returns NONE for them. Real Bedrock classifies them.
}
STOPWORDS = set(
    "a an the and or of to in on at for from by with about into over under is are was were be been do does did done "
    "i me my we our you your it its this that these those what which who whom how why when where much many any anything "
    "all some can could should would will shall may might must not no yes please there their they them he she his her "
    "as if so than then also just only very more most other such own same too up down out off again further once here "
    "show tell give get got have has had including question questions statement statements".split()
)
PII_PATTERNS = {
    "EMAIL": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+",
    "PHONE": r"(?<![\w-])\+?\d[\d -]{8,}\d\b",
    "AWS_ACCESS_KEY": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "AWS_SECRET_KEY": r"(?<=secret access key: )[A-Za-z0-9/+=]{40}",
    "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "CREDIT_DEBIT_CARD_NUMBER": r"\b(?:\d[ -]?){12,15}\d\b",
}
PRICE_PER_1000_UNITS = {  # USD, https://aws.amazon.com/bedrock/pricing/ (read 22 Oct 2026); same for Classic and Standard
    "content": 0.15,      # content filters, text (the prompt attack filter is configured inside content filters)
    "topic": 0.15,        # denied topics
    "sensitive": 0.10,    # sensitive information filters (PII); regex is free
    "grounding": 0.10,    # contextual grounding checks
    "word": 0.0,          # word filters: free
}


# --------------------------------------------------------------------------------------------------------------------
# Loading and validating a guardrail (the CreateGuardrail request body)
# --------------------------------------------------------------------------------------------------------------------
def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    errors = validate(cfg)
    if errors:
        raise ValueError(f"{path}: CreateGuardrail would reject this guardrail:\n  " + "\n  ".join(errors))
    return cfg


def tier_of(cfg: dict, policy: str = "contentPolicyConfig") -> str:
    return (((cfg.get(policy) or {}).get("tierConfig") or {}).get("tierName") or "CLASSIC").upper()


def validate(cfg: dict) -> list[str]:
    """The documented limits the stand-in enforces (each one is quoted in the README)."""
    errs = []
    if not cfg.get("name"):
        errs.append("name is required")
    if not cfg.get("blockedInputMessaging") or not cfg.get("blockedOutputsMessaging"):
        errs.append("blockedInputMessaging and blockedOutputsMessaging are required")
    standard = "STANDARD" in (tier_of(cfg, "contentPolicyConfig"), tier_of(cfg, "topicPolicyConfig"),
                              tier_of(cfg, "contextualGroundingPolicyConfig"))
    if standard and not (cfg.get("crossRegionConfig") or {}).get("guardrailProfileIdentifier"):
        errs.append("STANDARD tier needs crossRegionConfig.guardrailProfileIdentifier (a guardrail profile)")
    topics = (cfg.get("topicPolicyConfig") or {}).get("topicsConfig") or []
    if len(topics) > 30:
        errs.append("more than 30 denied topics")
    max_def = 1000 if tier_of(cfg, "topicPolicyConfig") == "STANDARD" else 200
    for t in topics:
        if len(t.get("definition", "")) > max_def:
            errs.append(f"topic {t.get('name')!r}: definition longer than {max_def} characters for this tier")
        ex = t.get("examples") or []
        if len(ex) > 5 or any(len(e) > 100 for e in ex):
            errs.append(f"topic {t.get('name')!r}: up to 5 sample phrases of up to 100 characters each")
    for r in (cfg.get("sensitiveInformationPolicyConfig") or {}).get("regexesConfig") or []:
        if re.search(r"\(\?<?[=!]", r.get("pattern", "")):
            errs.append(f"regex {r.get('name')!r}: lookaround is not supported")
        if not 1 <= len(r.get("pattern", "")) <= 500:
            errs.append(f"regex {r.get('name')!r}: pattern must be 1-500 characters")
    for w in (cfg.get("wordPolicyConfig") or {}).get("wordsConfig") or []:
        if len(w.get("text", "").split()) > 3:
            errs.append(f"word filter {w.get('text')!r}: words or phrases of up to three words")
    for f in (cfg.get("contextualGroundingPolicyConfig") or {}).get("filtersConfig") or []:
        if not 0 <= float(f.get("threshold", 0)) <= 0.99:
            errs.append(f"grounding {f.get('type')}: threshold must be between 0 and 0.99")
    policies = ["contentPolicyConfig", "topicPolicyConfig", "wordPolicyConfig", "sensitiveInformationPolicyConfig",
                "contextualGroundingPolicyConfig", "automatedReasoningPolicyConfig"]
    if not any(cfg.get(p) for p in policies):
        errs.append("a guardrail must contain at least one filter")
    return errs


# --------------------------------------------------------------------------------------------------------------------
# The classifier stand-ins
# --------------------------------------------------------------------------------------------------------------------
def _norm(text: str) -> str:
    return unicodedata.normalize("NFC", text).lower()


def _confidence(score: int) -> str:
    return "NONE" if score <= 0 else "LOW" if score == 1 else "MEDIUM" if score <= 3 else "HIGH"


def classify_prompt_attack(text: str, tier: str) -> tuple[str, list[str]]:
    langs = STANDARD_LANGUAGES if tier == "STANDARD" else CLASSIC_LANGUAGES
    t, score, hits = _norm(text), 0, []
    for pattern, category, weight, lang in PROMPT_ATTACK_PATTERNS:
        if lang not in langs or (category == "PROMPT_LEAKAGE" and tier != "STANDARD"):
            continue
        if re.search(pattern, t):
            score += weight
            hits.append(category)
    return _confidence(score), sorted(set(hits))


def classify_content(text: str, category: str) -> str:
    t = _norm(text)
    return _confidence(sum(w for p, w in CONTENT_PATTERNS.get(category, []) if re.search(p, t)))


def _keywords(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", _norm(text))
    out = set()
    for w in words:
        if w in STOPWORDS or len(w) < 2:
            continue
        w = re.sub(r"ies$", "y", w)
        w = re.sub(r"(?<=[a-z]{3})s$", "", w)
        out.add(w)
    return out


def topic_matches(text: str, topic: dict) -> bool:
    keys = _keywords(topic.get("definition", "") + " " + " ".join(topic.get("examples") or []) + " " + topic.get("name", ""))
    return len(keys & _keywords(text)) >= 2


def _pii_entities(cfg: dict) -> list[dict]:
    return (cfg.get("sensitiveInformationPolicyConfig") or {}).get("piiEntitiesConfig") or []


def _regexes(cfg: dict) -> list[dict]:
    return (cfg.get("sensitiveInformationPolicyConfig") or {}).get("regexesConfig") or []


def _action(item: dict, source: str, default: str = "BLOCK") -> tuple[bool, str]:
    """(enabled, action) for INPUT or OUTPUT, following the input*/output* fields with `action` as the fallback."""
    side = "input" if source == "INPUT" else "output"
    enabled = item.get(f"{side}Enabled", True)
    return enabled, (item.get(f"{side}Action") or item.get("action") or default).upper()


def grounding_scores(source_text: str, query: str, answer: str) -> tuple[float, float]:
    a, s, q = _keywords(answer), _keywords(source_text), _keywords(query)
    grounding = len(a & s) / len(a) if a else 1.0
    relevance = len(q & a) / len(q) if q else 1.0
    return round(grounding, 2), round(relevance, 2)


# --------------------------------------------------------------------------------------------------------------------
# One evaluation pass over some text: returns an assessment (ApplyGuardrail shape), the possibly masked text,
# whether anything BLOCKED, and the text units used per policy.
# --------------------------------------------------------------------------------------------------------------------
def units(chars: int) -> int:
    return math.ceil(chars / 1000) if chars else 0


def assess(cfg: dict, source: str, text: str, grounding: dict | None = None, policies: str = "all") -> dict:
    """policies="all" for normal content; "grounding" when the text only feeds the grounding check."""
    tier_c, tier_t = tier_of(cfg, "contentPolicyConfig"), tier_of(cfg, "topicPolicyConfig")
    a: dict = {}
    blocked, masked = False, text
    usage = {"contentPolicyUnits": 0, "topicPolicyUnits": 0, "wordPolicyUnits": 0,
             "sensitiveInformationPolicyUnits": 0, "sensitiveInformationPolicyFreeUnits": 0,
             "contextualGroundingPolicyUnits": 0}
    n = units(len(text))

    if policies == "all":
        filters = (cfg.get("contentPolicyConfig") or {}).get("filtersConfig") or []
        if filters:
            usage["contentPolicyUnits"] = n
        found = []
        for f in filters:
            ftype = f["type"].upper()
            if ftype == "PROMPT_ATTACK" and source != "INPUT":
                continue  # the prompt attack filter evaluates prompts only
            enabled, action = _action(f, source)
            strength = (f.get("inputStrength") if source == "INPUT" else f.get("outputStrength")) or "NONE"
            if not enabled or strength == "NONE":
                continue
            if ftype == "PROMPT_ATTACK":
                conf, cats = classify_prompt_attack(text, tier_c)
            else:
                conf, cats = classify_content(text, ftype), []
            detected = conf in BLOCKED_AT[strength.upper()]
            if conf != "NONE":
                entry = {"type": ftype, "confidence": conf, "filterStrength": strength, "detected": detected,
                         "action": "BLOCKED" if detected and action == "BLOCK" else "NONE"}
                if cats:
                    entry["_standInCategories"] = cats
                found.append(entry)
                blocked |= detected and action == "BLOCK"
        if found:
            a["contentPolicy"] = {"filters": found}

        topics = (cfg.get("topicPolicyConfig") or {}).get("topicsConfig") or []
        if topics:
            usage["topicPolicyUnits"] = n
        hits = []
        for t in topics:
            enabled, action = _action(t, source)
            if enabled and topic_matches(text, t):
                hits.append({"name": t["name"], "type": "DENY", "detected": True,
                             "action": "BLOCKED" if action == "BLOCK" else "NONE"})
                blocked |= action == "BLOCK"
        if hits:
            a["topicPolicy"] = {"topics": hits}

        wp = cfg.get("wordPolicyConfig") or {}
        words = []
        for w in wp.get("wordsConfig") or []:
            enabled, action = _action(w, source)
            if enabled and re.search(r"(?<!\w)" + re.escape(w["text"].lower()) + r"(?!\w)", text.lower()):
                words.append({"match": w["text"], "detected": True, "action": "BLOCKED" if action == "BLOCK" else "NONE"})
                blocked |= action == "BLOCK"
        if wp:
            usage["wordPolicyUnits"] = n
        if words:
            a["wordPolicy"] = {"customWords": words}

        pii_found, rx_found = [], []
        if _pii_entities(cfg):
            usage["sensitiveInformationPolicyUnits"] = n
        for e in _pii_entities(cfg):
            enabled, action = _action(e, source)
            pattern = PII_PATTERNS.get(e["type"])
            if not enabled or not pattern:
                continue
            for m in re.finditer(pattern, text):
                pii_found.append({"type": e["type"], "match": m.group(0), "detected": True,
                                  "action": {"BLOCK": "BLOCKED", "ANONYMIZE": "ANONYMIZED"}.get(action, "NONE")})
                blocked |= action == "BLOCK"
                if action == "ANONYMIZE":
                    masked = masked.replace(m.group(0), "{" + e["type"] + "}")
        for r in _regexes(cfg):
            enabled, action = _action(r, source)
            if not enabled:
                continue
            for m in re.finditer(r["pattern"], text):
                rx_found.append({"name": r["name"], "match": m.group(0), "detected": True,
                                 "action": {"BLOCK": "BLOCKED", "ANONYMIZE": "ANONYMIZED"}.get(action, "NONE")})
                blocked |= action == "BLOCK"
                if action == "ANONYMIZE":
                    masked = masked.replace(m.group(0), "{" + r["name"] + "}")
        if _regexes(cfg):
            usage["sensitiveInformationPolicyFreeUnits"] = n
        if pii_found or rx_found:
            a["sensitiveInformationPolicy"] = {"piiEntities": pii_found, "regexes": rx_found}

    gp = (cfg.get("contextualGroundingPolicyConfig") or {}).get("filtersConfig") or []
    if gp and source == "OUTPUT" and grounding:
        g, r = grounding_scores(grounding.get("source", ""), grounding.get("query", ""), text)
        usage["contextualGroundingPolicyUnits"] = units(len(grounding.get("source", "")) + len(grounding.get("query", "")) + len(text))
        res = []
        for f in gp:
            score = g if f["type"].upper() == "GROUNDING" else r
            detected = score < float(f["threshold"])
            action = (f.get("action") or "BLOCK").upper()
            res.append({"type": f["type"].upper(), "threshold": f["threshold"], "score": score, "detected": detected,
                        "action": "BLOCKED" if detected and action == "BLOCK" else "NONE"})
            blocked |= detected and action == "BLOCK"
        a["contextualGroundingPolicy"] = {"filters": res}

    return {"assessment": a, "blocked": blocked, "masked": masked, "usage": usage}


def _add(total: dict, usage: dict) -> None:
    for k, v in usage.items():
        total[k] = total.get(k, 0) + v


def cost_of(usage: dict) -> float:
    return round(
        usage.get("contentPolicyUnits", 0) * PRICE_PER_1000_UNITS["content"] / 1000
        + usage.get("topicPolicyUnits", 0) * PRICE_PER_1000_UNITS["topic"] / 1000
        + usage.get("sensitiveInformationPolicyUnits", 0) * PRICE_PER_1000_UNITS["sensitive"] / 1000
        + usage.get("contextualGroundingPolicyUnits", 0) * PRICE_PER_1000_UNITS["grounding"] / 1000, 8)


# --------------------------------------------------------------------------------------------------------------------
# ApplyGuardrail: evaluate any text, no model involved (lesson 12.2)
# --------------------------------------------------------------------------------------------------------------------
def apply_guardrail(cfg: dict, source: str, content: list[dict], output_scope: str = "INTERVENTIONS") -> dict:
    """Same request/response shape as bedrock-runtime ApplyGuardrail (a subset of fields)."""
    source = source.upper()
    total: dict = {}
    assessments, outputs, blocked, any_mask = [], [], False, False
    g_source = " ".join(c["text"]["text"] for c in content if "grounding_source" in (c["text"].get("qualifiers") or []))
    g_query = " ".join(c["text"]["text"] for c in content if "query" in (c["text"].get("qualifiers") or []))
    guarded = total_chars = 0
    for c in content:
        txt, quals = c["text"]["text"], c["text"].get("qualifiers") or []
        total_chars += len(txt)
        other = (not quals) or "guard_content" in quals
        if not other:
            continue  # grounding_source / query blocks are only used by the grounding check
        guarded += len(txt)
        r = assess(cfg, source, txt, grounding={"source": g_source, "query": g_query} if g_source else None)
        _add(total, r["usage"])
        if r["assessment"]:
            assessments.append(r["assessment"])
        blocked |= r["blocked"]
        any_mask |= r["masked"] != txt
        outputs.append({"text": r["masked"]})
    intervened = blocked or any_mask
    if blocked:
        msg = cfg["blockedInputMessaging"] if source == "INPUT" else cfg["blockedOutputsMessaging"]
        outputs = [{"text": msg}]
    elif not intervened:
        outputs = []
    return {"action": "GUARDRAIL_INTERVENED" if intervened else "NONE", "outputs": outputs,
            "assessments": assessments if (intervened or output_scope == "FULL") else [],
            "usage": total, "guardrailCoverage": {"textCharacters": {"guarded": guarded, "total": total_chars}}}


# --------------------------------------------------------------------------------------------------------------------
# Converse with guardrailConfig (lesson 12.1/12.3): which parts of the request the guardrail actually sees
# --------------------------------------------------------------------------------------------------------------------
def _blocks_text(block: dict) -> tuple[str, list[str], bool] | None:
    """(text, qualifiers, is_guard_content) for a content block the guardrail could see; None for tool blocks."""
    if "text" in block and isinstance(block["text"], str):
        return block["text"], [], False
    if "guardContent" in block:
        t = block["guardContent"]["text"]
        return t["text"], t.get("qualifiers") or [], True
    return None  # toolResult, toolUse, images...: not evaluated by a guardrail in Converse


def input_view(system: list[dict], messages: list[dict]) -> dict:
    """Which input text the guardrail evaluates, following the AWS 'Message and system prompt guardrail behavior' table."""
    msg_blocks = [b for m in messages for b in m["content"]]
    has_gc = any("guardContent" in b for b in msg_blocks)
    evaluated, grounding_src, grounding_q, total = [], [], [], 0
    for b in system:
        info = _blocks_text(b)
        if info:
            total += len(info[0])
            if info[2]:
                evaluated.append(info[0])  # system text counts only inside guardContent
    for b in msg_blocks:
        if "toolResult" in b:
            total += len(json.dumps(b["toolResult"]))
            continue
        info = _blocks_text(b)
        if not info:
            continue
        text, quals, is_gc = info
        total += len(text)
        if "grounding_source" in quals:
            grounding_src.append(text)
        if "query" in quals:
            grounding_q.append(text)
        if has_gc and not is_gc:
            continue
        if is_gc and quals and "guard_content" not in quals:
            continue
        evaluated.append(text)
    return {"evaluated": evaluated, "grounding_source": " ".join(grounding_src), "query": " ".join(grounding_q),
            "guarded_chars": sum(len(t) for t in evaluated), "total_chars": total}


def converse(cfg: dict | None, guardrail_config: dict | None, system: list[dict], messages: list[dict], model_fn) -> dict:
    """Run one Converse call through the guardrail. model_fn(system, messages) -> {"text": str, "toolUse": dict|None}."""
    if not cfg or not guardrail_config:
        out = model_fn(system, messages)
        return {"stopReason": "tool_use" if out.get("toolUse") else "end_turn", "output": out, "trace": None,
                "usage": {}, "coverage": None, "intervened": False}

    usage: dict = {}
    view = input_view(system, messages)
    in_assess, in_blocked = [], False
    for text in view["evaluated"]:
        r = assess(cfg, "INPUT", text)
        _add(usage, r["usage"])
        if r["assessment"]:
            in_assess.append(r["assessment"])
        in_blocked |= r["blocked"]
    coverage = {"textCharacters": {"guarded": view["guarded_chars"], "total": view["total_chars"]}}
    trace = {"inputAssessment": in_assess, "outputAssessments": []}
    if in_blocked:  # "the foundation model inference is discarded": the model never sees the prompt
        return {"stopReason": "guardrail_intervened", "output": {"text": cfg["blockedInputMessaging"], "toolUse": None},
                "trace": trace, "usage": usage, "coverage": coverage, "intervened": True}

    out = model_fn(system, messages)
    if out.get("toolUse"):  # the model's tool-call arguments are not evaluated
        return {"stopReason": "tool_use", "output": out, "trace": trace, "usage": usage, "coverage": coverage,
                "intervened": False}

    mode = (guardrail_config.get("streamProcessingMode") or "sync").lower()
    g = {"source": view["grounding_source"], "query": view["query"]} if view["grounding_source"] else None
    r = assess(cfg, "OUTPUT", out["text"], grounding=g)
    _add(usage, r["usage"])
    if r["assessment"]:
        trace["outputAssessments"].append(r["assessment"])
    text, intervened = out["text"], False
    if r["blocked"]:
        intervened = True
        if mode == "async":  # chunks already streamed before the scan finished (simplified: the first sentence)
            first = re.split(r"(?<=[.!?])\s", out["text"], maxsplit=1)[0]
            text = first + " " + cfg["blockedOutputsMessaging"]
        else:
            text = cfg["blockedOutputsMessaging"]
    elif r["masked"] != out["text"]:
        if mode == "async":
            pass  # "Amazon Bedrock Guardrails doesn't support the masking of sensitive information with asynchronous mode."
        else:
            text, intervened = r["masked"], True
    if guardrail_config.get("trace", "disabled") == "disabled":
        trace = None  # the caller asked for no trace: the app can't log what the guardrail saw
    return {"stopReason": "guardrail_intervened" if intervened else "end_turn", "output": {"text": text, "toolUse": None},
            "trace": trace, "usage": usage, "coverage": coverage, "intervened": intervened}


def copy_cfg(cfg: dict) -> dict:
    return copy.deepcopy(cfg)
