#!/usr/bin/env python3
"""House-voice checker: flags text that sounds generic or AI-written.

Owner rule (22 Oct 2026): everything we publish (site pages, notes, course lessons and slides,
lab guides, video scripts, reel captions, social posts, emails) must read like a practitioner
wrote it. Rules come from docs/social/voice-guide.md ("Avoid" list). This file is the canonical
copy; the course-content and labs repos carry an identical copy (keep them in sync).

Errors (exit 1): banned words/phrases, em dashes in prose, British spellings (house style is US
English since 6 Nov 2026: enroll, program, defense, center, behavior, organize ...).
Warnings: very long sentences, stacked "Not X. Not Y." patterns, exclamation marks.

Skips: fenced code blocks, inline code, URLs, HTML comments, quoted source text in blockquotes,
and any line containing the marker `style-ok` (use it for real exceptions, e.g. a product term
like "lessons unlock on 1 Nov", or quoting a source verbatim).

Usage: python3 tools/style/style_check.py [paths...]   (defaults to the paths in DEFAULT_PATHS)
       --warnings   also print warnings
"""
import re, sys, pathlib

BANNED = [
    r"\bdelv(e|es|ing)\b", r"\btapestry\b", r"\brealm\b", r"\blandscape\b", r"\bgame[- ]changer\b",
    r"\bunlock (the|your)\b", r"\bunleash", r"\bharness the power\b", r"\bseamless(ly)?\b", r"\brobust\b",
    r"\bleverag(e|es|ed|ing)\b", r"\bcrucial\b", r"\bpivotal\b", r"\bit'?s (worth|important to) not(e|ing)\b",
    r"\bit is important to note\b", r"\bnavigat(e|ing) the complexit", r"\bin conclusion\b", r"\bfurthermore\b",
    r"\bmoreover\b", r"\btestament to\b", r"\bembark(s|ing)?\b", r"\belevate(s|d)?\b", r"\bempower(s|ing|ed)?\b",
    r"\bsupercharge", r"\blet'?s dive\b", r"\bdeep dive\b", r"\bdive into\b",
    r"\bin today'?s (fast[- ]paced|digital|ever)", r"\bever[- ]evolving\b", r"\brapidly evolving\b",
]
BANNED_RE = re.compile("|".join(BANNED), re.I)
# US English (owner decision 6 Nov 2026). Hyphen/underscore/slash neighbors are skipped so code names
# like `enrol-dialog` are not flagged; use `style-ok` for a verbatim quote or a proper name.
UK_US = {"personalisation": "personalization", "organisations": "organizations", "authorisation": "authorization", "customisation": "customization", "visualisation": "visualization", "decentralised": "decentralized", "organisation": "organization", "personalised": "personalized", "minimisation": "minimization", "unauthorised": "unauthorized", "prioritising": "prioritizing", "optimisation": "optimization", "sanitisation": "sanitization", "standardised": "standardized", "tokenisation": "tokenization", "characterise": "characterize", "behavioural": "behavioral", "recognising": "recognizing", "summarising": "summarizing", "prioritised": "prioritized", "standardise": "standardize", "categorised": "categorized", "specialised": "specialized", "instalments": "installments", "utilisation": "utilization", "initialised": "initialized", "synchronise": "synchronize", "familiarise": "familiarize", "centralised": "centralized", "enrolments": "enrollments", "programmes": "programs", "behaviours": "behaviors", "favourites": "favorites", "organising": "organizing", "recognised": "recognized", "recognises": "recognizes", "summarised": "summarized", "summarises": "summarizes", "authorised": "authorized", "authorises": "authorizes", "memorising": "memorizing", "prioritise": "prioritize", "normalised": "normalized", "categorise": "categorize", "customised": "customized", "specialise": "specialize", "travelling": "traveling", "cancelling": "canceling", "fulfilment": "fulfillment", "instalment": "installment", "practising": "practicing", "initialise": "initialize", "serialised": "serialized", "randomised": "randomized", "neutralise": "neutralize", "capitalise": "capitalize", "centralise": "centralize", "legitimise": "legitimize", "enrolment": "enrollment", "programme": "program", "behaviour": "behavior", "favourite": "favorite", "organised": "organized", "recognise": "recognize", "summarise": "summarize", "minimised": "minimized", "minimises": "minimizes", "authorise": "authorize", "optimised": "optimized", "analysing": "analyzing", "normalise": "normalize", "sanitised": "sanitized", "emphasise": "emphasize", "customise": "customize", "apologise": "apologize", "modellers": "modelers", "modelling": "modeling", "travelled": "traveled", "cancelled": "canceled", "labelling": "labeling", "catalogue": "catalog", "judgement": "judgment", "artefacts": "artifacts", "jewellery": "jewelry", "enquiries": "inquiries", "sceptical": "skeptical", "manoeuvre": "maneuver", "visualise": "visualize", "serialise": "serialize", "tokenised": "tokenized", "randomise": "randomize", "finalised": "finalized", "stabilise": "stabilize", "harmonise": "harmonize", "criticise": "criticize", "defences": "defenses", "coloured": "colored", "organise": "organize", "minimise": "minimize", "memorise": "memorize", "realised": "realized", "optimise": "optimize", "analysed": "analyzed", "sanitise": "sanitize", "licences": "licenses", "modeller": "modeler", "modelled": "modeled", "labelled": "labeled", "dialogue": "dialog", "artefact": "artifact", "practise": "practice", "analogue": "analog", "pretence": "pretense", "tokenise": "tokenize", "mobilise": "mobilize", "finalise": "finalize", "monetise": "monetize", "defence": "defense", "centres": "centers", "centred": "centered", "colours": "colors", "realise": "realize", "analyse": "analyze", "utilise": "utilize", "licence": "license", "towards": "toward", "amongst": "among", "enquiry": "inquiry", "offence": "offense", "enrols": "enrolls", "centre": "center", "colour": "color", "honour": "honor", "cheque": "check", "ageing": "aging", "learnt": "learned", "fulfil": "fulfill", "whilst": "while", "tonnes": "tons", "metres": "meters", "enrol": "enroll", "maths": "math", "metre": "meter", "grey": "gray"}
# Where the spelling rule applies: prose files, user-facing strings in code, and course content data
# (lesson quizzes / module JSON). Lab inputs (JSON, YAML, requirements) are code, and the capstone rubrics
# are hash-locked by the grader (tools/capstone-grader/*.lock.json), so they are left alone.
UK_EXT = {".md", ".mdx", ".astro", ".html", ".js", ".mjs", ".ts"}
UK_DATA_PARTS = ("modules/", "src/content/")
UK_SKIP_PARTS = ("labs/m19/RUBRIC.md", "labs/m32/RUBRIC.md")
UK_RE = re.compile(r"(?<![-_/.#@])\b(" + "|".join(UK_US) + r")\b(?![-_/(])", re.I)
EMDASH = "—"
TEXT_EXT = {".md", ".mdx", ".txt", ".astro", ".html", ".json", ".yml", ".yaml"}
DEFAULT_PATHS = ["README.md", "labs"]
# Files that may legitimately contain the words (rule lists, this checker, raw source quotes).
IGNORE_PARTS = (".venv", "voice-guide.md", "style_check", "node_modules", "/build/", "/out/", ".work", "words-0")
# Published, recorded material: changing the script no longer changes the video. Checked as warnings only.
WARN_ONLY_PARTS = ()


def strip(line):
    line = re.sub(r"`[^`]*`", "", line)
    line = re.sub(r"https?://\S+", "", line)
    line = re.sub(r"<!--.*?-->", "", line)
    return line


def check_file(p, errors, warnings):
    s = str(p)
    if any(part in s for part in IGNORE_PARTS):
        return
    warn_only = any(part in s for part in WARN_ONLY_PARTS)
    try:
        text = p.read_text(encoding="utf-8")
    except Exception:
        return
    in_fence = in_comment = False
    is_code_file = p.suffix in {".js", ".mjs", ".ts"}
    for n, raw in enumerate(text.splitlines(), 1):
        if raw.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if "<!--" in raw and "-->" not in raw:
            in_comment = True
        if in_comment:
            if "-->" in raw:
                in_comment = False
            continue
        if in_fence or "style-ok" in raw or raw.lstrip().startswith(">"):
            continue
        if is_code_file:
            # only the human-facing strings inside code
            parts = re.findall(r"`([^`]*)`|'([^'\n]*)'|\"([^\"\n]*)\"", raw)
            line = " ".join(a or b or c for a, b, c in parts)
        else:
            line = strip(raw)
        target = warnings if warn_only else errors
        for m in BANNED_RE.finditer(line):
            target.append(f"{p}:{n}: banned phrase '{m.group(0)}'")
        uk_ok = (p.suffix in UK_EXT or any(x in s for x in UK_DATA_PARTS)) and not any(x in s for x in UK_SKIP_PARTS) and p.name != "requirements.txt"
        for m in (UK_RE.finditer(line) if uk_ok else ()):
            target.append(f"{p}:{n}: British spelling '{m.group(0)}' (house style is US English: {UK_US[m.group(0).lower()]})")
        if EMDASH in line and not line.lstrip().startswith("|"):
            target.append(f"{p}:{n}: em dash in prose (use a full stop, colon, comma or brackets)")
        for sent in re.split(r"(?<=[.!?])\s+", line):
            if len(sent.split()) > 40:
                warnings.append(f"{p}:{n}: long sentence ({len(sent.split())} words)")
        if len(re.findall(r"\bNot [A-Za-z ]{1,25}\.", line)) >= 2:
            warnings.append(f"{p}:{n}: stacked 'Not X. Not Y.' pattern")
        if re.search(r"[a-z0-9]!(\s|$)", line) and not is_code_file:
            warnings.append(f"{p}:{n}: exclamation mark")


def main(argv):
    show_warn = "--warnings" in argv
    paths = [a for a in argv if not a.startswith("--")] or DEFAULT_PATHS
    errors, warnings = [], []
    for root in paths:
        r = pathlib.Path(root)
        if not r.exists():
            continue
        files = [r] if r.is_file() else [f for f in r.rglob("*") if f.is_file()]
        for f in files:
            if f.suffix in TEXT_EXT or f.suffix in {".js", ".mjs"}:
                check_file(f, errors, warnings)
    for e in errors:
        print("ERROR", e)
    if show_warn:
        for w in warnings:
            print("warn ", w)
    print(f"style_check: {len(errors)} error(s), {len(warnings)} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
