"""Retrieval for the Helpdesk: a tiny keyword search over data/kb/*.md. Core file: do not edit.

It searches EVERY document for EVERY user. Each document says who it is for in its front matter
(tenant: all | acme | globex ..., audience: public | staff, source: tsg-kb | partner-feed), but this file
does not look at those fields. Whether a user may see a document is decided in guards.filter_retrieval().
"""
from __future__ import annotations

import os
import pathlib
import re
from dataclasses import dataclass

KB_DIR = pathlib.Path(__file__).resolve().parent.parent / "data" / "kb"
WORD = re.compile(r"[a-z0-9]+")
MIN_SCORE = 2          # one stray word in common is not a match
STOP = set("a an and are as at be by can do does for from get got how i if in is it me my of on or our please "
           "the this to was we what when where which who why will with you your show tell know need help about could would "
           "up there here any some".split())


@dataclass
class Doc:
    id: str
    title: str
    tenant: str
    audience: str
    source: str
    text: str
    path: str
    score: float = 0.0

    @property
    def flags(self) -> list[str]:
        """Things about the raw text a reviewer (or a detection rule) would want to know."""
        out = []
        if "<!--" in self.text:
            out.append("html_comment")
        if re.search(r"<\s*(img|script|iframe|svg)\b", self.text, re.I):
            out.append("html_tag")
        if re.search(r"[​-‏⁠﻿]", self.text):
            out.append("zero_width")
        return out


def parse(path: pathlib.Path) -> Doc:
    raw = path.read_text(encoding="utf-8")
    meta, body = {}, raw
    if raw.startswith("---"):
        _, head, body = raw.split("---", 2)
        for line in head.strip().splitlines():
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return Doc(id=meta.get("id", path.stem), title=meta.get("title", path.stem), tenant=meta.get("tenant", "all"),
               audience=meta.get("audience", "public"), source=meta.get("source", "unknown"),
               text=body.strip(), path=str(path))


def load_all() -> list[Doc]:
    """Every document in data/kb, plus any folder named in TSG_EXTRA_KB (the eval runner adds test pages there)."""
    dirs = [KB_DIR] + [pathlib.Path(x) for x in os.environ.get("TSG_EXTRA_KB", "").split(os.pathsep) if x]
    return [parse(p) for d in dirs for p in sorted(d.glob("*.md"))]


def tokens(text: str) -> list[str]:
    return [w for w in WORD.findall(text.lower()) if w not in STOP and len(w) > 1]


def search(query: str, k: int = 2, docs: list[Doc] | None = None) -> list[Doc]:
    """Return the k best documents for the query (title words count double). No access check here."""
    q = set(tokens(query))
    if not q:
        return []
    scored = []
    for d in (docs if docs is not None else load_all()):
        body, title = tokens(d.text), set(tokens(d.title))
        score = sum(1 for w in body if w in q) + 2 * len(q & title)
        if score >= MIN_SCORE:
            scored.append((score, d))
    scored.sort(key=lambda x: (-x[0], x[1].id))
    out = []
    for score, d in scored[:k]:
        d.score = float(score)
        out.append(d)
    return out
