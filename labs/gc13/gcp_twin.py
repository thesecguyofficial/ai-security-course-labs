"""
gcp_twin.py: offline TEACHING STAND-INS for the Google Cloud services the Helpdesk agent uses (GC13). No network.

    IdentityTwin    a verified sign-in: an ID token maps to one user and their Google groups
    RagEngineTwin   RAG Engine retrieveContexts: corpora, an optional metadata filter, project-level permission
    AgentSearchTwin Agent Search search on a data store with acl_enabled: results trimmed to what the caller may read
    ModelArmorTwin  Model Armor sanitize: the sanitizationResult shape from GC12, a tiny detector, and outages

What each twin copies from Google's documentation (the README's "About the twins" has the sources):
  * RAG Engine checks permission on the PROJECT ("The users must have permission to make a call in the project",
    vertex_rag_service.proto). A RagCorpus has no per-document ACL field and no IAM policy of its own in the v1 API,
    so whoever may retrieve from one corpus in the project may retrieve from all of them.
  * A metadata filter only narrows the search: "Only files with metadata that matches the filter expression are
    considered for retrieval." Whoever writes the filter decides what is searched.
  * Agent Search with access control: "Google uses your identity provider to identify the end user performing a
    search and determine if they have access to the documents that are returned as results." The twin trims by the
    CALLER's identity: if the agent calls with its own service account, the caller is the agent, not your user.
What the twins do NOT copy: real embeddings, ranking, Google's classifiers. Retrieval here is word overlap.
"""

from __future__ import annotations

import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
CANARY = "CANARY-FIN-7731"
INJECTION_MARKER = "[LAB-INJECTED-DIRECTIVE"


def load_json(path) -> dict:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


DIRECTORY = load_json(HERE / "data" / "directory.json")
DOCS = {d["id"]: d for d in load_json(HERE / "data" / "docs.json")["documents"]}
TICKETS = {k: v for k, v in load_json(HERE / "data" / "tickets.json").items() if not k.startswith("_")}

STOP = set("a an and are as at be by can do does for from get go how i in is it me my of on or our the their this "
           "to up us we what when where which who why will with you your please check docs about".split())


def words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOP and len(w) > 1}


# ---------------------------------------------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------------------------------------------
class IdentityTwin:
    """Stands in for a verified OIDC ID token (signature, audience and expiry already checked by your front end)."""

    @staticmethod
    def verify(id_token: str | None) -> str | None:
        return DIRECTORY["id_tokens"].get(id_token or "")

    @staticmethod
    def groups(email: str | None) -> list[str]:
        return list(DIRECTORY["users"].get(email or "", {}).get("groups", []))


# ---------------------------------------------------------------------------------------------------------------
# RAG Engine
# ---------------------------------------------------------------------------------------------------------------
def _cel_match(doc: dict, metadata_filter: str | None) -> bool:
    """A tiny subset of the CEL filters RAG Engine accepts: `team == "x"`, joined with || or &&."""
    if not metadata_filter:
        return True
    if "||" in metadata_filter:
        return any(_cel_match(doc, part) for part in metadata_filter.split("||"))
    if "&&" in metadata_filter:
        return all(_cel_match(doc, part) for part in metadata_filter.split("&&"))
    m = re.fullmatch(r'\s*team\s*==\s*"([^"]*)"\s*', metadata_filter)
    return bool(m) and doc.get("team") == m.group(1)


def _score(query: str, doc: dict) -> int:
    return len(words(query) & words(doc["title"] + " " + doc["text"]))


class RagEngineTwin:
    def __init__(self, deployment: dict):
        rag = deployment["retrieval"]["rag_engine"]
        self.corpora = {c["name"]: c for c in rag["corpora"]}
        self.project_roles = deployment["agent"]["project_roles"]
        self.calls: list[dict] = []

    def retrieve_contexts(self, caller: str, rag_corpus: str, text: str, metadata_filter: str | None = None,
                          top_k: int = 2) -> dict:
        """Shape of RetrieveContextsResponse: {"contexts": {"contexts": [{sourceUri, sourceDisplayName, text, score}]}}."""
        self.calls.append({"caller": caller, "rag_corpus": rag_corpus, "metadata_filter": metadata_filter})
        if "roles/aiplatform.user" not in self.project_roles and "roles/aiplatform.admin" not in self.project_roles:
            return {"error": {"code": 403, "status": "PERMISSION_DENIED"}}
        corpus = self.corpora.get(rag_corpus)
        if corpus is None:
            return {"error": {"code": 404, "status": "NOT_FOUND"}}
        hits = []
        for doc_id in corpus["documents"]:
            doc = DOCS[doc_id]
            s = _score(text, doc)
            if s > 0 and _cel_match(doc, metadata_filter):
                hits.append((s, doc))
        hits.sort(key=lambda h: (-h[0], h[1]["id"]))
        return {"contexts": {"contexts": [
            {"sourceUri": d["source"], "sourceDisplayName": d["title"], "text": d["text"], "score": round(s / 10, 2)}
            for s, d in hits[:top_k]]}}


# ---------------------------------------------------------------------------------------------------------------
# Agent Search
# ---------------------------------------------------------------------------------------------------------------
class AgentSearchTwin:
    def __init__(self, deployment: dict):
        self.cfg = deployment["retrieval"]["agent_search"]
        self.calls: list[dict] = []

    def _may_read(self, caller: str, doc: dict) -> bool:
        if not self.cfg["acl_enabled"]:
            return True
        if caller.startswith("serviceAccount:"):
            principals = {("user_id", caller.split(":", 1)[1])}
        else:
            email = caller.split(":", 1)[-1]
            principals = {("user_id", email)} | {("group_id", g) for g in IdentityTwin.groups(email)}
        for reader in doc["readers"]:
            if reader.get("idp_wide") or any((k, v) in principals for k, v in reader.items()):
                return True
        return False

    def search(self, caller: str, query: str, top_k: int = 2) -> dict:
        """Shape of SearchResponse, trimmed: {"results": [{"id", "document": {"name", "derivedStructData": {...}}}]}."""
        self.calls.append({"caller": caller, "query": query})
        hits = []
        for doc_id in self.cfg["documents"]:
            doc = DOCS[doc_id]
            s = _score(query, doc)
            if s > 0 and self._may_read(caller, doc):
                hits.append((s, doc))
        hits.sort(key=lambda h: (-h[0], h[1]["id"]))
        return {"results": [{"id": d["id"], "document": {
            "name": f"{self.cfg['data_store']}/branches/0/documents/{d['id']}",
            "derivedStructData": {"title": d["title"], "link": d["source"], "snippets": [{"snippet": d["text"]}]}}}
            for _, d in hits[:top_k]]}


# ---------------------------------------------------------------------------------------------------------------
# Model Armor
# ---------------------------------------------------------------------------------------------------------------
class ModelArmorUnavailable(ConnectionError):
    pass


class ModelArmorTwin:
    """Not Google's classifier: it matches the lab's injection marker and two classic phrases. Result shape as in
    GC12 (sanitizationResult.filterMatchState / invocationResult / filterResults.pi_and_jailbreak)."""

    PATTERNS = [re.escape(INJECTION_MARKER), r"ignore (all )?(previous|prior) instructions"]

    def __init__(self, available: bool = True):
        self.available = available
        self.calls = 0

    def sanitize(self, text: str, template_name: str) -> dict:
        self.calls += 1
        if not self.available:
            raise ModelArmorUnavailable(f"modelarmor: {template_name} unreachable (lab outage)")
        hit = any(re.search(p, text, re.I) for p in self.PATTERNS)
        state = "MATCH_FOUND" if hit else "NO_MATCH_FOUND"
        pi = {"executionState": "EXECUTION_SUCCESS", "matchState": state}
        if hit:
            pi["confidenceLevel"] = "HIGH"
        return {"sanitizationResult": {"filterMatchState": state, "invocationResult": "SUCCESS",
                                       "filterResults": {"pi_and_jailbreak": {"piAndJailbreakFilterResult": pi}}}}
