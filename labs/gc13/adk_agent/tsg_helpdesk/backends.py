"""
backends.py: what the Helpdesk agent's tools talk to.

    TSG_MODE=offline (default)  retrieval from the lab's RAG Engine twin (../../gcp_twin.py), no network
    TSG_MODE=cloud              retrieval from YOUR RAG Engine corpora (GUIDED-BUILD.md Step 2), as the identity
                                the agent runs with (Application Default Credentials locally, the service account
                                on Agent Runtime)

Tickets and email are local fakes in both modes: the ticket store is tickets.json in this folder (a copy of the
lab's data/tickets.json, so the folder deploys on its own) and "sent" email goes to the OUTBOX list below.
Nothing here sends email.
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import sys

LAB = pathlib.Path(__file__).resolve().parents[2]
MODE = os.environ.get("TSG_MODE", "offline")
HERE = pathlib.Path(__file__).resolve().parent
TICKETS = {k: v for k, v in json.loads((HERE / "tickets.json").read_text()).items() if not k.startswith("_")}
OUTBOX: list[dict] = []
STATE = {"tickets": copy.deepcopy(TICKETS)}

# Which corpus each group may search. The mapping lives here, on the server: the model never names a corpus.
GROUP_CORPUS = {
    "helpdesk-staff@example.com": os.environ.get("TSG_CORPUS_STAFF", "projects/example-chatbot-prod/locations/europe-west4/ragCorpora/kb-staff"),
    "finance-team@example.com": os.environ.get("TSG_CORPUS_FINANCE", "projects/example-chatbot-prod/locations/europe-west4/ragCorpora/kb-finance"),
}


def corpora_for(groups: list[str]) -> list[str]:
    return [GROUP_CORPUS[g] for g in groups if g in GROUP_CORPUS]


def _offline_retrieve(corpus: str, query: str) -> list[dict]:
    sys.path.append(str(LAB))
    from gcp_twin import RagEngineTwin, load_json
    dep = load_json(LAB / "twin" / "hardened" / "deployment.json")
    # GUIDED-BUILD Step 2 uploads the poisoned refund update into kb-staff ON PURPOSE (to test request G3).
    dep["retrieval"]["rag_engine"]["corpora"][0]["documents"].append("inbox-refund-update")
    for c in dep["retrieval"]["rag_engine"]["corpora"]:          # map your env names onto the twin's corpora
        if c["display_name"] in corpus or corpus.endswith(c["name"].rsplit("/", 1)[1]):
            corpus = c["name"]
    res = RagEngineTwin(dep).retrieve_contexts("serviceAccount:helpdesk-agent", corpus, query)
    return [{"source_uri": c["sourceUri"], "text": c["text"], "score": c["score"]}
            for c in res.get("contexts", {}).get("contexts", [])]


def _cloud_retrieve(corpus: str, query: str) -> list[dict]:
    import agentplatform     # google-cloud-agentplatform, installed with google-adk[gcp]
    client = agentplatform.Client(project=os.environ["GOOGLE_CLOUD_PROJECT"],
                                  location=os.environ.get("GOOGLE_CLOUD_LOCATION", "europe-west4"))
    resp = client.rag.retrieve_contexts(
        vertex_rag_store={"rag_resources": [{"rag_corpus": corpus}]},
        query={"text": query, "rag_retrieval_config": {"top_k": 3}},
    )
    found = (resp.contexts.contexts if resp.contexts else None) or []
    return [{"source_uri": c.source_uri, "text": c.text, "score": c.score} for c in found]


def search(query: str, groups: list[str]) -> dict:
    passages = []
    for corpus in corpora_for(groups):
        passages += (_cloud_retrieve if MODE == "cloud" else _offline_retrieve)(corpus, query)
    passages.sort(key=lambda p: -(p["score"] or 0))
    return {"passages": passages[:3]}


def get_ticket(ticket_id: str) -> dict | None:
    t = STATE["tickets"].get(ticket_id)
    return None if t is None else {"ticket_id": ticket_id, "customer": t["customer"], "status": t["status"],
                                   "text": t["text"]}


def send_email(to: str, subject: str, body: str) -> dict:
    OUTBOX.append({"to": to, "subject": subject, "body": body})
    return {"status": "sent", "to": to}


def close_ticket(ticket_id: str) -> dict:
    STATE["tickets"][ticket_id]["status"] = "closed"
    return {"status": "closed", "ticket_id": ticket_id}
