"""
helpdesk_agent.py: the TSG Helpdesk agent as ported to Google Cloud (GC13), built from a twin's deployment.json.

Four tools, the same jobs as the Module 6 knowledge bot and the Module 7 agent:
    search_kb(query, team)          read   RAG Engine retrieveContexts, or Agent Search search
    get_ticket(ticket_id)           read   a ticket (customer text is untrusted)
    send_email(to, subject, body)   WRITE  appends to an in-memory outbox; nothing is sent anywhere
    close_ticket(ticket_id)         WRITE  changes the ticket's status in memory

What changes between twins is only configuration: where the end user's identity comes from, who chooses the
search scope, which identity calls the backends, which tools need a person's approval, and the Model Armor plugin.
"""

from __future__ import annotations

import copy
import importlib

from adk_twin import ModelArmorPluginTwin, Runner, Tool
from gcp_twin import HERE, TICKETS, AgentSearchTwin, IdentityTwin, ModelArmorTwin, RagEngineTwin, load_json
from stand_in_model import StandInModel


def load_deployment(twin: str) -> dict:
    return load_json(HERE / "twin" / twin / "deployment.json")


def agent_principal(dep: dict) -> str:
    ident = dep["agent"]["identity"]
    if ident.get("identity_type") == "AGENT_IDENTITY":
        return "principal://agents.global.org-ORGANIZATION_ID.system.id.goog/resources/aiplatform/..."
    if ident.get("service_account"):
        return f"serviceAccount:{ident['service_account']}"
    # Agent Runtime's default identity: the AI Platform Reasoning Engine Service Agent (one per project)
    return f"serviceAccount:service-{dep['project_number']}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"


class Helpdesk:
    def __init__(self, dep: dict, armor_available: bool = True):
        self.dep = copy.deepcopy(dep)
        a = self.dep["agent"]
        self.principal = agent_principal(self.dep)
        self.rag = RagEngineTwin(self.dep)
        self.search = AgentSearchTwin(self.dep) if self.dep["retrieval"].get("agent_search") else None
        self.backend = self.dep["retrieval"]["backend"]
        self.outbox: list[dict] = []
        self.tickets = copy.deepcopy(TICKETS)
        self.armor = ModelArmorTwin(available=armor_available)
        plugins = []
        ma = a.get("plugins", {}).get("model_armor")
        if ma:
            plugins.append(ModelArmorPluginTwin(armor=self.armor, **ma))
        before = None
        if a.get("before_tool_callback"):
            mod, fn = a["before_tool_callback"].rsplit(".", 1)
            before = getattr(importlib.reload(importlib.import_module(mod)), fn)
        t = a["tools"]
        tools = {
            "search_kb": Tool("search_kb", self._search_kb, **{k: v for k, v in t["search_kb"].items() if k == "writes"}),
            "get_ticket": Tool("get_ticket", self._get_ticket),
            "send_email": Tool("send_email", self._send_email, writes=True, confirmation=t["send_email"]["confirmation"]),
            "close_ticket": Tool("close_ticket", self._close_ticket, writes=True,
                                 confirmation=t["close_ticket"]["confirmation"]),
        }
        self.runner = Runner(StandInModel(), tools, plugins=plugins, before_tool=before,
                             audit_fields=a["observability"]["tool_log_fields"], agent_principal=self.principal)

    # -- who is asking? -----------------------------------------------------------------------------------------
    def end_user(self, request: dict) -> str | None:
        if self.dep["agent"]["user_id_from"] == "verified_id_token":
            return IdentityTwin.verify(request.get("id_token"))
        return request.get("user_id")             # whatever the client put in the request body

    def ask(self, request: dict, human=None):
        user = self.end_user(request)
        if user is None:
            return None, {"answer": "Sign-in required.", "events": []}
        state = {"end_user": user, "groups": IdentityTwin.groups(user)}   # set by your server, not by the client
        turn = self.runner.run(request["message"], state, human=human)
        return user, {"answer": turn.answer, "events": turn.events, "paused": turn.paused}

    # -- tools ------------------------------------------------------------------------------------------------
    def _search_kb(self, args: dict, ctx) -> dict:
        if self.backend == "agent_search":
            cfg = self.dep["retrieval"]["agent_search"]
            caller = f"user:{ctx.state['end_user']}" if cfg["search_runs_as"] == "end_user" else self.principal
            return self.search.search(caller, args.get("query", ""))
        rag = self.dep["retrieval"]["rag_engine"]
        scope = rag["scope"]
        if scope["chosen_by"] == "model_args":
            # Today's port: one corpus, and the MODEL's "team" argument becomes the metadata filter.
            team = args.get("team")
            flt = f'team == "{team}"' if team and team != "all" else None
            return self.rag.retrieve_contexts(self.principal, rag["corpora"][0]["name"], args.get("query", ""), flt)
        # Hardened: the corpora come from the user's verified groups; the model's arguments can't widen them.
        merged = []
        for corpus in rag["corpora"]:
            if corpus.get("for_group") in ctx.state["groups"]:
                res = self.rag.retrieve_contexts(self.principal, corpus["name"], args.get("query", ""))
                merged += res.get("contexts", {}).get("contexts", [])
        merged.sort(key=lambda c: -c["score"])
        return {"contexts": {"contexts": merged[:2]}}

    def _get_ticket(self, args: dict, ctx) -> dict:
        tid = args.get("ticket_id")
        if tid not in self.tickets:
            return {"error": f"no ticket {tid}"}
        if self.dep["agent"]["tools"]["get_ticket"].get("check_ticket_team"):
            import controls
            if not controls.ticket_visible(tid, ctx.state["groups"]):
                return {"error": f"Ticket {tid} is not visible to this user."}
        t = self.tickets[tid]
        return {"ticket_id": tid, "customer": t["customer"], "status": t["status"], "text": t["text"]}

    def _send_email(self, args: dict, ctx) -> dict:
        self.outbox.append(dict(args))
        return {"status": "sent", "to": args.get("to")}

    def _close_ticket(self, args: dict, ctx) -> dict:
        self.tickets[args["ticket_id"]]["status"] = "closed"
        return {"status": "closed", "ticket_id": args["ticket_id"]}


def build(twin: str = "today", armor_available: bool = True, **overrides) -> Helpdesk:
    dep = load_deployment(twin)
    if overrides.get("backend"):
        dep["retrieval"]["backend"] = overrides["backend"]
    return Helpdesk(dep, armor_available=armor_available)
