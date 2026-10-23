"""
twin.py: offline teaching stand-ins for the Google Cloud pieces the Helpdesk agent runs on in GC14.

None of these is Google's service. Each copies only the DECISIONS this lab depends on, from Google's documentation:

  AgentIdentity   who the agent is: its own principal (Agent Identity) or the project's Reasoning Engine service agent
  IamTwin         may this principal use this permission on this resource? (bindings, principalSet, project parent)
  ModelArmorTwin  a verdict for a tool response: MATCH_FOUND or NO_MATCH_FOUND. The lab doesn't contain any attack
                  text; each case says how a prompt-injection filter would classify the response it came from.
  GatewayTwin     Agent Gateway, Agent-to-Anywhere: registry lookup, default deny, Unified Access Policy rules
                  (deny first, CEL conditions), DRY_RUN, and Model Armor on MCP tools/call requests and responses
                  (not on tools/list, which Google's page lists as not sanitized)
  MemoryBankTwin  memories kept per scope dict, generation limited to enabled topics, TTL, revisions

decide.py asks these twins about each proposed tool call in data/cases.json and prints who decided what.
"""

from __future__ import annotations

import copy
import json
import pathlib
import cel

HERE = pathlib.Path(__file__).resolve().parent
PERM_EGRESS = "iap.googleapis.com/resources.egressViaIAP"
ROLE_PERMS = {   # only the permissions this lab checks (from each role's documented purpose; trimmed)
    "roles/bigquery.dataViewer": {"bigquery.tables.getData"},
    "roles/bigquery.dataEditor": {"bigquery.tables.getData", "bigquery.tables.updateData"},
    "roles/bigquery.admin": {"bigquery.tables.getData", "bigquery.tables.updateData"},
    "roles/editor": {"bigquery.tables.getData", "bigquery.tables.updateData"},
    "roles/owner": {"bigquery.tables.getData", "bigquery.tables.updateData"},
    "roles/aiplatform.memoryViewer": {"aiplatform.memories.retrieve"},
    "roles/aiplatform.memoryEditor": {"aiplatform.memories.retrieve", "aiplatform.memories.generate"},
}


def load_json(path) -> dict:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def load_deployment(twin: str) -> dict:
    return load_json(HERE / "twin" / twin / "deployment.json")


def load_registry(rugpull: bool = False) -> dict:
    return load_json(HERE / "twin" / ("registry-rugpull.json" if rugpull else "registry.json"))


DIRECTORY = load_json(HERE / "data" / "directory.json")
CASES = load_json(HERE / "data" / "cases.json")["cases"]


# ---- identity --------------------------------------------------------------------------------------------------
def agent_principal(dep: dict) -> str:
    """The identity the agent's calls carry. Mirrors ReasoningEngineSpec.identity_type in the API definition:
    AGENT_IDENTITY -> the agent's own principal; otherwise the custom service account if set, else the project's
    Reasoning Engine service agent (one per project)."""
    a = dep["agent"]
    if a.get("identity_type") == "AGENT_IDENTITY":
        return a["effective_identity"]
    if a.get("service_account"):
        return f"serviceAccount:{a['service_account']}"
    return f"serviceAccount:service-{dep['project_number']}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"


def member_matches(member: str, principal: str) -> bool:
    """principalSet://.../attribute.platformContainer/aiplatform/projects/N matches every agent in project N."""
    if member == principal:
        return True
    if member.startswith("principalSet://") and "/attribute.platformContainer/aiplatform/projects/" in member:
        domain, rest = member[len("principalSet://"):].split("/attribute.platformContainer/aiplatform/", 1)
        return principal.startswith(f"principal://{domain}/resources/aiplatform/{rest}/")
    return False


class IamTwin:
    def __init__(self, dep: dict):
        self.bindings = dep["iam_bindings"]
        self.project_res = f"//cloudresourcemanager.googleapis.com/projects/{dep['project']}"

    def allows(self, principal: str, permission: str, resource: str) -> tuple[bool, str]:
        for b in self.bindings:
            on_target = b["resource"] == resource or b["resource"] == self.project_res   # project is the parent
            if on_target and member_matches(b["member"], principal) and permission in ROLE_PERMS.get(b["role"], ()):
                return True, f"{b['role']} on {b['resource'].split('/')[-1]} via {b['member'][:40]}..."
        return False, f"no binding grants {permission}"


# ---- Model Armor -----------------------------------------------------------------------------------------------
class ModelArmorTwin:
    def __init__(self, available: bool = True):
        self.available = available

    def sanitize(self, screen_class: str) -> str:
        if not self.available:
            raise ConnectionError("Model Armor unreachable (lab outage)")
        return "MATCH_FOUND" if screen_class == "injection-like" else "NO_MATCH_FOUND"


# ---- Agent Gateway ---------------------------------------------------------------------------------------------
class GatewayTwin:
    """Agent-to-Anywhere egress. None of this runs if the agent has no agent_gateway_config."""

    def __init__(self, dep: dict, registry: dict, armor: ModelArmorTwin):
        self.dep, self.armor = dep, armor
        self.gw = dep.get("gateway") or {}
        self.attached = bool(dep["agent"].get("agent_gateway_config"))
        self.servers = {s["displayName"]: s for s in registry["mcpServers"]}
        self.rules = dep["access_policy"]["details"]["rules"]

    @property
    def dry_run(self) -> bool:
        md = (self.gw.get("iap_authz_extension") or {}).get("metadata", {})
        return md.get("iamEnforcementMode") == "DRY_RUN"

    def attributes(self, server: str | None, tool: str | None, host: str | None) -> dict:
        if server is None:   # an unregistered destination (a plain URL)
            return {"destination.is_registered": False, "destination.unregistered.host": host,
                    "destination.unregistered.path": "/", "destination.unregistered.method": "get"}
        s = self.servers.get(server)
        if s is None:
            return {"destination.is_registered": False, "destination.unregistered.host": host or server}
        spec = next((t for t in s["toolspec"]["tools"] if t["name"] == tool), None)
        ann = (spec or {}).get("annotations", {})
        return {"destination.is_registered": True,
                "destination.agent_registry.resource_type": "MCP_SERVER",
                "destination.agent_registry.location": "europe-west4",
                "destination.agent_registry.project_id": self.dep["project"],
                "destination.agent_registry.mcp_server.name": s["name"],
                "destination.agent_registry.mcp_server.method": "tools",
                "destination.agent_registry.mcp_server.tool.name": tool,
                "destination.agent_registry.mcp_server.tool.annotations.read_only_hint": ann.get("readOnlyHint"),
                "destination.agent_registry.mcp_server.tool.annotations.destructive_hint": ann.get("destructiveHint"),
                "destination.agent_registry.mcp_server.tool.annotations.idempotent_hint": ann.get("idempotentHint"),
                "destination.agent_registry.mcp_server.tool.annotations.open_world_hint": ann.get("openWorldHint")}

    def authorize(self, principal: str, attrs: dict) -> tuple[str, str]:
        """Unified Access Policy: deny rules are evaluated first; then allow; nothing matched = default deny."""
        def matches(rule):
            if not any(member_matches(m, principal) for m in rule["principals"]):
                return False
            if PERM_EGRESS not in rule["operation"]["permissions"]:
                return False
            expr = rule.get("conditions", {}).get("iap.googleapis.com", {}).get("expression", "")
            return cel.evaluate(expr, attrs)
        for r in self.rules:
            if r["effect"] == "DENY" and matches(r):
                return "DENIED", r["description"].split(":")[0]
        for r in self.rules:
            if r["effect"] == "ALLOW" and matches(r):
                return "ALLOWED", r["description"].split(":")[0]
        return "DENIED", "default deny (no rule grants access)"

    def screen(self, screen_class: str) -> tuple[str, str]:
        """Model Armor on the gateway. Returns (verdict, why)."""
        ext = self.gw.get("model_armor_authz_extension")
        if not ext:
            return "NOT_SCREENED", "no Model Armor on this gateway"
        try:
            verdict = self.armor.sanitize(screen_class)
        except ConnectionError:
            return ("PASSED_UNSCREENED", "Model Armor unreachable, failOpen: true") if ext.get("failOpen") else \
                   ("BLOCK", "Model Armor unreachable, failOpen: false")
        return ("BLOCK", "Model Armor MATCH_FOUND") if verdict == "MATCH_FOUND" else ("ALLOW", "NO_MATCH_FOUND")


# ---- Memory Bank -----------------------------------------------------------------------------------------------
class MemoryBankTwin:
    def __init__(self, dep: dict, day: int = 0):
        cfg = dep.get("memory_bank") or {}
        self.topics = set(cfg.get("_lab_managed_topics", []))
        ttl = (cfg.get("ttl_config") or {}).get("default_ttl")
        self.ttl_days = int(ttl.rstrip("s")) // 86400 if ttl else None
        self.revisions_on = not cfg.get("disable_memory_revisions", False)
        self.memories = copy.deepcopy(load_json(HERE / "data" / "memories.json")["memories"])
        self.revisions: list[dict] = []
        self.day = day

    def retrieve(self, scope: dict) -> list[dict]:
        live = [m for m in self.memories if m["scope"] == scope
                and (m.get("expire_day") is None or m["expire_day"] > self.day)]
        return live

    def generate(self, scope: dict, topic: str) -> dict:
        """Stand-in for GenerateMemories: one extracted memory under a managed topic. Stored only if that topic is
        enabled for this Memory Bank; it expires after the TTL if one is set (Google's default is no TTL)."""
        if topic not in self.topics:
            return {"action": "SKIPPED", "why": f"topic {topic} is not enabled"}
        mem = {"scope": dict(scope), "topic": topic, "fact": "(an instruction taken from untrusted text)",
               "expire_day": None if self.ttl_days is None else self.day + self.ttl_days}
        self.memories.append(mem)
        if self.revisions_on:
            self.revisions.append({"action": "CREATED", **copy.deepcopy(mem)})
        return {"action": "CREATED", "expire_day": mem["expire_day"]}


def scope_condition_allows(expression_scope: dict, requested_scope: dict) -> bool:
    """IAM Condition on memories (Google's example): api.getAttribute('aiplatform.googleapis.com/memoryScope', {})
    == {'userId': 'userA'}. True only for an exact scope match."""
    return expression_scope == requested_scope
