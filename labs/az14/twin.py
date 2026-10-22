"""
twin.py: a TEACHING MODEL of the TSG Helpdesk running as a Foundry hosted agent. It is not Azure.
Each rule below comes from a Microsoft Learn page (the README's "About the twin" lists them with links):

  Endpoint    who may invoke an agent: Foundry Agent Consumer at account, project or agent scope
              ("Agent scope grants access only to the specified agent endpoint")
  Sessions    the platform scopes a session to the caller's Entra identity, or to the x-ms-user-identity value a
              trusted service sends; "never from a value the browser or client supplies directly"
  Identity    the agent container runs as its own Entra agent identity; Azure RBAC decides what it can touch
              (scope: storage account covers every container, a container scope covers one)
  Guardrail   rai_config.rai_policy_name; a name that doesn't exist can be accepted and then filters nothing
              ("the guardrail fails open")
  Egress      egressPolicy (preview): ordered rules, first match wins, defaultAction Allow|Deny, mode Audit|Enforced;
              Audit logs would-be denials but doesn't block; a denied call gets HTTP 403
  Toolbox     allowed_tools filters tools/list; require_approval is returned as _meta and "Enforcement is entirely
              the agent runtime's responsibility"; a hosted agent IS its own runtime
  Memory      (preview) scope partitions memories; "{{$userId}}" resolves per user, a fixed string is shared
  Code Interp. through a toolbox in a hosted agent "user isolation isn't supported": one container per project

Standard library only. Deterministic: same inputs, same output.
"""

import copy
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL_MARK = re.compile(r"\[LAB-PLACEHOLDER TOOL REQUEST: call (\w+)((?: \w+=[^\s\]]+)*)\]")
MEMORY_MARK = re.compile(r"\[LAB-PLACEHOLDER MEMORY WRITE: ([^\]]+)\]")
PROMPT_ATTACK = "[LAB-PLACEHOLDER PROMPT ATTACK]"
SECRETISH = re.compile(r"(KEY|SECRET|PASSWORD|TOKEN|CONN(ECTION)?_?STRING)", re.I)
WRITE_ROLES = {"Storage Blob Data Contributor", "Storage Blob Data Owner", "Contributor", "Owner"}
READ_ROLES = WRITE_ROLES | {"Storage Blob Data Reader", "Reader"}


def load(folder: str, name: str) -> dict:
    with open(os.path.join(HERE, folder, name), encoding="utf-8") as f:
        return json.load(f)


DIRECTORY = load("data", "directory.json")
DOCS = {d["id"]: d for d in load("data", "docs.json")["docs"]}


def user(name: str) -> dict:
    return DIRECTORY["users"][name]


# ------------------------------------------------------------------ setups
def setup(name: str) -> dict:
    """contoso = version 1; v1.1 = the fixes a demo review usually produces; fixes = the hardened build."""
    folder = "fixes" if name == "fixes" else "contoso"
    cfg = {"name": name}
    for part in ("deployment", "identity", "toolbox", "memory", "app"):
        cfg[part] = load(folder, f"{part}.json")
    if name == "v1.1":
        cfg = copy.deepcopy(cfg)
        a = cfg["deployment"]["agents"]["helpdesk-agent"]
        a["definition"]["rai_config"]["rai_policy_name"] = a["definition"]["rai_config"]["rai_policy_name"].replace("-v1", "")
        a["egressPolicy"] = {"mode": "Audit", "defaultAction": "Deny", "rules": [
            {"name": "allow-contoso", "ruleType": "Fqdn", "match": {"host": "*.contoso.com"}, "action": {"actionType": "Allow"}},
            {"name": "allow-learn", "ruleType": "Fqdn", "match": {"host": "learn.microsoft.com"}, "action": {"actionType": "Allow"}}]}
        cfg["memory"]["tool"]["scope"] = "{{$userId}}"
        cfg["toolbox"]["versions"]["1"]["tools"][0]["require_approval"] = "always"
    return cfg


def agent(cfg: dict, name: str = "helpdesk-agent") -> dict:
    return cfg["deployment"]["agents"][name]


def toolbox_tools(cfg: dict) -> list:
    tb = cfg["toolbox"]
    return tb["versions"][tb["default_version"]]["tools"]


# ------------------------------------------------------------------ Entra in: who may call which agent, as whom
def scope_covers(scope: str, target: str) -> bool:
    """An Azure RBAC scope covers itself and everything below it."""
    return target == scope or target.startswith(scope.rstrip("/") + "/")


def agent_resource(cfg: dict, agent_name: str) -> str:
    acc = cfg["deployment"]["foundry_account"]["name"]
    prj = cfg["deployment"]["project"]["name"]
    return (f"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-helpdesk/providers/"
            f"Microsoft.CognitiveServices/accounts/{acc}/projects/{prj}/agents/{agent_name}")


def can_invoke(cfg: dict, who: str, agent_name: str) -> bool:
    target = agent_resource(cfg, agent_name)
    groups = set(user(who)["groups"])
    for ra in cfg["identity"]["role_assignments"]:
        if ra["role"] != "Foundry Agent Consumer":
            continue
        p = ra["principal"]
        if (p.startswith("group:") and p[6:] in groups) or p == f"user:{who}":
            if scope_covers(ra["scope"], target):
                return True
    return False


def effective_user(cfg: dict, signed_in: str, header: str | None) -> str:
    """Whose session and memories this turn uses. Microsoft: derive x-ms-user-identity 'from an authenticated,
    server-side identity - never from a value the browser or client supplies directly'."""
    if cfg["app"]["user_identity_from"] == "request_header" and header:
        return header
    return signed_in


def read_session(cfg: dict, effective: str) -> list:
    """Sessions the effective identity can resume. Each caller gets their own session by default."""
    return [s["content"] for s in DIRECTORY["sessions"].values() if isinstance(s, dict) and s.get("owner") == effective]


# ------------------------------------------------------------------ agent identity out: what the container can touch
def agent_roles(cfg: dict, agent_name: str = "helpdesk-agent") -> list:
    return [ra for ra in cfg["identity"]["role_assignments"] if ra["principal"] == f"agent:{agent_name}"]


def storage_allowed(cfg: dict, container: str, write: bool) -> bool:
    acct = cfg["identity"]["storage_account_scope"]
    target = f"{acct}/blobServices/default/containers/{container}"
    for ra in agent_roles(cfg):
        if scope_covers(ra["scope"], target) and ra["role"] in (WRITE_ROLES if write else READ_ROLES):
            return True
    return False


# ------------------------------------------------------------------ guardrail and egress
def rai_policy_exists(cfg: dict, agent_name: str = "helpdesk-agent") -> bool | None:
    """None = no rai_config at all; False = it names a policy that doesn't exist (fails open); True = fine."""
    rc = agent(cfg, agent_name)["definition"].get("rai_config")
    if rc is None:
        return None
    name = rc.get("rai_policy_name") or "Microsoft.DefaultV2"
    return name.rsplit("/", 1)[-1] in cfg["deployment"]["rai_policies"]


def guardrail_blocks_input(cfg: dict, prompt: str) -> bool:
    """The stand-in classifier flags the lab's prompt-attack marker, but only if a real policy is applied."""
    return bool(rai_policy_exists(cfg)) and PROMPT_ATTACK in prompt


def host_of(url: str) -> str:
    return re.sub(r"^https?://", "", url).split("/")[0].split("?")[0].lower()


def host_matches(pattern: str, host: str) -> bool:
    pattern = pattern.lower()
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return host == pattern


def egress(cfg: dict, url: str, log: list) -> tuple[bool, str]:
    """Network egress controls (preview): first matching rule wins, else defaultAction; Audit never blocks Deny."""
    pol = agent(cfg)["egressPolicy"]
    host = host_of(url)
    if not pol:
        log.append({"event": "egress", "host": host, "action": "NoPolicy"})
        return True, "no egress policy: allowed"
    action = pol["defaultAction"]
    for r in pol["rules"]:
        if host_matches(r["match"]["host"], host):
            action = r["action"]["actionType"]
            break
    if action == "Deny" and pol["mode"] == "Audit":
        log.append({"event": "egress", "host": host, "action": "WouldDeny"})
        return True, "Audit mode: would deny, logged, not blocked"
    log.append({"event": "egress", "host": host, "action": action})
    return (action != "Deny"), ("HTTP 403 from the egress proxy" if action == "Deny" else "allowed by rule")


# ------------------------------------------------------------------ memory (preview)
class Memory:
    """A tiny memory store: scope -> list of items. Scope '{{$userId}}' resolves to the caller; anything else is
    one shared partition for everyone."""

    def __init__(self, cfg: dict):
        self.cfg, self.items = cfg, {}

    def scope_for(self, effective: str) -> str:
        s = self.cfg["memory"]["tool"]["scope"]
        return user(effective)["oid"] if s == "{{$userId}}" and effective in DIRECTORY["users"] else s

    def write(self, effective: str, text: str, source: str) -> bool:
        if self.cfg["memory"]["write_filter"]:
            import memory_guard  # challenge 2
            if not memory_guard.allow({"text": text, "source": source, "user": effective}):
                return False
        self.items.setdefault(self.scope_for(effective), []).append({"text": text, "source": source})
        return True

    def recall(self, effective: str) -> list:
        return [i["text"] for i in self.items.get(self.scope_for(effective), [])]


# ------------------------------------------------------------------ Code Interpreter
def code_interpreter_files(cfg: dict, effective: str) -> list:
    """Through a toolbox in a hosted agent, 'All users in the same project share the same container context.'
    Attached directly, each conversation gets its own session."""
    via_toolbox = any(t["type"] == "code_interpreter" for t in toolbox_tools(cfg))
    ups = {k: v for k, v in DIRECTORY["uploads"].items() if k != "_about"}
    if via_toolbox:
        return [u["content"] for u in ups.values()]
    return [ups[effective]["content"]] if effective in ups else []


# ------------------------------------------------------------------ tools
def offered_tools(cfg: dict) -> dict:
    """name -> (kind, source, tool definition) for every tool the MODEL can see this turn."""
    out = {}
    a = agent(cfg)
    for name in a["runtime"]["local_tools"]:
        out[name] = ("write" if name == "delete_blob" else "read", "local", None)
    for t in toolbox_tools(cfg):
        if t["type"] != "mcp":
            continue
        offered = cfg["toolbox"]["mcp_servers"][t["server_label"]]["tools"]
        allowed = t.get("allowed_tools")
        for n, kind in offered.items():
            if allowed is None or n in allowed:
                out[n] = (kind, "toolbox", t)
    return out


def reviewer(name: str, args: dict) -> bool:
    """The stand-in human approver on request 40 of the day: approves anything that looks internal."""
    return "contoso.com" in json.dumps(args)


def execute(cfg: dict, name: str, args: dict, who: str, effective: str, egress_log: list) -> tuple[bool, str]:
    if name == "read_blob":
        c = args.get("container", "kb")
        ok = storage_allowed(cfg, c, write=False)
        return ok, (f"read {c}/{args.get('name')}" if ok else f"403 AuthorizationPermissionMismatch on {c}")
    if name == "delete_blob":
        c = args.get("container")
        ok = storage_allowed(cfg, c, write=True)
        return ok, (f"delete_blob {c}/{args.get('name')} done as agent identity" if ok
                    else f"403 AuthorizationPermissionMismatch: agent identity can't delete in {c}")
    if name == "http_get":
        ok, why = egress(cfg, args["url"], egress_log)
        return ok, f"http_get {host_of(args['url'])}: {why}"
    if name == "get_config":
        env = agent(cfg)["definition"]["environment_variables"]
        return True, "config: " + ", ".join(f"{k}={v}" for k, v in env.items())
    # MCP tools on the toolbox
    _, _, tool = offered_tools(cfg)[name]
    conn = cfg["toolbox"]["connections"][tool["project_connection_id"]]
    acting_as = who if conn["credential_owner"] == "per-user" else conn["credential_owner"]
    return True, f"{name}({', '.join(f'{k}={v}' for k, v in args.items())}) done as {acting_as}"


def run_turn(cfg: dict, signed_in: str, ask: str, *, agent_name: str = "helpdesk-agent", header: str | None = None,
             actions: list | None = None, memory: Memory | None = None, remember: str | None = None,
             trace: list | None = None) -> dict:
    """One request to the hosted agent. The stand-in model (stand_in_model.py) obeys anything it reads."""
    import policy
    import stand_in_model as sim
    trace = trace if trace is not None else []
    memory = memory or Memory(cfg)
    out = {"status": 200, "answer": "", "executed": [], "refused": [], "notes": [], "egress": [], "session": [],
           "recalled": [], "ci_files": [], "docs": []}
    if not can_invoke(cfg, signed_in, agent_name):
        out["status"] = 403
        out["notes"].append(f"403: {signed_in} has no Foundry Agent Consumer role covering {agent_name}")
        return out
    if agent_name != "helpdesk-agent":
        out["answer"] = f"{agent_name} answered {signed_in}"
        return out
    if guardrail_blocks_input(cfg, ask):
        out["status"] = 400
        out["notes"].append('HTTP 400 "code": "content_filter" (input stage)')
        return out
    if PROMPT_ATTACK in ask:
        out["notes"].append("guardrail did not run: " + ("no rai_config" if rai_policy_exists(cfg) is None
                                                          else "rai_policy_name names a policy that doesn't exist"))
    eff = effective_user(cfg, signed_in, header)
    if eff != signed_in:
        out["notes"].append(f"session identity = '{eff}' (x-ms-user-identity taken from the client), signed in as {signed_in}")
    out["session"] = read_session(cfg, eff)
    if remember:
        memory.write(eff, remember, "user")
    out["recalled"] = memory.recall(eff)
    out["ci_files"] = code_interpreter_files(cfg, eff) if "/mnt/data" in ask else []

    # retrieval: the agent reads KB articles from Blob Storage as its own identity
    hits = sim.retrieve(ask)
    if hits and not storage_allowed(cfg, "kb", write=False):
        out["notes"].append("403 reading kb: agent identity has no data role on the container")
        hits = []
    out["docs"] = [h["id"] for h in hits]
    for h in hits:
        for m in MEMORY_MARK.finditer(h["text"]):
            stored = memory.write(eff, m.group(1), f"tool_result:{h['id']}")
            out["notes"].append(f"memory write from {h['id']}: {'stored' if stored else 'refused by memory_guard'}")

    tools = offered_tools(cfg)
    a = agent(cfg)
    for call in sim.plan(ask, hits, actions or []):
        name, args = call["name"], call["args"]
        if name not in tools:
            out["refused"].append(f"{name}: not offered to the model")
            continue
        kind, source, tdef = tools[name]
        if a["runtime"]["policy_check"]:                       # deterministic first: no model, no tired human
            ok, why = policy.check(name, args, user(signed_in)["upn"])
            if not ok:
                out["refused"].append(f"{name}: policy: {why}")
                trace.append({"name": "policy_deny", "tool": name, "args": args, "source": call["source"]})
                continue
        if source == "toolbox":
            meta = tdef.get("require_approval", "always")
            if a["runtime"]["approval_enforcement"] == "none":
                if meta == "always":
                    out["notes"].append(f"{name}: _meta.tool_configuration.require_approval='always', but this "
                                        "runtime doesn't enforce it")
            elif meta == "always" or kind == "write":
                ok = reviewer(name, args)
                trace.append({"name": "approval", "tool": name, "args": args, "approve": ok, "source": call["source"]})
                if not ok:
                    out["refused"].append(f"{name}: approval denied by reviewer")
                    continue
        ok, msg = execute(cfg, name, args, signed_in, eff, out["egress"])
        trace.append({"name": "execute_tool", "gen_ai.tool.name": name, "gen_ai.tool.call.arguments": json.dumps(args),
                      "source": call["source"], "ok": ok})
        (out["executed"] if ok else out["refused"]).append(msg)
    out["answer"] = sim.answer(hits, out["recalled"])
    return out
