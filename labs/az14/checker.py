"""
checker.py: review the hosted-agent deployment BEFORE anyone attacks it. 25 rules, each from a Microsoft Learn page.

    python3 checker.py                # make check:       version 1 (contoso/)
    python3 checker.py --with-fixes   # make check-fixed: the hardened build (fixes/)

A finding is (rule, severity, object, message). A note is something the config can't fix that you must know.
"""

import argparse
import sys

import twin

LEARN = "https://learn.microsoft.com/en-us/azure/foundry"


def check(setup_name: str):
    cfg = twin.setup(setup_name)
    F, notes = [], []

    def add(rule, sev, obj, msg):
        F.append((rule, sev, obj, msg))

    dep, ident, tb, mem, app = cfg["deployment"], cfg["identity"], cfg["toolbox"], cfg["memory"], cfg["app"]
    a = dep["agents"]["helpdesk-agent"]

    # ---- 14.2 runtime
    if app["user_identity_from"] != "validated_token":
        add("AZ14-01", "HIGH", "app helpdesk-web",
            "x-ms-user-identity comes from the client request. Microsoft: derive it \"from an authenticated, server-side "
            "identity - never from a value the browser or client supplies directly\". Anyone can read anyone's session.")
    if not app["session_per_user"]:
        add("AZ14-02", "HIGH", "app helpdesk-web",
            "Users are routed to a shared session. \"if you route two users to the same session, they can see each "
            "other's data.\"")
    for name, ag in dep["agents"].items():
        env = ag["definition"].get("environment_variables", {})
        for k in env:
            if twin.SECRETISH.search(k):
                add("AZ14-03", "HIGH", f"agent {name}",
                    f"Environment variable {k} looks like a secret. \"Don't put secrets in container images or "
                    "environment variables\". Use a connection (custom-keys) or managed identity.")
        if ag.get("debug_tools"):
            add("AZ14-04", "MEDIUM", f"agent {name}",
                f"Debug tools offered to the model: {ag['debug_tools']}. Anything a tool returns, injected text can ask for.")
        pol = ag.get("egressPolicy")
        if not pol:
            add("AZ14-05", "MEDIUM", f"agent {name}", "No network egress policy: the sandbox can call any host. "
                "Egress controls (preview) with defaultAction Deny make an allow list.")
        elif pol["defaultAction"] != "Deny" or pol["mode"] != "Enforced":
            add("AZ14-05", "MEDIUM", f"agent {name}",
                f"Egress policy mode={pol['mode']} defaultAction={pol['defaultAction']}: Audit logs but doesn't block.")
        rp = twin.rai_policy_exists(cfg, name)
        if rp is None:
            add("AZ14-06", "HIGH", f"agent {name}", "No rai_config: \"the agent runs without a content safety guardrail\".")
        elif rp is False:
            add("AZ14-06", "HIGH", f"agent {name}",
                "rai_policy_name names a policy that doesn't exist on the account. Microsoft: such an agent can report "
                "active while \"no content filtering is applied - the guardrail fails open\".")
        if ag.get("idle_timeout_minutes", 15) > 60:
            add("AZ14-07", "LOW", f"agent {name}",
                f"Idle timeout {ag['idle_timeout_minutes']} min (default 15): compute and session state stay up longer.")
    if not dep["foundry_account"]["network_injection"]:
        add("AZ14-08", "MEDIUM", f"account {dep['foundry_account']['name']}",
            "No VNet injection. For hosted agents it \"must be included when you first create the Foundry account\": "
            "fixing this means a new account.")
    if dep["registry"]["publicNetworkAccess"] != "Disabled":
        if dep["project"]["created"] < "2026-06-25":
            notes.append(("AZ14-N1", f"registry {dep['registry']['name']}",
                          "Public registry endpoint required: projects created before 25 Jun 2026 can't pull from a private ACR."))
        else:
            add("AZ14-09", "LOW", f"registry {dep['registry']['name']}", "Project supports a private ACR; registry is public.")

    # ---- 14.3 identity
    for ra in ident["role_assignments"]:
        if ra["principal"].startswith("agent:"):
            if ra["scope"] == ident["storage_account_scope"]:
                add("AZ14-10", "HIGH", ra["principal"],
                    f"{ra['role']} on the whole storage account. Scope it to the one container the agent needs.")
            if ra["role"] in twin.WRITE_ROLES:
                add("AZ14-11", "HIGH", ra["principal"],
                    f"{ra['role']}: a write role for an agent that only reads articles. Use Storage Blob Data Reader.")
        if ra["role"] == "Foundry Agent Consumer" and "/agents/" not in ra["scope"]:
            add("AZ14-12", "HIGH", ra["principal"],
                "Foundry Agent Consumer above agent scope. Microsoft: \"Project scope grants access to every agent endpoint in the "
                "project.\" Account scope is wider still. Grant it per agent.")
        if ra["principal"] == "project-mi" and ra["role"] == "AcrPull":
            add("AZ14-13", "LOW", "project-mi",
                "AcrPull works, but Microsoft recommends Container Registry Repository Reader for the project identity.")
    if not any(p.get("state") == "On" for p in ident["conditional_access"]):
        add("AZ14-14", "MEDIUM", "tenant", "No Conditional Access policy for agent identities "
            "(template: Block access for high-risk agent identities; agent risk is preview).")

    # ---- 14.4 / 14.5 tools
    for t in twin.toolbox_tools(cfg):
        if t["type"] == "mcp":
            server_tools = tb["mcp_servers"][t["server_label"]]["tools"]
            if t.get("allowed_tools") is None:
                add("AZ14-15", "HIGH", f"toolbox {tb['name']} v{tb['default_version']} {t['server_label']}",
                    f"No allowed_tools: the model sees all {len(server_tools)} tools, including "
                    f"{', '.join(n for n, k in server_tools.items() if k == 'write')}.")
            if t.get("require_approval") == "never" and "write" in server_tools.values():
                add("AZ14-16", "HIGH", f"toolbox {tb['name']} {t['server_label']}",
                    "require_approval 'never' on a server with write tools.")
            conn = tb["connections"][t["project_connection_id"]]
            if conn["authType"] in ("custom-keys", "project-managed-identity") and "write" in server_tools.values():
                add("AZ14-17", "HIGH", f"connection {t['project_connection_id']}",
                    f"authType {conn['authType']}: every user's write runs as {conn['credential_owner']}. "
                    "Use oauth2 or user-entra-token for per-user actions.")
        if t["type"] == "code_interpreter":
            add("AZ14-18", "HIGH", f"toolbox {tb['name']}",
                "Code Interpreter through a toolbox in a hosted agent: \"user isolation isn't supported. All users in "
                "the same project share the same container context.\"")
    if a["runtime"]["approval_enforcement"] != "runtime":
        add("AZ14-19", "HIGH", "agent helpdesk-agent",
            "The agent code doesn't enforce _meta.tool_configuration.require_approval. \"The MCP endpoint doesn't "
            "block tools/call. Enforcement is entirely the agent runtime's responsibility.\"")
    if not a["runtime"]["policy_check"]:
        add("AZ14-20", "HIGH", "agent helpdesk-agent",
            "No deterministic check on tool name + arguments before execution (policy.py).")

    # ---- 14.6 memory
    if mem["tool"]["scope"] != "{{$userId}}":
        add("AZ14-21", "HIGH", f"memory {mem['store']}",
            f"scope '{mem['tool']['scope']}' is shared by every user. Microsoft: set scope to {{{{$userId}}}} for "
            "per-user isolation.")
    if mem["options"]["procedural_memory_enabled"] or not mem["options"]["user_profile_details"]:
        add("AZ14-22", "MEDIUM", f"memory {mem['store']}",
            "Procedural memory on and/or no user_profile_details telling the extractor what not to store.")
    if not mem["write_filter"]:
        add("AZ14-23", "MEDIUM", f"memory {mem['store']}",
            "Nothing checks what gets written to memory: tool results can become 'facts' (memory_guard.py).")

    # ---- 14.7 observability
    readers = dep["tracing"]["trace_readers"]
    if not dep["tracing"]["application_insights"]:
        add("AZ14-24", "MEDIUM", "tracing", "Tracing is off: no execute_tool spans to investigate.")
    elif any(r in ("group:all-staff",) for r in readers):
        add("AZ14-24", "MEDIUM", "tracing", f"Trace readers {readers}: traces hold prompts and tool arguments. "
            "\"Treat trace data as production telemetry\".")
    if not dep["red_team"]["last_run_version"]:
        add("AZ14-25", "LOW", "agent helpdesk-agent", "No AI Red Teaming Agent run recorded for the deployed version.")

    # notes that no config change removes
    if any(ag.get("egressPolicy") for ag in dep["agents"].values()):
        notes.append(("AZ14-N2", "egress", "Network egress controls are preview, hosted agents only, and enforced "
                      "inside the sandbox: keep your own firewall too."))
    if any(v.get("policies") for v in tb["versions"].values()):
        notes.append(("AZ14-N3", f"toolbox {tb['name']}", "Microsoft's pages disagree on whether guardrails screen MCP "
                      "tool responses (tool-authentication page: yes; intervention-points page: MCP not listed). "
                      "Test it; don't count on it."))
    return F, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-fixes", action="store_true")
    s = "fixes" if ap.parse_args().with_fixes else "contoso"
    F, notes = check(s)
    for rule, sev, obj, msg in F:
        print(f"[{sev:6}] {rule} {obj}\n          {msg}")
    for rule, obj, msg in notes:
        print(f"[NOTE  ] {rule} {obj}\n          {msg}")
    sev = {k: sum(1 for f in F if f[1] == k) for k in ("HIGH", "MEDIUM", "LOW")}
    print(f"\n{len(F)} findings in {s}/: {sev['HIGH']} HIGH, {sev['MEDIUM']} MEDIUM, {sev['LOW']} LOW · {len(notes)} note(s)")
    print(f"Sources: {LEARN}/agents/concepts/hosted-agents and the pages listed in the README.")
    sys.exit(0)


if __name__ == "__main__":
    main()
