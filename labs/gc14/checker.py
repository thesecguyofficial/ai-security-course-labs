"""
checker.py: read the Helpdesk agent's Agent Runtime deployment like an auditor would.

    python3 checker.py --twin today       # make check
    python3 checker.py --twin hardened    # make check-hardened (1 left: your challenge)

Reads twin/<name>/deployment.json, twin/registry.json and twin/requirements.json. Some rules don't trust a setting:
GC14-07 asks the gateway twin what it would decide for a tool the agent must never reach. NOTES are facts about
the services that you design around; they are printed, not counted. Add --ci to exit 1 on any HIGH finding.
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from dataclasses import dataclass

from twin import (HERE, GatewayTwin, ModelArmorTwin, agent_principal, load_deployment, load_json, load_registry,
                  member_matches)

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SECRET_WORDS = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "CREDENTIAL")


@dataclass
class Finding:
    sev: str
    rule: str
    where: str
    what: str
    fix: str


def run(twin: str, dep: dict | None = None) -> list[Finding]:
    dep = dep or load_deployment(twin)
    req = load_json(HERE / "twin" / "requirements.json")
    reg = load_registry()
    agent, out = dep["agent"], []
    add = lambda *a: out.append(Finding(*a))       # noqa: E731
    principal = agent_principal(dep)
    env = agent.get("env_vars") or {}

    # ---- identity ---------------------------------------------------------------------------------------------
    if "gcp-sa-aiplatform-re" in principal:
        add("HIGH", "GC14-01", "Agent Runtime",
            "The agent runs as the project's Reasoning Engine service agent: every agent deployed this way shares one "
            "principal and its permissions, and Agent Gateway needs each agent to have its own Agent Identity.",
            "Deploy with identity_type AGENT_IDENTITY (or at least a dedicated service account) and grant only "
            "what this agent needs.")
    caa = env.get("GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES")
    if caa is False or str(caa).lower() == "false":
        add("HIGH", "GC14-02", "env_vars",
            "GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES is false: the agent is opted out of the default "
            "Context-Aware Access policy that binds its tokens. Google calls this 'strongly discouraged'.",
            "Remove the variable. If a Google sample told you to set it, find out why and record the decision.")
    for b in dep["iam_bindings"]:
        if b["role"] in req["data_roles"] and b["member"].startswith("principalSet://") \
                and b["resource"].startswith("//cloudresourcemanager.googleapis.com/projects/"):
            add("HIGH", "GC14-03", b["resource"].split("/")[-1],
                f"{b['role']} is granted project-wide to every agent in the project (a principalSet). Any agent, "
                "including ones deployed later, can read all data in the project.",
                "Keep only low-sensitivity roles on the principalSet; grant data roles to this agent's own principal "
                "on the dataset it needs.")
    dead = set(dep.get("_lab_deleted_agents", []))
    stale = [b for b in dep["iam_bindings"] if b["member"] in dead]
    if stale:
        add("MEDIUM", "GC14-04", "IAM",
            f"{len(stale)} binding(s) still name a deleted or redeployed agent ({stale[0]['role']} on "
            f"{stale[0]['resource'].split('/')[-1]}). Deleting an agent doesn't remove its bindings.",
            "Remove bindings for principals of deleted agents after every redeploy.")
    if agent.get("_lab_end_user_from") != "verified_token":
        add("HIGH", "GC14-17", "agent front end",
            "The end user is taken from the request body (user_id), which any caller can set.",
            "Take it from a verified ID token on your server and set user_id yourself.")

    # ---- gateway and access policy ----------------------------------------------------------------------------
    gwd = dep.get("gateway") or {}
    gw = GatewayTwin(dep, reg, ModelArmorTwin())
    if not gw.attached:
        add("HIGH", "GC14-05", "Agent Runtime", "No egress Agent Gateway: nothing checks where the agent connects.",
            "Attach an Agent-to-Anywhere gateway (agent_gateway_config) and bind an access policy.")
    elif gw.dry_run:
        add("HIGH", "GC14-05", gwd.get("name", "gateway").split("/")[-1],
            "The gateway's IAP authorization runs in DRY_RUN: denials are logged, nothing is blocked.",
            "Read the dry-run logs, then remove iamEnforcementMode DRY_RUN to enforce.")
    rules = dep["access_policy"]["details"]["rules"]
    for r in rules:
        expr = r.get("conditions", {}).get("iap.googleapis.com", {}).get("expression", "")
        if r["effect"] == "ALLOW" and not expr.strip():
            add("HIGH", "GC14-06", r["description"].split(":")[0],
                "An ALLOW rule with no condition: every destination, registered or not, is allowed.",
                "Allow named MCP servers and tools only; let everything else hit the default deny.")
        if r["effect"] == "ALLOW" and ".annotations." in expr:
            add("HIGH", "GC14-08", r["description"].split(":")[0],
                "An ALLOW rule trusts tool annotations (readOnlyHint, destructiveHint...). Whoever registers the "
                "MCP server declares them in its toolspec; a new tool with a wrong hint is allowed automatically.",
                "Allow tools by name: destination.agent_registry.mcp_server.tool.name in [...].")
    if gw.attached and principal.startswith("principal://"):
        for target in req["agent_job"]["tools_it_must_never_reach"]:
            server, tool = target.rsplit("/", 1)[1].split("::")
            result, rule = gw.authorize(principal, gw.attributes(server, tool, None))
            if result == "ALLOWED":
                add("HIGH", "GC14-07", f"{server}.{tool}",
                    f"The policy allows a tool this agent must never use ({rule}).",
                    "Add a DENY rule naming the server or tool for this agent's principal.")
    if gw.attached and not gwd.get("model_armor_authz_extension"):
        add("HIGH", "GC14-09", gwd.get("name", "gateway").split("/")[-1],
            "No Model Armor on the gateway: tool responses (ticket text, articles) reach the model unscreened.",
            "Add a Model Armor authz extension (policyProfile CONTENT_AUTHZ) with request and response templates.")
    ma = gwd.get("model_armor_authz_extension") or {}
    if ma and ma.get("failOpen"):
        add("MEDIUM", "GC14-10", ma.get("name", "model armor"),
            "Model Armor extension has failOpen: true: when screening fails, traffic passes unscreened.",
            "failOpen: false, and decide in writing what the helpdesk does during an outage.")

    # ---- memory -----------------------------------------------------------------------------------------------
    mb = dep.get("memory_bank") or {}
    if agent.get("_lab_memory_scope_from") != "verified_token":
        add("HIGH", "GC14-11", "Memory Bank",
            "Memory scope (user_id) comes from the request body: a caller can read or write another user's memories.",
            "Build the scope from the verified user. The agent's identity can reach every scope of its own Memory Bank.")
    if mb and not mb.get("ttl_config"):
        add("MEDIUM", "GC14-12", "Memory Bank",
            "No TTL: memories never expire (Google's default is no TTL), so a poisoned memory stays.",
            "Set ttl_config (default_ttl or granular_ttl) to match how long a memory is useful.")
    if "EXPLICIT_INSTRUCTIONS" in mb.get("_lab_managed_topics", []):
        add("MEDIUM", "GC14-13", "Memory Bank",
            "The managed topic EXPLICIT_INSTRUCTIONS is enabled: instructions found in conversations can become "
            "memories that steer later sessions.",
            "Enable only the topics the helpdesk needs (for example USER_PREFERENCES).")

    # ---- sandboxes, secrets, telemetry ------------------------------------------------------------------------
    for t in dep.get("sandbox_templates", []):
        if t["config"].get("egress_control_config", {}).get("internet_access"):
            add("HIGH", "GC14-14", t["display_name"],
                "A sandbox template with internet_access: true, for an agent whose job needs no browser.",
                "Remove the sandbox power, or turn internet access off and allow only what the task needs.")
    for k, v in env.items():
        if isinstance(v, str) and any(w in k.upper() for w in SECRET_WORDS):
            add("MEDIUM", "GC14-15", k, "A secret is set as a plain environment variable in the deployment config.",
                "Reference Secret Manager instead: env_vars {NAME: {secret, version}}.")
    if env.get("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"):
        broad = [b["member"] for b in dep["iam_bindings"] if b["role"] == "roles/cloudtrace.user"
                 and b["member"] in req["broad_groups"]]
        if broad:
            add("MEDIUM", "GC14-16", "telemetry",
                f"Prompts and responses are captured in telemetry, and {broad[0]} can read traces.",
                "Turn content capture off, or restrict who can read traces and logs.")

    # ---- GC14-18 (your challenge): Data Access audit logs for memories -----------------------------------------
    # TODO: report a MEDIUM finding "GC14-18" when "DATA_READ" is missing from
    #       dep["audit_logs"]["aiplatform.googleapis.com"]  (then memories.retrieve isn't logged).

    return sorted(out, key=lambda f: (SEV_ORDER[f.sev], f.rule))


NOTES = [
    "Agent Gateway's Model Armor screens MCP tools/call and prompts/get, not tools/list, resources/* or "
    "Streamable HTTP/SSE: tool descriptions from a server are not screened.",
    "IAM Unified Access Policies: Google's page says the feature doesn't support VPC Service Controls.",
    "Agent Platform Threat Detection (Preview) isn't available for an agent with Agent Gateway enabled.",
    "ADK tool confirmation isn't supported with VertexAiSessionService: keep approvals in your own app.",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--twin", choices=["today", "hardened"], default="today")
    ap.add_argument("--ci", action="store_true")
    a = ap.parse_args()
    found = run(a.twin)
    print(f"--- GC14 checker · {a.twin} ---\n")
    for f in found:
        w = textwrap.TextWrapper(width=112, initial_indent="          ", subsequent_indent="          ")
        print(f"  {f.sev:<7} {f.rule}  {f.where}")
        print(w.fill(f.what))
        print(textwrap.fill(f.fix, 112, initial_indent="          fix: ", subsequent_indent="               "))
    for n in NOTES:
        print(textwrap.fill(n, 112, initial_indent="  NOTE    ", subsequent_indent="          "))
    high = sum(1 for f in found if f.sev == "HIGH")
    print(f"\n{len(found)} findings ({high} HIGH), {len(NOTES)} notes.")
    if a.ci and high:
        sys.exit(1)


if __name__ == "__main__":
    main()
