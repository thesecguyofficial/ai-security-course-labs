"""
checker.py: review the ported Helpdesk BEFORE anyone attacks it. 19 rules, AZ13-01 to AZ13-19, each tied to a
Microsoft Learn page (lessons 13.1 and 13.2; the README lists the pages). Offline, standard library only.

    python3 checker.py                 # make check:       Contoso's version 1 (contoso/)
    python3 checker.py --with-fixes    # make check-fixed: the hardened build (fixes/): 0 findings, 1 note
    python3 checker.py --dir <folder>  # any folder with search.json, agent.json, app.json, roles.json

Severity: HIGH = data reaches the wrong person or a write runs unchecked; MEDIUM = a missing layer; LOW = hygiene.
"""

import argparse
import sys

import twin

WRITE = "write"


def check(folder: str) -> tuple[list, list]:
    F, notes = [], []
    add = lambda r, s, w, m: F.append((r, s, w, m))
    s = twin.load(folder, "search.json")
    ag = twin.load(folder, "agent.json")
    app = twin.load(folder, "app.json")
    roles = twin.load(folder, "roles.json")["assignments"]
    svc, idx, sync = s["service"], s["index"], s["permission_sync"]
    restricted = [d for d in twin.SOURCE["docs"] if "all" not in d["acl"]]
    labelled = [d for d in twin.SOURCE["docs"] if d["label"] != "General"]
    multi_chunk = any(len(d["chunks"]) > 1 for d in twin.SOURCE["docs"])
    where = f"search {svc['name']}"

    # ---- the search service (13.1)
    if not svc.get("disableLocalAuth") or svc.get("authOptions"):
        add("AZ13-01", "HIGH", where, "API keys are accepted (authOptions set, disableLocalAuth false). Key-based authentication "
            "is the default and a key carries no user: every caller with it is everyone. Use role-based access only.")
    if svc.get("publicNetworkAccess") == "enabled" and not svc["networkRuleSet"]["ipRules"]:
        add("AZ13-02", "MEDIUM", where, "public network access enabled with no IP rules. On Basic and above, use a private "
            "endpoint (and shared private links for indexers); Free has no private endpoints.")
    if svc.get("encryptionWithCmk", {}).get("enforcement") != "Enabled" and any(d["label"] == "Highly Confidential" for d in twin.SOURCE["docs"]):
        add("AZ13-03", "LOW", where, "customer-managed key not enforced while the index holds Highly Confidential content "
            "(Contoso's standard). CMK needs a billable tier and a Key Vault with purge protection.")
    if not svc.get("diagnosticLogs"):
        add("AZ13-04", "MEDIUM", where, "diagnostic logging off: no record of who queried the index.")

    # ---- the index (13.1)
    w = f"index {idx['name']}"
    if restricted and idx.get("permissionFilterOption") != "enabled":
        add("AZ13-05", "HIGH", w, f"{len(restricted)} source documents have restricted ACLs, but permissionFilterOption is not "
            "'enabled': no native query-time trimming. Anything that can query the index sees everything.")
    native = [f["name"] for f in idx["fields"] if f.get("permissionFilter")]
    if native and multi_chunk and not set(native) <= set(idx["projection"]["permission_fields_to_chunks"]):
        add("AZ13-06", "HIGH", w, f"permission fields {native} aren't projected to chunk rows. When a skillset chunks "
            "documents, permission fields move from indexer field mappings to index projections.")
    if idx.get("purviewEnabled") and labelled and multi_chunk and not idx["projection"]["label_to_chunks"]:
        add("AZ13-07", "HIGH", w, "Purview labels are on parent rows only. Microsoft: \"Without this projection, chunk-level "
            "references aren't filtered.\" Project sensitivityLabel to every chunk.")
    changed_after = [d["id"] for d in twin.SOURCE["docs"] if any(c["at"] > sync["last_run"] for c in d.get("acl_history", []))]
    if changed_after and not sync.get("resync_after_acl_change"):
        add("AZ13-08", "MEDIUM", w, f"ACLs changed after the last permission sync ({', '.join(changed_after)}) and nothing "
            "re-syncs on change: the index keeps serving the old permissions until the next scheduled run.")
    for f in idx["fields"]:
        if f["name"] == "group_ids" and f.get("retrievable", True):
            add("AZ13-09", "LOW", w, "security field group_ids is retrievable: every result shows which groups may read it. "
                "Set retrievable false (it hides the field; it is not access control).")
    if idx.get("vectorFilterMode") == "postFilter":
        add("AZ13-10", "LOW", w, "vectorFilterMode postFilter: filtering after the vector search can return fewer than k "
            "results for selective filters. Use preFilter (the default for indexes created after Oct 2023).")

    # ---- the agent (13.2)
    a = ag["agents"][0]
    wa = f"agent {a['name']}"
    for t in a["definition"]["tools"]:
        if t["type"] == "azure_ai_search" and restricted:
            add("AZ13-11", "HIGH", wa, "built-in Azure AI Search tool on an index with per-user content: one connection "
                "identity and one fixed filter for every user, so it can't trim per person. Use the knowledge base with the "
                "user's token, or your own function that queries with the user's token.")
        if t.get("server_label") == "knowledge-base" and restricted and "x-ms-query-source-authorization" not in (t.get("headers") or {}):
            add("AZ13-12", "HIGH", wa, "knowledge base MCP tool doesn't forward x-ms-query-source-authorization. Microsoft: "
                "\"Without the token, permission-enabled sources return results unfiltered.\"")
        if t["type"] == "mcp" and t.get("allowed_tools") is None:
            add("AZ13-13", "MEDIUM", wa, f"MCP tool '{t['server_label']}' has no allowed_tools: \"the default value includes all "
                "of the tools in the MCP server\", including any added later.")
        if t["type"] == "mcp" and t["server_label"] in ag["mcp_servers"]:
            writes = [n for n, k in ag["mcp_servers"][t["server_label"]]["tools"].items() if k == WRITE
                      and (t.get("allowed_tools") is None or n in t["allowed_tools"])]
            unguarded = [n for n in writes if not twin.needs_approval(t, n)]
            if unguarded:
                add("AZ13-14", "HIGH", wa, f"write tools {unguarded} run without approval (require_approval resolves to never).")
        if t.get("project_connection_id"):
            c = ag["connections"][t["project_connection_id"]]
            server = ag["mcp_servers"].get(t.get("server_label"), {"tools": {}})
            has_writes = any(k == WRITE for k in server["tools"].values())
            if c["authType"] in ("ApiKey", "CustomKeys") and (has_writes or t["type"] == "azure_ai_search"):
                add("AZ13-15", "HIGH", wa, f"connection {t['project_connection_id']} uses a shared secret ({c['authType']}"
                    f"{', ' + c['_note'] if c.get('_note') else ''}): every user acts as its owner. Use Entra auth or OAuth "
                    "identity passthrough for per-user data and actions.")
    for r in roles:
        if "project managed identity" in r["principal"] and r["role"] in ("Search Service Contributor", "Search Index Data Contributor"):
            add("AZ13-16", "MEDIUM", f"role {r['role']}", f"{r['principal']} only reads, but holds {r['role']}"
                + (" (can retrieve admin keys)" if r["role"] == "Search Service Contributor" else " (can write documents)")
                + ". Give it Search Index Data Reader, scoped to the index.")
    g = ag["guardrails"][a["guardrail"]]
    tr = any(c["point"] == "tool_response" and "IndirectAttack" in c["risk"] for c in g["controls"])
    reads_untrusted = [t for t in a["definition"]["tools"] if t["type"] in ("mcp", "azure_ai_search")]
    if not tr:
        add("AZ13-17", "MEDIUM", wa, "the agent's guardrail has no Indirect attack control on tool responses (Preview). "
            "Retrieved documents are untrusted input.")
    elif all(t["type"] not in twin.MODERATED_TOOL_TYPES for t in reads_untrusted):
        notes.append(("AZ13-17", "NOTE", wa, "Indirect attack on tool responses is configured, but every tool here is MCP, "
                      "which isn't on Microsoft's list of tools with moderation support: the control won't run. "
                      "Compensating controls in this build: allowed_tools, approval on writes, per-user identity."))
    if app["groups_from"] != "validated_token" or app["filter_builder"] == "string_concat":
        add("AZ13-18", "HIGH", "app helpdesk-web", f"security filter built from {app['groups_from']} by {app['filter_builder']}: "
            "\"The principal is just a string\". Take groups only from the validated token and never concatenate user input.")
    if not ag["audit_log"]["tool_calls"] or not ag["audit_log"]["approvals"] or not ag["tracing"]["application_insights"]:
        add("AZ13-19", "LOW", wa, "tool calls, approvals or traces aren't recorded. Microsoft: \"Log approvals and tool "
            "calls for auditing and troubleshooting.\"")
    return F, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-fixes", action="store_true")
    ap.add_argument("--dir")
    a = ap.parse_args()
    folder = a.dir or ("fixes" if a.with_fixes else "contoso")
    F, notes = check(folder)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for r, sev, w, m in sorted(F, key=lambda x: (order[x[1]], x[0])):
        print(f"[{sev:6}] {r} {w}\n          {m}")
    for r, sev, w, m in notes:
        print(f"[{sev:6}] {r} {w}\n          {m}")
    c = {k: sum(1 for f in F if f[1] == k) for k in order}
    print(f"\n{len(F)} findings in {folder}/: {c['HIGH']} HIGH, {c['MEDIUM']} MEDIUM, {c['LOW']} LOW"
          + (f" · {len(notes)} note" if notes else ""))
    sys.exit(0)


if __name__ == "__main__":
    main()
