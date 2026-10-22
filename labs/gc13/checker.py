"""
checker.py: find the controls the Helpdesk lost on its way from the laptop (Modules 6 and 7) to Google Cloud (GC13).

    python3 checker.py --twin today       # make check
    python3 checker.py --twin hardened    # make check-hardened (2 left: your challenge)

Reads twin/<name>/deployment.json and twin/requirements.json. Rule GC13-15 doesn't trust a setting: it probes
controls.py with an injected recipient and looks at what the code does. NOTES are facts about the services you
can't configure away; they are printed, not counted. Add --ci to exit 1 on any HIGH finding.
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from dataclasses import dataclass

from gcp_twin import DOCS, HERE, load_json

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
BROAD_ROLES = {"roles/owner", "roles/editor", "roles/aiplatform.admin", "roles/storage.admin",
               "roles/bigquery.dataEditor", "roles/bigquery.admin", "roles/discoveryengine.admin"}


@dataclass
class Finding:
    sev: str
    rule: str
    where: str
    what: str
    fix: str


class _Probe:
    """A stand-in for ADK's ToolContext and BaseTool, enough to call controls.before_tool."""
    def __init__(self, name):
        self.name = name


class _Ctx:
    def __init__(self, groups):
        self.state = {"end_user": "alice@example.com", "groups": groups}


def probe_recipient_policy() -> list[str]:
    import importlib
    import controls
    importlib.reload(controls)
    staff = ["helpdesk-staff@example.com"]
    bad = controls.before_tool(_Probe("send_email"), {"to": "collector@example.net", "ticket_id": "T-2042"}, _Ctx(staff))
    return [] if bad is not None else ["an email to collector@example.net about T-2042 reaches the approval step"]


def run(twin: str) -> list[Finding]:
    dep = load_json(HERE / "twin" / twin / "deployment.json")
    req = load_json(HERE / "twin" / "requirements.json")
    ret, agent, out = dep["retrieval"], dep["agent"], []
    add = lambda *a: out.append(Finding(*a))       # noqa: E731
    rag, search = ret.get("rag_engine"), ret.get("agent_search")
    restricted = {d for d, v in DOCS.items() if v["team"] != "all"}

    # ---- retrieval: who decides what gets searched? -------------------------------------------------------------
    if rag and rag["scope"]["chosen_by"] != "verified_groups":
        add("HIGH", "GC13-01", rag["corpora"][0]["display_name"],
            f"Per-user scope is a {rag['scope']['how'].replace('_', ' ')} chosen by {rag['scope']['chosen_by'].replace('_', ' ')}: "
            "a metadata filter narrows the search, it doesn't authorise it.",
            "Pick corpora (or the filter) in your tool from the user's verified groups, never from model arguments.")
    if rag:
        for c in rag["corpora"]:
            groups = {DOCS[d]["team"] for d in c["documents"]}
            if c["documents"] and set(c["documents"]) & restricted and len(groups) > 1:
                add("HIGH", "GC13-02", c["display_name"],
                    f"One corpus mixes documents for different groups ({', '.join(sorted(groups))}). RAG Engine has no "
                    "per-document ACL: anyone whose request reaches this corpus can retrieve all of it.",
                    "One corpus per audience (or Agent Search with document ACLs), chosen server-side.")
    if search:
        name = search["data_store"].rsplit("/", 1)[1]
        if not search["acl_enabled"] and set(search["documents"]) & restricted and req["users_have_different_access"]:
            add("HIGH", "GC13-03", name,
                "Agent Search data store without access control holds restricted documents.",
                "Access control can only be chosen when a data store is created: create a new one with "
                "\"This data store contains access control information\" (aclEnabled) and acl_info on each document.")
        if search["search_runs_as"] != "end_user" and req["users_have_different_access"]:
            add("HIGH", "GC13-04", name,
                "Search runs with the agent's identity, so document ACLs see the agent, not the person asking "
                "(agent-auth).",
                "Search with the end user's credentials (user-auth: their OAuth access token), or keep only "
                "everyone-may-read content in stores the agent searches as itself.")
        if search.get("user_role") == "roles/discoveryengine.viewer":
            add("MEDIUM", "GC13-05", name,
                "Users hold Discovery Engine Viewer, which Google now calls suitable only for initial testing.",
                "A custom role with discoveryengine.servingConfigs.search (and the other permissions Google lists).")
    for src in ret.get("import_sources", []):
        broad = [w for w in dep["buckets"].get(src, {}).get("objectCreators", []) if w in req["broad_groups"]]
        if broad:
            add("HIGH", "GC13-06", src,
                f"Documents are imported from a bucket that {', '.join(broad)} can write to: anyone there can plant "
                "instructions the agent will read (indirect prompt injection).",
                "Import only from a curated bucket written by a small editors group; review before import.")

    # ---- data protection --------------------------------------------------------------------------------------
    if req["cmek_required_for_customer_data_at_rest"]:
        missing = [c["display_name"] for c in (rag or {}).get("corpora", []) if not c.get("encryption_spec")]
        if search and not search.get("kms_key_name"):
            missing.append(search["data_store"].rsplit("/", 1)[1])
        if missing:
            add("MEDIUM", "GC13-07", ", ".join(missing),
                "No customer-managed key, but ExampleCo requires CMEK for customer data at rest.",
                "Both settings are fixed at creation (RagCorpus.encryption_spec, DataStore kms_key_name): create "
                "new ones with the helpdesk-data key and re-import.")
    needed = {"aiplatform.googleapis.com"} | ({"discoveryengine.googleapis.com"} if search else set())
    gap = sorted(needed - set(dep["perimeter"]["restricted_services"]))
    if gap:
        add("MEDIUM", "GC13-08", dep["perimeter"]["name"].rsplit("/", 1)[1],
            f"The perimeter doesn't restrict {', '.join(gap)}.",
            "Add them to the perimeter's restricted services (dry run first, GC11). To see every service a perimeter "
            "can restrict: gcloud access-context-manager supported-services list.")
    if search and req["ml_processing_must_stay_in"] == "EU" and search["location"] != "eu":
        add("MEDIUM", "GC13-09", search["data_store"].rsplit("/", 1)[1],
            f"Data store location is '{search['location']}', but ExampleCo's data must stay in the EU.",
            "Data store location can be global, us or eu: create it in eu.")

    # ---- the agent's identity ------------------------------------------------------------------------------------
    ident = agent["identity"]
    if ident.get("identity_type") != "AGENT_IDENTITY" and not ident.get("service_account"):
        add("HIGH", "GC13-10", "Agent Runtime",
            f"The agent runs as the default Reasoning Engine Service Agent "
            f"(service-{dep['project_number']}@gcp-sa-aiplatform-re...), one principal per project: every agent "
            "deployed this way shares its permissions, and logs can't tell them apart.",
            "Deploy with a dedicated service account (adk deploy agent_engine --service_account=...) or Agent "
            "Identity (preview), and grant only what this agent needs.")
    broad = sorted(set(agent["project_roles"]) & BROAD_ROLES)
    if broad:
        add("HIGH", "GC13-11", "agent identity",
            f"Project-wide roles far beyond the job: {', '.join(broad)}.",
            "Keep roles/aiplatform.user; grant data access on the dataset, bucket or data store it needs, read-only.")
    if agent["user_id_from"] != "verified_id_token":
        add("HIGH", "GC13-12", "agent front end",
            "The end user's identity is taken from the request body (user_id), which any caller can set.",
            "Take it from a verified ID token on your server and write it into session state yourself.")

    # ---- writes ----------------------------------------------------------------------------------------------------
    tools = agent["tools"]
    unapproved = [n for n, t in tools.items() if t.get("writes") and t.get("confirmation", "none") == "none"]
    if unapproved:
        add("HIGH", "GC13-13", ", ".join(unapproved),
            "Write tools run as soon as the model calls them: one injected instruction is one action.",
            "FunctionTool(..., require_confirmation=True), or an approval queue outside the agent; show the exact "
            "arguments to the person.")
    adk_conf = [n for n, t in tools.items() if t.get("confirmation") == "adk_confirmation"]
    if adk_conf and agent["session_service"] in ("VertexAiSessionService", "DatabaseSessionService"):
        add("MEDIUM", "GC13-14", ", ".join(adk_conf),
            f"ADK tool confirmation is used with {agent['session_service']}, which ADK lists as not supported.",
            "Test it on your session service, or move approval into an approval queue your app owns.")
    if agent.get("before_tool_callback") is None:
        add("HIGH", "GC13-15", "send_email", "No before_tool policy at all: recipients and tickets aren't checked.",
            "Add controls.before_tool as the agent's before_tool_callback.")
    else:
        for p in probe_recipient_policy():
            add("HIGH", "GC13-15", "controls.before_tool",
                f"No recipient policy for send_email: {p}, so one tired click sends it.",
                "Allow only example.com and the ticket's own customer, in code, before anyone is asked (Step 7).")

    # ---- Model Armor and logs ---------------------------------------------------------------------------------
    ma = agent.get("plugins", {}).get("model_armor")
    if not ma or not ma.get("tool_output_template_name"):
        add("HIGH", "GC13-16", "ModelArmorPlugin",
            "Tool results (retrieved documents, ticket text) aren't screened: indirect injection reaches the model.",
            "Set tool_output_template_name (ADK 2.12.0 or later).")
    if ma and not ma.get("block_on_screening_failure", True):
        add("MEDIUM", "GC13-16", "ModelArmorPlugin",
            "block_on_screening_failure is false: when Model Armor can't be reached, everything goes through unscreened.",
            "Set it true (ADK's default). To keep user input flowing in an outage but never tool output, register "
            "two ModelArmorPlugin instances with their own names: one for input, one for tool output.")
    obs = agent["observability"]
    if obs.get("ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS") == "true" and set(obs["trace_readers"]) & set(req["broad_groups"]):
        add("MEDIUM", "GC13-17", "Cloud Trace",
            "Prompts, tool arguments and tool results are captured in trace spans, and "
            f"{', '.join(set(obs['trace_readers']) & set(req['broad_groups']))} can read them.",
            "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS=false (ADK's deploy default), or restrict who reads traces.")

    # ---- GC13-18: your rule (README Step 7) -------------------------------------------------------------------
    # TODO: report a MEDIUM finding when the tool-call log can't say which person an action was for:
    #       "end_user" missing from agent["observability"]["tool_log_fields"].

    return sorted(out, key=lambda f: (SEV_ORDER[f.sev], f.rule))


def notes(twin: str) -> list[str]:
    dep = load_json(HERE / "twin" / twin / "deployment.json")
    n = []
    if dep["retrieval"].get("rag_engine"):
        n.append("RAG Engine permissions are granted on the project (a corpus has no IAM policy of its own in the v1 "
                 "API): the agent's identity can retrieve from every corpus in the project. The corpus choice lives "
                 "in your tool code; test it.")
        n.append("RAG Engine supports CMEK and VPC Service Controls, but Google says data residency and Access "
                 "Transparency aren't supported. Record the decision.")
        n.append("RAG Engine's metadata search is Preview, and off for projects that had VPC-SC before its Preview.")
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--twin", default="today")
    ap.add_argument("--ci", action="store_true")
    a = ap.parse_args()
    found = run(a.twin)
    print(f"--- GC13 checker · {a.twin} ---\n")
    wrap = lambda s, ind: textwrap.fill(s, 112, initial_indent=ind, subsequent_indent=" " * len(ind))  # noqa: E731
    for f in found:
        print(f"  {f.sev:<7} {f.rule}  {f.where}")
        print(wrap(f.what, "          "))
        print(wrap(f.fix, "          fix: ").replace("          fix: ", "          fix: ", 1))
    for note in notes(a.twin):
        print(wrap(note, "  NOTE    "))
    high = sum(1 for f in found if f.sev == "HIGH")
    print(f"\n{len(found)} findings ({high} HIGH), {len(notes(a.twin))} notes.")
    sys.exit(1 if a.ci and high else 0)


if __name__ == "__main__":
    main()
