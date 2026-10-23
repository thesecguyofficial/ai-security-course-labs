"""
The GC14 Helpdesk agent for the guided build (GUIDED-BUILD.md). Runs on Agent Runtime, in YOUR project only.

Two kinds of tools, both reached through the Agent Gateway the deployment is bound to:
  - Google's BigQuery remote MCP server (https://bigquery.googleapis.com/mcp), registered in Agent Registry
    automatically when the BigQuery API is enabled. The agent calls it with its own Agent Identity token.
  - fetch_page(url): a plain HTTPS GET. Its destination isn't in Agent Registry, so the gateway's default deny
    applies to it unless a policy allows the host.

There are no secrets in this file and nothing that acts on text found in data: the gateway, the access policy and
IAM decide what each call may do.
"""

import os
import urllib.request

import google.auth
import google.auth.transport.requests
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams

PROJECT = os.environ.get("TSG_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
MODEL = os.environ.get("TSG_MODEL", "gemini-3.5-flash")


def bigquery_headers(_context=None) -> dict:
    """A fresh access token for the agent's own identity, and the project to bill queries to."""
    creds, project = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    creds.refresh(google.auth.transport.requests.Request())
    return {"Authorization": f"Bearer {creds.token}", "x-goog-user-project": PROJECT or project}


def fetch_page(url: str) -> dict:
    """Fetch a public web page over HTTPS and return its first 2,000 characters.

    Args:
        url: an https:// address.
    """
    if not url.startswith("https://"):
        return {"status": "error", "error": "only https:// addresses"}
    try:
        with urllib.request.urlopen(url, timeout=10) as r:          # noqa: S310 (https only, checked above)
            return {"status": "ok", "http_status": r.status, "text": r.read(2000).decode("utf-8", "replace")}
    except Exception as e:                                          # the gateway's refusal arrives here
        return {"status": "error", "error": f"{type(e).__name__}: {e}"}


root_agent = LlmAgent(
    name="tsg_helpdesk_gc14",
    model=MODEL,
    description="TSG Helpdesk (GC14 guided build): answers questions about helpdesk tickets in BigQuery.",
    instruction=(
        f"You are the TSG Helpdesk assistant for project {PROJECT}. Tickets are in the BigQuery table "
        f"`{PROJECT}.helpdesk.tickets` (columns: ticket_id, status, summary). Use execute_sql_readonly for "
        "questions and execute_sql only when the user asks you to change a ticket. Use fetch_page only when the "
        "user gives you a URL. If a tool returns an error, say which tool failed and quote the error message."
    ),
    tools=[
        McpToolset(
            connection_params=StreamableHTTPConnectionParams(url="https://bigquery.googleapis.com/mcp"),
            header_provider=bigquery_headers,
        ),
        fetch_page,
    ],
)
