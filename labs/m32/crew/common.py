"""Small shared types for the TSG Ops Crew. Core file: do not edit (the self-check compares it with the original)."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Decision:
    """What a guard decided. allow=False stops the action; reason goes into the log."""
    allow: bool
    reason: str = ""


ALLOW = Decision(True, "")


@dataclass
class ToolCall:
    tool: str                 # e.g. "issue_refund", "send_email", "run_query", "crm_lookup"
    args: dict
    agent: str = ""           # which agent asked (triage | billing | analyst)
    server: str = "local"     # "local" = a tool in tools.py; "crm" = a tool on the MCP server
    why: str = ""             # what made the agent ask (shown in the transcript and the log)


@dataclass
class Handoff:
    """One agent asking the orchestrator to pass work to another agent."""
    frm: str                  # the agent handing off
    to: str                   # the agent it wants to run next
    task: str                 # the instruction it passes along
    why: str = ""


@dataclass
class Ctx:
    """Everything a guard may look at for one step of one turn."""
    requester: dict                               # {"email", "name", "role", "tenant"}  (the signed-in human)
    agent: str = ""                               # the agent this step runs as
    message: str = ""                             # the original human request
    internal_domain: str = ""
    request_id: str = ""
    depth: int = 0                                # how many hand-offs deep this agent is (0 = triage)
    tenant_scope: str = ""                        # the tenant this turn is allowed to touch (set at the first step)
    untrusted_sources: list = field(default_factory=list)  # ids of docs, memory items and tool results in context
    tool_calls: list = field(default_factory=list)          # ToolCalls already allowed this turn (every agent)
    handoffs: list = field(default_factory=list)            # Handoffs already allowed this turn
    data_read: list = field(default_factory=list)           # labels of data the turn has read (e.g. "customer_list")

    @property
    def untrusted_in_context(self) -> bool:
        return bool(self.untrusted_sources)
