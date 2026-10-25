"""Small shared types (Decision, ToolCall, Ctx). Core file: do not edit (the self-check compares it with the original)."""
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
    tool: str                 # e.g. "send_email", "lookup_order", "crm_lookup"
    args: dict
    server: str = "local"     # "local" = a tool in tools.py; "crm" = a tool on the MCP server
    why: str = ""             # what made the model ask for it (shown in the transcript and the log)


@dataclass
class Ctx:
    """Everything a guard may look at for one chat turn."""
    user: dict                                   # {"email", "name", "role", "tenant"}
    message: str
    internal_domain: str
    request_id: str = ""
    untrusted_sources: list = field(default_factory=list)  # doc ids and tool names whose text is in the context
    tool_calls: list = field(default_factory=list)          # ToolCalls already allowed this turn
    data_read: list = field(default_factory=list)           # labels of data the turn has read (e.g. "customer_list")

    @property
    def untrusted_in_context(self) -> bool:
        return bool(self.untrusted_sources)
