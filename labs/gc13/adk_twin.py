"""
adk_twin.py: a small, offline model of how an ADK runner executes one turn of an agent (GC13). Standard library only.

It is NOT the Agent Development Kit. It copies the ADK behaviours this lab depends on, which we checked against
ADK 2.12.0 (README, "About the twins"):
  * Plugin callbacks run BEFORE agent callbacks, and the first one that returns something other than None wins:
    for before_tool that result replaces the tool call (the tool never runs).
  * A tool wrapped with require_confirmation pauses: ADK emits an `adk_request_confirmation` function call carrying
    `originalFunctionCall` and `toolConfirmation`, and the tool only runs after a FunctionResponse with
    {"confirmed": true}. before_tool callbacks run on the first attempt AND again after confirmation.
  * after_tool callbacks can replace a tool's result (Model Armor's plugin returns {"error": ...} when a tool
    output is blocked).
  * The ModelArmorPlugin's decision rule: block on MATCH_FOUND; when screening fails (an exception, or an
    invocationResult other than SUCCESS) block only if block_on_screening_failure is true (ADK's default).
Every step is written to an audit log, shaped like the tool-call entries you would send to Cloud Logging.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Callable, Optional

from gcp_twin import ModelArmorTwin, ModelArmorUnavailable

BLOCKED_INPUT = "I'm sorry, but I can't help with that request."           # ADK's default blocked message
TOOL_OUTPUT_BLOCKED = "Tool output was blocked by Model Armor."             # ADK's default for tool output
CONFIRMATION_HINT = "This tool call requires confirmation, please approve or reject."


@dataclass
class ToolContext:
    state: dict
    function_call_id: str
    tool_confirmation: Optional[dict] = None


@dataclass
class Tool:
    name: str
    func: Callable[[dict, ToolContext], dict]
    writes: bool = False
    confirmation: str = "none"          # none | adk_confirmation | approval_queue


@dataclass
class ModelArmorPluginTwin:
    """Same configuration fields as google.adk.integrations.model_armor.ModelArmorConfig."""
    armor: ModelArmorTwin
    prompt_template_name: Optional[str] = None
    response_template_name: Optional[str] = None
    tool_output_template_name: Optional[str] = None
    block_on_screening_failure: bool = True
    log: list = field(default_factory=list)

    def _blocked(self, template: Optional[str], text: str, direction: str) -> bool:
        if not template:
            return False
        try:
            res = self.armor.sanitize(text, template)["sanitizationResult"]
        except ModelArmorUnavailable:
            self.log.append(f"model_armor {direction}: screening FAILED (unreachable)")
            return self.block_on_screening_failure
        if res["filterMatchState"] == "MATCH_FOUND":
            self.log.append(f"model_armor {direction}: MATCH_FOUND")
            return True
        if res["invocationResult"] != "SUCCESS":
            return self.block_on_screening_failure
        return False

    def before_model(self, user_text: str) -> Optional[str]:
        return BLOCKED_INPUT if self._blocked(self.prompt_template_name, user_text, "input") else None

    def after_model(self, answer: str) -> Optional[str]:
        return BLOCKED_INPUT if self._blocked(self.response_template_name, answer, "output") else None

    def after_tool(self, tool: Tool, args: dict, ctx: ToolContext, result: dict) -> Optional[dict]:
        return {"error": TOOL_OUTPUT_BLOCKED} if self._blocked(self.tool_output_template_name, str(result),
                                                               "tool output") else None


@dataclass
class Turn:
    answer: str
    events: list
    paused: Optional[dict] = None


class Runner:
    def __init__(self, model, tools: dict[str, Tool], *, plugins: list = (), before_tool=None, after_tool=None,
                 audit_fields=("agent_principal", "tool", "args", "decision"), agent_principal: str = ""):
        self.model, self.tools, self.plugins = model, tools, list(plugins)
        self.before_tool, self.after_tool = before_tool, after_tool
        self.audit_fields, self.agent_principal = list(audit_fields), agent_principal
        self.audit: list[dict] = []
        self._ids = itertools.count(1)

    # -- audit log ----------------------------------------------------------------------------------------------
    def _log(self, state: dict, tool: str, args: dict, decision: str):
        entry = {"agent_principal": self.agent_principal, "end_user": state.get("end_user"), "tool": tool,
                 "args": args, "decision": decision}
        self.audit.append({k: v for k, v in entry.items() if k in self.audit_fields})

    # -- one tool call, ADK order -------------------------------------------------------------------------------
    def _call_tool(self, name: str, args: dict, state: dict, human, events: list) -> tuple[dict, Optional[dict]]:
        tool = self.tools.get(name)
        if tool is None:
            return {"error": f"unknown tool {name}"}, None
        ctx = ToolContext(state=state, function_call_id=f"adk-call-{next(self._ids)}")
        confirmed = None
        while True:
            for hook in [getattr(p, "before_tool", None) for p in self.plugins] + [self.before_tool]:
                out = hook(tool, args, ctx) if hook else None
                if out is not None:
                    self._log(state, name, args, f"BLOCKED by before_tool: {out.get('error', out)}")
                    events.append(("blocked", name, args, out))
                    return out, None
            if tool.confirmation != "none" and not (confirmed and confirmed.get("confirmed")):
                request = {"name": "adk_request_confirmation",
                           "args": {"originalFunctionCall": {"id": ctx.function_call_id, "name": name, "args": args},
                                    "toolConfirmation": {"hint": CONFIRMATION_HINT, "confirmed": False}}}
                via = "approval queue" if tool.confirmation == "approval_queue" else "adk_request_confirmation"
                self._log(state, name, args, f"PAUSED for a person ({via})")
                events.append(("paused", name, args, dict(request, via=via)))
                decision = human(request) if human else None
                if decision is None:
                    return {"status": "pending_approval", "approval_id": ctx.function_call_id}, request
                confirmed = {"confirmed": bool(decision)}
                if not decision:
                    self._log(state, name, args, "REJECTED by a person")
                    events.append(("rejected", name, args, None))
                    return {"error": "The person rejected this action."}, None
                self._log(state, name, args, "APPROVED by a person")
                events.append(("approved", name, args, None))
                ctx.tool_confirmation = confirmed
                continue                         # ADK runs before_tool again after confirmation
            break
        result = tool.func(args, ctx)
        for hook in [getattr(p, "after_tool", None) for p in self.plugins] + [self.after_tool]:
            out = hook(tool, args, ctx, result) if hook else None
            if out is not None:
                self._log(state, name, args, f"RESULT REPLACED by after_tool: {out.get('error', out)}")
                events.append(("result_blocked", name, args, out))
                return out, None
        self._log(state, name, args, "EXECUTED")
        events.append(("executed", name, args, result))
        return result, None

    def run(self, user_text: str, state: dict, human=None, max_steps: int = 4) -> Turn:
        events: list = []
        for p in self.plugins:
            blocked = p.before_model(user_text) if hasattr(p, "before_model") else None
            if blocked:
                events.append(("input_blocked", None, None, blocked))
                return Turn(blocked, events)
        results: list[dict] = []
        for _ in range(max_steps):
            step = self.model.next_step(user_text, results)
            if "text" in step:
                answer = step["text"]
                for p in self.plugins:
                    blocked = p.after_model(answer) if hasattr(p, "after_model") else None
                    if blocked:
                        events.append(("output_blocked", None, None, blocked))
                        return Turn(blocked, events)
                return Turn(answer, events)
            name, args = step["call"]
            result, paused = self._call_tool(name, args, state, human, events)
            results.append({"tool": name, "args": args, "result": result})
            if paused:
                return Turn(self.model.next_step(user_text, results)["text"], events, paused)
        return Turn("(step limit reached)", events)
