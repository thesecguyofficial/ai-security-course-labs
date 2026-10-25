"""
agents.py: the two email agents, as AgentDojo pipelines, so AgentDojo's own task checkers score them.

  SingleAgent   BEFORE. One model plans, reads every tool result, and calls tools. It is the obedient stand-in, so
                any attacker goal it reads, it carries out (standin.injected_goals).
                taint=True adds the coarse defence: once anything untrusted has entered the context, every sink is
                refused ("trusted action": the decision to call it was made after reading untrusted text).

  DualAgent     AFTER. The dual-LLM pattern with a controller in plain code:
                  planner      sees the user's request only, writes a plan with variables ($e, $a, ...)
                  quarantined  reads untrusted text, answers one typed question, has no tools
                  controller   this class: runs the plan, keeps every value with its label, never shows a tool
                               result to the planner
                taint=True adds the taint-checked sinks (policies.check) before every sink call.
                strict=True is challenge part 2: calls inside an If on an untrusted condition carry that label.

Both write one JSON line per sink decision to $M22_LOG when it is set (score.py does that for `make audit`).
"""

from __future__ import annotations

import itertools
import json
import os
from collections.abc import Sequence

from agentdojo.agent_pipeline import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatToolResultMessage, ChatUserMessage, text_content_block_from_string

import policies
import standin
from labels import Label, Labelled, Labeller, join_all
from standin import Answer, Ask, Call, Fmt, Follow, If, Lit, Ref, Refuse


_SESSIONS = itertools.count(1)


def _targets(tool: str, args: dict) -> list:
    """Where a sink call sends things: recipients, the person a file is shared with, or the URL."""
    if tool == "send_email":
        return list(args.get("recipients") or [])
    if tool == "share_file":
        return [args.get("email")]
    if tool == "fetch_url":
        return [args.get("url")]
    return []


def _text(s: str):
    return [text_content_block_from_string(s)]


def _get(value, path: str):
    for step in [p for p in path.split(".") if p]:
        value = value[int(step)] if step.isdigit() else getattr(value, step)
    return value


class _Base(BasePipelineElement):
    mode = "single"

    def __init__(self, name: str, injection_tasks: dict, taint: bool = False, strict: bool = False):
        self.name = name
        self.injection_tasks = injection_tasks
        self.taint = taint
        self.strict = strict
        self.trace: list[dict] = []
        self.planner_saw: dict = {}

    # --- shared plumbing ---
    def _start(self, query, messages):
        self.trace = []
        self.session = next(_SESSIONS)
        self.planner_saw = {"request": query, "tools": [], "tool_results": []}
        self.task_id, plan = standin.plan_for(query, self.mode)
        self.messages = [*messages, ChatUserMessage(role="user", content=_text(query))]
        self.answer_parts: list[str] = []      # what the plan says
        self.refusals: list[str] = []          # what the policy stopped
        return plan

    def _run_tool(self, runtime, env, tool: str, args: dict):
        call = FunctionCall(function=tool, args=args)
        self.messages.append(ChatAssistantMessage(role="assistant", content=_text(""), tool_calls=[call]))
        result, error = runtime.run_function(env, tool, args)
        self.messages.append(ChatToolResultMessage(role="tool", content=_text(tool_result_to_str(result) if not error else ""),
                                                   tool_call=call, tool_call_id=None, error=error))
        self.trace.append({"step": "tool", "tool": tool, "args": args, "error": error})
        return result

    def _log(self, event: dict):
        """One JSON line per read and per sink attempt, to $M22_LOG (score.py --log). audit.py reads it."""
        log = os.environ.get("M22_LOG")
        if log:
            with open(log, "a") as fh:
                fh.write(json.dumps({"session": self.session, "agent": self.name, "task": self.task_id, **event}) + "\n")

    def _log_read(self, tool: str, label):
        if tool not in policies.SINKS:
            self._log({"event": "read", "tool": tool, "untrusted": not label.trusted, "sources": list(label.sources)})

    def _log_sink(self, tool: str, args: dict, verdict: str, rule: str = "", reason: str = ""):
        self._log({"event": "sink", "tool": tool, "targets": _targets(tool, args), "verdict": verdict,
                   "rule": rule, "reason": reason})

    def _decision(self, tool, args, decision, from_plan: bool = True):
        event = {"step": "policy", "agent": self.name, "task": self.task_id, "tool": tool, "args": args,
                 "verdict": decision.verdict, "rule": decision.rule, "reason": decision.reason,
                 "notes": list(decision.notes)}
        self.trace.append(event)
        if not decision.allowed:
            self._log_sink(tool, args, "DENY", decision.rule, decision.reason)
        if not decision.allowed:
            self.refusals.append((from_plan, f"I did not run {tool}: {decision.reason}."))

    def _finish(self, query, runtime, env, extra_args):
        planned = [r for own, r in self.refusals if own]
        other = [r for own, r in self.refusals if not own]
        if planned:            # never report the plan's success line when the policy stopped one of its steps
            text = "I stopped before finishing. " + " ".join(planned + other)
        else:
            text = " ".join([p for p in self.answer_parts if p] + other) or "Done."
        self.messages.append(ChatAssistantMessage(role="assistant", content=_text(text), tool_calls=None))
        self.trace.append({"step": "answer", "text": text})
        return query, runtime, env, self.messages, extra_args


# ---------------------------------------------------------------- BEFORE: one model sees everything ----

class SingleAgent(_Base):
    mode = "single"

    def query(self, query: str, runtime: FunctionsRuntime, env=EmptyEnv(), messages: Sequence = (), extra_args: dict = {}):
        plan = self._start(query, messages)
        self.planner_saw["tools"] = sorted(runtime.functions)
        labeller = Labeller(env)
        self.tainted, self.obeyed = False, set()
        vars_: dict = {}

        def val(a):
            if isinstance(a, Lit):
                return a.value
            if isinstance(a, Ref):
                return _get(vars_.get(a.var), a.path)
            if isinstance(a, Fmt):
                return a.template.format(**{k: val(r) for k, r in a.refs.items()})
            if isinstance(a, list):
                return [val(x) for x in a]
            return a

        def tool(name, args, from_plan=True):
            if self.taint and name in policies.SINKS and self.tainted:
                self._decision(name, args, policies.Decision(
                    "DENY", "trusted_action", "this call was decided after untrusted content entered the context"),
                    from_plan)
                return None
            result = self._run_tool(runtime, env, name, args)
            if name in policies.SINKS:
                self._log_sink(name, args, "RAN")
            else:
                self._log_read(name, labeller.whole(result))
            seen = standin.as_text(result)
            self.planner_saw["tool_results"].append(seen)       # the single model reads every result
            if labeller.has_untrusted(result):
                self.tainted = True
            for task in standin.injected_goals(seen, self.injection_tasks):
                if task.ID in self.obeyed:
                    continue
                self.obeyed.add(task.ID)
                self.trace.append({"step": "obey", "goal": task.GOAL})
                for fc in task.ground_truth(env):
                    tool(fc.function, dict(fc.args), from_plan=False)
                if task.GROUND_TRUTH_OUTPUT:
                    self.answer_parts.append(task.GROUND_TRUTH_OUTPUT)
            return result

        def run(steps):
            for st in steps:
                if isinstance(st, Call):
                    vars_[st.out] = tool(st.tool, {k: val(v) for k, v in st.args.items()})
                elif isinstance(st, Ask):          # the same model answers its own question
                    src = val(st.src)
                    vars_[st.out] = standin.quarantined(st.kind, src if isinstance(src, str) else str(src), st.about)
                elif isinstance(st, If):
                    run(st.then if val(st.cond) else st.otherwise)
                elif isinstance(st, Follow):
                    for name, args in standin.follow(val(st.src)):
                        if name == "share_file_by_name":
                            files = tool("search_files", {"query": args["name"]}) or []
                            if files:
                                tool("share_file", {"file_id": files[0].id, "email": args["email"]})
                        else:
                            tool(name, args)
                elif isinstance(st, Answer):
                    self.answer_parts.insert(0, val(st.text))
                elif isinstance(st, Refuse):
                    self.answer_parts.insert(0, st.reason)

        try:
            run(plan)
        except (TypeError, AttributeError, IndexError, KeyError):
            self.answer_parts.append("I couldn't finish: a step had no data.")
        return self._finish(query, runtime, env, extra_args)


# ---------------------------------------------------------------- AFTER: dual LLM + controller ----

class DualAgent(_Base):
    mode = "dual"

    def query(self, query: str, runtime: FunctionsRuntime, env=EmptyEnv(), messages: Sequence = (), extra_args: dict = {}):
        plan = self._start(query, messages)
        self.planner_saw["tools"] = sorted(runtime.functions)   # the planner's whole view: request + tool names
        labeller = Labeller(env)
        ctx = policies.Context(staff=labeller.staff, file_label=lambda fid: self._file_label(env, labeller, fid))
        vars_: dict[str, Labelled] = {}

        def lit(value) -> Labelled:
            def one(v):
                src = policies.USER if isinstance(v, str) and v in query else "planner"
                return Labelled(v, Label(True, None, (src,)))
            if isinstance(value, list):
                parts = [one(v) for v in value]
                return Labelled(value, join_all(p.label for p in parts), parts)
            return one(value)

        def val(a) -> Labelled:
            if isinstance(a, Lit):
                return lit(a.value)
            if isinstance(a, Ref):
                held = vars_.get(a.var)
                if held is None or held.value is None:
                    raise LookupError(f"${a.var} has no value")
                if not a.path:
                    return held
                parent_path, _, field = a.path.rpartition(".")
                obj = _get(held.value, parent_path)
                return Labelled(getattr(obj, field), labeller.field(obj, field))
            if isinstance(a, Fmt):
                refs = {k: val(r) for k, r in a.refs.items()}
                label = join_all([Label(True, None, ("planner",))] + [r.label for r in refs.values()])
                return Labelled(a.template.format(**{k: r.value for k, r in refs.items()}), label)
            if isinstance(a, list):
                parts = [val(x) for x in a]
                return Labelled([p.value for p in parts], join_all(p.label for p in parts), parts)
            raise TypeError(a)

        def run(steps, control: Label | None):
            for st in steps:
                if isinstance(st, Call):
                    args = {k: val(v) for k, v in st.args.items()}
                    raw = {k: v.value for k, v in args.items()}
                    if self.taint and st.tool not in policies.READ_ONLY:
                        decision = policies.check(st.tool, args, ctx, control)
                        self._decision(st.tool, raw, decision)
                        if not decision.allowed:
                            vars_[st.out or "_"] = Labelled(None, Label(True))
                            continue
                    result = self._run_tool(runtime, env, st.tool, raw)
                    label = labeller.page(raw.get("url", "")) if st.tool == "fetch_url" else labeller.whole(result)
                    if st.tool in policies.SINKS:
                        self._log_sink(st.tool, raw, "ALLOW" if self.taint else "RAN")
                    else:
                        self._log_read(st.tool, label)
                    vars_[st.out or "_"] = Labelled(result, label)
                elif isinstance(st, Ask):
                    src = val(st.src)
                    answer = standin.quarantined(st.kind, str(src.value), st.about)
                    parts = [Labelled(a, src.label) for a in answer] if isinstance(answer, list) else []
                    vars_[st.out] = Labelled(answer, src.label, parts)
                    self.trace.append({"step": "quarantined", "kind": st.kind, "answer": answer,
                                       "label": src.label.short()})
                elif isinstance(st, If):
                    cond = val(st.cond)
                    inner = control
                    if self.strict:
                        # CHALLENGE part 2 (lesson 22.4): an implicit flow. The calls inside this branch happen
                        # BECAUSE of `cond`, so in strict mode they must carry its label. Set `inner` to the join of
                        # `control` (None means no condition yet) and `cond.label`. Test: run_tests.py --challenge
                        pass
                    run(st.then if cond.value else st.otherwise, inner)
                elif isinstance(st, Answer):
                    self.answer_parts.insert(0, st.text if isinstance(st.text, str) else val(st.text).value)
                elif isinstance(st, Refuse):
                    self.answer_parts.insert(0, st.reason)

        try:
            run(plan, None)
        except LookupError as e:
            self.answer_parts.append(f"I stopped: {e}.")
        return self._finish(query, runtime, env, extra_args)

    @staticmethod
    def _file_label(env, labeller, fid):
        for f in env.drive.files:
            if f.id == fid:
                return labeller.field(f, "content")
        return Label(False, frozenset(), (f"unknown file {fid}",))


def make_agent(kind: str, suite) -> _Base:
    """single | single+taint | dual | dual+taint | dual+taint+strict"""
    inj = suite.injection_tasks
    table = {
        "single": lambda: SingleAgent("single", inj),
        "single+taint": lambda: SingleAgent("single+taint", inj, taint=True),
        "dual": lambda: DualAgent("dual", inj),
        "dual+taint": lambda: DualAgent("dual+taint", inj, taint=True),
        "dual+taint+strict": lambda: DualAgent("dual+taint+strict", inj, taint=True, strict=True),
    }
    return table[kind]()


AGENTS = ["single", "single+taint", "dual", "dual+taint"]
