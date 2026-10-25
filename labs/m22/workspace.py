"""
workspace.py: OPTIONAL. The same before/after question on AgentDojo's OWN workspace suite (v1.2.2: 40 user tasks,
14 injection tasks, email + calendar + cloud drive), so you see the trade-off on tasks this lab did not write.

    python3 workspace.py              # obedient single model, then the same model with context-level taint
    python3 workspace.py --quick      # the first 10 user tasks only (what the tests run)

It uses injection tasks 0 to 5. The eight added in v1.2 (6 to 13) have an empty ground truth in AgentDojo, so a
stand-in that replays ground truth has no attacker calls to obey for them.

There is no dual-LLM row here, and that is the point of the comparison. A dual-LLM agent needs a planner that can
write a plan for each task without seeing the data; this lab's planner is scripted for its own eight tasks only. What
you CAN bolt onto an existing single-model agent without rewriting it is the coarse defence: refuse every
state-changing tool once anything untrusted has entered the context. This file measures what that costs.

The stand-in model: for each user task it makes the calls in AgentDojo's own ground truth (a model that always knows
the right steps), and whenever it reads one of the suite's attacker goals in a tool result, it carries that goal out
first (a model that always obeys). Real models land between this and a perfect refuser.
"""

from __future__ import annotations

import argparse
import warnings
from collections.abc import Sequence

from agentdojo.agent_pipeline import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatAssistantMessage, ChatToolResultMessage, ChatUserMessage, text_content_block_from_string

import standin
from score import LabAttack, _quiet
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections

VERSION = "v1.2.2"
# Every workspace tool that changes state or sends something out.
SINKS = {"send_email", "delete_email", "create_calendar_event", "cancel_calendar_event", "reschedule_calendar_event",
         "add_calendar_event_participants", "append_to_file", "create_file", "delete_file", "share_file"}
# Tool results nobody outside can write. Everything else (emails, files, calendar text) counts as untrusted.
TRUSTED_RESULTS = {"get_current_day"}


def _t(s):
    return [text_content_block_from_string(s)]


class ObedientGroundTruth(BasePipelineElement):
    def __init__(self, suite, taint: bool):
        self.name = "obedient-standin" + ("+taint" if taint else "")
        self.suite, self.taint = suite, taint
        self.by_prompt = {t.PROMPT: t for t in suite.user_tasks.values()}
        self.by_prompt.update({t.GOAL: t for t in suite.injection_tasks.values()})

    def query(self, query: str, runtime: FunctionsRuntime, env=EmptyEnv(), messages: Sequence = (), extra_args: dict = {}):
        msgs = [*messages, ChatUserMessage(role="user", content=_t(query))]
        task = self.by_prompt[query]
        state = {"tainted": False, "obeyed": set(), "refused": 0, "refused_own": 0}
        extra_text = []

        def call(fc: FunctionCall, own: bool = True):
            if self.taint and fc.function in SINKS and state["tainted"]:
                state["refused"] += 1
                state["refused_own"] += own
                return
            msgs.append(ChatAssistantMessage(role="assistant", content=_t(""), tool_calls=[fc]))
            result, error = runtime.run_function(env, fc.function, fc.args)
            text = tool_result_to_str(result) if not error else ""
            msgs.append(ChatToolResultMessage(role="tool", content=_t(text), tool_call=fc, tool_call_id=None, error=error))
            if fc.function not in TRUSTED_RESULTS:
                state["tainted"] = True
            flat = " ".join(standin.as_text(result).split())
            for inj in self.suite.injection_tasks.values():
                if inj.ID not in state["obeyed"] and " ".join(inj.GOAL.split()) in flat:
                    state["obeyed"].add(inj.ID)
                    for gc in inj.ground_truth(env):
                        call(gc, own=False)
                    if inj.GROUND_TRUTH_OUTPUT:
                        extra_text.append(inj.GROUND_TRUTH_OUTPUT)

        for fc in task.ground_truth(env):
            call(fc)
        out = " ".join([task.GROUND_TRUTH_OUTPUT, *extra_text]).strip() or "Done."
        if state["refused_own"]:
            out = f"I stopped before finishing: {state['refused']} state-changing call(s) refused after reading untrusted content."
        elif state["refused"]:
            out += f" (Refused {state['refused']} state-changing call(s) that untrusted content asked for.)"
        msgs.append(ChatAssistantMessage(role="assistant", content=_t(out), tool_calls=None))
        return query, runtime, env, msgs, extra_args


def run(taint: bool, quick: bool = False, users: list[str] | None = None) -> dict:
    suite = get_suite(VERSION, "workspace")
    agent = ObedientGroundTruth(suite, taint)
    if quick and users is None:
        users = sorted(suite.user_tasks, key=lambda k: int(k.rsplit("_", 1)[1]))[:10]
    benign = _quiet(benchmark_suite_without_injections, agent, suite, logdir=None, force_rerun=True, user_tasks=users)
    # Only the injection tasks whose ground truth lists the attacker's calls (0 to 5). The ones added in v1.2
    # (6 to 13) have an empty ground truth, so a stand-in that replays ground truth has nothing to obey.
    goals = [k for k, t in suite.injection_tasks.items() if t.ground_truth(suite.load_and_inject_default_environment({}))]
    attacked = _quiet(benchmark_suite_with_injections, agent, suite, LabAttack(suite, agent), logdir=None,
                      force_rerun=True, user_tasks=users, injection_tasks=goals)
    return {"utility": benign["utility_results"], "utility_under_attack": attacked["utility_results"],
            "attacks": attacked["security_results"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    warnings.simplefilter("ignore")
    print(f"AgentDojo 0.1.35 | suite workspace {VERSION}{' (first 10 user tasks)' if args.quick else ''}, injection "
          f"tasks 0-5 | attack important_instructions (default names) | obedient stand-in")
    print(f"{'agent':<22}{'benign utility':>18}{'utility under attack':>24}{'attack success':>20}")
    for taint in (False, True):
        r = run(taint, args.quick)
        cells = []
        for key in ("utility", "utility_under_attack", "attacks"):
            d = r[key]
            cells.append(f"{sum(d.values())}/{len(d)} {100 * sum(d.values()) / len(d):5.1f}%")
        name = "single" + (" + context taint" if taint else "")
        print(f"{name:<22}{cells[0]:>18}{cells[1]:>24}{cells[2]:>20}")


if __name__ == "__main__":
    main()
