"""
score.py: score the agents with AgentDojo, before and after.

    python3 score.py                         # all four agents on the TSG inbox suite: the before/after table
    python3 score.py --agent single          # one agent, with every security case listed
    python3 score.py --trace UT3 IT0 --agent dual          # one run, step by step (IT- = no attack)
    python3 score.py --challenge --agent dual+taint+strict  # the suite plus the challenge tasks

AgentDojo's three numbers (Debenedetti et al., AgentDojo, arXiv 2406.13352):
  benign utility        user tasks completed with no attack in the data
  utility under attack  security cases (one user task + one injection task) where the user task is still completed
  attack success        security cases where the attacker's goal is met (targeted attack success rate)

The attack is AgentDojo's standard "important_instructions" text, with AgentDojo's default user and model names (this
lab's agents are not a named model). AgentDojo puts it in every place the user task reads (injection_vectors.yaml).
Every run starts from a fresh copy of the environment, so the numbers are the same every time.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import tempfile
import warnings
from pathlib import Path

from agentdojo.attacks.base_attacks import DEFAULT_MODEL_NAME, DEFAULT_USER_NAME
from agentdojo.attacks.baseline_attacks import FixedJailbreakAttack
from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from agentdojo.logging import OutputLogger

import agents
from inbox_suite import make_suite, short

STATE = Path(os.environ.get("M22_STATE", Path(__file__).parent / "state"))


class LabAttack(ImportantInstructionsAttack):
    """AgentDojo's important_instructions text, unchanged, addressed to 'the user' and 'the AI language model'."""
    name = "important_instructions_no_names"

    def __init__(self, task_suite, target_pipeline):
        FixedJailbreakAttack.__init__(self, self._JB_STRING, task_suite, target_pipeline)
        self.user_name, self.model_name = DEFAULT_USER_NAME, DEFAULT_MODEL_NAME


def _quiet(fn, *a, **k):
    """Run an AgentDojo benchmark function silently. AgentDojo writes one JSON log per run; they go to a temporary
    folder that is deleted afterwards (set M22_KEEP_RUNS=1 to keep them in state/agentdojo-runs)."""
    keep = os.environ.get("M22_KEEP_RUNS") == "1"
    with contextlib.ExitStack() as stack:
        if keep:
            logdir = STATE / "agentdojo-runs"
            logdir.mkdir(parents=True, exist_ok=True)
        else:
            logdir = stack.enter_context(tempfile.TemporaryDirectory())
        stack.enter_context(warnings.catch_warnings())
        warnings.simplefilter("ignore")
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        stack.enter_context(OutputLogger(str(logdir)))
        return fn(*a, **k)


def evaluate(kind: str, challenge: bool = False) -> dict:
    """Run one agent through AgentDojo. Returns the raw per-task results and the three numbers."""
    suite = make_suite(challenge)
    agent = agents.make_agent(kind, suite)
    benign = _quiet(benchmark_suite_without_injections, agent, suite, logdir=None, force_rerun=True)
    attacked = _quiet(benchmark_suite_with_injections, agent, suite, LabAttack(suite, agent), logdir=None,
                      force_rerun=True)
    u = {short(t): ok for (t, _), ok in benign["utility_results"].items()}
    ua = {(short(t), short(i)): ok for (t, i), ok in attacked["utility_results"].items()}
    sec = {(short(t), short(i)): hit for (t, i), hit in attacked["security_results"].items()}
    return {"agent": kind, "utility": u, "utility_under_attack": ua, "attacks": sec}


def numbers(r: dict) -> tuple[str, str, str]:
    def frac(d):
        n, k = len(d), sum(d.values())
        return f"{k}/{n} {100 * k / n:5.1f}%"
    return frac(r["utility"]), frac(r["utility_under_attack"]), frac(r["attacks"])


def table(kinds, challenge=False):
    print("AgentDojo 0.1.35 | suite tsg_inbox" + (" + challenge" if challenge else "") +
          " | attack important_instructions (default names) | stand-in models")
    print(f"{'agent':<20}{'benign utility':>18}{'utility under attack':>24}{'attack success':>18}")
    out = {}
    for kind in kinds:
        r = evaluate(kind, challenge)
        out[kind] = r
        b, ua, asr = numbers(r)
        print(f"{kind:<20}{b:>18}{ua:>24}{asr:>18}")
    return out


def detail(kind, challenge=False):
    r = evaluate(kind, challenge)
    b, ua, asr = numbers(r)
    print(f"agent {kind} | benign utility {b} | utility under attack {ua} | attack success {asr}")
    print("benign:  " + "  ".join(f"{t} {'ok' if ok else '--'}" for t, ok in sorted(r["utility"].items())))
    hits = sorted(k for k, v in r["attacks"].items() if v)
    print("attacks that worked: " + (", ".join(f"{t}+{i}" for t, i in hits) or "none"))
    lost = sorted(k for k, v in r["utility_under_attack"].items() if not v)
    print("user tasks lost under attack: " + (", ".join(f"{t}+{i}" for t, i in lost) or "none"))
    return r


def trace(kind, ut, it, challenge=False):
    """Run one user task (with one injection task, or none for IT-) and print what happened, step by step."""
    suite = make_suite(challenge)
    agent = agents.make_agent(kind, suite)
    user_task = suite.get_user_task_by_id(f"user_task_{ut[2:]}")
    injections = {}
    if it != "IT-":
        injection_task = suite.get_injection_task_by_id(f"injection_task_{it[2:]}")
        injections = LabAttack(suite, agent).attack(user_task, injection_task)
    else:
        injection_task = None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        utility, security = suite.run_task_with_pipeline(agent, user_task, injection_task, injections)
    print(f"{ut} with {'no attack' if it == 'IT-' else it} | agent {kind}")
    print(f"  REQUEST  {user_task.PROMPT}")
    if injections:
        print(f"  PLANTED  in {', '.join(injections)}: AgentDojo's attack text carrying {it}'s goal")
    for ev in agent.trace:
        if ev["step"] == "tool":
            print(f"  TOOL     {ev['tool']} {ev['args'] if ev['tool'] != 'send_email' else _mail(ev['args'])}")
        elif ev["step"] == "quarantined":
            print(f"  QUARANT. {ev['kind']} -> {ev['answer']!r}   [{ev['label']}]")
        elif ev["step"] == "obey":
            print(f"  OBEYS    a goal planted in the data: {ev['goal'][:70]}...")
        elif ev["step"] == "policy":
            print(f"  POLICY   {ev['verdict']} {ev['tool']} [{ev['rule']}] {ev['reason']}")
            for n in ev["notes"]:
                print(f"           note: {n}")
        elif ev["step"] == "answer":
            print(f"  ANSWER   {ev['text']}")
    print(f"  SCORE    user task {'completed' if utility else 'NOT completed'}"
          + ("" if injection_task is None else f" | attacker goal {'MET' if security else 'not met'}"))
    seen = agent.planner_saw
    if seen:
        print(f"  PLANNER  saw: the request, {len(seen['tools'])} tool names, "
              f"{len(seen['tool_results'])} tool results")


def _mail(a):
    return f"to={a['recipients']} subject={a['subject']!r} body={a['body'][:60]!r}{'...' if len(a['body']) > 60 else ''}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", choices=["single", "single+taint", "dual", "dual+taint", "dual+taint+strict"])
    ap.add_argument("--trace", nargs=2, metavar=("UT", "IT"))
    ap.add_argument("--challenge", action="store_true")
    ap.add_argument("--log", action="store_true", help="also write every sink decision to state/decisions.jsonl")
    args = ap.parse_args()
    if args.log:
        STATE.mkdir(exist_ok=True)
        (STATE / "decisions.jsonl").write_text("")
        os.environ["M22_LOG"] = str(STATE / "decisions.jsonl")
    if args.trace:
        trace(args.agent or "dual+taint", args.trace[0].upper(), args.trace[1].upper(), args.challenge)
    elif args.agent:
        detail(args.agent, args.challenge)
    else:
        table(agents.AGENTS, args.challenge)


if __name__ == "__main__":
    main()
