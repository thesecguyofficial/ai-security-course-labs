"""
tools.py: the helpdesk agent's three tools. All local, all inside this lab folder.

    read_file(path)                 reads a text file inside data/workspace/ (never outside it, in any mode)
    run_task(command)               a STAND-IN for a shell tool. It NEVER executes anything, in any mode.
                                    It appends the requested command to state/tasks.log and writes a marker
                                    file in state/markers/ saying what a real shell would have been asked to do.
    send_email(to, subject, body)   "sends" by appending one JSON line to state/outbox.jsonl.
                                    No network, no SMTP, no sockets.

The tools themselves do no policy checks (apart from read_file's hard workspace boundary, which is lab
safety, not a lesson). Every security control lives in controls.py, outside the model and outside the
tools, which is where lesson 7.2 says it belongs.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

LAB = Path(__file__).resolve().parent
WORKSPACE = (LAB / "data" / "workspace").resolve()


def state_dir() -> Path:
    """Where the outbox, markers, audit log and kill switch live. Tests point M07_STATE at a temp folder."""
    return Path(os.environ.get("M07_STATE", LAB / "state")).resolve()


class ToolError(Exception):
    """A tool could not do what was asked (bad path, missing file). Not a security decision."""


# --------------------------------------------------------------------------- read_file

def resolve_in_workspace(path: str) -> Path:
    """Resolve a workspace-relative path and refuse anything that lands outside data/workspace/."""
    candidate = (WORKSPACE / path).resolve()
    if not candidate.is_relative_to(WORKSPACE):
        raise ToolError(f"path is outside the lab workspace: {path!r}")
    return candidate


def read_file(path: str) -> str:
    p = resolve_in_workspace(path)
    if not p.is_file():
        raise ToolError(f"no such file in the workspace: {path!r}")
    return p.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- run_task (stand-in shell)

def parse_command(command: str) -> tuple[str, list[str]]:
    """Split a command string the way a shell would, without running it. Returns (verb, arguments)."""
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    if not parts:
        return "", []
    return parts[0], parts[1:]


def run_task(command: str, run_id: str) -> str:
    """Record the command and write a marker. NOTHING IS EXECUTED: no subprocess, no os.system, no eval."""
    state = state_dir()
    markers = state / "markers"
    markers.mkdir(parents=True, exist_ok=True)
    verb, args = parse_command(command)
    n = len(list(markers.glob("task-*.marker"))) + 1
    marker = markers / f"task-{n:04d}.marker"
    marker.write_text(
        "SIMULATED, NOT EXECUTED (lab stand-in for a shell tool)\n"
        f"run: {run_id}\ncommand: {command}\nverb: {verb}\nargs: {args}\n",
        encoding="utf-8",
    )
    with (state / "tasks.log").open("a", encoding="utf-8") as f:
        f.write(f"{run_id}\t{command}\n")
    return f"(simulated) {command!r} was recorded, not executed. Marker: state/markers/{marker.name}"


# --------------------------------------------------------------------------- send_email (local outbox)

def send_email(to: str, subject: str, body: str, run_id: str) -> str:
    state = state_dir()
    state.mkdir(parents=True, exist_ok=True)
    entry = {"run": run_id, "to": to, "subject": subject, "body": body}
    with (state / "outbox.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return f"queued for {to} in the local outbox (state/outbox.jsonl). No network was used."


def read_outbox() -> list[dict]:
    p = state_dir() / "outbox.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


TOOL_DESCRIPTIONS = {
    "read_file": "read_file(path): read a text file from the helpdesk workspace, e.g. tickets/T-1042.md",
    "run_task": "run_task(command): run a shell command in the workspace, e.g. ls kb",
    "send_email": "send_email(to, subject, body): send an email",
}
