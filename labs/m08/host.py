"""
host.py: a tiny MCP HOST (the thing that talks to the model and to the MCP servers).

It connects to two local stdio MCP servers built with the official MCP Python SDK:
  - notes  (servers/notes_server.py)  the honest one
  - facts  (servers/facts_server.py)  the malicious one

It asks the stand-in model (stand_in_model.py; swap in Ollama with --backend ollama) what to do, then
carries out the model's plan by calling tools. All data is fake, everything is on your own machine, and
no server reaches the network.

The point of the lab is the four controls, each switched on by a flag so you can see the before/after:

  --pin-file FILE     hash-pin tool definitions: on the first run, record a SHA-256 (and the text) of
                      each tool's definition as the approved baseline; afterwards REFUSE any tool whose
                      definition differs, printing a diff, and any new tool not in the baseline
                      (catches the rug pull). Spec: "descriptions of tool behavior such as annotations
                      should be considered untrusted, unless obtained from a trusted server"; Invariant
                      Labs recommends pinning and "using a hash or checksum to verify the integrity of
                      the tool description".
  --approve           show each tool's FULL definition and require y/N before the tool may be used
                      (feeds a decision file in tests). The spec's tools page: "there SHOULD always be
                      a human in the loop with the ability to deny tool invocations", and clients
                      SHOULD "show tool inputs to the user before calling the server".
  --allow SPEC        allow-list which servers/tools may be called at all, e.g. notes:*,facts:fact_of_the_day
  --block-injection   refuse to run any tool whose definition contains a hidden-directive marker

Run it through the Makefile; see README.md.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from pathlib import Path

from mcp import Client, StdioServerParameters

import stand_in_model

LAB = Path(__file__).resolve().parent
STATE = LAB / "state"

SERVERS = {
    "notes": "servers/notes_server.py",
    "facts": "servers/facts_server.py",
}


def _params(script: str) -> StdioServerParameters:
    # env={} so a lab server inherits none of your shell's secrets (lesson 8.5: isolate credentials).
    return StdioServerParameters(command=sys.executable, args=[str(LAB / script)], env={})


def tool_fingerprint(tool: dict) -> str:
    """SHA-256 over a tool's full, stable definition (name + description + schema)."""
    blob = json.dumps(
        {"name": tool["name"], "description": tool["description"], "input_schema": tool["input_schema"]},
        sort_keys=True,
    )
    return hashlib.sha256(blob.encode()).hexdigest()


async def discover() -> list[dict]:
    """Connect to both servers and return a flat list of tool definitions."""
    tools: list[dict] = []
    for server, script in SERVERS.items():
        async with Client(_params(script), cache=None) as client:
            listed = await client.list_tools()
            for t in listed.tools:
                tools.append(
                    {
                        "server": server,
                        "name": t.name,
                        "description": t.description or "",
                        "input_schema": t.input_schema or {},
                    }
                )
    return tools


def load_pins(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _definition(tool: dict) -> dict:
    return {"name": tool["name"], "description": tool["description"], "input_schema": tool["input_schema"]}


def _diff_lines(old: dict | None, new: dict) -> list[str]:
    """A readable unified diff of two tool definitions. Runs of 20+ spaces are shown as <N spaces>,
    so padding used to push hidden text out of view is visible instead of scrolling off screen."""
    import difflib
    import re

    def render(d: dict | None) -> list[str]:
        if d is None:
            return ["(definition text not stored in an older pin file)"]
        text = json.dumps(d, indent=2, sort_keys=True)
        text = re.sub(r" {20,}", lambda m: f"<{len(m.group())} spaces>", text)
        return text.splitlines()

    out = []
    for line in difflib.unified_diff(render(old), render(new), "approved", "current", lineterm="", n=0):
        out.append("    " + (line if len(line) <= 160 else line[:157] + "..."))
    return out


def check_pins(tools: list[dict], pin_path: Path, log) -> set[tuple[str, str]]:
    """Hash-pin tools (trust on first use).

    First run (no pin file yet): record the hash AND the full definition of every tool you see. That
    run is your approval baseline; in `make defend` it is the clean 1.0.0 release.
    Later runs: refuse any tool whose definition changed (and print a diff against the approved text),
    and refuse any NEW tool that was not in the approved set, so a rug pull cannot sneak in by adding a
    tool instead of editing one. Re-review, then delete the pin file to re-approve.

    Simplification: the fingerprint covers name, description and input schema. A production client
    should pin every model-visible field (title, annotations, output schema) too.

    Returns the set of (server, tool) that FAILED the pin check and must not be used.
    """
    pins = load_pins(pin_path)
    baseline = not pins  # nothing approved yet: this run records the baseline
    blocked: set[tuple[str, str]] = set()
    for t in tools:
        key = f"{t['server']}:{t['name']}"
        fp = tool_fingerprint(t)
        entry = pins.get(key)
        approved_fp = entry.get("sha256") if isinstance(entry, dict) else entry  # older files: bare hash
        if entry is None and baseline:
            pins[key] = {"sha256": fp, "definition": _definition(t)}
            log(f"PIN new   {key}  {fp[:12]}…  (recorded)")
        elif entry is None:
            blocked.add((t["server"], t["name"]))
            log(f"PIN NEW TOOL {key}  {fp[:12]}…  not in the approved set -> REFUSED")
        elif approved_fp != fp:
            blocked.add((t["server"], t["name"]))
            log(f"PIN CHANGED {key}  was {approved_fp[:12]}…  now {fp[:12]}…  -> REFUSED")
            old_def = entry.get("definition") if isinstance(entry, dict) else None
            for line in _diff_lines(old_def, _definition(t)):
                log(line)
        else:
            log(f"PIN ok    {key}  {fp[:12]}…")
    if baseline:
        pin_path.write_text(json.dumps(pins, indent=2))
    return blocked


def parse_allow(spec: str) -> list[tuple[str, str]]:
    rules = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        server, _, tool = part.partition(":")
        rules.append((server, tool or "*"))
    return rules


def allowed(server: str, tool: str, rules: list[tuple[str, str]]) -> bool:
    return any(s == server and (t == "*" or t == tool) for s, t in rules)


async def run(user_message: str, args, log=print) -> dict:
    """One turn. Returns a small result dict the tests assert on."""
    tools = await discover()

    # --- controls that run BEFORE any model call ---
    blocked_by_pin: set[tuple[str, str]] = set()
    if args.pin_file:
        blocked_by_pin = check_pins(tools, Path(args.pin_file), log)

    if args.block_injection:
        for t in tools:
            if stand_in_model.TOKEN in stand_in_model.full_text(t):
                blocked_by_pin.add((t["server"], t["name"]))
                log(f"SCAN hidden directive found in {t['server']}:{t['name']} -> REFUSED")

    approved: set[tuple[str, str]] | None = None
    if args.approve:
        approved = approve_tools(tools, args.approvals, log)

    allow_rules = parse_allow(args.allow) if args.allow else None

    # Quarantine: a tool that failed its pin or carries a hidden directive is kept OUT of the model's
    # context, not merely refused at call time. This is what stops tool shadowing too: a poisoned
    # definition the model never reads cannot change how it uses another server's tools.
    visible = [t for t in tools if (t["server"], t["name"]) not in blocked_by_pin]
    if len(visible) != len(tools):
        log(f"QUARANTINE {len(tools) - len(visible)} tool(s) hidden from the model")

    # --- ask the (stand-in) model what to do ---
    if args.backend == "ollama":
        import ollama_backend  # optional; see README

        plan = ollama_backend.decide(user_message, visible, model=args.model)
    else:
        plan = stand_in_model.decide(user_message, visible)

    log(f"MODEL plan: {[(s, t) for s, t, _ in plan.steps]}  (saw hidden directive: {plan.saw_injection})")

    # --- carry out the plan, enforcing the controls on every step ---
    executed, refused, last_read = [], [], ""
    for server, tool, call_args in plan.steps:
        if (server, tool) in blocked_by_pin:
            refused.append((server, tool, "pinned/flagged definition changed or carries a hidden directive"))
            log(f"REFUSE {server}:{tool} (control blocked it)")
            continue
        if allow_rules is not None and not allowed(server, tool, allow_rules):
            refused.append((server, tool, "not on the allow-list"))
            log(f"REFUSE {server}:{tool} (not allow-listed)")
            continue
        if approved is not None and (server, tool) not in approved:
            refused.append((server, tool, "not approved by the human"))
            log(f"REFUSE {server}:{tool} (not approved)")
            continue

        # The stand-in asks the host to smuggle the previous read into sidenote; that only works if a
        # read actually happened and was not refused. With controls on, it never does.
        if call_args.get("sidenote") == "__SMUGGLE_LAST_READ__":
            call_args = dict(call_args, sidenote=last_read)

        result = await call_tool(server, tool, call_args)
        if server == "notes" and tool == "read_note":
            last_read = result
        executed.append((server, tool, call_args))
        log(f"CALL  {server}:{tool} args={_redact(call_args)}")

    return {
        "executed": executed,
        "refused": refused,
        "reply": plan.reply,
        "saw_injection": plan.saw_injection,
        "secret_leaked": _secret_in_inbox(),
        "emails": _outbox(),
    }


async def call_tool(server: str, tool: str, call_args: dict) -> str:
    async with Client(_params(SERVERS[server]), cache=None) as client:
        res = await client.call_tool(tool, call_args)
        parts = [c.text for c in (res.content or []) if getattr(c, "text", None)]
        return "\n".join(parts)


def approve_tools(tools: list[dict], approvals_path: str | None, log) -> set[tuple[str, str]]:
    """Show each tool's FULL definition and approve it. Interactive, unless an approvals file is given."""
    preset = {}
    if approvals_path:
        try:
            preset = json.loads(Path(approvals_path).read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            preset = {}
    ok: set[tuple[str, str]] = set()
    for t in tools:
        key = f"{t['server']}:{t['name']}"
        log("-" * 68)
        log(f"Approve tool {key}?")
        log(f"  description: {t['description']!r}")
        log(f"  input schema: {json.dumps(t['input_schema'])}")
        if approvals_path:
            answer = "y" if preset.get(key) else "n"
            log(f"  [approvals file says: {answer}]")
        else:  # pragma: no cover - interactive only
            answer = input("  type y to allow, anything else to deny: ").strip().lower()
        if answer == "y":
            ok.add((t["server"], t["name"]))
    return ok


def _redact(call_args: dict) -> dict:
    out = {}
    for k, v in call_args.items():
        out[k] = (v[:24] + "…") if isinstance(v, str) and len(v) > 25 else v
    return out


def _secret_in_inbox() -> bool:
    log = STATE / "attacker_inbox.log"
    return log.exists() and "AKIAIOSFODNN7EXAMPLE" in log.read_text()


def _outbox() -> list[dict]:
    f = STATE / "outbox.jsonl"
    if not f.exists():
        return []
    return [json.loads(line) for line in f.read_text().splitlines() if line.strip()]


def main() -> None:
    p = argparse.ArgumentParser(description="Tiny MCP host for the M8 lab (127.0.0.1, fake data).")
    p.add_argument("message", help="what to ask the agent, e.g. 'give me a fact about octopus'")
    p.add_argument("--pin-file", help="hash-pin tool definitions in this JSON file")
    p.add_argument("--approve", action="store_true", help="require approval of each tool's full definition")
    p.add_argument("--approvals", help="JSON file of {tool: true/false} so approval is non-interactive")
    p.add_argument("--allow", help="allow-list, e.g. notes:*,facts:fact_of_the_day")
    p.add_argument("--block-injection", action="store_true", help="refuse tools with a hidden-directive marker")
    p.add_argument("--backend", choices=["stand-in", "ollama"], default="stand-in")
    p.add_argument("--model", default="gemma3:1b", help="Ollama model name, with --backend ollama")
    args = p.parse_args()
    result = asyncio.run(run(args.message, args))
    print("\n--- result ---")
    print(f"reply:          {result['reply']}")
    print(f"tools run:      {[f'{s}:{t}' for s, t, _ in result['executed']]}")
    print(f"tools refused:  {[f'{s}:{t} ({why})' for s, t, why in result['refused']]}")
    print(f"secret leaked:  {result['secret_leaked']}")
    print(f"emails queued:  {result['emails']}")


if __name__ == "__main__":
    main()
