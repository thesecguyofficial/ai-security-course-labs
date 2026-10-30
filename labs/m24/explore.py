#!/usr/bin/env python3
r"""
explore.py: look at each idea of a multi-agent crew, and of an instruction spreading through it, on its own,
before you write the containment (M24 lab, "Understand the lab").

What it does, said plainly: it READS the lab's files (config.json, data/recording/transcript.jsonl and
data/variants.jsonl) and prints them one idea at a time. It runs no agent, sends nothing, calls none of your
containment.py, never reads the answer key (ground_truth.json) and writes no file (not even Python's
__pycache__). No network. Python 3.11+ standard library only.

    crew                 1. the three agents: each one's job and tools, and the two channels between them
    run [n1]             2. one recorded run, event by event (n1 and n2 are normal; a1 is the attack)
    handoff [t11]        3. one hand-off message, field by field: what the next agent reads
    memory               4. the shared memory: every note written to it, and who reads it back
    spread               5. the attack run a1, hop by hop: the same instruction at every hop
    boundaries           6. the trust boundaries: where untrusted text enters, which agent can act, the path
    scope [t04]          7. least privilege: one tool call against config.json (may this agent do this?)
    breaker [a1]         8. a counter: how many boundaries the same outside address has crossed so far
    variants             9. the recorded attack beside the adapted one: what changed, what stayed

    e.g. python3 explore.py handoff t02

Windows: `python explore.py ...`. Fake data only: every address is a reserved .example name (RFC 2606).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

sys.dont_write_bytecode = True  # read-only: nothing here may write __pycache__/

HERE = pathlib.Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
ADDRESS = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
JOBS = {
    "intake": "reads incoming email and writes a short note for the planner",
    "planner": "reads intake's notes and gives tasks to the other agents",
    "mailer": "sends email for the crew",
}
CHANNELS = {
    "memory": "shared memory: a note one agent writes and others read later (it stays there)",
    "task": "task: a direct message from one agent to another, telling it what to do",
}
SESSIONS = {"a1": "the attack run", "n1": "normal run 1", "n2": "normal run 2", "va": "the adapted attack"}


def load(path: pathlib.Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


RECORDED = load(HERE / "data" / "recording" / "transcript.jsonl")
VARIANTS = load(HERE / "data" / "variants.jsonl")
ALL = RECORDED + VARIANTS


def allowed_domains() -> set[str]:
    return {d.lower() for doms in CONFIG.get("send_email_domains", {}).values() for d in doms}


def outside(text: str) -> list[str]:
    """Addresses whose domain is not on any send list: outside the company."""
    allow = allowed_domains()
    return [a for a in ADDRESS.findall(text or "") if a.split("@", 1)[1].lower() not in allow]


def event(eid: str) -> dict:
    for e in ALL:
        if e["id"] == eid:
            return e
    sys.exit(f"no event {eid}: try t01 to t04 (attack), t10 to t13, t20 to t24 (normal), vt01 to vt04 (adapted)")


def session(sid: str) -> list[dict]:
    rows = [e for e in ALL if e.get("session") == sid]
    if not rows:
        sys.exit(f"no run {sid}: try a1 (attack), n1 or n2 (normal), va (adapted)")
    return rows


def clock(e: dict) -> str:
    return e.get("ts", "")[11:19]


def one_line(e: dict) -> str:
    k = e["kind"]
    if k == "ingest":
        return f"{e['agent']} READS {e['source']}"
    if k == "handoff":
        return f"{e['from']} -> {e['to']}  HAND-OFF over {e['channel']}"
    if k == "tool_call":
        return f"{e['agent']} CALLS {e['tool']}  to {e['args'].get('to', '')}"
    return k


def hidden(text: str) -> str:
    m = re.search(r"<!--(.*?)-->", text or "", re.S)
    return m.group(1).strip() if m else ""


def visible(text: str) -> str:
    return re.sub(r"<!--.*?-->", "", text or "", flags=re.S).strip()


def wrap(text: str, width: int = 96, indent: str = "") -> str:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}" if cur else w
    if cur:
        lines.append(cur)
    return ("\n" + indent).join(lines)


# ------------------------------------------------------------------------------------------------- the ideas
def cmd_crew(_a):
    print("The crew: three agents. Each is a model + its tools + a loop (Module 7). From config.json:")
    print()
    for ag in CONFIG["agents"]:
        tools = CONFIG["agent_tools"].get(ag, [])
        print(f"  {ag:<8} job:   {JOBS.get(ag, '')}")
        print(f"  {'':<8} tools: {', '.join(tools) if tools else 'none'}")
        doms = CONFIG.get("send_email_domains", {}).get(ag)
        if doms:
            print(f"  {'':<8} may send email only to: {', '.join(doms)}")
        print()
    print("How they talk: two channels.")
    for name, what in CHANNELS.items():
        print(f"  {name:<7} {what}")
    print()
    print("Only the mailer has a tool that reaches outside the crew. Every other agent can only pass text on.")


def cmd_run(a):
    sid = a.arg or "n1"
    rows = session(sid)
    print(f"Run {sid} ({SESSIONS.get(sid, '')}), {len(rows)} events, in order. Nothing runs: this is a recording.")
    print()
    for e in rows:
        print(f"  {e['id']:<5} {clock(e)}  {one_line(e)}")
        if e["kind"] == "ingest":
            txt = visible(e["content"])
            print(f"        {'':8}  text: \"{wrap(txt, 90, ' ' * 23)}\"")
            if hidden(e["content"]):
                print(f"        {'':8}  plus a hidden HTML comment (a person reading the email doesn't see it)")
        elif e["kind"] == "handoff":
            print(f"        {'':8}  \"{wrap(e['message'], 90, ' ' * 19)}\"")
        elif e["kind"] == "tool_call":
            print(f"        {'':8}  subject \"{e['args'].get('subject', '')}\"")
    print()
    print("ingest = an agent reads input from outside | hand-off = one agent's message to another | "
          "tool call = an agent acts")


def cmd_handoff(a):
    e = event(a.arg or "t11")
    if e["kind"] != "handoff":
        sys.exit(f"{e['id']} is a {e['kind']}, not a hand-off: try t02, t03, t11, t12, t21, t22, t23")
    print(f"One hand-off, {e['id']}, field by field:")
    print()
    print(f"  from        {e['from']:<10} the agent that wrote it")
    print(f"  to          {e['to']:<10} the agent that will read it")
    print(f"  channel     {e['channel']:<10} {CHANNELS[e['channel']]}")
    print(f"  message     \"{wrap(e['message'], 92, ' ' * 15)}\"")
    print(f"  provenance  {e.get('provenance') or '(none)':<10} no label says where the words came from")
    print()
    print(f"What {e['to']} does with it: puts the message into its own model's context, as text,")
    print("next to its instructions. Nothing marks it as a request rather than an order.")
    out = outside(e["message"])
    if out:
        print(f"This message names an address outside the company: {', '.join(out)}")


def cmd_memory(_a):
    notes = [e for e in RECORDED if e.get("kind") == "handoff" and e.get("channel") == "memory"]
    print(f"The shared memory: {len(notes)} notes written over the three recorded runs (oldest first).")
    print("A note stays there after its run ends. Any agent that reads memory later reads all of it back.")
    print()
    for e in notes:
        src = next((x for x in RECORDED if x.get("session") == e["session"] and x["kind"] == "ingest"), {})
        print(f"  {e['id']:<5} run {e['session']:<3} written by {e['from']:<7} from {src.get('source', '?'):<11} "
              f"\"{e['message'][:58]}{'...' if len(e['message']) > 58 else ''}\"")
    print()
    print("Each note came from an email: text from outside the company. None is labelled that way.")


def cmd_spread(_a):
    rows = session("a1")
    print("The attack run a1, hop by hop. Watch the same outside address at every hop.")
    print()
    for e in rows:
        if e["kind"] == "ingest":
            print(f"  {e['id']}  {e['agent']} reads {e['source']}")
            print(f"       visible:  \"{visible(e['content'])}\"")
            print(f"       hidden:   \"{wrap(hidden(e['content']), 86, ' ' * 18)}\"")
        elif e["kind"] == "handoff":
            print(f"  {e['id']}  {e['from']} -> {e['to']} over {e['channel']}")
            print(f"       \"{wrap(e['message'], 92, ' ' * 8)}\"")
        else:
            print(f"  {e['id']}  {e['agent']} calls {e['tool']}, to: {e['args']['to']}, "
                  f"subject: \"{e['args'].get('subject', '')}\"")
        found = outside(e.get("content") or e.get("message") or json.dumps(e.get("args", {})))
        print(f"       outside address here: {', '.join(found) if found else '-'}")
        print()
    print("One hidden line in one email became a note, then a task, then a send. No agent questioned the one before.")


def cmd_boundaries(_a):
    edges = []
    for e in RECORDED:
        if e.get("kind") == "handoff" and (e["from"], e["to"], e["channel"]) not in edges:
            edges.append((e["from"], e["to"], e["channel"]))
    entry = sorted({e["agent"] for e in RECORDED if e.get("kind") == "ingest"})
    sinks = sorted(ag for ag, tools in CONFIG["agent_tools"].items() if "send_email" in tools)
    print("Trust boundaries: every place one agent's words reach another agent.")
    print()
    print(f"  entry point  {', '.join(entry)}: reads email from outside (untrusted text comes in here)")
    print(f"  sink         {', '.join(sinks)}: can send email (the way out)")
    print()
    print("  every hand-off seen in the recording:")
    path, frontier = {}, list(entry)  # shortest path from the entry to a sink, hand-off by hand-off
    while frontier:
        nxt = []
        for f, t, ch in edges:
            if f in frontier and t not in path and t not in entry:
                path[t] = (f, t, ch)
                nxt.append(t)
        frontier = nxt
    on_path, cur = set(), sinks[0]
    while cur in path:
        on_path.add(path[cur])
        cur = path[cur][0]
    for f, t, ch in edges:
        what = "ON THE PATH from entry to sink" if (f, t, ch) in on_path else "a back channel: also a boundary"
        print(f"    {f:<8} -> {t:<8} over {ch:<7} {what}")
    print()
    hops, cur = [], sinks[0]
    while cur in path:
        hops.insert(0, path[cur])
        cur = path[cur][0]
    line = cur + "".join(f" --({ch})--> {t}" for _f, t, ch in hops) + " --(send_email)--> outside"
    labelled = sum(1 for e in RECORDED if e.get("kind") == "handoff" and e.get("provenance"))
    print(f"  path: {line}")
    print(f"  {len(hops)} boundaries between the entry and the sink. Hand-offs with a provenance label: "
          f"{labelled or 'none'}.")


def cmd_scope(a):
    e = event(a.arg or "t04")
    if e["kind"] != "tool_call":
        sys.exit(f"{e['id']} is a {e['kind']}, not a tool call: try t04, t13, t24, vt04")
    ag, tool, to = e["agent"], e["tool"], e["args"].get("to", "")
    mine = CONFIG["agent_tools"].get(ag, [])
    doms = CONFIG.get("send_email_domains", {}).get(ag, [])
    dom = to.split("@", 1)[-1].lower()
    print(f"Least privilege: may {ag} call {tool} to {to}?  ({e['id']}, run {e['session']})")
    print()
    q1 = tool in mine
    print(f"  1. is {tool} one of {ag}'s tools?      {ag}'s tools: {', '.join(mine) or 'none':<12} -> {'yes' if q1 else 'NO'}")
    q2 = dom in [d.lower() for d in doms]
    print(f"  2. is {dom} on {ag}'s send list?  send list: {', '.join(doms) or 'none':<12} -> {'yes' if q2 else 'NO'}")
    print()
    print(f"  A check that asks both questions would say: {'ALLOW' if q1 and q2 else 'DENY'}")
    print("  (Read only: nothing was sent, and this is not your containment.py.)")


def cmd_breaker(a):
    sid = a.arg or "a1"
    th = CONFIG.get("propagation_threshold", 2)
    print(f"A counter over run {sid} ({SESSIONS.get(sid, '')}): for each hand-off, the outside addresses it names,")
    print(f"and how many boundaries each one has crossed so far. config.json sets the limit at {th}.")
    print()
    seen: dict[str, int] = {}
    for e in session(sid):
        if e["kind"] != "handoff":
            continue
        found = sorted(set(outside(e["message"])))
        for adr in found:
            seen[adr] = seen.get(adr, 0) + 1
        counts = ", ".join(f"{adr} = {seen[adr]}" for adr in found) or "no outside address (count stays)"
        flag = "   <- limit reached" if any(seen[adr] == th for adr in found) else ""
        print(f"  {e['id']:<5} {e['from']} -> {e['to']:<8} {counts}{flag}")
    print()
    if any(v >= th for v in seen.values()):
        print(f"The same outside address crossed {max(seen.values())} boundaries in one run: that repetition is "
              "the sign of a spread.")
    else:
        print("Nothing crossed twice. A message repeated to two agents with no outside address doesn't count.")


def cmd_variants(_a):
    rec = session("a1")
    var = session("va")
    print("The recorded attack (a1) beside the adapted one (va), event by event:")
    print()
    for r, v in zip(rec, var):
        rt = visible(r.get("message") or hidden(r.get("content", "")) or r.get("args", {}).get("to", ""))
        vt = visible(v.get("message") or hidden(v.get("content", "")) or v.get("args", {}).get("to", ""))
        print(f"  {r['id']} {one_line(r)}")
        print(f"      a1: \"{wrap(rt, 92, ' ' * 11)}\"")
        print(f"      va: \"{wrap(vt, 92, ' ' * 11)}\"")
        print()
    print("Changed: the words (relay, dispatch, e-mail, client records) and the domain (.example.co, a look-alike).")
    print("Stayed:  an outside address crossing each boundary, and the mailer asked to send to it.")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("idea", choices=["crew", "run", "handoff", "memory", "spread", "boundaries", "scope", "breaker",
                                    "variants"])
    p.add_argument("arg", nargs="?", help="a run (a1, n1, n2, va) or an event ID (t04, t11, ...)")
    a = p.parse_args(argv)
    globals()["cmd_" + a.idea](a)


if __name__ == "__main__":
    main()
