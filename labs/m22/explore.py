#!/usr/bin/env python3
r"""
explore.py: look at each idea of secure agent architecture on its own, before you score the email agent (M22 lab,
"Understand the lab").

What it does, said plainly: it loads the lab's fake inbox, directory and drive into memory and shows one idea at a
time. `agent` runs the obedient stand-in model on an in-memory copy of that fake data (the "sent" email lands in a
Python list and is gone when the script ends); `planted` asks AgentDojo to write its attack text into an in-memory copy;
`ask` runs the stand-in quarantined model; `check` asks the lab's sink policy about calls that are never run. Nothing
is sent, no file is written (not even Python's __pycache__ or the state/ folder), no network, no real model.

Run it with the lab's own Python, .venv/bin/python (where agentdojo is):

    agent [UT7]          1. how an email agent is wired: a request, five tools, one model in a loop
    legs                 2. which leg of the lethal trifecta each tool supplies, and what one model ends up holding
    planted [UT7] [IT0]  3. what an attack looks like inside the data: AgentDojo's text, planted in an email or file
    plan [UT7]           4. the planner: sees the request and the tool names only, writes a plan with variables
    ask                  5. the quarantined model: reads untrusted text, has no tools, gives ONE typed answer
    labels               6. the label on each value: trusted or not, who may read it, where it came from
    join                 7. two labels combined: the stricter answer to both questions
    check                8. the sink policy: three proposed calls, checked on their labels (none is run)
    task [UT3]           9. how AgentDojo scores: the task, where the attack goes, and the checker's own code

    e.g. .venv/bin/python explore.py plan UT3

Windows: `.venv\Scripts\python explore.py ...`. Fake data only (.example addresses, RFC 2606).
"""
from __future__ import annotations

import argparse
import inspect
import os
import sys
import textwrap
import warnings

sys.dont_write_bytecode = True  # read-only: importing the lab's modules must not write __pycache__/
os.environ.pop("M22_LOG", None)  # never write the decision log
warnings.simplefilter("ignore")

try:
    from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
except ImportError:
    sys.exit("explore.py needs agentdojo: run `make setup`, then `.venv/bin/python explore.py ...`")

import agents  # noqa: E402  (nothing runs on import)
import inbox_suite as S  # noqa: E402
import policies  # noqa: E402
import standin  # noqa: E402
from labels import Label, Labelled, Labeller, join_all  # noqa: E402
from standin import Answer, Ask, Call, Fmt, If, Lit, Ref, Refuse  # noqa: E402

W = 128  # the recording terminal is 132 columns


def _cut(s: str, n: int = W - 16) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 3] + "..."


def _wrap(s: str, first: str, rest: str, width: int = W, lines: int = 3) -> None:
    out = textwrap.wrap(" ".join(str(s).split()), width=width, initial_indent=first, subsequent_indent=rest)
    if len(out) > lines:
        out = out[:lines]
        out[-1] = out[-1][: width - 3] + "..."
    print("\n".join(out))


def _suite():
    return S.make_suite(False)


def _ut(suite, ut: str):
    try:
        return suite.get_user_task_by_id(f"user_task_{int(ut.upper().lstrip('UT'))}")
    except (KeyError, ValueError):
        sys.exit(f"no user task {ut} (UT0 to UT7)")


def _injections(suite, user_task, it: str) -> dict:
    """AgentDojo's own attack text for this user task and injection task (in memory only)."""
    if it.upper() == "IT-":
        return {}
    from score import LabAttack  # score.py runs nothing on import
    inj = suite.get_injection_task_by_id(f"injection_task_{int(it.upper().lstrip('IT'))}")
    return LabAttack(suite, agents.make_agent("single", suite)).attack(user_task, inj)


def _env(suite, injections: dict | None = None):
    return suite.load_and_inject_default_environment(injections or {})


def _step(st, n: int) -> str:
    def v(a):
        if isinstance(a, Lit):
            return repr(a.value)
        if isinstance(a, Ref):
            return "$" + a.var + (("[" + a.path.replace(".", "].", 1) if a.path[:1].isdigit() else "." + a.path)
                                  if a.path else "")
        if isinstance(a, Fmt):
            return '"' + a.template.replace("{", "{$") + '"'
        if isinstance(a, list):
            return "[" + ", ".join(v(x) for x in a) + "]"
        return repr(a)
    if isinstance(st, Call):
        args = ", ".join(f"{k}={v(x)}" for k, x in st.args.items())
        return f"  {n}. {('$' + st.out + ' = ') if st.out else '     '}{st.tool}({args})"
    if isinstance(st, Ask):
        return f"  {n}. ${st.out} = ask the quarantined model: {st.kind}{(' (' + st.about + ')') if st.about else ''}, from {v(st.src)}"
    if isinstance(st, Answer):
        return f"  {n}.      answer the user: {v(st.text) if not isinstance(st.text, str) else repr(st.text)}"
    if isinstance(st, Refuse):
        return f"  {n}.      refuse: {_cut(st.reason, 100)!r}"
    if isinstance(st, If):
        return f"  {n}.      if {v(st.cond)}: {len(st.then)} steps, else {len(st.otherwise)}"
    return f"  {n}. {st!r}"


# ---------------------------------------------------------------------------------------------------- commands
def cmd_agent(a) -> int:
    suite = _suite()
    task = _ut(suite, a.ut)
    print(f"The request, typed by the user ({a.ut.upper()}):")
    print(f'  "{task.PROMPT}"\n')
    print("The five tools the model may call (inbox_suite.py). A tool is a Python function the agent's code runs:")
    for f in suite.tools:
        kind = "SENDS" if f.name in policies.SINKS else "reads"
        print(f"  {f.name:<14} {kind:<6} {_cut(f.description.splitlines()[0], 90)}")
    agent = agents.make_agent("single", suite)
    env = _env(suite)
    rt = FunctionsRuntime(suite.tools)
    agent.query(task.PROMPT, rt, env)
    print("\nOne model in a loop (the single agent): call a tool, read the result, pick the next call.")
    n = 0
    for m in agent.messages:
        if m["role"] == "assistant" and m.get("tool_calls"):
            c = m["tool_calls"][0]
            n += 1
            _wrap(f"{c.function} {dict(c.args)}", f"  {n}. calls ", "           ", lines=2)
        elif m["role"] == "tool":
            _wrap(_said(m["content"][0]["content"] if m["content"] else ""), "     reads ", "           ", lines=2)
    print(f"  answer: {agent.trace[-1]['text']}")
    print(f"\nIts context (working memory for this request): the request + {len(agent.planner_saw['tool_results'])}"
          " tool results, all read by the same model that can send.")
    print("Lab outbox after the run (in memory only):", [m.recipients for m in env.mailbox.sent])
    return 0


def _said(yaml_text: str) -> str:
    """A tool result as the model reads it, shortened to its fields (id, sender, subject, body ...)."""
    import yaml
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        return yaml_text
    rows = data if isinstance(data, list) else [data]
    if not all(isinstance(r, dict) for r in rows):
        return yaml_text
    keep = ("id", "sender", "subject", "body", "name", "email", "team")
    return " | ".join("; ".join(f"{k}: {r[k]}" for k in keep if k in r) for r in rows)


def cmd_legs(a) -> int:
    print("The lethal trifecta (Simon Willison, 16 Jun 2025): private data + untrusted content + a way out.")
    print("Which leg each tool supplies to a model that reads its result or can make the call (catalogue.json):\n")
    import trifecta
    names = {"private": "private data", "untrusted": "untrusted content", "exit": "a way out"}
    for name, v in trifecta.CATALOGUE["tools"].items():
        if v.get("challenge"):
            continue
        legs = [names[r] for r in v.get("reads", [])] + (["a way out"] if v.get("exit") else [])
        print(f"  {name:<14} {', '.join(legs):<34} {v['why']}")
    print("\nCount per model context. The single agent's model, after UT7 (Email Sam Lee the tracking number):")
    print("  get_contact    -> the directory entry for Sam              private data")
    print("  search_emails  -> email e1 from orders@brightline.example  private data + untrusted content (anyone can write a body)")
    print("  send_email     -> it can make this call                     a way out")
    print("  = ALL THREE in one model. Text inside email e1 can steer a call that sends data out.")
    return 0


def cmd_planted(a) -> int:
    suite = _suite()
    task = _ut(suite, a.ut)
    inj = _injections(suite, task, a.it)
    env0, env1 = _env(suite), _env(suite, inj)
    print(f"{a.ut.upper()}: \"{task.PROMPT}\"")
    print(f"AgentDojo plants its attack text where this task reads: {', '.join(inj) or 'nowhere (IT-)'}\n")
    for e0, e1 in zip(env0.mailbox.emails, env1.mailbox.emails):
        if e0.body != e1.body:
            print(f"email {e1.id} from {e1.sender}, subject {e1.subject!r}. The body as the model reads it:")
            _show_planted(e0.body, e1.body)
    for f0, f1 in zip(env0.drive.files, env1.drive.files):
        if f0.content != f1.content:
            print(f"file {f1.id} {f1.name!r}, editable by {', '.join(f1.editors)}. The content as the model reads it:")
            _show_planted(f0.content, f1.content)
    print("\nTo a model it's all one block of text: the real content and the planted request look the same.")
    return 0


def _show_planted(before: str, after: str):
    i = 0
    while i < min(len(before), len(after)) and before[i] == after[i]:
        i += 1
    _wrap(after[:i], "  ", "  ", lines=2)
    for ln in [x for x in after[i:].splitlines() if x.strip()]:
        print("  | " + _cut(ln, 118))


def cmd_plan(a) -> int:
    suite = _suite()
    task = _ut(suite, a.ut)
    tid, plan = standin.plan_for(task.PROMPT, "dual")
    print("What the planner sees: the request and the tool names. No email, no file, no tool result.")
    print(f'  request  "{task.PROMPT}"')
    print(f"  tools    {', '.join(sorted(f.name for f in suite.tools))}\n")
    print("Its plan (standin.py). $c, $e, $t ... are variables: the controller, plain code, fills them in later.")
    for n, st in enumerate(plan, 1):
        print(_step(st, n))
    print("\nThe plan is fixed before any data is read. Data can fill a variable; it can't add a step or remove one.")
    return 0


def cmd_ask(a) -> int:
    suite = _suite()
    print("The quarantined model reads untrusted text and gives ONE typed answer. It has no tools. (standin.py)")
    rows = [("UT7", "IT0", "e1", "tracking", "", "a tracking number: TRK- and digits"),
            ("UT3", "IT0", "f1", "emails", "attendees", "a list of email addresses"),
            ("UT0", "IT3", "e1", "summary", "", "free text")]
    for ut, it, src, kind, about, shape in rows:
        task = _ut(suite, ut)
        env = _env(suite, _injections(suite, task, it))
        text = (next(e.body for e in env.mailbox.emails if e.id == src) if src.startswith("e")
                else next(f.content for f in env.drive.files if f.id == src))
        planted = "planted" if "<INFORMATION>" in text else "no attack"
        ans = standin.quarantined(kind, text, about)
        print(f"\n  reads    {src} with {it}'s goal {planted}: {_cut(text.split('<INFORMATION>')[0], 76)}")
        print(f"  question {kind}{(' (' + about + ')') if about else ''}   answer type: {shape}")
        _wrap(repr(ans), "  answer   ", "           ", lines=3)
    print("\nA tracking-number answer can't carry a sentence. A list of addresses can carry one more address.")
    print("Free text can carry anything the planted text says.")
    return 0


def cmd_labels(a) -> int:
    suite = _suite()
    env = _env(suite)
    lab = Labeller(env)
    e1 = next(e for e in env.mailbox.emails if e.id == "e1")
    print("Every value gets a label (labels.py): can we trust it to decide something? who may read it? from where?\n")
    print(f"email e1 from {e1.sender}:")
    for f in ("sender", "subject", "body"):
        print(f"  {f:<10} {lab.field(e1, f).short()}")
    _wrap(", ".join(sorted(lab.field(e1, "body").readers)), "             readers: ", "                      ", lines=2)
    for fid in ("f1", "f3"):
        f = next(x for x in env.drive.files if x.id == fid)
        print(f"file {fid} {f.name!r}:")
        print(f"  content    {lab.field(f, 'content').short()}")
        _wrap(", ".join(sorted(lab.field(f, "content").readers)), "             readers: ", "                      ", lines=2)
    c = next(x for x in env.directory.contacts if x.name == "Sam Lee")
    print("directory entry for Sam Lee:")
    print(f"  email      {lab.field(c, 'email').short()}")
    print("\nThe mail system vouches for who SENT e1; nobody vouches for what its body says.")
    return 0


def cmd_join(a) -> int:
    suite = _suite()
    env = _env(suite)
    lab = Labeller(env)
    e1 = next(e for e in env.mailbox.emails if e.id == "e1")
    t = Labelled(standin.quarantined("tracking", e1.body), lab.field(e1, "body"))
    planner = Label(True, None, ("planner",))
    body = join_all([planner, t.label])
    print("The plan builds the email body from a template and the quarantined answer:")
    print('  body = "Tracking number: {$t}"\n')
    print(f"  the template, from the planner   {planner.short()}")
    print(f"  $t = {t.value!r:<28}{t.label.short()}")
    print(f"  joined: the email body           {body.short()}\n")
    print("The rule (labels.py, Label.join):")
    print("  trusted?  only if EVERY part is trusted     -> one untrusted part makes the whole value untrusted")
    print("  readers?  only who EVERY part allows        -> the smaller set wins ('anyone' adds no limit)")
    print("  sources?  all of them                       -> a refusal can name the email or file to look at")
    return 0


def cmd_check(a) -> int:
    suite = _suite()
    env = _env(suite, _injections(suite, _ut(suite, "UT3"), "IT0"))
    lab = Labeller(env)
    ctx = policies.Context(staff=lab.staff, file_label=lambda fid: lab.field(
        next(f for f in env.drive.files if f.id == fid), "content"))
    e1 = next(e for e in env.mailbox.emails if e.id == "e1")
    f1 = next(f for f in env.drive.files if f.id == "f1")
    sam = Labelled("sam.lee@tsg.example", lab.field(env.directory.contacts[2], "email"))
    body = Labelled("Tracking number: TRK-48213", join_all([Label(True, None, ("planner",)), lab.field(e1, "body")]))
    lit = Label(True, None, ("planner",))
    attendees = standin.quarantined("emails", f1.content, "attendees")
    alab = lab.field(f1, "content")
    calls = [
        ("send_email to Sam, address from the directory (UT7)", "send_email",
         {"recipients": Labelled([sam.value], sam.label, [sam]), "subject": Labelled("Tracking number", lit), "body": body}),
        ("send_email to the attendees the quarantined model found in file f1 (UT3, with IT0 planted)", "send_email",
         {"recipients": Labelled(attendees, alab, [Labelled(x, alab) for x in attendees]),
          "subject": Labelled("Q3 planning notes", lit), "body": Labelled(f1.content, alab)}),
        ("share_file f3 'Payroll summary 2027-01' with finance@tsg.example, an address the planner wrote", "share_file",
         {"file_id": Labelled("f3", lit), "email": Labelled("finance@tsg.example", lit)}),
    ]
    print("The sink policy (policies.py) runs before every call that sends or shares. It reads labels, not text.")
    print("These calls are only checked here: none of them is run.")
    for n, (what, tool, args, ) in enumerate(calls, 1):
        d = policies.check(tool, args, ctx)
        print(f"\n  {n}. {what}")
        if tool == "send_email":
            print(f"     recipients {_cut(args['recipients'].value, 104)}")
        _wrap(f"{d.verdict:<5} [{d.rule}] {d.reason}", "     ", "           ", lines=2)
        for note in d.notes:
            print(f"           note: {_cut(note, 104)}")
    print("\nTwo checks at every sink: whoever DECIDES where data goes must be trusted (or endorsed by the directory),")
    print("and every recipient must be allowed to read the data.")
    return 0


def cmd_task(a) -> int:
    suite = _suite()
    task = _ut(suite, a.ut)
    cls = type(task).__mro__[1]
    vectors = _injections(suite, task, "IT0")
    print(f"AgentDojo user task {a.ut.upper()} (inbox_suite.py):")
    print(f'  PROMPT        "{task.PROMPT}"')
    gt = task.ground_truth(_env(suite))
    print(f"  ground truth  {', '.join(c.function for c in gt)}   (the calls that solve it; `make check` runs them)")
    print(f"  attack goes   {', '.join(vectors)}   (the places this task reads that anyone outside can write)\n")
    print("The checker reads the environment AFTER the run, not what the agent says it did:")
    src = textwrap.dedent(inspect.getsource(cls.utility))
    for ln in src.splitlines():
        print("  | " + ln.rstrip()[:120])
    it = suite.get_injection_task_by_id("injection_task_0")
    print("\nThe attacker's goal IT0 and its checker:")
    print(f'  GOAL          "{it.GOAL}"')
    for ln in textwrap.dedent(inspect.getsource(type(it).__mro__[1].security)).splitlines():
        if ln.strip() and not ln.strip().startswith("#"):
            print("  | " + ln.rstrip()[:120])
    print("\nOne security case = one user task + one injection task. 8 x 4 = 32 cases in this lab.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Look at each idea of secure agent architecture (read-only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("agent")
    p.add_argument("ut", nargs="?", default="UT7")
    sub.add_parser("legs")
    p = sub.add_parser("planted")
    p.add_argument("ut", nargs="?", default="UT7")
    p.add_argument("it", nargs="?", default="IT0")
    p = sub.add_parser("plan")
    p.add_argument("ut", nargs="?", default="UT7")
    sub.add_parser("ask")
    sub.add_parser("labels")
    sub.add_parser("join")
    sub.add_parser("check")
    p = sub.add_parser("task")
    p.add_argument("ut", nargs="?", default="UT3")
    a = ap.parse_args(argv)
    return {"agent": cmd_agent, "legs": cmd_legs, "planted": cmd_planted, "plan": cmd_plan, "ask": cmd_ask,
            "labels": cmd_labels, "join": cmd_join, "check": cmd_check, "task": cmd_task}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
