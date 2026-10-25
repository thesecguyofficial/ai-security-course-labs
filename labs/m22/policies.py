"""
policies.py: the taint-checked sinks (lessons 22.3 and 22.4).

A sink is a tool call that changes something or sends something out: `send_email`, `share_file`, and in the challenge
`fetch_url`. Before the controller runs a sink, it calls `check()` with every argument's value AND label. The model is
not asked; the policy reads the labels, which the model cannot write.

Two rules, the same two the information-flow papers use (FIDES calls them trusted action and permitted flow):

  integrity        a value that DECIDES where data goes or what is acted on (a recipient, a file ID, a URL) must be
                   trusted. One way to make an untrusted value trusted is to check it against a trusted list: an
                   address that is exactly an entry in the IT directory is accepted ("endorsed by the directory").
  confidentiality  every recipient must be allowed to read every piece of data in the call. The one exception is a
                   recipient the user typed in the request: the user may share their own data (declassification by the
                   user, recorded as such).

Fail closed: any tool not listed here that changes state is refused (`UNKNOWN_SINK`).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from labels import Label, Labelled, join_all

SINKS = {"send_email", "share_file", "fetch_url"}
READ_ONLY = {"search_emails", "get_contact", "search_files"}
USER = "user prompt"

# Challenge part 1: the only hosts an untrusted URL may point at.
ALLOWED_URL_HOSTS = {"track.brightline.example"}


@dataclass
class Decision:
    verdict: str                 # ALLOW or DENY
    rule: str
    reason: str
    notes: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"


@dataclass
class Context:
    staff: frozenset[str]                       # the IT directory: endorses untrusted addresses that match exactly
    file_label: callable                        # file_id -> Label of that file's content


def _deny(rule, reason):
    return Decision("DENY", rule, reason)


def _recipient_ok(r: Labelled, data: Label, ctx: Context, notes: list) -> Decision | None:
    if not r.label.trusted:
        if r.value in ctx.staff:
            notes.append(f"{r.value}: untrusted ({', '.join(r.label.sources)}), endorsed by the IT directory")
        else:
            return _deny("recipient_integrity",
                         f"recipient {r.value} came from untrusted content ({', '.join(r.label.sources)})")
    if not data.allows(r.value):
        if USER in r.label.sources:
            notes.append(f"{r.value}: not a reader of this data, but the user typed it (user's own decision)")
        else:
            return _deny("readers_only", f"{r.value} may not read data from {', '.join(data.sources)}")
    return None


def check_send_email(args: dict[str, Labelled], ctx: Context) -> Decision:
    data = join_all([args["subject"].label, args["body"].label])
    notes: list[str] = []
    for r in args["recipients"].parts:
        bad = _recipient_ok(r, data, ctx, notes)
        if bad:
            return bad
    return Decision("ALLOW", "send_email", "every recipient is trusted or endorsed, and may read the data", tuple(notes))


def check_share_file(args: dict[str, Labelled], ctx: Context) -> Decision:
    fid = args["file_id"]
    if not fid.label.trusted:
        return _deny("target_integrity", f"file ID {fid.value} came from untrusted content ({', '.join(fid.label.sources)})")
    notes: list[str] = []
    bad = _recipient_ok(args["email"], ctx.file_label(fid.value), ctx, notes)
    if bad:
        return bad
    return Decision("ALLOW", "share_file", "the file ID is trusted and the person may read the file", tuple(notes))


def check_fetch_url(args: dict[str, Labelled], ctx: Context) -> Decision:
    """CHALLENGE part 1 (lesson 22.1): a URL is a way out. Today this allows every URL.

    Write the rule: refuse an untrusted URL unless its host is in ALLOWED_URL_HOSTS (use urlsplit(...).hostname).
    A trusted URL (the user typed it) may go anywhere. Test: python3 run_tests.py --challenge
    """
    _ = urlsplit  # you'll need this
    return Decision("ALLOW", "fetch_url_TODO", "no rule yet")


CHECKS = {"send_email": check_send_email, "share_file": check_share_file, "fetch_url": check_fetch_url}


def check(tool: str, args: dict[str, Labelled], ctx: Context, control: Label | None = None) -> Decision:
    """The one entry point. `control` is the label of the conditions the call sits inside (strict mode, challenge 2)."""
    if tool in READ_ONLY:
        return Decision("ALLOW", "read_only", "reads only")
    if tool not in CHECKS:
        return _deny("UNKNOWN_SINK", f"{tool} has no policy (fail closed)")
    if control is not None and not control.trusted:
        return _deny("control_integrity", f"this call only happens because of a condition decided by untrusted "
                                          f"content ({', '.join(control.sources)})")
    return CHECKS[tool](args, ctx)
