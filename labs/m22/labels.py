"""
labels.py: the labels that travel with every value in the hardened agent (lesson 22.4).

A label answers two questions about a value:

  integrity        can we trust it to decide something?  trusted  = came from the user, the planner, or a system
                   that vouches for it (the mail system's sender field, the IT directory); untrusted = anyone could
                   have written it (an email body, a shared file anyone outside can edit, a web page)
  confidentiality  who may see it?  `readers`: a set of addresses, or None for "anyone"

Combining two values (joining labels) keeps the stricter answer to both questions: untrusted if either is, and only
the readers both allow. `sources` records where the value came from, so a refusal can name the email or file to look at.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Label:
    trusted: bool
    readers: frozenset[str] | None = None        # None = anyone may read it
    sources: tuple[str, ...] = ()

    def join(self, other: "Label") -> "Label":
        if self.readers is None:
            readers = other.readers
        elif other.readers is None:
            readers = self.readers
        else:
            readers = self.readers & other.readers
        return Label(self.trusted and other.trusted, readers, tuple(sorted(set(self.sources) | set(other.sources))))

    def allows(self, reader: str) -> bool:
        return self.readers is None or reader in self.readers

    def short(self) -> str:
        who = "anyone" if self.readers is None else f"{len(self.readers)} readers"
        return f"{'trusted' if self.trusted else 'UNTRUSTED'}, {who}, from {', '.join(self.sources) or '-'}"


PUBLIC_TRUSTED = Label(True, None, ())


def join_all(labels) -> Label:
    out = PUBLIC_TRUSTED
    for lab in labels:
        out = out.join(lab)
    return out


@dataclass
class Labelled:
    """A value plus its label. `parts` keeps one Labelled per list element, so a policy can check each recipient."""
    value: Any
    label: Label
    parts: list["Labelled"] = field(default_factory=list)


class Labeller:
    """Labels tool results. Built from the environment, because 'staff' means 'everyone in the IT directory'."""

    def __init__(self, env):
        self.staff = frozenset(c.email for c in env.directory.contacts)

    # Which tool outputs carry text that someone outside could have written?
    def email_field(self, e, name: str) -> Label:
        readers = self.staff | {e.sender} | set(e.recipients)
        if name in ("id", "date", "sender", "recipients"):
            return Label(True, readers, (f"mail system ({e.id})",))
        return Label(False, readers, (f"email {e.id} from {e.sender}",))

    def file_field(self, f, name: str) -> Label:
        readers = {f.owner, *f.shared_with} | (self.staff if f.audience == "staff" else set())
        if name != "content":
            return Label(True, frozenset(readers), (f"drive metadata ({f.id})",))
        outsiders = [e for e in f.editors if e not in self.staff]
        return Label(not outsiders, frozenset(readers), (f"file {f.id} {f.name!r}" +
                                                       (f" (editable by {', '.join(outsiders)})" if outsiders else ""),))

    def field(self, obj, name: str) -> Label:
        kind = type(obj).__name__
        if kind == "Email":
            return self.email_field(obj, name)
        if kind == "File":
            return self.file_field(obj, name)
        if kind == "Contact":
            return Label(True, None, ("IT directory",))
        return PUBLIC_TRUSTED

    def whole(self, obj) -> Label:
        """The label of a whole tool result: the join of every field it holds."""
        if isinstance(obj, list):
            return join_all(self.whole(o) for o in obj) if obj else PUBLIC_TRUSTED
        if hasattr(obj, "model_fields"):
            return join_all(self.field(obj, n) for n in type(obj).model_fields)
        return PUBLIC_TRUSTED

    def page(self, url: str) -> Label:
        return Label(False, None, (f"web page {url}",))

    def has_untrusted(self, obj) -> bool:
        return not self.whole(obj).trusted
