"""
cel.py: a tiny evaluator for the subset of CEL (Common Expression Language) this lab's access policies use.

Agent Gateway's IAM Unified Access Policies put a CEL expression in each rule's condition. Google's page lists the
attributes (destination.is_registered, destination.agent_registry.mcp_server.name, ...tool.name,
...tool.annotations.read_only_hint, destination.unregistered.host, ...) and the operators each one supports
(==, !=, in, and startsWith/endsWith/contains on the unregistered host and path only).

This is NOT Google's CEL engine. It understands exactly:
    literals      'text'  "text"  true  false  ['a', 'b']
    attributes    dotted names, looked up in a flat dict (a missing attribute is null)
    operators     ==  !=  in  &&  ||  !  ( )
    methods       .startsWith('x')  .endsWith('x')  .contains('x')
Anything else raises CelError, so a typo in a policy file fails loudly instead of quietly allowing traffic.
"""

from __future__ import annotations

import re

TOKEN = re.compile(r"\s*(?:(?P<str>'[^']*'|\"[^\"]*\")|(?P<op>==|!=|&&|\|\||[()\[\],!.])|(?P<name>[A-Za-z_][A-Za-z0-9_]*))")


class CelError(ValueError):
    pass


def tokenize(expr: str) -> list[tuple[str, str]]:
    out, pos = [], 0
    while pos < len(expr):
        if expr[pos:].strip() == "":
            break
        m = TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise CelError(f"can't read the expression at: {expr[pos:pos + 20]!r}")
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, expr: str, attrs: dict):
        self.t, self.i, self.attrs = tokenize(expr), 0, attrs

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, value=None):
        tok = self.peek()
        if value is not None and tok[1] != value:
            raise CelError(f"expected {value!r}, found {tok[1]!r}")
        self.i += 1
        return tok

    def parse(self):
        v = self.or_()
        if self.i != len(self.t):
            raise CelError(f"unexpected {self.peek()[1]!r}")
        return v

    def or_(self):
        v = self.and_()
        while self.peek()[1] == "||":
            self.take()
            r = self.and_()
            v = bool(v) or bool(r)
        return v

    def and_(self):
        v = self.not_()
        while self.peek()[1] == "&&":
            self.take()
            r = self.not_()
            v = bool(v) and bool(r)
        return v

    def not_(self):
        if self.peek()[1] == "!":
            self.take()
            return not bool(self.not_())
        return self.compare()

    def compare(self):
        left = self.operand()
        op = self.peek()[1]
        if op in ("==", "!="):
            self.take()
            right = self.operand()
            return (left == right) if op == "==" else (left != right)
        if op == "in":
            self.take()
            right = self.operand()
            if not isinstance(right, list):
                raise CelError("'in' needs a list on the right")
            return left in right
        return left

    def operand(self):
        kind, val = self.peek()
        if val == "(":
            self.take()
            v = self.or_()
            self.take(")")
            return v
        if val == "[":
            self.take()
            items = []
            while self.peek()[1] != "]":
                items.append(self.operand())
                if self.peek()[1] == ",":
                    self.take()
            self.take("]")
            return items
        if kind == "str":
            self.take()
            return val[1:-1]
        if kind == "name":
            if val in ("true", "false"):
                self.take()
                return val == "true"
            if val == "in":
                raise CelError("'in' without a left side")
            parts = [self.take()[1]]
            while self.peek()[1] == ".":
                self.take()
                name = self.take()[1]
                if name in ("startsWith", "endsWith", "contains"):
                    return self.method(".".join(parts), name)
                parts.append(name)
            return self.attrs.get(".".join(parts))
        raise CelError(f"unexpected {val!r}")

    def method(self, attr: str, name: str):
        if not attr.startswith(("destination.unregistered.host", "destination.unregistered.path")):
            raise CelError(f"{name}() only works on destination.unregistered.host and .path (Google's CEL attribute page)")
        self.take("(")
        arg = self.operand()
        self.take(")")
        value = self.attrs.get(attr)
        if value is None:
            return False
        return {"startsWith": value.startswith, "endsWith": value.endswith, "contains": value.__contains__}[name](arg)


def evaluate(expr: str, attrs: dict) -> bool:
    """True if the condition matches. An empty condition matches everything (a rule without a condition)."""
    if not expr or not expr.strip():
        return True
    return bool(_Parser(expr, attrs).parse())
