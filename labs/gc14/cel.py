"""
cel.py: a tiny evaluator for the subset of CEL (Common Expression Language) this lab's access policies use.

Agent Gateway's IAM Unified Access Policies put a CEL expression in each rule's condition. Google's "CEL attributes
for IAM Unified Access Policies" page lists the attributes (destination.is_registered,
destination.agent_registry.mcp_server.name, ...tool.name, ...tool.annotations.read_only_hint,
destination.unregistered.host, ...) and the operators each one supports. ATTRIBUTES below copies that table.

This is NOT Google's CEL engine. It understands exactly:
    literals      'text'  "text"  true  false  ['a', 'b']
    attributes    the dotted names in ATTRIBUTES, looked up in a flat dict (a value the request doesn't have is null)
    operators     ==  !=  in  &&  ||  !  ( )
    methods       .startsWith('x')  .endsWith('x')  .contains('x')  (only on the unregistered host and path)
Anything else raises CelError: an unknown attribute, a number, `in` on an attribute that doesn't support it, a
missing comma. A typo in a policy file fails loudly instead of quietly changing what a rule matches.
"""

from __future__ import annotations

import re

# attribute -> operators Google's page lists for it ("method" = startsWith/endsWith/contains)
_EQ, _IN, _METHOD = "==/!=", "in", "method"
ATTRIBUTES = {
    "destination.is_registered": {_EQ},
    "destination.agent_registry.resource_type": {_EQ, _IN},
    "destination.agent_registry.location": {_EQ, _IN},
    "destination.agent_registry.project_id": {_EQ, _IN},
    "destination.agent_registry.agent.name": {_EQ, _IN},
    "destination.agent_registry.mcp_server.name": {_EQ, _IN},
    "destination.agent_registry.mcp_server.method": {_EQ, _IN},
    "destination.agent_registry.mcp_server.tool.name": {_EQ, _IN},
    "destination.agent_registry.mcp_server.tool.annotations.read_only_hint": {_EQ},
    "destination.agent_registry.mcp_server.tool.annotations.destructive_hint": {_EQ},
    "destination.agent_registry.mcp_server.tool.annotations.idempotent_hint": {_EQ},
    "destination.agent_registry.mcp_server.tool.annotations.open_world_hint": {_EQ},
    "destination.agent_registry.mcp_server.prompt.name": {_EQ, _IN},
    "destination.agent_registry.mcp_server.resource.name": {_EQ, _IN},
    "destination.agent_registry.endpoint.name": {_EQ, _IN},
    "destination.unregistered.host": {_EQ, _IN, _METHOD},
    "destination.unregistered.path": {_EQ, _IN, _METHOD},
    "destination.unregistered.method": {_EQ, _IN},
}
METHODS = ("startsWith", "endsWith", "contains")

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


class _Attr:
    """An attribute reference: its name and the value the request has for it."""

    def __init__(self, name: str, value):
        self.name, self.value = name, value


def _val(x):
    return x.value if isinstance(x, _Attr) else x


class _Parser:
    def __init__(self, expr: str, attrs: dict):
        self.t, self.i, self.attrs = tokenize(expr), 0, attrs

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, value=None):
        tok = self.peek()
        if tok[0] is None:
            raise CelError("the expression ends too early" + (f" (expected {value!r})" if value else ""))
        if value is not None and tok[1] != value:
            raise CelError(f"expected {value!r}, found {tok[1]!r}")
        self.i += 1
        return tok

    def parse(self):
        if not self.t:
            raise CelError("empty expression")
        v = self.or_()
        if self.i != len(self.t):
            raise CelError(f"unexpected {self.peek()[1]!r}")
        return v

    # precedence, lowest first: ||, &&, comparison (== != in), unary !, operand
    def or_(self):
        v = self.and_()
        while self.peek()[1] == "||":
            self.take()
            r = self.and_()
            v = bool(v) or bool(r)
        return v

    def and_(self):
        v = self.compare()
        while self.peek()[1] == "&&":
            self.take()
            r = self.compare()
            v = bool(v) and bool(r)
        return v

    def compare(self):
        left = self.unary()
        op = self.peek()[1]
        if op in ("==", "!="):
            self.take()
            self._check_op(left, _EQ, op)
            right = self.unary()
            self._check_op(right, _EQ, op)
            same = _val(left) == _val(right)
            return same if op == "==" else not same
        if op == "in":
            self.take()
            self._check_op(left, _IN, "in")
            right = self.unary()
            if not isinstance(right, list):
                raise CelError("'in' needs a list on the right, like ['a', 'b']")
            return _val(left) in right
        return _val(left)

    @staticmethod
    def _check_op(side, kind: str, shown: str):
        if isinstance(side, _Attr) and kind not in ATTRIBUTES[side.name]:
            raise CelError(f"{side.name} doesn't support '{shown}' (Google's CEL attribute page)")

    def unary(self):
        if self.peek()[1] == "!":
            self.take()
            return not bool(_val(self.unary()))
        return self.operand()

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
                kind_i, _ = self.peek()
                if kind_i not in ("str", "name"):
                    raise CelError(f"a list holds literals, found {self.peek()[1]!r}")
                item = self.operand()
                if isinstance(item, _Attr):
                    raise CelError("a list holds literals, not attributes")
                items.append(item)
                if self.peek()[1] == ",":
                    self.take()
                elif self.peek()[1] != "]":
                    raise CelError(f"expected ',' or ']' in a list, found {self.peek()[1]!r}")
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
                k, name = self.take()
                if k != "name":
                    raise CelError(f"expected a name after '.', found {name!r}")
                if name in METHODS:
                    return self.method(".".join(parts), name)
                parts.append(name)
            return self.attribute(".".join(parts))
        raise CelError(f"unexpected {val!r}")

    def attribute(self, name: str) -> _Attr:
        if name not in ATTRIBUTES:
            raise CelError(f"unknown attribute {name!r} (not on Google's CEL attribute page)")
        return _Attr(name, self.attrs.get(name))

    def method(self, attr: str, name: str):
        if attr not in ATTRIBUTES or _METHOD not in ATTRIBUTES[attr]:
            raise CelError(f"{name}() only works on destination.unregistered.host and .path (Google's CEL attribute page)")
        self.take("(")
        kind, arg = self.take()
        if kind != "str":
            raise CelError(f"{name}() takes one string, found {arg!r}")
        self.take(")")
        value = self.attrs.get(attr)
        if value is None:
            return False
        arg = arg[1:-1]
        return {"startsWith": value.startswith, "endsWith": value.endswith, "contains": value.__contains__}[name](arg)


def evaluate(expr: str, attrs: dict) -> bool:
    """True if the condition matches. An empty condition matches everything (a rule without a condition)."""
    if not expr or not expr.strip():
        return True
    return bool(_val(_Parser(expr, attrs).parse()))


def check(expr: str) -> None:
    """Parse a condition against an empty request: raises CelError if it isn't in the supported subset."""
    evaluate(expr, {})
