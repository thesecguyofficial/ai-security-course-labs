"""
cedar.py: a SMALL Cedar evaluator for the lab, standard library only. It is not the real Cedar engine.

It understands the subset that AWS's Policy in AgentCore pages use for gateway tools (policy-conditions,
policy-core-concepts, policy-getting-started):

    permit | forbid (
        principal [is AgentCore::OAuthUser | == <entity>],
        action    [== AgentCore::Action::"Target___tool" | in [<entity>, ...]],
        resource  [== AgentCore::Gateway::"<gateway ARN>"]
    )
    [when { <expr> }] [unless { <expr> }] ;

<expr>: && || ! == != < <= > >= like has, ( ), "strings", integers, true/false, [sets].contains(x),
context.input.<argument>, principal.hasTag("claim"), principal.getTag("claim"), principal.id

Semantics copied from AWS's description: "The engine enforces default-deny and forbid-wins semantics
automatically" (policy-core-concepts). As in Cedar, a policy whose condition hits an error (for example a missing
attribute) does not apply; AgentCore counts it as a "mismatched" policy (observability-policy-metrics).

NOT supported (and not needed here): Dogwood temporal and guardrail condition blocks (the lab models the one
temporal rule it needs in temporal.json), entity hierarchies, extension functions, arithmetic.

    python3 cedar.py setups/hardened/policies bob reset_mfa '{"target_username": "ceo", "caller_username": "bob"}'
"""

from __future__ import annotations

import fnmatch
import json
import pathlib
import re
import sys
from dataclasses import dataclass, field

TOKEN = re.compile(r'\s*(?:(//[^\n]*)|("(?:[^"\\]|\\.)*")|(::|==|!=|<=|>=|&&|\|\||[(){}\[\],;.<>!])|([A-Za-z_][A-Za-z0-9_]*)|(-?\d+))')


class CedarError(Exception):
    """A condition could not be evaluated (missing attribute, wrong type): the policy does not apply."""


@dataclass
class Policy:
    name: str
    effect: str                      # permit | forbid
    principal: tuple                 # ("any",) | ("is", "AgentCore::OAuthUser") | ("eq", entity)
    action: tuple                    # ("any",) | ("eq", entity) | ("in", [entities])
    resource: tuple                  # ("any",) | ("eq", entity)
    conditions: list = field(default_factory=list)   # [("when"|"unless", ast)]
    text: str = ""


# --------------------------------------------------------------------------------------------------------------------
# Tokeniser and parser
# --------------------------------------------------------------------------------------------------------------------
def tokenise(text: str) -> list[tuple[str, str]]:
    out, pos = [], 0
    while pos < len(text):
        if text[pos:].strip() == "":
            break
        m = TOKEN.match(text, pos)
        if not m:
            raise SyntaxError(f"cannot read Cedar near: {text[pos:pos + 30]!r}")
        pos = m.end()
        comment, string, punct, ident, number = m.groups()
        if comment:
            continue
        if string is not None:
            out.append(("str", json.loads(string)))
        elif punct:
            out.append(("p", punct))
        elif ident:
            out.append(("id", ident))
        else:
            out.append(("int", int(number)))
    return out


class Parser:
    def __init__(self, tokens):
        self.t, self.i = tokens, 0

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else ("eof", None)

    def take(self, kind=None, value=None):
        tok = self.peek()
        if (kind and tok[0] != kind) or (value is not None and tok[1] != value):
            raise SyntaxError(f"expected {value or kind}, found {tok[1]!r}")
        self.i += 1
        return tok

    def accept(self, value):
        if self.peek()[1] == value and self.peek()[0] in ("p", "id"):
            self.i += 1
            return True
        return False

    # entity: AgentCore::Action::"name"
    def entity(self):
        parts = [self.take("id")[1]]
        while self.accept("::"):
            if self.peek()[0] == "str":
                return ("entity", "::".join(parts), self.take("str")[1])
            parts.append(self.take("id")[1])
        return ("path", "::".join(parts))

    def policy(self, name):
        start = self.i
        effect = self.take("id")[1]
        if effect not in ("permit", "forbid"):
            raise SyntaxError("a policy starts with permit or forbid")
        self.take("p", "(")
        self.take("id", "principal")
        if self.accept("is"):
            principal = ("is", self.entity()[1])
        elif self.accept("=="):
            principal = ("eq", self.entity())
        else:
            principal = ("any",)
        self.take("p", ",")
        self.take("id", "action")
        if self.accept("=="):
            action = ("eq", self.entity())
        elif self.accept("in"):
            self.take("p", "[")
            items = [self.entity()]
            while self.accept(","):
                items.append(self.entity())
            self.take("p", "]")
            action = ("in", items)
        else:
            action = ("any",)
        self.take("p", ",")
        self.take("id", "resource")
        resource = ("eq", self.entity()) if self.accept("==") else ("any",)
        self.take("p", ")")
        conditions = []
        while self.peek()[1] in ("when", "unless"):
            kind = self.take("id")[1]
            self.take("p", "{")
            conditions.append((kind, self.expr()))
            self.take("p", "}")
        self.take("p", ";")
        return Policy(name, effect, principal, action, resource, conditions)

    def expr(self):
        left = self.and_()
        while self.accept("||"):
            left = ("or", left, self.and_())
        return left

    def and_(self):
        left = self.unary()
        while self.accept("&&"):
            left = ("and", left, self.unary())
        return left

    def unary(self):
        if self.accept("!"):
            return ("not", self.unary())
        return self.rel()

    def rel(self):
        left = self.postfix()
        op = self.peek()[1]
        if op in ("==", "!=", "<", "<=", ">", ">=") and self.peek()[0] == "p":
            self.i += 1
            return ("cmp", op, left, self.postfix())
        if op == "like":
            self.i += 1
            return ("like", left, self.take("str")[1])
        if op == "has":
            self.i += 1
            tok = self.take()
            return ("has", left, tok[1])
        return left

    def postfix(self):
        node = self.primary()
        while self.accept("."):
            name = self.take("id")[1]
            if self.accept("("):
                args = []
                if not self.accept(")"):
                    args.append(self.expr())
                    while self.accept(","):
                        args.append(self.expr())
                    self.take("p", ")")
                node = ("call", node, name, args)
            else:
                node = ("attr", node, name)
        return node

    def primary(self):
        kind, val = self.peek()
        if kind == "str":
            self.i += 1
            return ("lit", val)
        if kind == "int":
            self.i += 1
            return ("lit", val)
        if kind == "id" and val in ("true", "false"):
            self.i += 1
            return ("lit", val == "true")
        if kind == "id" and val in ("principal", "action", "resource", "context"):
            self.i += 1
            return ("var", val)
        if self.accept("("):
            e = self.expr()
            self.take("p", ")")
            return e
        if self.accept("["):
            items = []
            if not self.accept("]"):
                items.append(self.expr())
                while self.accept(","):
                    items.append(self.expr())
                self.take("p", "]")
            return ("set", items)
        if kind == "id":
            return ("entity_lit", self.entity())
        raise SyntaxError(f"unexpected {val!r}")


def parse(text: str, name: str = "policy") -> Policy:
    p = Parser(tokenise(text))
    pol = p.policy(name)
    if p.peek()[0] != "eof":
        raise SyntaxError(f"{name}: one statement per policy (AgentCore stores each policy separately)")
    pol.text = text.strip()
    return pol


def load_dir(folder) -> list[Policy]:
    folder = pathlib.Path(folder)
    return [parse(p.read_text(encoding="utf-8"), p.stem) for p in sorted(folder.glob("*.cedar"))]


# --------------------------------------------------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------------------------------------------------
def _value(node, req):
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "var":
        return req[node[1]]
    if kind == "set":
        return [_value(n, req) for n in node[1]]
    if kind == "entity_lit":
        return node[1]
    if kind == "attr":
        base = _value(node[1], req)
        if isinstance(base, dict) and node[2] in base:
            return base[node[2]]
        raise CedarError(f"missing attribute {node[2]}")
    if kind == "call":
        base, name, args = _value(node[1], req), node[2], [_value(a, req) for a in node[3]]
        if name == "hasTag":
            return args[0] in base.get("tags", {})
        if name == "getTag":
            if args[0] not in base.get("tags", {}):
                raise CedarError(f"no tag {args[0]}")
            return base["tags"][args[0]]
        if name == "contains":
            if not isinstance(base, list):
                raise CedarError("contains() on a non-set")
            return args[0] in base
        raise CedarError(f"unsupported method {name}")
    if kind in ("cmp", "like", "has", "and", "or", "not"):
        return _bool(node, req)
    raise CedarError(f"cannot evaluate {kind}")


def _bool(node, req) -> bool:
    kind = node[0]
    if kind == "and":
        return _bool(node[1], req) and _bool(node[2], req)      # Cedar short-circuits
    if kind == "or":
        return _bool(node[1], req) or _bool(node[2], req)
    if kind == "not":
        return not _bool(node[1], req)
    if kind == "has":
        base = _value(node[1], req)
        return isinstance(base, dict) and node[2] in base
    if kind == "like":
        v = _value(node[1], req)
        if not isinstance(v, str):
            raise CedarError("like on a non-string")
        return fnmatch.fnmatchcase(v, node[2])
    if kind == "cmp":
        op, a, b = node[1], _value(node[2], req), _value(node[3], req)
        if op in ("<", "<=", ">", ">="):
            if not (isinstance(a, int) and isinstance(b, int)) or isinstance(a, bool) or isinstance(b, bool):
                raise CedarError("comparison needs two numbers")
            return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
        return (a == b) if op == "==" else (a != b)
    v = _value(node, req)
    if not isinstance(v, bool):
        raise CedarError("condition is not a boolean")
    return v


def _scope_matches(pol: Policy, req) -> bool:
    if pol.principal[0] == "is" and req["principal"]["type"] != pol.principal[1]:
        return False
    if pol.principal[0] == "eq" and (req["principal"]["type"], req["principal"]["id"]) != pol.principal[1][1:]:
        return False
    act = ("entity", "AgentCore::Action", req["action"])
    if pol.action[0] == "eq" and pol.action[1] != act:
        return False
    if pol.action[0] == "in" and act not in pol.action[1]:
        return False
    if pol.resource[0] == "eq" and pol.resource[1] != ("entity", "AgentCore::Gateway", req["resource"]):
        return False
    return True


def applies(pol: Policy, req) -> bool:
    """True/False, or raises CedarError (the policy is then 'mismatched' and does not apply)."""
    if not _scope_matches(pol, req):
        return False
    for kind, cond in pol.conditions:
        v = _bool(cond, req)
        if (kind == "when" and not v) or (kind == "unless" and v):
            return False
    return True


def authorize(policies: list[Policy], req: dict) -> dict:
    """Default deny, forbid wins. Returns the decision and the policies that determined it."""
    permits, forbids, mismatched = [], [], []
    for pol in policies:
        try:
            if applies(pol, req):
                (permits if pol.effect == "permit" else forbids).append(pol.name)
        except CedarError:
            mismatched.append(pol.name)
    if forbids:
        return {"decision": "DENY", "determining": forbids, "mismatched": mismatched}
    if permits:
        return {"decision": "ALLOW", "determining": permits, "mismatched": mismatched}
    return {"decision": "DENY", "determining": [], "mismatched": mismatched,
            "reason": "No policy applies to the request (denied by default)."}


def check_wildcards(pol: Policy) -> list[str]:
    """AWS: a policy naming a specific action must also name a specific gateway; permit(principal, action, resource)
    with wildcards is rejected at deploy (policy-getting-started)."""
    problems = []
    if pol.action[0] != "any" and pol.resource[0] == "any":
        problems.append(f"{pol.name}: names an action but not a gateway")
    if pol.action[0] == "any" and pol.resource[0] == "any" and pol.effect == "permit":
        problems.append(f"{pol.name}: permit with wildcard action and resource")
    return problems


def request(principal: dict, tool: str, args: dict, gateway_arn: str, target: str = "HelpdeskTools") -> dict:
    return {"principal": principal, "action": f"{target}___{tool}", "resource": gateway_arn, "context": {"input": args}}


if __name__ == "__main__":
    import twin
    if len(sys.argv) != 5:
        sys.exit(__doc__.strip().splitlines()[-1])
    folder, user, tool, args = sys.argv[1], sys.argv[2], sys.argv[3], json.loads(sys.argv[4])
    principal = twin.principal_from_claims(twin.user_token(user))
    print(json.dumps(authorize(load_dir(folder), request(principal, tool, args, twin.COMPANY["gateway_arn"])), indent=2))
