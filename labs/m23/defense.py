"""
defense.py: YOU WRITE THIS. Five defensive checks. Nothing here attacks anything; each function reads one
recorded event (or the list of login events) and returns a verdict. The harness (replay.py) runs them over
the frozen trace and the adapted variants and scores catch rate and false positives.

Fill in the five functions below. Until you do, every function returns "nothing wrong", so `make replay`
shows 0 of 5 caught. When they are right, it shows 5 of 5 on the recorded trace AND the variants, with 0
false positives. Build on behaviour, not exact wording (lesson 23.4): the variants paraphrase, encode and
use look-alike names, so a check that matches the recorded strings exactly will fail them.

`config` is the dict from config.json: model_callers, model_api_domains, allowed_tools,
allowed_email_domains, allowed_fetch_hosts, rate. Read it; do not hard-code the recorded values.

Return contract (the harness relies on it):
  input_check(event, config)      -> a short reason string if the content is an injection, else None
  allowlist(tool_call, config)    -> True to ALLOW the tool call, False to DENY it
  output_check(event, config)     -> a short reason string if output exfiltrates data, else None
  rate_anomaly(login_events, config) -> a set (or list) of account names that are over budget / anomalous
  egress_signature(egress, config)  -> a short reason string if this egress line is suspicious, else None
"""

from __future__ import annotations


def input_check(event: dict, config: dict) -> str | None:
    """Flag a content event (user_msg, retrieval or tool_result) that carries an instruction dressed as data.

    Look at event.get("text", ""). Flag when it shows instruction-override intent or hidden text, for example:
      - override phrasing aimed at instructions/directions/rules: "ignore previous instructions",
        "disregard all prior directions", "you are now ...", a leading "system:" role.
        (Do NOT flag an ordinary user saying "ignore my earlier message" - that is a normal sentence.)
      - text hidden from a reader: content inside an HTML comment, or zero-width characters.
    Return a short reason (names the signal) or None. The variant paraphrases and adds a zero-width char,
    so match the structure, not the exact words.
    """
    # TODO (lesson 23.3): return a reason string when event["text"] carries injection, else None.
    return None


def allowlist(tool_call: dict, config: dict) -> bool:
    """Deny by default. Allow a tool call only if the tool AND its destination argument are permitted.

    tool_call["tool"] and tool_call["args"]. Rules:
      - the tool must be in config["allowed_tools"];
      - send_email: the recipient domain (after '@') must be in config["allowed_email_domains"];
      - fetch_url: the URL host must be in config["allowed_fetch_hosts"];
      - tools with no outward destination (search_kb, get_ticket) are allowed once the tool is on the list.
    Return True to allow, False to deny. A look-alike domain like attacker.example.co is simply not on the
    list, so deny-by-default refuses it without you listing every bad name.
    """
    # TODO (lesson 23.3): return True only for permitted tool + destination, else False.
    return True


def output_check(event: dict, config: dict) -> str | None:
    """Flag model output (or a tool call) that sends data to an outside destination.

    Look at event.get("text", "") (and, if you like, a fetch_url's args). Flag when it contains a URL whose
    host is not in config["allowed_fetch_hosts"] and which carries data (a query parameter such as d=, x=,
    data=, or an obviously encoded blob). Return a short reason or None. The variant uses a different host
    and a different parameter name, so key on "external host + data-bearing query", not one exact URL.
    (Challenge 2 extends this to a rendered image, e.g. ![](https://host/p.png?d=...).)
    """
    # TODO (lesson 23.3): return a reason string when output leaks data to an outside host, else None.
    return None


def rate_anomaly(login_events: list[dict], config: dict) -> set[str]:
    """Return the accounts that made too many failed sign-ins too fast (an automated loop / denial of wallet).

    Each item has actor, result ("fail"/"ok") and ts (ISO8601). Flag an account with more than
    config["rate"]["login_fail_per_min"] failed sign-ins inside any 60-second window. Return a set of the
    flagged account names. The variant is a smaller, slightly slower burst that is still over budget.
    """
    # TODO (lesson 23.3): return the set of accounts over the per-minute failed-login budget.
    return set()


def egress_signature(egress: dict, config: dict) -> str | None:
    """Flag an outbound connection to a model API from a host that is not supposed to call one.

    egress has host and dest. Flag when dest is (or ends with) one of config["model_api_domains"] AND host is
    not in config["model_callers"]. Return a short reason or None. The variant uses a model-API SUBDOMAIN
    (eu.api.model-vendor.example), so match the domain by suffix, not by exact string.
    """
    # TODO (lesson 23.2): return a reason string for a model-API call from a non-caller host, else None.
    return None
