"""
containment.py: YOU WRITE THIS. Four containment controls (plus one challenge function). Nothing here attacks
anything; each function reads recorded events and returns a verdict. The harness (replay.py) runs them over the
recorded, illustrative multi-agent run and the adapted variant and proves the dangerous action never executes while
the normal runs still complete.

Fill in the four controls below. Until you do, boundary_filter allows every hand-off, tool_scope allows every
tool call, the breaker never trips and detect finds nothing, so `make replay` shows "contained: NO". When they
are right it shows "contained: YES" on the recording AND the variants, with 0 false positives on the normal runs.
Build on behaviour, not exact wording (lesson 24.4): the adapted variant paraphrases the instruction and uses a look-alike domain.

`config` is the dict from config.json: agents, agent_tools, send_email_domains, propagation_threshold.

Return contract (the harness relies on it):
  boundary_filter(handoff, config)      -> True to ALLOW the hand-off, False to BLOCK it
  tool_scope(agent, tool_call, config)  -> True to ALLOW the tool call, False to DENY it
  circuit_breaker(events, config)       -> a truthy value (e.g. the hand-off id where it trips) if it trips, else None
  detect(events, config)                -> a list of propagation findings (empty list if none)
  memory_residue(events, config)        -> (challenge 2) a list of memory-channel hand-off IDs still carrying an instruction
"""

from __future__ import annotations


def boundary_filter(handoff: dict, config: dict) -> bool:
    """Decide whether an agent-to-agent message may cross a trust boundary.

    handoff has from, to, channel and message. BLOCK (return False) a message that carries instruction-like
    content: an external recipient (an email whose domain is not in config["send_email_domains"]), a
    self-forwarding phrase ("pass this instruction along", "forward these steps onward"), or override phrasing
    ("ignore previous instructions", "you are now"). ALLOW (return True) a normal, typed summary. The variant
    paraphrases and uses a look-alike domain, so key on the behaviour (an external recipient crossing a
    boundary), not the exact words.
    """
    # TODO (lesson 24.3): return False to block an instruction-bearing hand-off, True otherwise.
    return True


def tool_scope(agent: str, tool_call: dict, config: dict) -> bool:
    """Deny by default. Allow a tool call only if this agent is scoped for it.

    tool_call has tool and args. Rules:
      - the tool must be in config["agent_tools"][agent] (an agent not listed, or with no tools, is denied);
      - send_email: the recipient domain (after '@') must be in config["send_email_domains"][agent].
    Return True to allow, False to deny. A look-alike domain like attacker.example.co is simply not on the
    list, so deny-by-default refuses it. No other agent may send at all.
    """
    # TODO (lesson 24.3): return True only for a permitted agent + tool + destination, else False.
    return True


def circuit_breaker(events: list[dict], config: dict):
    """Trip when the SAME instruction crosses more than one trust boundary (propagation).

    events is a run's events in order. Build a fingerprint of the instruction-bearing content in each hand-off
    (for example, the external recipient it names, or a normalised key phrase). If the same fingerprint appears
    in at least config["propagation_threshold"] hand-offs (default 2), trip: return something truthy, such as
    the ID of the hand-off where the threshold was reached. Otherwise return None. A benign message repeated
    across agents is not instruction-bearing, so it must not trip this.
    """
    # TODO (lesson 24.3): return a truthy value when the same instruction crosses >= threshold boundaries.
    return None


def detect(events: list[dict], config: dict) -> list:
    """Flag propagation: the same instruction-bearing content appearing in more than one agent's traffic.

    Return a list of findings (empty if none). A useful finding names the content (or its fingerprint) and the
    agents it travelled through, so a reviewer can see the path. A benign repeated message must not be flagged.
    """
    # TODO (lesson 24.4): return a list of propagation findings (same instruction across >1 agent), else [].
    return []


def memory_residue(events: list[dict], config: dict) -> list:
    """Challenge 2 (lesson 24.3): what the kill-switch must quarantine.

    A kill-switch has to purge the instruction left in SHARED MEMORY, not just stop live hand-offs, or the next
    run re-reads it. Return the list of hand-off IDs whose channel is "memory" and whose message is
    instruction-bearing. Those are the memory writes to quarantine before the crew runs again.
    """
    # TODO (challenge 2): return the memory-channel hand-off IDs that still carry an instruction.
    return None
