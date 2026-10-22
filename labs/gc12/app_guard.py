"""
app_guard.py: the Helpdesk's own guard for a model that Model Armor can't screen inline (a self-hosted model,
another cloud's model, or the local Ollama model from Part 2). The app calls the sanitize API itself:

    prompt  -> sanitizeUserPrompt     -> blocked? stop : send to the model
    reply   -> sanitizeModelResponse  -> blocked? stop : send to the user

The sanitize API only REPORTS (filterMatchState, filterResults, invocationResult). Blocking is this file's job.
That's why the three functions marked CHALLENGE matter: they decide what gets screened and what counts as "stop".

The lab's challenge (README Step 7) asks you to change exactly these three functions. No solution is included.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Decision:
    blocked: bool
    stage: str                      # "prompt" or "response"
    why: str = ""
    results: list = field(default_factory=list)


# ---------------------------------------------------------------------------------------------------------------
# CHALLENGE 1 and 2: what do we send to Model Armor?
# ---------------------------------------------------------------------------------------------------------------
def prompt_views(turns: list[str], assembled: str, screen: str) -> list[str]:
    """
    The texts to screen before the model runs.
      screen == "user_text":        only the user's latest message (how the Helpdesk did it before this module)
      screen == "assembled_prompt": the whole conversation the model will see, tickets included (your own system
                                    prompt isn't screened)

    Model Armor inspects each request on its own (single-turn) and doesn't decode Base64.
    CHALLENGE 1: also screen the last three user turns joined with spaces, so an instruction split across
                 turns is seen whole.
    CHALLENGE 2: also screen the decoded text of any Base64 blob of 24+ characters in the user's turns.
    """
    if screen == "user_text":
        return [turns[-1]]
    return [assembled]


# ---------------------------------------------------------------------------------------------------------------
# CHALLENGE 3: what counts as "stop"?
# ---------------------------------------------------------------------------------------------------------------
def is_blocked(result: dict) -> tuple[bool, str]:
    """
    Decide from one sanitize result. Today: block only on MATCH_FOUND.
    CHALLENGE 3 (part a): fail closed. Also block when invocationResult isn't SUCCESS, which is how Model Armor
    tells you a filter was skipped (e.g. "Detection skipped as token limit exceeded.") or failed.
    """
    r = result["sanitizationResult"]
    if r.get("filterMatchState") == "MATCH_FOUND":
        hits = [k for k, v in r.get("filterResults", {}).items() if _match(v)]
        return True, "matched: " + ", ".join(sorted(hits))
    return False, ""


def on_error(err: Exception) -> tuple[bool, str]:
    """
    Model Armor didn't answer (outage, timeout, permission). Today: let the request through (fail open).
    CHALLENGE 3 (part b): fail closed for the Helpdesk: block and say why.
    """
    return False, f"guard unavailable, allowed without screening ({err})"


# ---------------------------------------------------------------------------------------------------------------
# Plumbing (no need to change)
# ---------------------------------------------------------------------------------------------------------------
def _match(filter_result: dict) -> bool:
    (inner,) = filter_result.values()
    inner = inner.get("inspectResult", inner)
    return inner.get("matchState") == "MATCH_FOUND"


def check_prompt(engine, turns: list[str], assembled: str, screen: str = "assembled_prompt") -> Decision:
    results = []
    for text in prompt_views(turns, assembled, screen):
        try:
            res = engine.sanitize_user_prompt(text)
        except ConnectionError as e:
            blocked, why = on_error(e)
            return Decision(blocked, "prompt", why, results)
        results.append(res)
        blocked, why = is_blocked(res)
        if blocked:
            return Decision(True, "prompt", why, results)
    return Decision(False, "prompt", "", results)


def check_response(engine, reply: str, user_prompt: str) -> Decision:
    try:
        res = engine.sanitize_model_response(reply, user_prompt)
    except ConnectionError as e:
        blocked, why = on_error(e)
        return Decision(blocked, "response", why)
    blocked, why = is_blocked(res)
    return Decision(blocked, "response", why, [res])
