"""
memory_guard.py: what your code checks before anything is written to the agent's long-term memory (lesson 14.6).

Foundry Memory (preview) "extracts key information from the conversation". The conversation includes tool results:
a KB article the agent read can end up as a "fact" about you, recalled in every later session. Per-user scope stops
other users seeing it. It doesn't stop your own memory being poisoned.

CHALLENGE 2: make allow() refuse attack A8's write and keep L3's.
Suggested rules (deterministic):
  - only remember what the USER said (item["source"] == "user"); never what came from a tool result
  - refuse items that contain a URL, an email address, or words like "password", "always", "from now on"
"""


def allow(item: dict) -> bool:
    """item = {"text": str, "source": "user" | "tool_result:<doc id>", "user": str}. True = store it."""
    return True
