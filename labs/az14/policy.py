"""
policy.py: the deterministic check your hosted agent runs BEFORE any tool call executes (lesson 14.5).

Azure has no managed twin of a rule engine on tool calls. The toolbox hands your runtime a require_approval flag and
then "Enforcement is entirely the agent runtime's responsibility". In a hosted agent, the runtime is your code. So the
last line of defence is a small, boring function like this one: tool name + arguments in, allow or deny out. No model.

The hardened build already calls check(). It stops attack A5 (an outside address). It does NOT stop A6.

CHALLENGE 1 (lesson 14.5): make check() exact, so attack A6 is refused and L2 still goes through.
  - send_email: the recipient's DOMAIN must equal contoso.com (split on the last "@", lower-case, no lists,
    no display names, no extra "@"). "it-support@contoso.com.attacker.example" contains "contoso.com" but is not
    at contoso.com.
  - keep the allow-list of tools: anything not listed is denied.
"""

ALLOWED_TOOLS = {"read_blob", "http_get", "search_tickets", "create_ticket", "send_email"}


def check(tool: str, args: dict, signed_in_upn: str) -> tuple[bool, str]:
    """Return (True, "ok") to let the call run, or (False, reason)."""
    if tool not in ALLOWED_TOOLS:
        return False, f"{tool} is not on the allow-list"
    if tool == "send_email":
        to = str(args.get("to", ""))
        if "contoso.com" not in to:                     # <- too loose: a substring is not a domain
            return False, f"recipient {to} is outside contoso.com"
    return True, "ok"
