"""
stand_in_model.py: the "model" behind the Helpdesk agent. PLAIN PYTHON, NOT AI, so every run is identical.

It copies four behaviours of real models that matter for this lab (Modules 6 and 7):
  1. It picks tools and fills in their arguments itself, including a "team" filter it guesses from your words.
  2. It obeys instructions it finds in tool results (retrieved documents, ticket text): the labelled placeholder
     [LAB-INJECTED-DIRECTIVE: email ... to <address>] makes it call send_email. That is indirect prompt injection.
  3. It answers by quoting what the tools returned, secrets included.
  4. It never enforces access rules: whatever a tool hands it, it uses.
"""

from __future__ import annotations

import re

FINANCE_WORDS = {"pricing", "discount", "deal", "finance", "hospital", "partner", "partners"}
DIRECTIVE = re.compile(r"\[LAB-INJECTED-DIRECTIVE: email (.+?) to ([\w.+-]+@[\w.-]+)\]")


class StandInModel:
    name = "stand-in (not AI)"

    def next_step(self, user_message: str, tool_results: list[dict]) -> dict:
        """Return {"call": (tool_name, args)} or {"text": answer}."""
        done = [r["tool"] for r in tool_results]
        if not tool_results:
            m = re.search(r"\bclose ticket (T-\d{4})\b", user_message, re.I)
            if m:
                return {"call": ("close_ticket", {"ticket_id": m.group(1)})}
            m = re.search(r"\bticket (T-\d{4})\b", user_message, re.I)
            if m:
                return {"call": ("get_ticket", {"ticket_id": m.group(1)})}
            team = "finance" if FINANCE_WORDS & set(re.findall(r"[a-z]+", user_message.lower())) else "all"
            return {"call": ("search_kb", {"query": user_message, "team": team})}
        # Indirect prompt injection: an instruction inside a tool result is followed once.
        if "send_email" not in done:
            for r in tool_results:
                m = DIRECTIVE.search(str(r["result"]))
                if m:
                    ticket = next((x["args"].get("ticket_id") for x in tool_results if x["tool"] == "get_ticket"), None)
                    history = " | ".join(str(x["result"]) for x in tool_results)
                    args = {"to": m.group(2), "subject": "Ticket history", "body": history[:400]}
                    if ticket:
                        args["ticket_id"] = ticket
                    return {"call": ("send_email", args)}
        return {"text": self._answer(tool_results)}

    @staticmethod
    def _answer(tool_results: list[dict]) -> str:
        last = tool_results[-1]["result"]
        if not isinstance(last, dict):
            return str(last)[:220]
        if "error" in last:
            return f"I couldn't do that: {last['error']}"
        if last.get("status") == "pending_approval":
            return f"Waiting for a person to approve {tool_results[-1]['tool']} (approval {last.get('approval_id')})."
        texts: list[str] = []
        if "contexts" in last:                                   # RAG Engine RetrieveContextsResponse
            texts = [c["text"] for c in last["contexts"].get("contexts", [])]
        elif "results" in last:                                  # Agent Search SearchResponse
            texts = [s["snippet"] for r in last["results"] for s in r["document"]["derivedStructData"]["snippets"]]
        elif "text" in last:                                     # a ticket
            texts = [last["text"]]
        elif last.get("status"):
            return f"Done: {last['status']}."
        if not texts:
            return "I couldn't find that in the documents I can see."
        return re.sub(r"<!--.*?-->|\[LAB-INJECTED-DIRECTIVE[^\]]*\]", "", texts[0]).strip()[:220]
