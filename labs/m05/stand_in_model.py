"""
stand_in_model.py: a STAND-IN for an AI model. This is NOT AI.

It is a few dozen lines of plain, predictable Python, so the lab gives the same result every time and needs no
model download. It copies the ONE behaviour this lab is about: a model's output is shaped by whatever text it
was given. A real model does the same thing, just less predictably (lesson 1.2).

What it does: it reads the user's question (and, when asked to summarise, a ticket from the database) and returns
a "plan", a small dictionary that the app then acts on:

    {
      "answer": "text the app shows in the web page",
      "search_term": "words the app uses to search the tickets table",
      "service": "name of a service the app checks with a helper program",
      "filename": "name of a file the app saves a summary to (used by the challenge)",
    }

Real apps ask real models for exactly this kind of structured output ("reply in JSON with these fields").
The point of the lab: everything in this dictionary is UNTRUSTED, because the person typing the question
(or whoever wrote the ticket) controls what ends up in it.

Want a real model? See helpdesk_app.py --backend ollama (optional, needs Ollama from lesson 0.6).
"""

import re


def plan(question: str, latest_ticket_text: str = "") -> dict:
    """Turn a question into a plan. Deterministic: same input, same output, every time."""
    q = question.strip()
    result = {"answer": "", "search_term": "", "service": "", "filename": ""}

    # 1. "search my tickets for X"  ->  the model extracts X as a search term.
    #    A real model does the same: it copies the user's words into the field you asked for.
    m = re.search(r"search (?:my )?tickets for[:\s]+(.+)$", q, re.IGNORECASE)
    if m:
        result["search_term"] = m.group(1).strip()
        result["answer"] = f"Here are your tickets matching: {result['search_term']}"
        return result

    # 2. "check the status of X"  ->  the model picks a service name for the helper program.
    m = re.search(r"status of[:\s]+(.+)$", q, re.IGNORECASE)
    if m:
        result["service"] = m.group(1).strip()
        result["answer"] = f"Checking the status of {result['service']}."
        return result

    # 3. "save a summary as X"  ->  the model picks a file name (the challenge uses this).
    m = re.search(r"save (?:a )?summary as[:\s]+(.+)$", q, re.IGNORECASE)
    if m:
        result["filename"] = m.group(1).strip()
        result["answer"] = f"Saving a summary of your latest ticket as {result['filename']}."
        return result

    # 4. "summarise my latest ticket"  ->  the model quotes the ticket it was given.
    #    The ticket was written by whoever OPENED it, so someone else's words come out of the
    #    model and into your page. This is how a stranger's text reaches an innocent user.
    if re.search(r"summari[sz]e", q, re.IGNORECASE):
        result["answer"] = f"Summary of your latest ticket: {latest_ticket_text}"
        return result

    # 5. Anything else: a polite echo, like a chatbot repeating the question back.
    result["answer"] = (f"You asked: {q}. Try: 'search my tickets for VPN', "
                        f"'check the status of vpn' or 'summarise my latest ticket'.")
    return result
