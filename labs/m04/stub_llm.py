"""
M4.6 lab: a STAND-IN for a real AI model.

!!! This is NOT an AI model. !!!
It is a few lines of ordinary Python that pretend to be one, so the redaction exercise runs on any laptop
with no model download and gives the same output every time. It copies two real-world behaviours:

  1. Models often repeat back what you told them ("Thanks Jane, I've noted jane.doe@example.com").
  2. Models connected to company data (RAG, tools) can return OTHER people's records in an answer
     (lesson 4.1: sensitive information disclosure).

It also writes what it received into logs/provider.log. That file plays the role of the AI provider's
side: whatever reaches it has left your control (retention, abuse monitoring, legal holds; lesson 4.2).

Want a real model instead? See chat_app.py --backend ollama (optional, needs Ollama from lesson 0.6).
"""

import logging
import pathlib

LOG_DIR = pathlib.Path(__file__).resolve().parent / "logs"

# A fake "customer database" the pretend model can see. All values are reserved test data:
# example.org is a reserved domain, 5555 5555 5555 4444 is a well-known card-network test number.
FAKE_CRM_RECORD = ("Customer record: John Smith, john.smith@example.org, card 5555 5555 5555 4444, "
                   "last login from 198.51.100.7.")

provider_log = logging.getLogger("provider")


def _setup_provider_log():
    if provider_log.handlers:
        return
    LOG_DIR.mkdir(exist_ok=True)
    handler = logging.FileHandler(LOG_DIR / "provider.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s PROVIDER RECEIVED: %(message)s"))
    provider_log.addHandler(handler)
    provider_log.setLevel(logging.INFO)
    provider_log.propagate = False


def stub_llm(messages: list[dict]) -> str:
    """Take OpenAI-style messages [{"role": ..., "content": ...}] and return a canned reply."""
    _setup_provider_log()
    last = messages[-1]["content"]
    provider_log.info(last)  # the "provider" keeps a copy of exactly what it was sent

    if "look up" in last.lower() or "lookup" in last.lower():
        # Behaviour 2: the answer contains someone else's personal data.
        return f"Here is what I found. {FAKE_CRM_RECORD}"
    # Behaviour 1: repeat the user's words back.
    return f"Thanks, I've noted your message: \"{last}\". A support agent will follow up."
