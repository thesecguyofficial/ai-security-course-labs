"""
tm.py: the same TSG Helpdesk starter, written as code for OWASP pytm, which then lists threats for you.

pytm (OWASP, MIT licence) describes a system in Python: elements, flows, trust boundaries, and facts about each
element. Its built-in threat library checks those facts and prints findings. Run it with `make pytm` after
`make setup`. Fake system; nothing here talks to the network.

    .venv/bin/python tm.py                       # findings per element, then every finding for the model
    .venv/bin/python tm.py --target "Chat app"   # every finding for another element
"""

import sys

from pytm import LLM, TM, Actor, Boundary, Dataflow, Datastore, Process

tm = TM("TSG Helpdesk (starter)")
tm.description = "Lab 2.5 starter: the chat path and the nightly ticket import."

servers = Boundary("Our servers")
model_boundary = Boundary("Model boundary")

customer = Actor("Customer")
chat_app = Process("Chat app")
chat_app.inBoundary = servers
nightly = Process("Nightly import")
nightly.inBoundary = servers
tickets = Datastore("Ticketing system")
tickets.inBoundary = servers
kb = Datastore("Knowledge base")
kb.inBoundary = servers

model = LLM("Model")              # pytm 1.4 has an element type for a language model
model.inBoundary = model_boundary
model.isSelfHosted = True         # facts about the model: pytm's AI threats check these
model.isThirdParty = False        # local Ollama; the AWS version (Bedrock) would be True
model.hasSystemPrompt = True
model.processesUntrustedInput = True
model.hasRAG = True
model.hasAgentCapabilities = True
model.hasAccessToSensitiveSystems = True
model.processesPersonalData = True

Dataflow(customer, chat_app, "F1 chat message")
Dataflow(chat_app, model, "F2 system prompt + chat")
Dataflow(kb, model, "F4 retrieved articles")
Dataflow(model, chat_app, "F5 model output")
Dataflow(chat_app, customer, "F10 answer")
Dataflow(customer, tickets, "F15 ticket text")
Dataflow(tickets, nightly, "F11 resolved tickets")
Dataflow(nightly, kb, "F11 new articles")


def main():
    target = sys.argv[sys.argv.index("--target") + 1] if "--target" in sys.argv else "Model"
    sys.argv = sys.argv[:1]       # pytm reads its own command-line options; give it none
    tm.resolve()                  # check every threat in pytm's library against every element
    by_target = {}
    for f in tm.findings:
        by_target.setdefault(f.target, []).append(f)
    print(f"pytm: {len(tm.findings)} findings for {len(by_target)} elements\n")
    for name, found in by_target.items():
        print(f"   {name:<26} {len(found):>3}   e.g. {found[0].threat_id} {found[0].description}")
    print(f"\nall findings for {target}:")
    for f in by_target.get(target, []):
        print(f"   {f.threat_id:<6} {f.severity:<10} {f.description}")
    print("\nA list to judge, not an answer: you decide which findings are real for this system.")


if __name__ == "__main__":
    main()
