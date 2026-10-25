# M22 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Needs Python 3.11+ and ONE package, agentdojo (the benchmark), in this folder's own virtual environment.
# Nothing leaves this folder: the models are local stand-ins, the mail and drive are fake, no network.
VENV := .venv
PY   := $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)

.PHONY: setup check trifecta before after score story audit hunt workspace test challenge clean

setup:      ## create .venv and install the pinned agentdojo (about 260 MB)
	python3 -m venv $(VENV)
	$(VENV)/bin/python -m pip install -r requirements.txt

check:      ## AgentDojo's validity check for the TSG inbox suite
	$(PY) inbox_suite.py

trifecta:   ## where the three legs sit in each design, and which tool supplies which leg
	$(PY) trifecta.py --tools
	@echo
	$(PY) trifecta.py

before:     ## the single-model agent, scored by AgentDojo: 32 of 32 attacks work
	$(PY) score.py --agent single

after:      ## the dual-LLM agent with taint-checked sinks: 3 of 32, and what they are
	$(PY) score.py --agent dual+taint

score:      ## all four designs in one table
	$(PY) score.py

story:      ## one attack (a planted address in the shared notes, UT3 + IT0), through three designs
	$(PY) score.py --trace UT3 IT0 --agent single
	@echo
	$(PY) score.py --trace UT3 IT0 --agent dual
	@echo
	$(PY) score.py --trace UT3 IT0 --agent dual+taint

audit:      ## run all four designs with the decision log on, then show it session by session
	$(PY) score.py --log > /dev/null
	$(PY) audit.py show

hunt:       ## three questions over the saved log (Q3 is the challenge)
	$(PY) audit.py hunt --file data/hunt-decisions.jsonl

workspace:  ## OPTIONAL: AgentDojo's own workspace suite (40 tasks), before and after context taint (about 2 minutes)
	$(PY) workspace.py

test:       ## the proof (20 tests, about 20 seconds)
	$(PY) run_tests.py

challenge:  ## the same plus the three-part challenge: 4 of 24 fail until you do it
	$(PY) run_tests.py --challenge

clean:      ## delete the decision log and caches
	rm -rf state __pycache__
