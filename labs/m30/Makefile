# M30 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead (py instead of python3).
# Needs Python 3.11+ and nothing else: standard library only, no model download, no API key, no network.
# The agent is a local stand-in (plain Python), the workspace is fake, and attack text is a labelled placeholder.
VENV := .venv
PY   := $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)
C    ?= r42-fix

.PHONY: setup card naive gate fix story control new-tool refuse hunt ci test challenge clean

setup:     ## create this folder's .venv (nothing to install) and check the Python version
	python3 -m venv $(VENV)
	$(VENV)/bin/python -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11 or newer needed'; print('Python', sys.version.split()[0], 'OK, nothing to install')"

card:      ## score cards for the release in production (r41) and the candidate (r42), 20 trials per case
	$(PY) evals.py --release r41
	@echo
	$(PY) evals.py --release r42

naive:     ## THE PROBLEM: the one-trial, one-number gate lets r42 through; on another day it says FAIL
	-$(PY) naive_gate.py r42
	-$(PY) naive_gate.py r42 --seed day-1

gate:      ## THE GATE: r41 -> r42 is STOPPED, and it says which family and why
	-$(PY) gate.py r41 r42

story:     ## one case, one trial, in both releases: the same document, a different result
	$(PY) agent.py --release r41 --case S-DOC-03 --trial 4
	@echo
	$(PY) agent.py --release r42 --case S-DOC-03 --trial 4

fix:       ## THE FIX: r42-fix (data marking back on documents) SHIPS
	$(PY) gate.py r41 r42-fix

control:   ## negative control: every defence off. The gate must STOP it (this target fails if it doesn't)
	$(PY) gate.py r41 weak --expect-fail

new-tool:  ## r43 adds fetch_url: STOPPED, but only because nobody wrote web cases (challenge 1)
	-$(PY) gate.py r41 r43

refuse:    ## r44 "fixes" injection by refusing the work: it SHIPS, because G6 is not written (challenge 3)
	-$(PY) gate.py r41 r44

hunt:      ## six weeks of a team's gate log: find how their gate was quietly weakened
	$(PY) history.py --file data/gate-history.jsonl

ci:        ## exactly what ci/m30-security-gate.yml runs: tests, negative control, then the gate on C (default r42-fix)
	$(PY) run_tests.py
	$(PY) gate.py r41 weak --expect-fail
	$(PY) gate.py r41 $(C) --out results/gate.json

test:      ## the proof (20 tests, under a second)
	$(PY) run_tests.py

challenge: ## the same plus the three-part challenge: 4 of 25 fail until you do it
	$(PY) run_tests.py --challenge

clean:     ## delete score cards, the gate log and caches
	rm -rf results state __pycache__
