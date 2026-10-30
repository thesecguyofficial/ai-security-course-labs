# M29 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Python 3.11+ and the standard library only. Nothing leaves this folder: no network, no cloud calls, fake data.
VENV := .venv
PY   := $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)

.PHONY: setup check explore first-draft hardened hunt story respond triage patterns test challenge clean

setup:         ## create .venv (no packages to install)
	python3 -m venv $(VENV)
	$(VENV)/bin/python -m pip install -r requirements.txt

check:         ## prints the Python version: the lab needs 3.11 or newer, and nothing else
	$(PY) -c 'import sys; v = sys.version.split()[0]; print("Python", v, "OK: standard library only, nothing else to install" if sys.version_info >= (3, 11) else "TOO OLD: this lab needs Python 3.11 or newer")'

explore:       ## the read-only helper's menu (README Step 1b)
	$(PY) explore.py

first-draft:   ## 15 cases against the FIRST DRAFT: it misses 14 of them
	$(PY) suite.py first-draft

hardened:      ## the same 15 cases against the hardened setup: 0 missed, 5 of 5 normal cases still work
	$(PY) suite.py hardened

hunt:          ## shadow AI discovery across the org: first draft, then hardened
	$(PY) hunt.py first-draft
	@echo; $(PY) hunt.py hardened

story:         ## the decoy key checked with two read-only calls: which rules fire, and why not
	$(PY) detect.py first-draft honeytoken-read-only
	@echo; $(PY) detect.py hardened honeytoken-read-only

respond:       ## the attacker's 30 minutes with a leaked key, against each responder
	$(PY) respond.py first-draft
	@echo; $(PY) respond.py hardened

triage:        ## a poisoned alert meets the AI triage agent: first draft, hardened, hardened with a fooled model
	$(PY) triage.py first-draft allowlist
	@echo; $(PY) triage.py hardened allowlist
	@echo; $(PY) triage.py hardened allowlist --fooled

patterns:      ## print the hardened rules as EventBridge patterns (used in GUIDED-BUILD.md)
	$(PY) detect.py hardened --patterns

test:          ## the proof (21 tests)
	$(PY) run_tests.py

challenge:     ## the same plus the three-part challenge: 4 of 26 fail until you do it
	$(PY) run_tests.py --challenge

clean:         ## delete caches and lab state
	rm -rf state __pycache__
