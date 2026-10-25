# M28 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Needs Python 3.11+ and ONE package, cryptography, in this folder's own virtual environment.
# Nothing leaves this folder: no network, no AWS, no real data. The "AWS" parts are local stand-ins.
VENV := .venv
PY   := $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)

.PHONY: setup leak hardened macie two-locks tokens hunt test challenge clean

setup:      ## create .venv and install the pinned cryptography package
	python3 -m venv $(VENV)
	$(VENV)/bin/python -m pip install -r requirements.txt

leak:       ## the FIRST DRAFT pipeline: 7 of 7 leaks, while every normal job works
	$(PY) pipeline.py first-draft

hardened:   ## the same calls through the hardened pipeline: 0 of 7 leaks, 3 of 3 normal jobs
	$(PY) pipeline.py hardened

macie:      ## the Macie stand-in's one-time job, first draft then hardened
	$(PY) macie.py first-draft
	@echo
	$(PY) macie.py hardened

two-locks:  ## loosen the raw bucket's policy by mistake: the raw key still refuses, and CloudTrail shows it
	$(PY) demo.py two-locks

tokens:     ## keyed tokens: the same customer is recognisable across records without the name
	$(PY) demo.py tokens

hunt:       ## an investigator's questions over a day of KMS events (Q3 is the challenge)
	$(PY) hunt.py

test:       ## the proof (20 tests)
	$(PY) run_tests.py

challenge:  ## the same plus the three-part challenge: 4 of 24 fail until you do it
	$(PY) run_tests.py --challenge

clean:      ## delete lab state and caches
	rm -rf state __pycache__
