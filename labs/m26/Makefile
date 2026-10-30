# M26 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Needs Python 3.11+ and ONE package, PyYAML, in this folder's own virtual environment.
# Nothing leaves this folder: the scanner only reads files, the probe only talks to its own server on 127.0.0.1,
# and nothing here runs a container, a model or the custom model code in models/suspicious-model/.
VENV := .venv
PY   := $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)

.PHONY: setup check scan probe cache attack hardened hunt test challenge clean

setup:      ## create .venv and install the pinned PyYAML
	python3 -m venv $(VENV)
	$(VENV)/bin/python -m pip install -r requirements.txt

check:      ## is the lab ready? prints the PyYAML version the lab was tested with
	$(VENV)/bin/python -c "import yaml; print('PyYAML', yaml.__version__, 'OK')"

scan:       ## the configuration scan of the FIRST DRAFT stack (exit code 1: it has critical and high findings)
	-$(PY) scan.py stacks/first-draft

probe:      ## knock on every path of the practice server: first draft, then vLLM's --api-key on its own
	$(PY) probe.py first-draft
	@echo
	$(PY) probe.py key-only

cache:      ## the prefix-cache isolation test on the first draft (one shared cache)
	-$(PY) cachetest.py first-draft

attack:     ## all three against the first draft: scan, probe, cache isolation
	@$(MAKE) --no-print-directory scan
	@echo
	@$(MAKE) --no-print-directory probe
	@echo
	@$(MAKE) --no-print-directory cache

hardened:   ## the same three against the hardened stack: 0 findings, nothing open without a key, ISOLATED
	$(PY) scan.py stacks/hardened
	@echo
	$(PY) probe.py hardened
	@echo
	$(PY) cachetest.py hardened

hunt:       ## an investigator's questions over a morning of gateway logs (Q3 is the challenge)
	$(PY) hunt.py

test:       ## the proof (19 tests)
	$(PY) run_tests.py

challenge:  ## the same plus the three-part challenge: 3 of 22 fail until you do it
	$(PY) run_tests.py --challenge

clean:      ## delete caches and any stray marker file
	rm -rf __pycache__ PWNED-LAB-MARKER
