# GC14 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Offline part: Python 3.11+ standard library only. No packages, no network, no Google Cloud account.
PY := python3

.PHONY: check check-fixed decide decide-fixed decide-dry rugpull outage logs test challenge clean

check:        ## review today's deployment like an auditor: 14 findings, 9 HIGH
	$(PY) checker.py --twin today

check-fixed:  ## the same review on the hardened deployment: 1 left (GC14-08, your challenge)
	$(PY) checker.py --twin hardened

decide:       ## the decision table on today's deployment: 6 of 6 hijacked calls go through
	$(PY) decide.py --twin today

decide-fixed: ## the decision table on the hardened deployment: 0 of 6
	$(PY) decide.py --twin hardened

decide-dry:   ## hardened, but the gateway policy in DRY_RUN: 2 of 6 go through (logged, not blocked)
	$(PY) decide.py --twin hardened --dry-run

rugpull:      ## hardened, after the tickets team re-registers its server with a new tool: 1 of 6 (your challenge)
	$(PY) decide.py --twin hardened --rugpull

outage:       ## hardened, Model Armor unreachable, failOpen false: screened responses are blocked, 0 of 6
	$(PY) decide.py --twin hardened --outage

logs:         ## the gateway's decisions as JSON log lines, today vs hardened in DRY_RUN
	$(PY) decide.py --twin today --logs
	$(PY) decide.py --twin hardened --dry-run --logs

test:         ## the proof (25 tests)
	$(PY) run_tests.py

challenge:    ## same, plus the challenge (4 of 29 fail until you finish it)
	$(PY) run_tests.py --challenge

clean:        ## remove Python caches
	rm -rf __pycache__ cloud/agent/__pycache__ cloud/agent/helpdesk/__pycache__

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
.PHONY: setup
setup:        ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11
