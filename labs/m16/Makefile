# M16 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Everything here needs only Python 3.11+ (standard library): no AWS account, no packages, no network.
PY := python3
ENTITY ?= BedrockAPIKey-q4m8

.PHONY: setup simulate old old-rules old-logs detect inventory posture posture-hardened pivot report-check test challenge clean

simulate:          ## write one day of telemetry for both logging setups into out/
	$(PY) simulate.py

old: simulate      ## the SOC's old rules on the old logs: 1 of 5 caught, 1 false alarm
	$(PY) evaluate.py first-draft --pack soc-v1

old-rules: simulate ## the old rules on the new logs: still 1 of 5 (the GuardDuty rule drops every Low finding)
	$(PY) evaluate.py hardened --pack soc-v1

old-logs: simulate ## this module's rules on the old logs: 1 of 5 (you can't detect what you didn't log)
	$(PY) evaluate.py first-draft

detect: simulate   ## this module's rules on the new logs: the alerts, then the score (3 of 5 until the challenge)
	$(PY) detect.py hardened
	@echo
	$(PY) evaluate.py hardened

inventory:         ## the AI inventory (16.3): managed, self-hosted, external endpoints, what isn't approved
	$(PY) inventory.py

posture:           ## AWS Config-style checks (16.4) on the first draft: 15 of 16 NON_COMPLIANT
	$(PY) posture.py first-draft

posture-hardened:  ## the same on the hardened setup: 0 NON_COMPLIANT
	$(PY) posture.py hardened

pivot: simulate    ## every record about one entity (make pivot ENTITY=cust-8841)
	$(PY) report.py pivot $(ENTITY)

report-check: simulate ## challenge 3: is report/INCIDENT-REPORT.md complete for S1?
	$(PY) report.py check report/INCIDENT-REPORT.md --scenario S1

test:              ## the proof (18 tests)
	$(PY) run_tests.py

challenge:         ## the same plus the challenge: 6 of 24 fail until you do it
	$(PY) run_tests.py --challenge

clean:             ## remove generated telemetry and caches
	rm -rf out __pycache__

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
setup:             ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11
