# AZ16 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Everything here needs only Python 3.11+ (standard library): no Azure subscription, no packages, no network.
PY := python3
ENTITY ?= sp-contoso-ci

.PHONY: setup simulate old old-rules old-logs detect inventory posture posture-hardened pivot cost report-check test challenge clean

simulate:          ## write one day of telemetry for both logging setups into out/
	$(PY) simulate.py

old: simulate      ## the SOC's old rules on the old logs: 1 of 5 caught, 1 false alarm
	$(PY) evaluate.py first-draft --pack soc-v1

old-rules: simulate ## the old rules on the new logs: still 1 of 5 (the High-only Defender rule drops 6 of 8 AI alerts)
	$(PY) evaluate.py hardened --pack soc-v1

old-logs: simulate ## this module's rules on the old logs: 1 of 5 (you can't detect what you didn't log)
	$(PY) evaluate.py first-draft

detect: simulate   ## this module's rules on the new logs: the alerts, then the score (3 of 5 until the challenge)
	$(PY) detect.py hardened
	@echo
	$(PY) evaluate.py hardened

inventory:         ## the AI inventory (16.3): Resource Graph, Defender CSPM AI-SPM, your own exposure check
	$(PY) inventory.py

posture:           ## Azure Policy-style checks (16.4) on the first draft: 18 of 19 NON_COMPLIANT
	$(PY) posture.py first-draft

posture-hardened:  ## the same on the hardened setup: 0 NON_COMPLIANT
	$(PY) posture.py hardened

pivot: simulate    ## every record about one entity (make pivot ENTITY=203.0.113.50)
	$(PY) report.py pivot $(ENTITY)

cost: simulate     ## tokens the Foundry metric counted that the gateway's LLM log never saw
	$(PY) report.py cost

report-check: simulate ## challenge 3: is report/INCIDENT-REPORT.md complete for S1?
	$(PY) report.py check report/INCIDENT-REPORT.md --scenario S1

test:              ## the proof (18 tests)
	$(PY) run_tests.py

challenge:         ## the same plus the challenge: 6 of 24 fail until you do it
	$(PY) run_tests.py --challenge

clean:             ## remove generated telemetry and caches
	rm -rf out __pycache__

# Every lab answers `make setup` (the repo-wide setup.sh calls it). This one needs nothing installed.
setup:             ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11
