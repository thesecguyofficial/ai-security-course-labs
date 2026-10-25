# M27 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Needs only Python 3.11+ (standard library): no packages, no network. Nothing here opens a connection or moves data:
# the "connections" are recorded request descriptions, and the logs are illustrative records written under state/.
PY := python3

.PHONY: setup review hardened replay logs alerts test challenge clean

setup:     ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11

review:    ## audit the FIRST DRAFT sandbox config: 16 of 18 rules fail
	-$(PY) checker.py first-draft

hardened:  ## audit the hardened config: 0 findings
	$(PY) checker.py hardened

replay:    ## 14 recorded requests against both configs: 7 of 8 unexpected allowed before, 0 of 8 after, 6 of 6 normal
	$(PY) egress.py compare

logs:      ## the log records each config would leave (documented field names, illustrative values) in state/
	$(PY) logs.py first-draft
	$(PY) logs.py hardened

alerts:    ## the lesson's starting thresholds over those logs: pages and tickets
	$(PY) alerts.py first-draft
	$(PY) alerts.py hardened

test:      ## the proof (17 tests)
	$(PY) run_tests.py

challenge: ## the same plus the three-part challenge: 3 of 21 fail until you do it
	$(PY) run_tests.py --challenge

clean:     ## delete generated logs and caches
	rm -rf state __pycache__
