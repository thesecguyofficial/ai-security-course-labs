# AZ10 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Standard library only: no virtual environment, no packages, no network, no Azure subscription.
PY := python3

.PHONY: check check-fixed scan attack attack-safe hunt hunt-naive test challenge clean

check:        ## find the risky Azure AI settings in Contoso's estate (25 findings)
	$(PY) checker.py

check-fixed:  ## the same estate with everything in fixes/ applied (4 left: your challenge)
	$(PY) checker.py --with-fixes

scan:         ## what a thief finds in the repository that went public (3 secrets)
	-$(PY) secret_scan.py contoso/repo-snapshot

attack:       ## what a thief can do TODAY (expect 10 of 12 attacker requests allowed)
	$(PY) attack.py --mode vulnerable

attack-safe:  ## the same requests against fixes/ (expect 3 of 12: your challenge)
	$(PY) attack.py --mode safe

hunt:         ## hunt both intrusions in the sample Activity Log, request logs and token metrics
	$(PY) hunt.py

hunt-naive:   ## the daily usage check many teams rely on: see what it misses
	$(PY) hunt.py --naive

test:         ## the proof: attacks work today, fixes hold, legit work survives, the hunt finds the timeline (17 tests)
	$(PY) run_tests.py

challenge:    ## same, plus the challenge (3 of 21 fail until you close the gaps)
	$(PY) run_tests.py --challenge

clean:        ## remove Python caches
	rm -rf __pycache__

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
.PHONY: setup
setup:        ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11
