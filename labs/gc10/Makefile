# GC10 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Standard library only: no virtual environment, no packages, no network, no Google Cloud account.
PY := python3

.PHONY: check check-fixed attack attack-safe twin-preview hunt hunt-naive scan test challenge clean

check:        ## find the AI-specific IAM, org policy, API key, budget and logging mistakes (18 findings)
	$(PY) policy_checker.py

check-fixed:  ## the same, with the files in fixes/ applied
	$(PY) policy_checker.py --with-fixes

attack:       ## what the attackers can do TODAY (expect 8 of 9 attacker requests allowed)
	$(PY) attack.py --mode vulnerable

attack-safe:  ## the same requests with fixes/ applied (expect 2 of 9: your challenge)
	$(PY) attack.py --mode safe

twin-preview: ## no Organization? preview what gcp-twin/allowed-models-dryrun.json would deny (local dry run)
	$(PY) attack.py --preview-org-policy gcp-twin/allowed-models-dryrun.json

hunt:         ## hunt for LLMjacking in the sample Cloud Audit Logs, all rules
	$(PY) hunt.py

hunt-naive:   ## the "GenerateContent on an unapproved model" rule many teams start with: see what it misses
	$(PY) hunt.py --naive

scan:         ## look for Google API key strings in the fictional repo
	$(PY) policy_checker.py --scan examplecorp/repo

test:         ## the proof: the attacks work today, the fixes hold, the hunt finds both intrusions (19 tests)
	$(PY) run_tests.py

challenge:    ## same, plus the challenge (3 of 25 fail until you close the gaps)
	$(PY) run_tests.py --challenge

clean:        ## remove Python caches
	rm -rf __pycache__

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
.PHONY: setup
setup:        ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11
