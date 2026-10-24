# M10 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Standard library only: no virtual environment, no packages, no network, no AWS account.
PY := python3

.PHONY: check check-fixed attack attack-safe blunt hunt hunt-naive test challenge validate clean

check:        ## find the over-broad AI permissions in AnyCompany's setup (13 findings)
	$(PY) policy_checker.py

check-fixed:  ## the same, with the SCPs in fixes/ added to the org root
	$(PY) policy_checker.py --with-fixes

attack:       ## what a thief can do TODAY (expect 10 of 11 attacker requests allowed)
	$(PY) attack.py --mode vulnerable

attack-safe:  ## the same requests with the three fix SCPs (expect 2 of 11: your challenge)
	$(PY) attack.py --mode safe

blunt:        ## try the blunt "Deny bedrock:* except these models" SCP instead: watch legit traffic break
	$(PY) attack.py --mode safe --allowlist examples/blunt-allowlist-scp.json

hunt:         ## hunt for LLMjacking in the sample CloudTrail file, all rules
	$(PY) hunt.py

hunt-naive:   ## the InvokeModel-only rule many teams start with: see what it misses
	$(PY) hunt.py --naive

test:         ## the proof: the attacks work today, the fixes hold, the hunt finds the timeline (17 tests)
	$(PY) run_tests.py

challenge:    ## same, plus the challenge (3 of 22 fail until you close the gaps)
	$(PY) run_tests.py --challenge

validate:     ## OPTIONAL, needs the AWS CLI + credentials, free: IAM Access Analyzer checks the fix SCPs
	@for f in fixes/scp-*.json; do echo "== $$f"; aws accessanalyzer validate-policy --policy-type SERVICE_CONTROL_POLICY --policy-document file://$$f --query 'findings[].[findingType,issueCode,findingDetails]' --output text; done

clean:        ## remove Python caches
	rm -rf __pycache__

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
.PHONY: setup
setup:        ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11
