# AZ11 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Offline part: Python standard library only. No packages, no network, no Azure subscription.
PY := python3

.PHONY: check check-fixed attack attack-safe hunt test challenge cost up cloud-check policy probe logs evidence down clean

check:        ## the checker on Contoso's version 1 plan (15 findings)
	$(PY) checker.py

check-fixed:  ## the same checker on the hardened build (3 left: two are your challenge)
	$(PY) checker.py --with-fixes

attack:       ## replay 7 attacker + 4 legitimate requests against version 1 (expect 7 of 7 attacker requests allowed)
	$(PY) attack.py --mode vulnerable

attack-safe:  ## the same requests against the hardened build (expect 2 of 7: your challenge)
	$(PY) attack.py --mode safe

hunt:         ## who asked the model what? AI gateway logs from Contoso's pilot (3 suspicious exchanges)
	$(PY) hunt.py

test:         ## the proof: 18 tests, one per control
	$(PY) run_tests.py

challenge:    ## same, plus the challenge (3 of 22 fail until you close the gaps)
	$(PY) run_tests.py --challenge

# ---------------- optional: your own Azure subscription (README Step 8). Costs money while it exists.
cost:         ## what the cloud build bills, before you start
	./cloud/cloud.sh cost

up:           ## terraform plan -> checker on YOUR plan -> apply (asks first)
	./cloud/cloud.sh up

cloud-check:  ## re-run the checker on your saved plan
	$(PY) checker.py --plan cloud-plan.json

policy:       ## assign the guardrails, including your challenge-1 policy
	./cloud/cloud.sh policy

probe:        ## outside (expect refused) and inside the VNet (expect private IPs and HTTP 200)
	./cloud/cloud.sh probe-outside
	./cloud/cloud.sh probe-inside

logs:         ## what the Foundry resource logged (wait a few minutes after probe)
	./cloud/cloud.sh logs

evidence:     ## the settings an auditor asks for, read back from Azure
	./cloud/cloud.sh evidence

down:         ## delete everything (the Key Vault name stays reserved for 7 days)
	./cloud/cloud.sh down

clean:        ## remove Python caches
	rm -rf __pycache__

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
.PHONY: setup
setup:        ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11
