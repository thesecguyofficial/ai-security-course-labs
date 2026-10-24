# M14 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Steps 1-8 need only Python 3.11+ (standard library): no AWS account, no packages, no network, no model download.
PY := python3
TF ?= terraform

.PHONY: check check-hardened attack hardened hunt test challenge cloud-zip cloud-up cloud-down clean

check:          ## review the FIRST DRAFT deployment: 27 findings (14 HIGH)
	$(PY) checker.py first-draft || true

check-hardened: ## the hardened deployment: 2 MEDIUM left (challenges 1 and 2)
	$(PY) checker.py hardened

attack:         ## 12 attacks + 7 normal requests against the first draft: 12 of 12 work
	$(PY) evaluate.py first-draft

hardened:       ## the same suite against the hardened setup: 2 of 12 work (A11, A12) until the challenge
	$(PY) evaluate.py hardened

hunt:           ## investigate a morning of CloudTrail, gateway spans and app logs
	$(PY) hunt.py

test:           ## the proof (20 tests)
	$(PY) run_tests.py

challenge:      ## the same plus the challenge: 6 of 28 fail until you do it
	$(PY) run_tests.py --challenge

# ---- OPTIONAL, needs Terraform 1.6+ (or OpenTofu: TF=tofu), the AWS CLI and YOUR sandbox account. GUIDED-BUILD.md.
cloud-zip:
	$(PY) -c "import zipfile; z = zipfile.ZipFile('cloud/terraform/tools.zip', 'w'); z.write('cloud/lambda/helpdesk_tools.py', 'helpdesk_tools.py'); z.close()"

cloud-up: cloud-zip ## Cognito, tools Lambda, gateway + target, policy engine + Cedar policies (ENFORCE), memory. Asks you to type yes.
	cd cloud/terraform && $(TF) init -input=false && $(TF) apply

cloud-down: cloud-zip ## DELETE everything cloud-up created (do it today). The runtime is removed with the AgentCore CLI (GUIDED-BUILD Part D).
	cd cloud/terraform && $(TF) destroy

clean:          ## remove caches and Terraform working files
	rm -rf __pycache__ cloud/__pycache__ cloud/lambda/__pycache__ cloud/terraform/.terraform cloud/terraform/.terraform.lock.hcl cloud/terraform/*.zip

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
.PHONY: setup
setup:        ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11
