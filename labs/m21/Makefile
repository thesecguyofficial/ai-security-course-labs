# M21 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Needs Python 3.11+ and ONE package, cedarpy (the Cedar engine), in this folder's own virtual environment.
# Nothing leaves this folder: no network, no real payments, no real email. OPA is optional (make opa).
VENV := .venv
PY   := $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)
TF   ?= terraform

.PHONY: setup check attack hardened story approve-demo shadow audit hunt opa test challenge clean cloud-zip cloud-up cloud-down

setup:         ## create .venv and install the pinned cedarpy
	python3 -m venv $(VENV)
	$(VENV)/bin/python -m pip install -r requirements.txt

check:         ## print the Cedar engine's version from .venv (did make setup work?)
	$(PY) -c "import importlib.metadata as m; print('cedarpy', m.version('cedarpy'), 'OK')"

attack:        ## 12 attacks + 6 normal requests against the FIRST DRAFT: 11 of 12 work
	$(PY) suite.py first-draft

hardened:      ## the same suite against the hardened PEP: 0 of 12 work, 6 of 6 normal requests still work
	$(PY) suite.py hardened

story:         ## one injected ticket, first draft then hardened, step by step
	@rm -rf state
	$(PY) helpdesk.py first-draft T-605 --as bob
	@rm -rf state; echo; $(PY) helpdesk.py hardened T-605 --as bob

approve-demo:  ## a real $250 refund: held, approved by alice (not bob), then paid exactly once
	@rm -rf state
	$(PY) helpdesk.py hardened T-502 --as bob
	$(PY) approvals.py list
	-$(PY) approvals.py approve APR-0001 --as bob
	$(PY) approvals.py approve APR-0001 --as alice
	$(PY) helpdesk.py hardened T-502 --as bob --after-approval

shadow:        ## the hardened policies in LOG_ONLY: they decide and record, and enforce nothing
	$(PY) suite.py hardened --mode LOG_ONLY

audit:         ## read the signed receipts and verify the chain
	$(PY) receipts.py show
	$(PY) receipts.py verify

hunt:          ## an investigator's questions over a morning of receipts (Q4 is the challenge)
	$(PY) receipts.py hunt --file data/hunt-receipts.jsonl

opa:           ## OPTIONAL (needs the opa binary): Rego unit tests, then the suite with OPA as the decision point
	opa test rego/ -v
	$(PY) suite.py hardened --engine opa

test:          ## the proof (23 tests; the OPA one is skipped without opa)
	$(PY) run_tests.py

challenge:     ## the same plus the three-part challenge: 4 of 28 fail until you do it
	$(PY) run_tests.py --challenge

clean:         ## delete lab state, caches and Terraform working files
	rm -rf state __pycache__ cloud/terraform/.terraform cloud/terraform/.terraform.lock.hcl cloud/terraform/*.zip

# ---- OPTIONAL guided build (GUIDED-BUILD.md): Terraform 1.6+ (or OpenTofu: TF=tofu), the AWS CLI, YOUR sandbox account.
cloud-zip:
	python3 -c "import zipfile; z = zipfile.ZipFile('cloud/terraform/tools.zip', 'w'); z.write('cloud/lambda/refund_tools.py', 'refund_tools.py'); z.close()"

cloud-up: cloud-zip ## Cognito, tools Lambda, gateway + target, policy engine + 4 Cedar policies (ENFORCE). Asks you to type yes.
	cd cloud/terraform && $(TF) init -input=false && $(TF) apply

cloud-down: cloud-zip ## DELETE everything cloud-up created (do it today). Delete the temporal policy first (GUIDED-BUILD Part D).
	cd cloud/terraform && $(TF) destroy
