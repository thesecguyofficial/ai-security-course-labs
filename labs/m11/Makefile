# M11 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Steps 1-6 need only Python 3.11+ (standard library): no AWS account, no Terraform, no network.
PY := python3
TF ?= terraform

.PHONY: check check-hardened attack attack-safe test challenge package twin validate up smoke verify down clean

check:           ## review the FIRST DRAFT plan: 15 findings (7 HIGH)
	$(PY) checker.py twin/first-draft.plan.json || true

check-hardened:  ## the hardened plan: 0 findings
	$(PY) checker.py twin/hardened.plan.json

attack:          ## first draft: 7 of 7 attacks and mistakes allowed, and who would see them
	$(PY) attack.py --plan first-draft

attack-safe:     ## hardened: 0 of 7, the Helpdesk still works
	$(PY) attack.py --plan hardened

test:            ## the proof: every control checked (make test)
	$(PY) run_tests.py

challenge:       ## the same plus the challenge: 3 tests fail until you do it
	$(PY) run_tests.py --challenge

package:         ## zip the Lambda code (needed by Terraform)
	$(PY) package.py

# ---- OPTIONAL: needs Terraform (or OpenTofu: make twin TF=tofu). Still no AWS account needed.
twin: package    ## re-make the plan JSON from YOUR edited Terraform, offline (mock credentials, no AWS calls)
	@for d in hardened first-draft; do \
	  cp twin/offline_override.tf terraform/$$d/zz_offline_override.tf && \
	  ( cd terraform/$$d && $(TF) init -input=false -no-color >/dev/null && $(TF) plan -input=false -no-color -out=tfplan >/dev/null && \
	    $(TF) show -json tfplan > ../../twin/$$d.plan.json ); rc=$$?; \
	  rm -f terraform/$$d/zz_offline_override.tf terraform/$$d/tfplan; [ $$rc -eq 0 ] || exit $$rc; \
	  echo "wrote twin/$$d.plan.json"; done

validate:        ## terraform fmt + validate both folders (offline after the first init)
	@for d in hardened first-draft; do ( cd terraform/$$d && $(TF) fmt -check -recursive && $(TF) init -backend=false -input=false >/dev/null && $(TF) validate ) || exit 1; done

# ---- OPTIONAL, COSTS MONEY (about $0.02 an hour while it runs; README Step 7). Your own sandbox account only.
up: package      ## deploy the HARDENED Helpdesk (asks you to type yes)
	cd terraform/hardened && $(TF) init -input=false && $(TF) apply -var account_id=$$(aws sts get-caller-identity --query Account --output text)

smoke:           ## ask the deployed Helpdesk one question
	aws lambda invoke --function-name tsg-helpdesk --cli-binary-format raw-in-base64-out \
	  --payload '{"question":"How do I reset my VPN token?"}' /dev/stdout

verify:          ## show the logging configuration and the newest prompt log event
	aws bedrock get-model-invocation-logging-configuration
	aws logs filter-log-events --log-group-name /tsg-helpdesk/bedrock/model-invocations --limit 1 --query 'events[0].message' --output text

down: package    ## DELETE everything `make up` created (do it today)
	cd terraform/hardened && $(TF) destroy -var account_id=$$(aws sts get-caller-identity --query Account --output text)

clean:           ## remove caches and build output
	rm -rf __pycache__ terraform/*/build terraform/*/.terraform terraform/*/.terraform.lock.hcl terraform/*/tfplan

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
.PHONY: setup
setup:        ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11
