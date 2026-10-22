# M12 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Steps 1-7 need only Python 3.11+ (standard library): no AWS account, no packages, no network, no model download.
PY := python3
TF ?= terraform

.PHONY: check check-tuned attack guarded tuned sweep cost enforce enforce-fixed test challenge \
        cloud-up cloud-eval cloud-simulate cloud-down clean

check:          ## review the FIRST DRAFT rollout: 18 findings (7 HIGH)
	$(PY) checker.py first-draft || true

check-tuned:    ## the reviewed rollout: 0 findings (until you write M12-17)
	$(PY) checker.py tuned

attack:         ## no guardrail: 15 of 15 attacks work against the worst-case stand-in model
	$(PY) evaluate.py --guardrail none

guarded:        ## the Friday pull request: the guardrail is on and still 15 of 15 work
	$(PY) evaluate.py --guardrail first-draft

tuned:          ## the reviewed guardrail and request: catch rate AND false positives
	$(PY) evaluate.py --guardrail tuned

sweep:          ## filter strength vs catch rate vs false positives
	$(PY) evaluate.py --sweep

cost:           ## monthly list-price estimate, and what guardContent saves
	$(PY) evaluate.py --cost

enforce:        ## who can call a model without the guardrail? first-draft role and org policy
	$(PY) enforce.py --role first-draft --org first-draft

enforce-fixed:  ## the same six requests with the enforced role and the fixed org policy
	$(PY) enforce.py --role enforced --org fixed

test:           ## the proof (17 tests)
	$(PY) run_tests.py

challenge:      ## the same plus the challenge: 4 of 23 fail until you do it
	$(PY) run_tests.py --challenge

# ---- OPTIONAL, needs Terraform 1.6+ (or OpenTofu: TF=tofu), the AWS CLI, boto3 and YOUR sandbox account. README Step 8.
cloud-up:       ## create the reviewed guardrail + version 1 (asks you to type yes). No model calls.
	cd cloud/terraform && $(TF) init -input=false && $(TF) apply -var account_id=$$(aws sts get-caller-identity --query Account --output text)

cloud-eval:     ## run the suite against the REAL guardrail with ApplyGuardrail (a few US cents)
	$(PY) cloud/cloud_eval.py --guardrail-id $$(cd cloud/terraform && $(TF) output -raw guardrail_id) --version $$(cd cloud/terraform && $(TF) output -raw guardrail_version)

cloud-simulate: ## free: the real IAM policy simulator on the enforced Helpdesk role policy
	$(PY) cloud/cloud_simulate.py

cloud-down:     ## DELETE everything cloud-up created (do it today)
	cd cloud/terraform && $(TF) destroy -var account_id=$$(aws sts get-caller-identity --query Account --output text)

clean:          ## remove caches and Terraform working files
	rm -rf __pycache__ cloud/__pycache__ cloud/terraform/.terraform cloud/terraform/.terraform.lock.hcl
