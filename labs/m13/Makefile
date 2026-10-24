# M13 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Steps 1-8 need only Python 3.11+ (standard library): no AWS account, no packages, no network, no model download.
PY := python3
TF ?= terraform

.PHONY: check check-ported check-harness attack ported harness parity parity-ported parity-harness ingest test challenge \
        cloud-up cloud-sync cloud-down clean

check:          ## review the FIRST DRAFT port: 17 findings (9 HIGH)
	$(PY) checker.py first-draft || true

check-ported:   ## the port on Bedrock Agents Classic, fixed: 1 LOW (challenge 1)
	$(PY) checker.py ported

check-harness:  ## the port on an AgentCore harness: 1 LOW (until you write M13-20)
	$(PY) checker.py harness

attack:         ## 8 attacks + 5 normal requests against the first draft: 7 of 7 work
	$(PY) evaluate.py first-draft

ported:         ## the same suite against the Classic port
	$(PY) evaluate.py ported

harness:        ## the same suite against the harness port
	$(PY) evaluate.py harness

parity:         ## which of the 10 local controls from M6 and M7 survived? first draft
	$(PY) parity.py first-draft || true

parity-ported:
	$(PY) parity.py ported

parity-harness:
	$(PY) parity.py harness

ingest:         ## what the managed knowledge base indexes, and for whom
	$(PY) twin.py ingest ported

test:           ## the proof (19 tests)
	$(PY) run_tests.py

challenge:      ## the same plus the challenge: 5 of 26 fail until you do it
	$(PY) run_tests.py --challenge

# ---- OPTIONAL, needs Terraform 1.6+ (or OpenTofu: TF=tofu), the AWS CLI and YOUR sandbox account. README Step 9.
cloud-up:       ## knowledge base, bucket, ACL file, KMS key (add HARNESS=1 for the AgentCore harness). Asks you to type yes.
	cd cloud/terraform && $(TF) init -input=false && $(TF) apply $(if $(HARNESS),-var create_harness=true,)

cloud-sync:     ## start the ingestion job (run again after any change to documents or the ACL file)
	aws bedrock-agent start-ingestion-job --knowledge-base-id $$(cd cloud/terraform && $(TF) output -raw knowledge_base_id) \
	  --data-source-id $$(cd cloud/terraform && $(TF) output -raw data_source_id)

cloud-down:     ## DELETE everything cloud-up created (do it today)
	cd cloud/terraform && $(TF) destroy $(if $(HARNESS),-var create_harness=true,)

clean:          ## remove caches and Terraform working files
	rm -rf __pycache__ cloud/__pycache__ cloud/terraform/.terraform cloud/terraform/.terraform.lock.hcl

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
.PHONY: setup
setup:        ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11
