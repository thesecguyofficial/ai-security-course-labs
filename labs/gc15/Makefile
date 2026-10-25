# GC15 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Steps 1-8 need only Python 3.11+ (standard library): no Google Cloud account, no packages, no network, no model download.
PY := python3
PROJECT ?= $(shell gcloud config get-value project 2>/dev/null)
REGION ?= us-central1
ENDPOINT_ID ?= $(shell cat cloud/out/endpoint-id 2>/dev/null)

.PHONY: setup check check-hardened attack hardened files scan hunt test challenge clean cost cloud-down cloud-check

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
setup:          ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11

check:          ## review the FIRST DRAFT deployment: 35 findings (15 HIGH)
	$(PY) checker.py first-draft || true

check-hardened: ## the hardened deployment: 2 MEDIUM left (challenges 1 and 2)
	$(PY) checker.py hardened

attack:         ## 15 attacks + 6 normal requests against the first draft: 15 of 15 work
	$(PY) evaluate.py first-draft

hardened:       ## the same suite against the hardened setup: 2 of 15 work (A14, A15) until the challenge
	$(PY) evaluate.py hardened

files:          ## write the lab's model files to artifacts/ so you can look at them
	$(PY) model_files.py build

scan: files     ## scan the first draft's model files, then the hardened ones
	-$(PY) model_files.py scan artifacts/v1-pickle
	$(PY) model_files.py scan artifacts/v3-safe

hunt:           ## investigate a morning of Cloud Audit Logs
	$(PY) hunt.py

test:           ## the proof (20 tests)
	$(PY) run_tests.py

challenge:      ## the same plus the challenge: 6 of 27 fail until you do it
	$(PY) run_tests.py --challenge

clean:          ## remove caches, built model files and the guided build's local notes
	rm -rf __pycache__ cloud/__pycache__ artifacts cloud/out

# ---- OPTIONAL: YOUR sandbox project, us-central1. Read GUIDED-BUILD.md first: a deployed model bills every hour it
# ---- is deployed, whether anyone calls it or not. The guide creates the auto-undeploy job BEFORE it deploys.
cost:           ## what the guided build costs per hour (list prices read 25 Oct 2026; check the pages)
	$(PY) cloud/cost.py

cloud-down:     ## DELETE the guided build: undeploy, endpoint, forwarding rule, model, job, bucket, image. Run it today.
	@test -n "$(PROJECT)" || (echo "set PROJECT=your-sandbox-project" && exit 1)
	-for dm in $$(gcloud ai endpoints describe $(ENDPOINT_ID) --region=$(REGION) --format='value(deployedModels[].id)' | tr ';' ' '); do \
	   gcloud ai endpoints undeploy-model $(ENDPOINT_ID) --region=$(REGION) --deployed-model-id=$$dm --quiet; done
	-gcloud compute forwarding-rules delete tsg-gc15-psc --region=$(REGION) --quiet
	-gcloud compute addresses delete tsg-gc15-psc-ip --region=$(REGION) --quiet
	-gcloud ai endpoints delete $(ENDPOINT_ID) --region=$(REGION) --quiet
	-for m in $$(gcloud ai models list --region=$(REGION) --filter='displayName=tsg-gc15-summariser' --format='value(name)'); do \
	   gcloud ai models delete $$m --region=$(REGION) --quiet; done
	-gcloud scheduler jobs delete tsg-gc15-undeploy --location=$(REGION) --quiet
	-gcloud storage rm --recursive gs://$(PROJECT)-tsg-gc15-models
	-gcloud artifacts repositories delete tsg-gc15 --location=$(REGION) --quiet
	@echo "Done. The KMS key versions: destroy them by hand (GUIDED-BUILD.md Step 9); key rings can't be deleted. Then: make cloud-check"

cloud-check:    ## after cloud-down: list anything with the guided build's names that still exists
	-gcloud ai endpoints list --region=$(REGION) --filter='displayName~tsg-gc15' --format='table(name,displayName)'
	-gcloud ai models list --region=$(REGION) --filter='displayName~tsg-gc15' --format='table(name,displayName)'
	-gcloud compute forwarding-rules list --filter='name~tsg-gc15' --format='table(name,region)'
	-gcloud scheduler jobs list --location=$(REGION) --filter='name~tsg-gc15' --format='table(name,state)'
