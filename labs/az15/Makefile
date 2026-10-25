# AZ15 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Steps 1-8 need only Python 3.11+ (standard library): no Azure subscription, no packages, no network, no model download.
PY := python3
RG ?= rg-tsg-az15-lab
LOCATION ?= eastus
WS ?= tsg-az15-lab
EP ?= tsg-az15-summariser

.PHONY: setup check check-hardened attack hardened files scan hunt test challenge clean \
        cloud-check-tools cloud-up cloud-deploy cloud-ask cloud-down cloud-check

setup:          ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11

check:          ## review the FIRST DRAFT: 31 findings (15 HIGH)
	$(PY) checker.py first-draft || true

check-hardened: ## the hardened setup: 2 MEDIUM left (challenges 1 and 2)
	$(PY) checker.py hardened

attack:         ## 15 attacks + 6 normal requests against the first draft: 15 of 15 work
	$(PY) evaluate.py first-draft

hardened:       ## the same suite against the hardened setup: 2 of 15 work (A14, A15) until the challenge
	$(PY) evaluate.py hardened

files:          ## write the lab's model files to artifacts/ so you can look at them
	$(PY) model_files.py build

scan: files     ## scan the first draft's model files, then the hardened ones
	-$(PY) model_files.py scan artifacts/v1-pickle
	$(PY) model_files.py scan artifacts/v2-safe

hunt:           ## investigate a morning of Activity Log and endpoint traffic log rows
	$(PY) hunt.py

test:           ## the proof (21 tests)
	$(PY) run_tests.py

challenge:      ## the same plus the challenge: 7 of 29 fail until you do it
	$(PY) run_tests.py --challenge

clean:          ## remove caches and built model files
	rm -rf __pycache__ artifacts cloud/out

# ---- OPTIONAL: YOUR sandbox subscription, Azure CLI with the ml extension. Read GUIDED-BUILD.md first: an online
# ---- endpoint bills for its VM every hour it exists. cloud-deploy creates the auto-teardown timer BEFORE the endpoint.
cloud-check-tools: ## is the Azure CLI there, with the ml extension, signed in to the right subscription?
	az version --query '"azure-cli"' -o tsv
	az extension show --name ml --query version -o tsv
	az account show --query "{subscription:name, id:id}" -o table

cloud-up:       ## resource group + workspace in approved-outbound mode (no FQDN rules) + provision the managed network
	bash cloud/cloud.sh up "$(RG)" "$(LOCATION)" "$(WS)"

cloud-deploy:   ## timer first (deletes the endpoint after 60 min), then the endpoint and its deployment (needs MODEL_ID)
	bash cloud/cloud.sh deploy "$(RG)" "$(LOCATION)" "$(WS)" "$(EP)"

cloud-ask:      ## the five requests of GUIDED-BUILD Part C
	bash cloud/cloud.sh ask "$(RG)" "$(LOCATION)" "$(WS)" "$(EP)"

cloud-down:     ## DELETE everything: endpoint, timer, workspace, resource groups. Run it today.
	bash cloud/cloud.sh down "$(RG)" "$(LOCATION)" "$(WS)" "$(EP)"

cloud-check:    ## after cloud-down: list anything with the lab's names that still exists
	-az group list --query "[?starts_with(name, 'rg-tsg-az15')].{name:name, state:properties.provisioningState}" -o table
	-az ml workspace list --query "[?starts_with(name, 'tsg-az15')].name" -o tsv
