# GC13 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Offline part: Python standard library only, no packages, no network, no Google Cloud account.
PY := python3
REGION ?= europe-west4

.PHONY: check check-hardened attack attack-safe attack-search outage logs test challenge adk-offline cost plan up down clean

check:          ## controls the Helpdesk lost on the way to Google Cloud (16 findings)
	$(PY) checker.py --twin today

check-hardened: ## the same on the hardened port (2 left: your challenge)
	$(PY) checker.py --twin hardened

attack:         ## 5 attacks + 2 legitimate requests against today's port (5 of 5 attacks succeed)
	$(PY) attack.py --twin today

attack-safe:    ## the same against the hardened port, RAG Engine corpus per group (0 of 5)
	$(PY) attack.py --twin hardened

attack-search:  ## the hardened port with Agent Search document ACLs instead (0 of 5)
	$(PY) attack.py --twin hardened --backend agent_search

outage:         ## hardened, but Model Armor unreachable: watch what fails open
	$(PY) attack.py --twin hardened --outage

logs:           ## the tool-call log, today vs hardened: who did what, for whom?
	$(PY) attack.py --twin today --logs
	$(PY) attack.py --twin hardened --logs

test:           ## the proof (24 tests)
	$(PY) run_tests.py

challenge:      ## same, plus the challenge (5 of 30 fail until you finish it)
	$(PY) run_tests.py --challenge

adk-offline:    ## optional: the REAL ADK runtime with a stand-in model (needs: pip install -r adk_agent/requirements.txt)
	cd adk_agent && TSG_MODEL_ARMOR_TEMPLATE=projects/PROJECT_ID/locations/$(REGION)/templates/helpdesk-guard $(PY) run_requests.py

# ---- optional: your own Google Cloud project (GUIDED-BUILD.md). ----
cost:           ## print the cost estimate before you deploy anything
	@sed -n '/^## Cost/,/^## Teardown/p' GUIDED-BUILD.md | sed '$$d'

plan:           ## terraform init + plan (needs terraform and terraform/terraform.tfvars)
	cd terraform && terraform init -input=false && terraform plan -out=plan.out

up:             ## terraform apply of the saved plan (read `make cost` first)
	cd terraform && terraform apply plan.out

down:           ## TEARDOWN: destroy, then RAG Engine tier to unprovisioned (stops the Spanner bill) (PROJECT=your-project-id)
	cd terraform && terraform destroy
	terraform/scripts/rag_tier.sh $(PROJECT) $(REGION) unprovisioned

clean:          ## remove Python caches and local plan files
	rm -rf __pycache__ adk_agent/__pycache__ adk_agent/tsg_helpdesk/__pycache__ terraform/plan.out
