# GC12 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Offline part: Python standard library only, no packages, no network, no Google Cloud account.
PY := python3

.PHONY: check check-hardened attack attack-safe outage-inline suite sweep outage test challenge cost plan up down clean

check:          ## gaps in how the Helpdesk uses Model Armor today (16 findings)
	$(PY) checker.py --twin today

check-hardened: ## the same on the hardened twin (3 left: your challenge)
	$(PY) checker.py --twin hardened

attack:         ## Gemini on Agent Platform with Model Armor inline, as configured today (4 of 4 attacks leak)
	$(PY) attack.py --twin today

attack-safe:    ## the same with the hardened floor setting (0 of 4 reach the model)
	$(PY) attack.py --twin hardened

outage-inline:  ## hardened, but Model Armor unreachable: the integration fails open
	$(PY) attack.py --twin hardened --outage

suite:          ## the automated suite: 14 attacks + 14 legitimate requests, no guard vs today vs hardened
	$(PY) run_suite.py

sweep:          ## hardened guard at HIGH, MEDIUM_AND_ABOVE, LOW_AND_ABOVE: catch rate vs false positives
	$(PY) run_suite.py --sweep

outage:         ## the self-hosted path (app_guard.py) while Model Armor is down
	$(PY) run_suite.py --outage

test:           ## the proof (23 tests)
	$(PY) run_tests.py

challenge:      ## same, plus the challenge (5 of 29 fail until you finish it)
	$(PY) run_tests.py --challenge

# ---- optional: your own Google Cloud project (README Step 8). ----
cost:           ## print the cost estimate before you deploy anything
	@sed -n '/^### Cost/,/^### Deploy/p' README.md | sed '$$d'

plan:           ## terraform init + plan (needs terraform and terraform/terraform.tfvars)
	cd terraform && terraform init -input=false && terraform plan -out=plan.out

up:             ## terraform apply of the saved plan (read `make cost` first)
	cd terraform && terraform apply plan.out

down:           ## destroy the templates and IAM, then switch the floor setting off (PROJECT=your-project-id)
	cd terraform && terraform destroy
	terraform/scripts/reset_floor.sh $(PROJECT)

clean:          ## remove Python caches and local plan files
	rm -rf __pycache__ engines/__pycache__ terraform/plan.out

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
.PHONY: setup
setup:        ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11
