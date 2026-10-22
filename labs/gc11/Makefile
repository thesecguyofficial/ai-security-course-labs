# GC11 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Offline part: Python standard library only, no packages, no network, no Google Cloud account.
PY := python3

.PHONY: check check-hardened attack attack-safe residency-trap dryrun-report test challenge cost plan up down clean

check:          ## find the gaps in the TSG Helpdesk as it runs today (16 findings)
	$(PY) checker.py --twin today

check-hardened: ## the same, on what terraform/ builds (2 left: your challenge)
	$(PY) checker.py --twin hardened

attack:         ## what attackers, users and an auditor get TODAY (5 of 5 attacks work)
	$(PY) attack.py --twin today

attack-safe:    ## the same against the hardened twin (1 of 5: the dry-run perimeter)
	$(PY) attack.py --twin hardened

residency-trap: ## a developer moves to the eu multi-region endpoint: watch the private path break
	$(PY) attack.py --twin eu-multiregion

dryrun-report:  ## a week of VPC Service Controls dry-run logs: who would you block?
	$(PY) dryrun_report.py

test:           ## the proof: attacks work today, the hardened twin holds, terraform/ matches it (21 tests)
	$(PY) run_tests.py

challenge:      ## same, plus the challenge (3 of 27 fail until you close the gaps)
	$(PY) run_tests.py --challenge

# ---- optional: your own Google Cloud project (README Step 8). Costs money while it exists. ----
cost:           ## print the cost estimate before you deploy anything
	@sed -n '/^### Cost/,/^### Deploy/p' README.md | sed '$$d'

plan:           ## terraform init + plan (needs terraform and terraform/terraform.tfvars)
	cd terraform && terraform init -input=false && terraform plan -out=plan.out && terraform show -json plan.out > plan.json
	$(PY) checker.py --plan terraform/plan.json --app twin/hardened/app.json

up:             ## terraform apply of the saved plan (asks nothing more: read `make cost` first)
	cd terraform && terraform apply plan.out

down:           ## destroy everything this lab created (KMS key versions are scheduled for destruction)
	cd terraform && terraform destroy

clean:          ## remove Python caches and local plan files
	rm -rf __pycache__ terraform/plan.out terraform/plan.json
