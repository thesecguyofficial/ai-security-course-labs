# AZ12 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Offline part: Python standard library only. No packages, no network, no Azure subscription.
PY := python3

.PHONY: check check-fixed attack attack-safe compare selfhosted hunt test challenge llmguard cost cs-up cs-try cs-suite blocklist-up guardrail-up guardrail-probe evidence down clean

check:        ## review Contoso's guardrail setup before anyone attacks it (15 findings)
	$(PY) checker.py

check-fixed:  ## the same review on the hardened build (3 left: your challenge)
	$(PY) checker.py --with-fixes

attack:       ## the suite (15 attacks, 13 legitimate) against Contoso version 1: 10 attacks work, 3 false positives
	$(PY) run_suite.py --setup contoso

attack-safe:  ## the same suite against the hardened build: 2 attacks left (your challenge), 1 known false positive
	$(PY) run_suite.py --setup hardened

compare:      ## no guardrail vs Microsoft.DefaultV2 vs version 1 vs hardened, side by side
	$(PY) run_suite.py --compare

selfhosted:   ## Content Safety API in front of a model Foundry does not host: two wrappers
	$(PY) selfhosted.py

hunt:         ## what the guardrail logs tell you: a prober, a bypass, filters that came too late
	$(PY) hunt.py

test:         ## the proof: 18 tests
	$(PY) run_tests.py

challenge:    ## same, plus the challenge (4 of 22 fail until you close the gaps)
	$(PY) run_tests.py --challenge

llmguard:     ## OPTIONAL: the suite with LLM Guard's ML classifier (pip install llm-guard first; downloads a model)
	$(PY) run_suite.py --compare --detector llmguard

# ---------------- optional: your own Azure subscription (README Step 9). Small costs; read `make cost` first.
cost:            ## what the cloud path bills
	./cloud/cloud.sh cost

cs-up:           ## a free-tier (F0) Content Safety resource, keys disabled
	./cloud/cloud.sh cs-up

cs-try:          ## four single Content Safety calls, raw JSON printed
	./cloud/cloud.sh cs-try

cs-suite:        ## the same 28 requests against the REAL Prompt Shields and text analysis
	./cloud/cloud.sh cs-suite

blocklist-up:    ## a custom blocklist (one term) on your AZ11 resource
	./cloud/cloud.sh blocklist-up

guardrail-up:    ## contoso-helpdesk-v2 as a real guardrail on your AZ11 deployment (needs AZ11_NAME)
	./cloud/cloud.sh guardrail-up

guardrail-probe: ## 5 suite cases (PICK=... to choose) from inside the AZ11 VNet, through the real guardrail
	./cloud/cloud.sh guardrail-probe

evidence:        ## the settings an auditor asks for, read back from Azure
	./cloud/cloud.sh evidence

down:            ## back to Microsoft.DefaultV2; delete the guardrail, blocklist and Content Safety resource
	./cloud/cloud.sh down

clean:           ## remove Python caches
	rm -rf __pycache__ cloud/__pycache__
