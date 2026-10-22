# AZ14 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Offline part: Python standard library only. No packages, no network, no Azure subscription.
PY := python3

.PHONY: check check-fixed attack attack-v11 attack-safe compare hunt test challenge cost up kb toolbox toolbox-v2 agent grant ask grant-wide grant-narrow direct-call down clean

check:        ## review the hosted-agent deployment before anyone attacks it (24 findings)
	$(PY) checker.py

check-fixed:  ## the same review on the hardened build (0 findings, 2 notes)
	$(PY) checker.py --with-fixes

attack:       ## 11 attacks and 5 legitimate requests against Contoso version 1: 11 attacks work
	$(PY) attack.py --setup contoso

attack-v11:   ## what a demo review usually fixes: 9 attacks still work
	$(PY) attack.py --setup v1.1

attack-safe:  ## the hardened build: 2 attacks left (your challenges 1 and 2)
	$(PY) attack.py --setup fixes

compare:      ## version 1 vs v1.1 vs hardened, side by side, with attack success rates
	$(PY) attack.py --compare

hunt:         ## one day of traces: outside email, egress, identity mismatch, secrets in spans
	$(PY) hunt.py

test:         ## the proof: 18 tests
	$(PY) run_tests.py

challenge:    ## same, plus the challenge (4 of 22 fail until you close the gaps)
	$(PY) run_tests.py --challenge

# ---------------- optional: your own Azure subscription (GUIDED-BUILD.md). Small costs; read `make cost` first.
cost:          ## what the guided build bills
	./cloud/cloud.sh cost

up:            ## G1: resource group, Foundry resource + project + model, storage, registry, roles
	./cloud/cloud.sh up

kb:            ## G2: the knowledge store: containers kb and hr-exports, four blobs
	./cloud/cloud.sh kb

toolbox:       ## G3: toolbox helpdesk-tools v1 (Microsoft Learn MCP, require_approval always)
	./cloud/cloud.sh toolbox

agent:         ## G4: build the image in ACR and create the hosted agent version
	./cloud/cloud.sh agent

grant:         ## G4.3: agent identity gets Storage Blob Data Reader on container kb only
	./cloud/cloud.sh grant

ask:           ## G5: the five requests (PICK=1..5 for one)
	./cloud/cloud.sh ask

grant-wide:    ## G6: the one-setting change: the same role at storage-account scope
	./cloud/cloud.sh grant-wide

grant-narrow:  ## G6: undo it
	./cloud/cloud.sh grant-narrow

direct-call:   ## G6b: call the toolbox tool directly: require_approval doesn't block it
	./cloud/cloud.sh direct-call

down:          ## G8: delete the agent, toolbox, Foundry resource (purged) and the resource group
	./cloud/cloud.sh down

clean:         ## remove Python caches and local state
	rm -rf __pycache__ cloud/__pycache__ cloud/.state cloud/agent/policy.py
