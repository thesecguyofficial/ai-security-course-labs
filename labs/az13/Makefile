# AZ13 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Offline part: Python standard library only. No packages, no network, no Azure subscription.
PY := python3

.PHONY: check check-fixed attack attack-v11 attack-safe compare hunt test challenge cost up index kb agent ask ask-nohdr ask-approval down clean

check:        ## review the ported Helpdesk before anyone attacks it (19 findings)
	$(PY) checker.py

check-fixed:  ## the same review on the hardened build (0 findings, 1 note)
	$(PY) checker.py --with-fixes

attack:       ## 9 attacks and 5 legitimate requests against Contoso version 1: 9 attacks work
	$(PY) attack.py --setup contoso

attack-v11:   ## the obvious fixes only (native ACL on, token forwarded): 6 attacks still work
	$(PY) attack.py --setup v1.1

attack-safe:  ## the hardened build: 2 attacks left (your challenges 1 and 2)
	$(PY) attack.py --setup fixes

compare:      ## version 1 vs v1.1 vs hardened, side by side
	$(PY) attack.py --compare

hunt:         ## the Helpdesk's own audit log: token-less retrieves, rubber-stamp approvals, an outside email
	$(PY) hunt.py

test:         ## the proof: 18 tests
	$(PY) run_tests.py

challenge:    ## same, plus the challenge (5 of 23 fail until you close the gaps)
	$(PY) run_tests.py --challenge

# ---------------- optional: your own Azure subscription (GUIDED-BUILD.md). Small costs; read `make cost` first.
cost:          ## what the guided build bills
	./cloud/cloud.sh cost

up:            ## G1: resource group, Free search service (keys off), Foundry resource + project, model, roles
	./cloud/cloud.sh up

index:         ## G2: two Entra groups, the permission-aware index, four documents, three direct queries
	./cloud/cloud.sh index

kb:            ## G3: knowledge source + knowledge base, retrieve with and without your token
	./cloud/cloud.sh kb

agent:         ## G4: the prompt agent (knowledge base MCP tool + send_email function tool)
	./cloud/cloud.sh agent

ask:           ## G5: the five example requests through the agent (PICK=1..5 for one)
	./cloud/cloud.sh ask

ask-nohdr:     ## G6: the same leak attempt with the user-token header removed from the tool
	./cloud/cloud.sh ask-nohdr

ask-approval:  ## G6b: require_approval flipped to always: read the mcp_approval_request
	./cloud/cloud.sh ask-approval

down:          ## G8: delete the agent, connection, knowledge base, index, groups and the resource group
	./cloud/cloud.sh down

clean:         ## remove Python caches and local state
	rm -rf __pycache__ cloud/__pycache__ cloud/.state
