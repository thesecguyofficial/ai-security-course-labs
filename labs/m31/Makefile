# M31 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Needs Python 3.11+ only (standard library). Nothing leaves this folder: no network, no blockchain, no testnet,
# no wallet software, no real money. Balances live in state/ledger.json.
VENV := .venv
PY   := $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)

.PHONY: setup flow attack hardened story approve-demo log hunt test challenge clean

setup:         ## create .venv (no packages needed) and issue the lab mandate
	python3 -m venv $(VENV)
	$(VENV)/bin/python -m pip install -q -r requirements.txt
	@rm -rf state
	$(VENV)/bin/python mandate.py issue

flow:          ## one paid weather call through the hardened guard, with the x402 headers decoded
	@rm -rf state
	$(PY) agent.py hardened T-WEATHER --wire

attack:        ## 10 attacks + 5 normal requests against the FIRST DRAFT: 9 of 10 work
	$(PY) suite.py first-draft

hardened:      ## the same suite against the hardened guard: 0 of 10 work, 5 of 5 normal requests still work
	$(PY) suite.py hardened

story:         ## one injected "buy" in a product page, first draft then hardened
	@rm -rf state
	$(PY) agent.py first-draft T-READ-SHOES
	@rm -rf state; echo; $(PY) agent.py hardened T-READ-SHOES

approve-demo:  ## a 3.00 report: held, approved by the user on the trusted surface, then paid exactly once
	@rm -rf state
	$(PY) agent.py hardened T-QUARTERLY
	$(PY) mandate.py approvals
	$(PY) mandate.py approve APR-0001
	$(PY) agent.py hardened T-QUARTERLY

log:           ## the hunt questions over YOUR last run's decisions (state/decisions.jsonl)
	$(PY) hunt.py --file state/decisions.jsonl

hunt:          ## the hunt questions over a recorded morning (Q4 is the challenge)
	$(PY) hunt.py

test:          ## the proof (22 tests)
	$(PY) run_tests.py

challenge:     ## the same plus the three-part challenge: 4 of 26 fail until you do it
	$(PY) run_tests.py --challenge

clean:         ## delete lab state and caches
	rm -rf state __pycache__
