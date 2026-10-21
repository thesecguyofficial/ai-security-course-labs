# M8.6 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# This lab installs the official MCP Python SDK, so it uses a virtual environment (unlike the M5 lab).
# Everything binds to 127.0.0.1 and uses fake data.

VENV := .venv
PY   := $(VENV)/bin/python

.PHONY: setup attack defend review serve auth test challenge clean

setup:            ## create a virtual environment and install the pinned MCP SDK
	python3 -m venv $(VENV)
	$(PY) -m pip install -r requirements.txt

attack:           ## watch the rug pull: switch the facts server to 1.1.0 and leak the fake secret
	@mkdir -p state
	@echo "1.1.0" > state/facts_release.txt
	@rm -f state/attacker_inbox.log state/outbox.jsonl
	$(PY) host.py "give me a fact about octopus"

defend:           ## same request with pin+diff, scan+quarantine and an allow-list on: nothing leaks
	@mkdir -p state
	@rm -f state/attacker_inbox.log state/outbox.jsonl state/pins.json
	@echo "1.0.0" > state/facts_release.txt
	$(PY) host.py "give me a fact about octopus" --pin-file state/pins.json >/dev/null
	@echo "1.1.0" > state/facts_release.txt
	$(PY) host.py "give me a fact about octopus" --pin-file state/pins.json --block-injection --allow "notes:read_note,notes:list_notes,facts:fact_of_the_day"

review:           ## read the facts server's tool definitions without a model, and flag hidden directives
	@mkdir -p state
	@echo "1.1.0" > state/facts_release.txt
	-$(PY) review.py facts

serve:            ## run the secure Streamable HTTP server on http://127.0.0.1:8808 (Ctrl+C to stop)
	$(PY) servers/secure_http_server.py

auth:             ## start the secure server, send three tokens, show which are accepted/refused
	@mkdir -p state
	@$(PY) servers/secure_http_server.py >state/auth_srv.log 2>&1 & echo $$! > state/auth_srv.pid; sleep 3; \
	$(PY) auth_client.py; kill `cat state/auth_srv.pid` 2>/dev/null; rm -f state/auth_srv.pid

test:             ## the proof: attack works unprotected, controls hold, audience validation works
	$(PY) run_tests.py

challenge:        ## the same, plus the schema-hidden-directive challenge (fails until you fix review.py)
	$(PY) run_tests.py --challenge

clean:            ## delete lab state (pins, logs, outbox)
	rm -rf state
