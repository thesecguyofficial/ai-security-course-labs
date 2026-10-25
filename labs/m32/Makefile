# M32 advanced capstone shortcuts (Mac/Linux). Windows: run the python3 command shown after each target instead.
# Standard library only: no virtual environment or installs needed. Python 3.11 or newer.
# Everything runs on 127.0.0.1 with fake data. send_email writes to state/outbox.jsonl; nothing is sent.
PY := python3

.PHONY: setup run ask attack test challenge eval regress simulate detect detect-check cloud pin rugpull unrugpull check export lab-test clean

setup:        ## nothing to install: checks your Python is 3.11 or newer
	@$(PY) -c "import sys; v = sys.version_info; ok = v >= (3, 11); print(f'Python {v.major}.{v.minor}:', 'OK' if ok else 'too old, install 3.11 or newer (lesson 0.6)'); sys.exit(0 if ok else 1)"

run:          ## the web app on http://127.0.0.1:8732      (python3 -m crew.app)
	$(PY) -m crew.app

ask:          ## one question from the command line: make ask U=alice@acme.example Q="Refund order 5001"
	$(PY) -m crew.app --ask "$(U)" "$(Q)"

attack:       ## the six known findings, one attack each, and what happened   (python3 tour.py)
	$(PY) tour.py

test:         ## normal use (F01-F10) and the lab's own integration test: both pass on the starting point
	$(PY) -m unittest discover -s tests -t . -v -p "test_functional.py"
	$(PY) run_tests.py

challenge:    ## the six findings as tests (S01-S11): red until you fix crew/guards.py
	$(PY) -m unittest discover -s tests -t . -v -p "test_security.py"

eval:         ## the security eval gate: core cases + evals/my_cases.json   (python3 evals/run_evals.py)
	$(PY) evals/run_evals.py

regress:      ## prove the gate can fail: each regression must be caught
	$(PY) evals/run_evals.py --core-only --regression injection --expect-fail
	$(PY) evals/run_evals.py --core-only --regression handoff --expect-fail
	$(PY) evals/run_evals.py --core-only --regression output --expect-fail

simulate:     ## write the attack day (seed 1) to detections/logs/attack-day.jsonl
	$(PY) detections/attack_sim.py

detect:       ## your rules on the attack day; LOG=state/app-log.jsonl to run them on your own app's log
	$(PY) detections/detect.py $(if $(LOG),--log $(LOG))

detect-check: ## score your rules on seeds 1, 2 and 3 (all five incidents, max 2 false alerts a day)
	$(PY) detections/score.py

cloud:        ## review cloud/<stream>/deployment.json (stream from capstone.json; aws for now)
	$(PY) cloud/cloud_check.py

pin:          ## record the crm MCP server's tools as they are now (crew/mcp_pins.json)
	$(PY) -m crew.mcp_client --pin

rugpull:      ## switch the crm MCP server to release 2 for `make run` and `make ask`
	@mkdir -p state && echo 2 > state/mcp_release && echo "crm MCP server: release 2 (make unrugpull to undo)"

unrugpull:    ## back to release 1
	@rm -f state/mcp_release && echo "crm MCP server: release 1"

check:        ## the self-check: every objective check in RUBRIC.md   (python3 selfcheck.py)
	$(PY) selfcheck.py

export:       ## make your own repo: make export DEST=../my-advanced-capstone
	$(PY) export.py "$(DEST)"

lab-test:     ## (course maintainers) the lab's own integration test
	$(PY) run_tests.py

clean:        ## delete state/ and results/
	rm -rf state results __pycache__ */__pycache__
