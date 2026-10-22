# M7.9 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Standard library only: no virtual environment or installs needed. Python 3.11 or newer.
# Nothing leaves this folder: run_task never executes anything, send_email writes to state/outbox.jsonl.
PY := python3

.PHONY: attack defend ladder detect kill unkill test challenge clean

attack:     ## UNSAFE agent, no controls: the attachment's placeholder makes it email the customer list outside
	$(PY) agent.py --ticket T-1042
	@echo; echo "outbox (state/outbox.jsonl), newest last:"; tail -n 2 state/outbox.jsonl | cut -c1-110

defend:     ## every control on, with a reviewer who approves everything; then the same with spotlighting off
	$(PY) agent.py --ticket T-1042 --safe --approver approve-all
	@echo; echo "=== again, assuming the model ignores the UNTRUSTED labels ==="
	$(PY) agent.py --ticket T-1042 --safe --no-spotlight --approver approve-all

ladder:     ## the same hijack against one control at a time, then all of them
	$(PY) ladder.py

detect:     ## read the audit log, verify its hash chain, flag suspicious sequences
	-$(PY) detect.py

kill:       ## engage the kill switch (safe-mode agents stop before their next action)
	@mkdir -p state && echo "engaged by make kill" > state/KILL && echo "kill switch ENGAGED (state/KILL)"

unkill:     ## release the kill switch
	@rm -f state/KILL && echo "kill switch released"

test:       ## the proof: the hijack works unprotected, each control holds, detection sees it
	$(PY) run_tests.py

challenge:  ## same, plus the data-scope challenge (fails until you implement check_data_scope)
	$(PY) run_tests.py --challenge

clean:      ## delete lab state (outbox, markers, audit log, kill switch)
	rm -rf state __pycache__
