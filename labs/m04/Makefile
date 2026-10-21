# M4.6 lab shortcuts (Mac/Linux). Windows: run the commands from the README instead.
VENV := .venv
PY   := $(VENV)/bin/python

.PHONY: setup leak safe check test challenge chat clean

setup:            ## create a virtual environment, install Presidio + the small spaCy English model
	python3 -m venv $(VENV)
	$(PY) -m pip install -r requirements.txt
	$(PY) -m spacy download en_core_web_sm

leak:             ## run the scripted chat with NO redaction, then check the logs (expect FAIL)
	$(PY) chat_app.py --script conversation.txt --fresh
	-$(PY) check_logs.py

safe:             ## run the scripted chat WITH redaction, then check the logs (expect PASS)
	$(PY) chat_app.py --script conversation.txt --fresh --redact
	$(PY) check_logs.py

check:            ## check whatever is in logs/ right now
	$(PY) check_logs.py

test:             ## the full self-check: OFF must leak, ON must be clean
	$(PY) run_tests.py

challenge:        ## same, plus the employee-ID canary (passes once you add your recognizer)
	$(PY) run_tests.py --challenge

chat:             ## chat by hand with redaction on
	$(PY) chat_app.py --redact

clean:            ## delete logs
	rm -rf logs
