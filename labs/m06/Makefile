# M6.7 lab shortcuts (Mac/Linux). Windows: run the commands from the README instead.
VENV := .venv
PY   := $(VENV)/bin/python

.PHONY: setup attack attack-safe ask ask-safe inspect test challenge clean

setup:        ## create a virtual environment and install qdrant-client (one package + its dependencies)
	python3 -m venv $(VENV)
	$(PY) -m pip install -r requirements.txt

attack:       ## run the three attacks against the VULNERABLE app (expect 3 of 3 to work)
	$(PY) attack.py --mode vulnerable

attack-safe:  ## run the same attacks against the SAFE app (expect 0 of 3)
	$(PY) attack.py --mode safe

ask:          ## ask your own question, vulnerable app:  make ask Q="How do I get a refund?"
	$(PY) rag_app.py --mode vulnerable "$(Q)"

ask-safe:     ## the same question, safe app
	$(PY) rag_app.py --mode safe "$(Q)"

inspect:      ## build the store on disk and look inside it like an attacker with a copy of the files
	$(PY) inspect_store.py

test:         ## the proof: attacks work on the vulnerable app AND the fixes hold on the safe app
	$(PY) run_tests.py

challenge:    ## same, plus "delete means delete" (fails until you implement delete_document)
	$(PY) run_tests.py --challenge

clean:        ## delete the on-disk store and caches (keeps .venv)
	rm -rf .store __pycache__
