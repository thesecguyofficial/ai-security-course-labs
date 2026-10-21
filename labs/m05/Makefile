# M5.6 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Standard library only: no virtual environment or installs needed. Python 3.11 or newer.
PY := python3

.PHONY: run run-safe attack attack-safe test challenge clean

run:          ## start the VULNERABLE app on http://127.0.0.1:8055 (Ctrl+C to stop)
	$(PY) helpdesk_app.py --mode vulnerable

run-safe:     ## start the SAFE app on http://127.0.0.1:8055
	$(PY) helpdesk_app.py --mode safe

attack:       ## send the three attacks to the vulnerable app (expect 3 of 3 exploited)
	$(PY) attack.py --mode vulnerable

attack-safe:  ## send the same attacks to the safe app (expect 0 of 3)
	$(PY) attack.py --mode safe

test:         ## the proof: exploits work in vulnerable mode AND fixes hold in safe mode
	$(PY) run_tests.py

challenge:    ## same, plus the path-traversal challenge (fails until you fix safe_export_path)
	$(PY) run_tests.py --challenge

clean:        ## delete files the app or the challenge created
	rm -rf exports escaped.txt __pycache__
