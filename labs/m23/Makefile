# M23 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Everything here needs only Python 3.11+ (standard library): no packages, no network, nothing runs the attack.
PY := python3

.PHONY: setup investigate replay audit test challenge clean

setup:        ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11

investigate:  ## read the recorded trail: where the input entered, what it reached for, tempo, egress beacon
	$(PY) investigate.py

replay:       ## replay the recorded trace AND adapted variants against your defense.py and score it
	$(PY) replay.py

audit:        ## print every defence decision with its reason (after you have written defense.py)
	$(PY) replay.py --audit

test:         ## the recorded trail and the provided investigation (passes before you write defense.py)
	$(PY) run_tests.py

challenge:    ## the above plus your defence and the three-part challenge (fails until you finish)
	$(PY) run_tests.py --challenge

clean:        ## remove caches
	rm -rf __pycache__
