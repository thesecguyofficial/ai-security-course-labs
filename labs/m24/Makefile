# M24 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Everything here needs only Python 3.11+ (standard library): no packages, no network, nothing runs the attack.
PY := python3

.PHONY: setup trace replay report test challenge clean

setup:        ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11

trace:        ## read the recorded run: the entry point, the propagation path, the sink action
	$(PY) trace.py

replay:       ## replay the recording AND adapted variants through your containment.py and score it
	$(PY) replay.py

report:       ## the four-line containment proof (detected, denied, breaker tripped, normal completes)
	$(PY) replay.py --report

test:         ## the recording and the provided trace (passes before you write containment.py)
	$(PY) run_tests.py

challenge:    ## the above plus your containment and the three-part challenge (fails until you finish)
	$(PY) run_tests.py --challenge

clean:        ## remove caches
	rm -rf __pycache__
