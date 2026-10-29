# M2.5 lab shortcuts (Mac/Linux). Windows: run the commands from the README instead.
VENV := .venv
PY   := $(VENV)/bin/python

.PHONY: setup check explore pytm clean

setup:    ## create a virtual environment and install pytm (one package + its dependencies)
	python3 -m venv $(VENV)
	$(PY) -m pip install -r requirements.txt

check:    ## print the pytm version the lab was tested with (1.4.0)
	$(PY) -c "import importlib.metadata as m; print('pytm', m.version('pytm'))"

explore:  ## read the starter model one step at a time (plain Python, no setup needed)
	python3 explore.py elements
	python3 explore.py flows
	python3 explore.py boundaries

pytm:     ## the same starter as code: pytm lists threats from its library
	$(PY) tm.py

clean:    ## remove the virtual environment
	rm -rf $(VENV)
