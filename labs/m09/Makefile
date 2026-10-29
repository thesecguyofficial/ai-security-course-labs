# M9.7 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# This lab installs a few packages (scanners + safetensors), so it uses a virtual environment.
# Everything stays inside this folder. `make setup` downloads packages with pip; after that no make target
# uses the network. (explore.py hub, in Step 1b, is the only lab command that does.)

VENV := .venv
PY   := $(VENV)/bin/python

.PHONY: setup check models attack scan safe pin tamper test challenge clean

setup:            ## create a virtual environment and install the pinned tools
	python3 -m venv $(VENV)
	$(PY) -m pip install -r requirements.txt

check:            ## confirm the tools installed: prints each tool's version
	@$(PY) -c "from importlib.metadata import version as v; print('picklescan', v('picklescan'), '| fickling', v('fickling'), '| safetensors', v('safetensors'), '| numpy', v('numpy'))"
	@$(VENV)/bin/picklescan --help > /dev/null && $(VENV)/bin/fickling --version > /dev/null && echo "OK: picklescan and fickling run from .venv/bin"

models:           ## build benign_model.pkl, evil_model.pkl and model.safetensors in ./models/
	$(PY) make_models.py

attack:           ## detonate: load evil_model.pkl the naive way and watch the marker appear
	@rm -f state/PWNED_BY_LAB_MODEL.txt
	$(PY) loader.py naive models/evil_model.pkl

scan:             ## scan both pickles: benign is clean, evil is flagged DANGEROUS
	-$(PY) scan.py models/benign_model.pkl
	@echo
	-$(PY) scan.py models/evil_model.pkl

safe:             ## load the safetensors model: tensors load, no code runs
	$(PY) loader.py safe models/model.safetensors

pin:              ## pin the safetensors model by its SHA-256, then verify it
	$(PY) pin.py write models/model.safetensors
	$(PY) pin.py verify models/model.safetensors

tamper:           ## pin the model, change one byte, and watch verification fail
	$(PY) pin.py write models/model.safetensors
	@cp models/model.safetensors models/model.safetensors.bak
	@printf '\0' >> models/model.safetensors
	-$(PY) pin.py verify models/model.safetensors
	@mv models/model.safetensors.bak models/model.safetensors

test:             ## the proof: attack works, scanners catch it, safetensors is safe, pin catches tampering
	$(PY) run_tests.py

challenge:        ## the same, plus the safe_load() challenge (fails until you implement it)
	$(PY) run_tests.py --challenge

clean:            ## delete built models, pins and lab state (keeps .venv)
	rm -rf models state pins.json __pycache__ *.pyc
