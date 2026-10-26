# Repo-wide shortcuts (Mac/Linux). Windows: use setup.ps1 and `py tools\doctor.py`.
PY := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
SETUP_FILES := setup.sh setup.ps1 tools/doctor.py

.PHONY: style setup check doctor test-setup checksums

style:       ## house-voice check + copy-paste check of shell blocks, on the README, the labs and docs/
	python3 tools/style/style_check.py --warnings README.md labs docs
	python3 tools/style/codeblock_check.py .

setup:       ## one-time lab setup (asks before each install): same as ./setup.sh
	./setup.sh

check:       ## report what is missing, change nothing
	./setup.sh --check

doctor:      ## is this computer ready? one line per item, with the next step for anything missing
	$(PY) tools/doctor.py

test-setup:  ## tests for the setup scripts and the doctor (shellcheck runs if installed: pip install shellcheck-py)
	python3 -m unittest discover -s tools/tests -v

checksums:   ## rewrite SHA256SUMS after changing a setup file (CI checks it is current)
	sha256sum $(SETUP_FILES) > SHA256SUMS 2>/dev/null || shasum -a 256 $(SETUP_FILES) > SHA256SUMS
	cat SHA256SUMS
