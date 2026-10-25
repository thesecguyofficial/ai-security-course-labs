# M18 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Standard library only: Python 3.11+, no packages, no cloud account, no network. Everything stays in this folder.
PY := python3

.PHONY: inventory triage what-if draft crosswalk evidence pack-draft start mine mine-crosswalk mine-pack test challenge clean

inventory:      ## Step 1: the AI inventory rows for TSG Helpdesk (writes out/ai-inventory.csv)
	$(PY) govlab.py inventory

triage:         ## Step 2: EU AI Act role, tier and dates for the Helpdesk (a decision aid, not legal advice)
	$(PY) govlab.py triage

what-if:        ## Step 2: the same if the Helpdesk were re-used to screen job applicants
	$(PY) govlab.py triage --what-if hiring

draft:          ## Step 3: check the team's first draft (22 errors on purpose)
	-$(PY) govlab.py check first-draft

crosswalk:      ## Step 3: which framework items the first draft can prove, and which it can't
	$(PY) govlab.py crosswalk first-draft

evidence:       ## Step 3: the first draft's evidence index, row by row
	-$(PY) govlab.py evidence first-draft

pack-draft:     ## Step 3: a pack of the first draft, marked DRAFT (a real pack is refused while errors are open)
	-$(PY) govlab.py pack first-draft
	$(PY) govlab.py pack first-draft --draft

start:          ## Step 4: copy the templates into my-assessment/ (your working folder)
	$(PY) govlab.py start

mine:           ## Steps 4 to 7: check your assessment
	-$(PY) govlab.py evidence my-assessment --fill
	$(PY) govlab.py check my-assessment

mine-crosswalk: ## Step 7: the crosswalk for your assessment
	$(PY) govlab.py crosswalk my-assessment

mine-pack:      ## Step 8: build and verify your evidence pack
	$(PY) govlab.py pack my-assessment
	$(PY) govlab.py verify-pack out/evidence-pack-tsg-helpdesk-2026-10-24

test:           ## the proof: the toolkit works on the shipped first draft (15 tests)
	$(PY) run_tests.py

challenge:      ## the same, plus 5 tests on your own assessment in my-assessment/ (they fail until you finish it)
	$(PY) run_tests.py --challenge

clean:          ## delete out/ (keeps my-assessment/)
	rm -rf out __pycache__
