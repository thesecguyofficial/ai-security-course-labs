# M3.9 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Standard library only: no virtual environment or installs needed for the core lab. Python 3.10 or newer.
# `make eval` also needs Node.js 22.22 or newer (it runs promptfoo through npx).
PY := python3
# Nothing leaves your laptop: no usage data or update checks from promptfoo, even if you run it by hand from here.
export PROMPTFOO_DISABLE_TELEMETRY := 1
export PROMPTFOO_DISABLE_UPDATE := 1

.PHONY: attack attack-safe matrix hidden test challenge eval eval-weak run run-safe alerts clean

attack:       ## the weak app, no fixes: the planted note and the invisible note both get their way
	@$(PY) support_bot.py reset >/dev/null
	$(PY) support_bot.py summarise data/emails/03_planted_note.txt
	$(PY) support_bot.py summarise data/emails/04_hidden_unicode.txt

attack-safe:  ## the same two emails with all four fixes on
	@$(PY) support_bot.py reset >/dev/null
	$(PY) support_bot.py summarise data/emails/03_planted_note.txt --fixes all
	$(PY) support_bot.py summarise data/emails/04_hidden_unicode.txt --fixes all

matrix:       ## each fix on its own, then all together, for the planted note
	@$(PY) support_bot.py reset >/dev/null
	$(PY) support_bot.py matrix data/emails/03_planted_note.txt

hidden:       ## reveal the invisible characters in email 04 (show_hidden.py exits 1 when it finds some: handy in CI)
	$(PY) show_hidden.py data/emails/04_hidden_unicode.txt || true

test:         ## the proof: the attack works with no fixes, each fix does its job, all fixes hold
	$(PY) run_tests.py

challenge:    ## same, plus the redirect challenge (fails until you fix is_allowed_url in defences.py)
	$(PY) run_tests.py --challenge

eval:         ## promptfoo suite against the LOCAL app with all fixes (expect 4 of 4 to pass)
	$(PY) run_eval.py --fixes all

eval-weak:    ## the same suite with no fixes (expect 2 failures: proof the suite can catch the attack)
	-$(PY) run_eval.py --fixes none

run:          ## start the WEAK app's API on http://127.0.0.1:8003 (Ctrl+C to stop)
	$(PY) support_bot.py serve --fixes none

run-safe:     ## start the app with all fixes on http://127.0.0.1:8003
	$(PY) support_bot.py serve --fixes all

alerts:       ## show the security alerts written to logs/events.jsonl
	$(PY) support_bot.py alerts

clean:        ## delete state, logs and promptfoo results
	$(PY) support_bot.py reset
	rm -rf .promptfoo __pycache__
