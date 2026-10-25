# M20 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Everything in parts A and C needs only Python 3.11+ (standard library): no account, no packages, no internet.
PY := python3

.PHONY: setup watch attack hardened hunt test challenge realms keycloak-attack keycloak-hardened aws-check aws-check-hardened aws-hunt clean

setup:              ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11

watch:              ## one request through the hardened chain, every hop and token printed
	$(PY) watch.py hardened alice "Summarise T-4711 and email me the summary"

attack:             ## 8 attacks + 3 normal requests against the FIRST DRAFT: 8 of 8 work
	$(PY) evaluate.py first-draft

hardened:           ## the same suite against the hardened setup: 1 of 8 works (A8) until the challenge
	$(PY) evaluate.py hardened

hunt:               ## investigate a morning of API audit logs
	$(PY) hunt.py

test:               ## the proof (local authorization server)
	$(PY) run_tests.py

challenge:          ## the same plus the two-part challenge: 3 tests fail until you do it
	$(PY) run_tests.py --challenge

# ---- PART B, optional: the same chain on Keycloak (README, part B) ----
realms:             ## rewrite keycloak/import/*.json from setups/*/authz.json
	$(PY) keycloak/make_realms.py

keycloak-attack:    ## the suite against the first-draft realm (Keycloak must be running on 127.0.0.1:8180)
	$(PY) evaluate.py first-draft --idp keycloak

keycloak-hardened:  ## the suite against the hardened realm
	$(PY) evaluate.py hardened --idp keycloak

# ---- PART C: AgentCore Identity offline (lesson 20.5); the guided build is aws/GUIDED-BUILD.md ----
aws-check:          ## review the first-draft AWS agent identity setup
	$(PY) aws/check.py first-draft || true

aws-check-hardened: ## the hardened one: 0 findings
	$(PY) aws/check.py hardened

aws-hunt:           ## who did what, for whom: CloudTrail + app log
	$(PY) aws/attribution.py

clean:              ## remove caches
	rm -rf __pycache__ aws/__pycache__ keycloak/__pycache__ tools/__pycache__
