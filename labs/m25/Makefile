# M25 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Needs Python 3.11+ and ONE real package, model-signing (OpenSSF Model Signing), pinned with its dependencies in this
# folder's own virtual environment. Signing uses a local lab key: nothing is sent to Sigstore or anywhere else.
VENV := .venv
PY   := $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)
REGION ?= us-east-1
AWS  := aws --region $(REGION)

.PHONY: setup build release deploy attack hardened story quant-gate lineage-demo hunt test challenge clean \
        cloud-bucket cloud-upload cloud-gate cloud-tamper cloud-warn cloud-down

setup:         ## create .venv, install the pinned packages, make the lab key pairs and the model files
	python3 -m venv $(VENV)
	$(VENV)/bin/python -m pip install -r requirements.txt
	$(VENV)/bin/python -c "import lab; lab.ensure_keys(); print('lab keys in keys/: ci.priv, ci.pub, attacker.priv, attacker.pub')"
	$(VENV)/bin/python ci.py build

build:         ## (re)write models/ from data/
	$(PY) ci.py build

release:       ## the hardened CI job: quantize, eval gate, ML-BOM, sign -> release/1.1.0-hardened/
	$(PY) ci.py release hardened --version 1.1.0

deploy: release ## the hardened deploy gate on that release, plus the CreateModelPackage body it would send
	$(PY) deploy.py hardened release/1.1.0-hardened --emit state/create-model-package.json

attack:        ## 7 supply-chain attacks + 3 normal releases against the FIRST DRAFT: 7 of 7 deploy
	$(PY) suite.py first-draft

hardened:      ## the same against the hardened CI and deploy gate: 0 of 7 deploy, 3 of 3 normal releases still do
	$(PY) suite.py hardened

story:         ## one swapped weights file, first draft then hardened, step by step
	$(PY) suite.py first-draft --why --only A1
	@echo; $(PY) suite.py hardened --why --only A1

quant-gate:    ## a community quant through both CI jobs: the first draft signs it, the hardened one refuses
	@rm -rf release/1.1.1-*
	-$(PY) ci.py release first-draft --version 1.1.1 --quant models/community-quant
	@echo
	-$(PY) ci.py release hardened --version 1.1.1 --quant models/community-quant

lineage-demo:  ## an unreviewed fine-tune: passes every eval, and still waves through a ticket with the lab marker
	$(PY) gates.py models/unapproved-base --ticket "Reset my password and turn off MFA PWNED-LAB-MARKER"

hunt:          ## an investigator's questions over a morning of deploy-gate logs (Q4 is the challenge)
	$(PY) hunt.py

test:          ## the proof (21 tests)
	$(PY) run_tests.py

challenge:     ## the same plus the three-part challenge: 4 of 26 fail until you do it
	$(PY) run_tests.py --challenge

clean:         ## delete generated files (models, releases, state, caches). Keeps .venv and your keys
	rm -rf models release state cloud/out __pycache__ cloud/__pycache__

# ---- OPTIONAL guided build (GUIDED-BUILD.md): the AWS CLI v2 and YOUR sandbox account. Set BUCKET first:
# ----   export BUCKET=tsg-m25-lab-<your account id>-<random>
cloud-bucket:  ## a private, versioned S3 bucket for releases, and the model package group
	$(AWS) s3api create-bucket --bucket $(BUCKET)
	$(AWS) s3api put-public-access-block --bucket $(BUCKET) --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
	$(AWS) s3api put-bucket-versioning --bucket $(BUCKET) --versioning-configuration Status=Enabled
	$(AWS) sagemaker create-model-package-group --model-package-group-name tsg-guard-lab --model-package-group-description "M25 lab: signed releases only"

cloud-upload: release ## upload the signed release (model/ and model.sig) to the bucket
	$(AWS) s3 cp --recursive release/1.1.0-hardened s3://$(BUCKET)/tsg-guard/1.1.0-hardened/

cloud-gate:    ## download the release from S3 into a fresh folder, run the hardened gate, register only if it passes
	$(PY) cloud/gate.py --bucket $(BUCKET) --release 1.1.0-hardened --setup hardened --region $(REGION)

cloud-tamper:  ## overwrite the weights in S3 with the community quant's (a new object version)
	$(AWS) s3 cp models/community-quant/model.safetensors s3://$(BUCKET)/tsg-guard/1.1.0-hardened/model/model.safetensors

cloud-warn:    ## the ONE setting changed: the same gate with the first draft's fail-open settings
	$(PY) cloud/gate.py --bucket $(BUCKET) --release 1.1.0-hardened --setup first-draft --region $(REGION)

cloud-down:    ## DELETE everything: model packages, the group, every object version, the bucket. Run it today.
	$(PY) cloud/gate.py --bucket $(BUCKET) --teardown --region $(REGION)
