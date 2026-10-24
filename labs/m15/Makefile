# M15 lab shortcuts (Mac/Linux). Windows: run the python commands from the README instead.
# Steps 1-8 need only Python 3.11+ (standard library): no AWS account, no packages, no network, no model download.
PY := python3
STACK ?= tsg-m15-lab
REGION ?= us-east-1
OUT := cloud/out
AWS := aws --region $(REGION)

.PHONY: check check-hardened attack hardened files scan hunt test challenge clean setup \
        cloud-base cloud-render cloud-upload cloud-register cloud-deploy cloud-ask cloud-down

check:          ## review the FIRST DRAFT deployment: 35 findings (19 HIGH)
	$(PY) checker.py first-draft || true

check-hardened: ## the hardened deployment: 2 MEDIUM left (challenges 1 and 2)
	$(PY) checker.py hardened

attack:         ## 15 attacks + 6 normal requests against the first draft: 15 of 15 work
	$(PY) evaluate.py first-draft

hardened:       ## the same suite against the hardened setup: 2 of 15 work (A14, A15) until the challenge
	$(PY) evaluate.py hardened

files:          ## write the lab's model files to artifacts/ so you can look at them
	$(PY) model_files.py build

scan: files     ## scan the first draft's model files, then the hardened ones
	-$(PY) model_files.py scan artifacts/v1-pickle
	$(PY) model_files.py scan artifacts/v2-safe

hunt:           ## investigate a morning of CloudTrail records
	$(PY) hunt.py

test:           ## the proof (20 tests)
	$(PY) run_tests.py

challenge:      ## the same plus the challenge: 7 of 28 fail until you do it
	$(PY) run_tests.py --challenge

clean:          ## remove caches, built model files and rendered cloud requests
	rm -rf __pycache__ cloud/__pycache__ artifacts $(OUT)

# Added for the repo-wide setup (setup.sh): every lab answers `make setup`. This one needs nothing installed.
setup:          ## nothing to install: checks your Python is 3.11 or newer
	$(PY) ../../tools/check_python.py 3.11

# ---- OPTIONAL: YOUR sandbox account, us-east-1, AWS CLI v2. Read GUIDED-BUILD.md first: a GPU endpoint costs money
# ---- every hour it exists. cloud-deploy creates the auto-teardown schedule BEFORE it creates the endpoint.
cloud-base:     ## VPC (no internet), S3 + runtime VPC endpoints with policies, KMS key, buckets, roles, app Lambda, trail
	$(AWS) cloudformation deploy --stack-name $(STACK) --template-file cloud/base.yaml --capabilities CAPABILITY_IAM
	mkdir -p $(OUT) && $(AWS) cloudformation describe-stacks --stack-name $(STACK) --output json > $(OUT)/stack.json

cloud-render:   ## fill cloud/requests/*.json with your stack outputs (needs MODEL_DIR, LICENCE, MODEL_SOURCE; see render.py)
	$(PY) cloud/render.py

cloud-down:     ## DELETE everything: endpoint, config, model, registry, schedule, bucket contents, the stack. Run it today.
	-$(AWS) sagemaker delete-endpoint --endpoint-name tsg-summariser-lab
	-$(AWS) sagemaker wait endpoint-deleted --endpoint-name tsg-summariser-lab
	-$(AWS) sagemaker delete-endpoint-config --endpoint-config-name tsg-summariser-lab-cfg
	-$(AWS) sagemaker delete-model --model-name tsg-summariser-lab
	-$(AWS) scheduler delete-schedule --name tsg-m15-teardown
	-for arn in $$($(AWS) sagemaker list-model-packages --model-package-group-name tsg-summariser-lab --query 'ModelPackageSummaryList[].ModelPackageArn' --output text); do \
	   $(AWS) sagemaker delete-model-package --model-package-name $$arn; done
	-$(AWS) sagemaker delete-model-package-group --model-package-group-name tsg-summariser-lab
	-for b in $$($(AWS) cloudformation describe-stacks --stack-name $(STACK) --query "Stacks[0].Outputs[?ends_with(OutputKey,'Bucket')].OutputValue" --output text); do \
	   $(AWS) s3 rm s3://$$b --recursive; done
	$(AWS) cloudformation delete-stack --stack-name $(STACK)
	$(AWS) cloudformation wait stack-delete-complete --stack-name $(STACK)
	@echo "Done. The KMS key is scheduled for deletion in 7 days (no charge while pending). Check: make cloud-check"

cloud-check:    ## after cloud-down: list anything with the lab's names that still exists
	-$(AWS) sagemaker list-endpoints --name-contains tsg-summariser --query 'Endpoints[].[EndpointName,EndpointStatus]' --output text
	-$(AWS) cloudformation describe-stacks --stack-name $(STACK) --query 'Stacks[0].StackStatus' --output text
