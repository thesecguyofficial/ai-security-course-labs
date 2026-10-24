"""
cloud/render.py: fill the request templates in cloud/requests/ with your stack's outputs. Standard library only.

    aws cloudformation describe-stacks --stack-name tsg-m15-lab --output json > cloud/out/stack.json
    MODEL_DIR=~/models/qwen3-0.6b python3 cloud/render.py           # writes cloud/out/*.json

Settings (environment variables, all optional except MODEL_DIR for the model package):
  MODEL_DIR       the model folder you downloaded and scanned (its file hashes go into the registry metadata)
  LICENCE         the licence you read on the model's page, e.g. apache-2.0 (you must check it yourself)
  MODEL_SOURCE    where the files came from, e.g. huggingface.co/Qwen/Qwen3-0.6B
  IMAGE           the inference image (default: the LMI image named on AWS's Available Images page, Oct 2026)
  INSTANCE_TYPE   default ml.g5.xlarge
  PACKAGE_ARN     the model package ARN (after you register it)
  TEARDOWN_HOURS  hours from now until EventBridge Scheduler deletes the endpoint (default 2)

Every file it writes is a request body for `aws ... --cli-input-json file://cloud/out/<name>.json`.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import model_files  # noqa: E402

DEFAULT_IMAGE = "763104351884.dkr.ecr.us-east-1.amazonaws.com/djl-inference:0.38.0-lmi30.0.0-cu130"


def values() -> dict:
    stack = json.loads((HERE / "out" / "stack.json").read_text())["Stacks"][0]
    v = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    v["SubnetIds"] = v["SubnetIds"].split(",")
    at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=float(os.environ.get("TEARDOWN_HOURS", "2")))
    v.update({"IMAGE": os.environ.get("IMAGE", DEFAULT_IMAGE), "INSTANCE_TYPE": os.environ.get("INSTANCE_TYPE", "ml.g5.xlarge"),
              "PACKAGE_ARN": os.environ.get("PACKAGE_ARN", "PACKAGE_ARN_NOT_SET"), "LICENCE": os.environ.get("LICENCE", "NOT-CHECKED"),
              "MODEL_SOURCE": os.environ.get("MODEL_SOURCE", "NOT-RECORDED"), "TEARDOWN_AT": at.strftime("%Y-%m-%dT%H:%M:%S")})
    return v


def fill(obj, v):
    if isinstance(obj, dict):
        return {k: fill(x, v) for k, x in obj.items()}
    if isinstance(obj, list):
        return [fill(x, v) for x in obj]
    if isinstance(obj, str):
        if obj.startswith("${") and obj.endswith("}") and obj[2:-1] in v and not isinstance(v[obj[2:-1]], str):
            return v[obj[2:-1]]                       # a whole value that is a list (SubnetIds)
        for k, x in v.items():
            if isinstance(x, str):
                obj = obj.replace("${" + k + "}", x)
    return obj


def main() -> int:
    v = values()
    out = HERE / "out"
    out.mkdir(exist_ok=True)
    for tpl in sorted((HERE / "requests").glob("*.json")):
        body = fill(json.loads(tpl.read_text()), v)
        if tpl.name == "create-model-package.json":
            folder = os.environ.get("MODEL_DIR")
            if not folder:
                print("skipped create-model-package.json: set MODEL_DIR to the folder you scanned")
                continue
            files = model_files.read_folder(pathlib.Path(folder).expanduser())
            body["CustomerMetadataProperties"].update(model_files.manifest(files))
            if len(body["CustomerMetadataProperties"]) > 50:
                print("too many files for one metadata map (50 keys): keep only the files the model needs")
                return 1
        (out / tpl.name).write_text(json.dumps(body, indent=2) + "\n")
        print(f"wrote cloud/out/{tpl.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
