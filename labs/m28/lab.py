"""
lab.py: shared settings for lab M28 (paths, the pinned clock, the fake account, reading a setup).

Everything in this lab is local: the "AWS" pieces (KMS, S3, Bedrock's invocation logging, Macie) are small stand-ins
written for teaching. They keep the documented names and field shapes so the guided build feels familiar, but they
are not AWS and they never touch the network.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / "data"
SETUPS = HERE / "setups"

ACCOUNT = "123456789012"          # the documentation account ID AWS uses in its own examples
REGION = "us-east-1"
# The lab's clock is pinned, so every run (and every test) gives the same answer.
NOW = dt.datetime(2027, 4, 3, 9, 0, 0, tzinfo=dt.timezone.utc)

RAW_BUCKET = "tsg-invocation-logs-raw"
REDACTED_BUCKET = "tsg-invocation-logs-redacted"
LOG_PREFIX = f"AWSLogs/{ACCOUNT}/BedrockModelInvocationLogs/"

# Principals (IAM roles) in the lab account. "service:" principals stand for AWS service principals.
BEDROCK = "service:bedrock.amazonaws.com"
MACIE = f"arn:aws:iam::{ACCOUNT}:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"
REDACTOR = f"arn:aws:iam::{ACCOUNT}:role/tsg-log-redactor"
ANALYST = f"arn:aws:iam::{ACCOUNT}:role/tsg-analytics"
BREAK_GLASS = f"arn:aws:iam::{ACCOUNT}:role/tsg-incident-break-glass"
ERASURE = f"arn:aws:iam::{ACCOUNT}:role/tsg-privacy-erasure"     # handles deletion requests (challenge 2)
ROOT = f"arn:aws:iam::{ACCOUNT}:root"


def state_dir() -> pathlib.Path:
    """Where this run keeps its state. Tests point M28_STATE at a fresh temporary folder."""
    d = pathlib.Path(os.environ.get("M28_STATE", HERE / "state"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_setup(name: str) -> dict:
    """A setup is a folder of JSON files: pipeline.json (design choices) and identifiers.json (what to detect)."""
    folder = SETUPS / name
    if not folder.is_dir():
        raise SystemExit(f"unknown setup {name!r}: choose one of {sorted(p.name for p in SETUPS.iterdir())}")
    setup = json.loads((folder / "pipeline.json").read_text())
    setup["identifiers"] = json.loads((folder / "identifiers.json").read_text())
    setup["name"] = name
    return setup


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def short(principal: str) -> str:
    """'arn:aws:iam::123456789012:role/tsg-analytics' -> 'tsg-analytics' (for printing)."""
    if principal.startswith("service:"):
        return principal.split(":", 1)[1]
    return principal.rsplit("/", 1)[-1]
