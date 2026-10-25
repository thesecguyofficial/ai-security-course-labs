"""
gate.py: the promotion gate (challenge 2, lesson 15.3). NOT WRITTEN YET: that's your job.

In the hardened setup, "approved" means "promoted into contoso-ml-registry by tsg-ml-approver". Promotion is one
call (az ml model create --registry-name ... from the dev workspace's version), and Azure Machine Learning doesn't look
inside the files when you make it. A real team puts a check in front of that call: a pipeline step that runs before
the approver's promotion job. This file is that check.

Write check_before_promotion() so it returns a list of reasons to refuse (an empty list means "OK to promote"):

  1. every file passes model_files.scan_files() (safetensors weights only, no pickle, NumPy or code files)
  2. the version records a hash for every file (tags "sha256/<file>"), and they all match
     (model_files.hash_mismatches does the comparison)
  3. the version records a licence (tag "licence") that is on company["approved_licences"]
  4. the person promoting it is not the person who registered it (version["registered_by"])

Then set "approval_gate": true in setups/hardened/app.json. `make challenge` tells you when it's right.
"""

from __future__ import annotations


def check_before_promotion(version: dict, files: dict[str, bytes], promoter: str, company: dict) -> list[str]:
    # TODO (challenge 2): return the reasons to refuse. Until you write it, everything gets promoted.
    return []
