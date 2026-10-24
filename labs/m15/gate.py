"""
gate.py: the approval gate (challenge 2, lesson 15.3). NOT WRITTEN YET: that's your job.

Approving a model version is one API call (UpdateModelPackage with ModelApprovalStatus=Approved). SageMaker AI
doesn't look inside the files when you make it. A real team puts a check in front of that call: a pipeline step, or
a function triggered by the EventBridge event "SageMaker Model Package State Change" that sets the status back to
Rejected when the version fails. This file is that check.

Write check_before_approval() so it returns a list of reasons to refuse (an empty list means "OK to approve"):

  1. every file passes model_files.scan_files() (safetensors weights only, no pickle, NumPy or code files)
  2. the package records a hash for every file (CustomerMetadataProperties "sha256/<file>"), and they all match
     (model_files.hash_mismatches does the comparison)
  3. the package records a licence ("licence") that is on company["approved_licences"]
  4. the approver is not the person who registered the version (package["_registered_by"])

Then set "approval_gate": true in setups/hardened/app.json. `make challenge` tells you when it's right.
"""

from __future__ import annotations


def check_before_approval(package: dict, files: dict[str, bytes], approver: str, company: dict) -> list[str]:
    # TODO (challenge 2): return the reasons to refuse. Until you write it, everything gets approved.
    return []
