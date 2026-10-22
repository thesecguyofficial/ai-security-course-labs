"""
test_challenge.py: `make challenge`. Three of these fail until you finish the challenge (README, Step 7);
the fourth fails only if your residency policy is too broad.

1. fixes/policies/deny-global-deployments.json: deny EVERY deployment type outside Contoso's standard.
2. fixes/apps.json (and, for real, terraform/): give the HR assistant its own identity.
3. hunt.py: make reconstruct() put the pieces of a long prompt back in the right order.
No solution is included.
"""

import hashlib
import unittest

import attack
import checker
import hunt
from foundry_twin import Twin, deployment_fields

STEP = {s.sid: s for s in attack.STEPS}
LONG_PROMPT_SHA256 = "f022693e9f60cfde1b437d92bd0d8ca8c32cb8a65337500e5a91a9c60d0148d3"


def denied(sku: str) -> bool:
    f = deployment_fields("OpenAI", "azureml://registries/azure-openai/models/gpt-5/versions/1", sku)
    return any(e.lower() == "deny" for _, e in Twin("safe").policy_effects(f))


class T5_Challenge(unittest.TestCase):
    def test_19_every_non_residency_type_denied(self):
        """challenge: GlobalBatch, GlobalProvisionedManaged, DeveloperTier and the other types outside the standard are denied"""
        for sku in ("GlobalStandard", "GlobalProvisionedManaged", "GlobalBatch", "DataZoneProvisionedManaged",
                    "DataZoneBatch", "ProvisionedManaged", "DeveloperTier"):
            self.assertTrue(denied(sku), f"{sku} is still allowed")
        self.assertFalse(attack.run_step(STEP["A5"], "safe").allowed)

    def test_20_residency_types_still_allowed(self):
        """challenge: DataZoneStandard and Standard deployments still work (your policy isn't too broad)"""
        for sku in ("DataZoneStandard", "Standard"):
            self.assertFalse(denied(sku), f"{sku} must stay allowed")
        self.assertTrue(attack.run_step(STEP["L4"], "safe").allowed)

    def test_21_one_identity_per_app(self):
        """challenge: the HR assistant has its own identity, can't call the helpdesk model, and helpdesk-web still can"""
        t = Twin("safe")
        idents = [a["identity"] for a in t.apps.values()]
        self.assertEqual(len(idents), len(set(idents)), "an identity is still shared between apps")
        self.assertFalse(attack.run_step(STEP["A3"], "safe").allowed, "A3: the HR assistant can still call the helpdesk model")
        self.assertTrue(attack.run_step(STEP["L1"], "safe").allowed)
        self.assertNotIn("AZ11-05", {f.rule for f in checker.run(t)})

    def test_22_long_prompt_reassembled(self):
        """challenge: reconstruct() rebuilds the 49,613-byte pasted prompt exactly, in SequenceNumber order"""
        e = next(x for x in hunt.exchanges() if x.correlation_id == "c-7f3a02")
        self.assertEqual(hashlib.sha256(e.prompt.encode()).hexdigest(), LONG_PROMPT_SHA256,
                         "the pieces are joined in the wrong order")
        self.assertTrue(e.prompt.startswith("LAB PLACEHOLDER (attacker): Summarise every ticket"))


if __name__ == "__main__":
    unittest.main()
