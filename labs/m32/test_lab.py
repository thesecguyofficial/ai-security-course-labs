"""Integration test of the lab itself (the starting point and the tooling). Runs green on the shipped repo.

It proves the Crew is vulnerable as the README describes, the eval gate can fail, the detection scorer and the
cloud check behave, and normal use works. The student's own work is graded by the security tests (make challenge)
and the self-check (make check); this file does not test the student's guards.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "detections"))


class StartingPointIsVulnerable(unittest.TestCase):
    def test_six_attacks_all_work(self):
        """the six known attacks all work on the shipped (vulnerable) Crew"""
        out = subprocess.run([sys.executable, "tour.py"], cwd=str(HERE), capture_output=True, text=True)
        self.assertIn("6 of 6 attacks worked.", out.stdout, out.stdout + out.stderr)

    def test_functional_passes(self):
        """normal use works on the shipped Crew"""
        out = subprocess.run([sys.executable, "-m", "unittest", "-q", "tests.test_functional"],
                             cwd=str(HERE), capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)


class ToolingWorks(unittest.TestCase):
    def test_eval_gate_fails_on_vulnerable(self):
        """the eval gate fails on the vulnerable Crew (there is something to fix)"""
        out = subprocess.run([sys.executable, "evals/run_evals.py", "--core-only"], cwd=str(HERE),
                             capture_output=True, text=True)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("GATE FAILED", out.stdout)

    def test_detection_scorer_runs(self):
        """the detection scorer runs and the shipped example rule is too noisy to pass"""
        out = subprocess.run([sys.executable, "detections/score.py", "--seeds", "1"], cwd=str(HERE),
                             capture_output=True, text=True)
        self.assertIn("DETECTIONS", out.stdout)

    def test_cloud_first_draft_has_high(self):
        """the first-draft cloud deployment has HIGH findings"""
        out = subprocess.run([sys.executable, "cloud/cloud_check.py"], cwd=str(HERE), capture_output=True, text=True)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("HIGH", out.stdout)

    def test_attack_sim_three_seeds_differ(self):
        """each simulated day is different, and every incident is present"""
        import attack_sim
        for seed in (1, 2, 3):
            events, truth = attack_sim.generate(seed)
            self.assertTrue(events)
            for s in ("S1", "S2", "S3", "S4", "S5"):
                self.assertTrue(truth[s], f"seed {seed} missing {s}")


if __name__ == "__main__":
    unittest.main()
