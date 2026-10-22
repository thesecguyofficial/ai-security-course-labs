"""
run_tests.py: run the lab's tests and print one line per test.

    python3 run_tests.py               # make test:      the attacks work today, the hardened port holds, the twins keep to the documented behaviour
    python3 run_tests.py --challenge   # make challenge: the same, plus the challenge (5 tests fail until you finish it)

Exit code 0 = all passed, 1 = something failed (so it works in CI too).
"""

import io
import sys
import unittest


class OneLineResult(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test)
        print(f"[PASS] {test.shortDescription()}")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        print(f"[FAIL] {test.shortDescription()}")

    def addError(self, test, err):
        super().addError(test, err)
        print(f"[ERROR] {test.shortDescription()}")

    def printErrors(self):
        # Short version: one reason per failed test instead of a full traceback.
        # For the full detail, run:  python3 -m unittest -v test_lab test_challenge
        for test, err in self.failures + self.errors:
            reason = err.strip().splitlines()[-1]
            print(f"  why {test.id().split('.')[-1]}: {reason}")


def main():
    names = ["test_lab"] + (["test_challenge"] if "--challenge" in sys.argv else [])
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    # unittest's own summary (with timings) goes to a buffer; we print one line of our own instead.
    runner = unittest.TextTestRunner(resultclass=OneLineResult, verbosity=0, stream=io.StringIO())
    result = runner.run(suite)
    total, bad = result.testsRun, len(result.failures) + len(result.errors)
    print(f"\n{'ALL TESTS PASSED' if bad == 0 else f'{bad} of {total} TESTS FAILED'} ({total} run)")
    sys.exit(0 if bad == 0 else 1)


if __name__ == "__main__":
    main()
