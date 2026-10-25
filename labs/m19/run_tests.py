"""
run_tests.py: run the lab's tests, one line per result.

    python3 run_tests.py               # make lab-test: the starting point is as the brief says; the tools work


Exit code 0 = all passed, 1 = something failed (so it works in CI too).
"""

import sys
import unittest


class OneLineResult(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test)
        self.stream.writeln(f"[PASS] {test.shortDescription()}")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.stream.writeln(f"[FAIL] {test.shortDescription()}")

    def addError(self, test, err):
        super().addError(test, err)
        self.stream.writeln(f"[ERROR] {test.shortDescription()}")

    def printErrors(self):
        for test, err in self.failures + self.errors:
            reason = err.strip().splitlines()[-1]
            self.stream.writeln(f"  why {test.id().split('.')[-1]}: {reason}")


def main() -> None:
    names = ["test_lab"]
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    runner = unittest.TextTestRunner(resultclass=OneLineResult, verbosity=0, stream=sys.stdout)
    result = runner.run(suite)
    total, bad = result.testsRun, len(result.failures) + len(result.errors)
    print(f"\n{'ALL TESTS PASSED' if bad == 0 else f'{bad} of {total} TESTS FAILED'} ({total} run)")
    sys.exit(0 if bad == 0 else 1)


if __name__ == "__main__":
    main()
