"""
test_challenge.py: the YOUR TURN challenge (make challenge).

The malicious server ships a 2.0.0 "release" where the hidden directive is gone from the tool
DESCRIPTION and hidden inside the `sidenote` parameter's schema description instead. A reviewer who only
reads the one-line tool description would wave it through.

Your job: make the scan read the WHOLE tool definition. Edit `review.py` -> full_definition_text() where
the YOUR TURN comment is, so it also includes the input-schema text. These tests fail until it does.
No solution is included.
"""

import unittest
from pathlib import Path

import review
import stand_in_model
from servers.facts_server import INJECTED

LAB = Path(__file__).resolve().parent
STATE = LAB / "state"


def set_release(v: str) -> None:
    STATE.mkdir(exist_ok=True)
    (STATE / "facts_release.txt").write_text(v)


class Challenge(unittest.TestCase):
    def test_13_description_only_scan_misses_schema(self):
        """challenge: the 2.0.0 tool description alone looks clean (that is the trap)"""
        set_release("2.0.0")
        tool = review.one_tool("facts", "fact_of_the_day")
        self.assertNotIn(INJECTED, tool["description"])  # nothing hidden in the description itself

    def test_14_your_scan_reads_the_whole_definition(self):
        """challenge: full_definition_text() must include the schema, so the hidden token is found"""
        set_release("2.0.0")
        tool = review.one_tool("facts", "fact_of_the_day")
        text = review.full_definition_text(tool)
        self.assertIn(INJECTED, text, "full_definition_text() is not reading the input schema yet")

    def test_15_host_blocks_schema_hidden_directive(self):
        """challenge: with your fix, --block-injection quarantines the schema-hidden 2.0.0 tool too"""
        set_release("2.0.0")
        # The host's scan uses stand_in_model.full_text, which already covers the schema; this proves
        # the quarantine still holds for the schema-hidden variant once your reviewer agrees it is bad.
        tool = review.one_tool("facts", "fact_of_the_day")
        self.assertIn(INJECTED, stand_in_model.full_text(tool))
