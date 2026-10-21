"""
test_challenge.py: the YOUR TURN extension behind `make challenge`.

The model can now choose a file name ("save a summary as vpn-notes"). The app saves the summary under
exports/<name>.txt using safe_export_path() in helpdesk_app.py. Today that function trusts the model, so a name
like ../../escaped walks out of the exports folder (path traversal).

These tests FAIL until you fix safe_export_path(). Before your fix, test 18 really does write escaped.txt one
folder up from exports/ (still inside this lab folder): that file is the proof of the bug. `make clean` removes it.
"""

import logging
import os
import unittest

import helpdesk_app as app

logging.disable(logging.CRITICAL)


class T4_Challenge_PathTraversal(unittest.TestCase):

    def test_14_ordinary_name_allowed(self):
        """challenge: an ordinary name still saves inside exports/"""
        path = os.path.realpath(app.safe_export_path("vpn-notes"))
        self.assertTrue(path.startswith(os.path.realpath(app.EXPORT_DIR) + os.sep))

    def test_15_dotdot_refused(self):
        """challenge: '../../escaped' is refused (ValueError)"""
        with self.assertRaises(ValueError):
            app.safe_export_path(os.path.join("..", "..", "escaped"))

    def test_16_absolute_refused(self):
        """challenge: an absolute path is refused (ValueError)"""
        with self.assertRaises(ValueError):
            app.safe_export_path(os.path.abspath(os.path.join(os.sep, "tmp", "escaped")))

    def test_17_empty_refused(self):
        """challenge: an empty name is refused (ValueError)"""
        with self.assertRaises(ValueError):
            app.safe_export_path("")

    def test_18_end_to_end(self):
        """challenge: asking the model to 'save a summary as ../escaped' is refused by the app"""
        r = app.answer_question("save a summary as ../escaped", safe=True)
        self.assertTrue(r["saved"] == "refused", f"the app saved the file to {r['saved']}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
