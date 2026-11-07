"""tools/flag.py makes exactly the flags the course site accepts (vectors from lib/learn/flags.js, 7 Nov 2026)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import flag  # noqa: E402


class FlagTests(unittest.TestCase):
    def test_same_flags_as_the_site(self):
        self.assertEqual(flag.make_flag("TSG-3F2A9C", "m3-layers"), "TSG{m3-layers-9152fb8abb2e}")
        self.assertEqual(flag.make_flag("TSG-3F2A9C", "m3-redirect"), "TSG{m3-redirect-286781cfb359}")

    def test_code_is_cleaned_and_checked(self):
        self.assertEqual(flag.clean_code(" tsg-3f2a9c "), "TSG-3F2A9C")
        for bad in ("", None, "TSG-3F2A9", "TSG-3F2A9CX", "abc", "TSG_3F2A9C"):
            self.assertIsNone(flag.clean_code(bad))


if __name__ == "__main__":
    unittest.main()
