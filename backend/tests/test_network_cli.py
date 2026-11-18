"""Command-line options of the standalone network crawl."""

import unittest

from vulnmapper.network.__main__ import parse_config


class TestNetworkCli(unittest.TestCase):
    def test_checklist_is_off_by_default(self):
        self.assertFalse(parse_config(["--seed", "192.0.2.1"]).checklist)

    def test_checklist_flag_turns_config_collection_on(self):
        self.assertTrue(parse_config(["--seed", "192.0.2.1", "--checklist"]).checklist)


if __name__ == "__main__":
    unittest.main()
