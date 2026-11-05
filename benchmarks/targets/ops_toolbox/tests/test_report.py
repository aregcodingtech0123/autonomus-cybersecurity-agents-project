"""Unit tests for report helpers."""

import unittest

from toolbox.report import load_rows, parse_options, shard_for


class ReportTests(unittest.TestCase):
    def test_options_must_be_a_mapping(self):
        with self.assertRaises(ValueError):
            parse_options("[1, 2]")

    def test_unknown_report_kind_is_rejected_before_any_query(self):
        with self.assertRaises(KeyError):
            load_rows(None, "daily; DROP TABLE report_daily")

    def test_shards_stay_in_range(self):
        self.assertIn(shard_for("north-wind"), range(16))
