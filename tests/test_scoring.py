import unittest

import pandas as pd

from services.scoring import analyse, build_investigation_report, filter_records


class ScoringTests(unittest.TestCase):
    def setUp(self):
        source = pd.DataFrame([
            {"device": "High", "failed_connections": 10, "external_connections": 20, "unusual_port": 1, "bytes_out": 5_000_001},
            {"device": "Review", "failed_connections": 10, "external_connections": 0, "unusual_port": 0, "bytes_out": 0},
            {"device": "Zero", "failed_connections": 0, "external_connections": 0, "unusual_port": 0, "bytes_out": 0},
            {"device": "Duplicate", "failed_connections": "bad", "external_connections": "", "unusual_port": 0, "bytes_out": 0},
            {"device": "Duplicate", "failed_connections": 10, "external_connections": 0, "unusual_port": 0, "bytes_out": 0},
        ])
        source["_record_id"] = range(len(source))
        self.source = source
        self.results = analyse(source)

    def test_existing_score_classes_and_unknown_data(self):
        by_device = self.results.set_index(["device", "_record_id"])
        self.assertEqual(by_device.loc[("High", 0), "priority_score"], 100)
        self.assertEqual(by_device.loc[("High", 0), "status"], "High-priority review")
        self.assertEqual(by_device.loc[("Review", 1), "status"], "Review recommended")
        self.assertEqual(by_device.loc[("Zero", 2), "status"], "No configured rule triggered")
        self.assertEqual(by_device.loc[("Duplicate", 3), "priority_score"], 0)
        self.assertIn("failed_connections", by_device.loc[("Duplicate", 3), "invalid_fields"])

    def test_combined_literal_search_and_classification(self):
        selected = filter_records(self.results, "dup", "Review recommended")
        self.assertEqual(selected["device"].tolist(), ["Duplicate"])
        self.assertTrue(filter_records(self.results, ".*", "All classifications").empty)

    def test_report_exports_only_expected_public_columns_and_records(self):
        selected = filter_records(self.results, "high", "High-priority review")
        report = build_investigation_report(selected, self.source)
        self.assertEqual(len(report), 1)
        self.assertEqual(report.iloc[0]["Device"], "High")
        self.assertEqual(
            report.columns.tolist(),
            [
                "Device",
                "Priority score",
                "Risk classification",
                "Failed connections",
                "External connections",
                "Unusual port indicator",
                "Outgoing bytes",
                "Evidence explaining triggered rules",
                "Invalid or missing fields",
            ],
        )
        self.assertIn("Failed connections (+30)", report.iloc[0]["Evidence explaining triggered rules"])

    def test_empty_dataset_scores_and_filters_cleanly(self):
        empty = analyse(pd.DataFrame(columns=[
            "device", "failed_connections", "external_connections", "unusual_port", "bytes_out", "_record_id"
        ]))
        self.assertTrue(empty.empty)
        self.assertTrue(filter_records(empty, "", "All classifications").empty)


if __name__ == "__main__":
    unittest.main()
