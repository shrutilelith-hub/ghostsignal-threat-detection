import json
import unittest
from datetime import datetime, timedelta, timezone

import pandas as pd

from collectors.structured_logs import ingest_event_text, parse_event_line
from services import event_aggregation
from services.event_aggregation import (
    aggregate_device_events,
    count_scoring_usable_events,
    uploaded_batch_status,
)
from services.scoring import analyse


def event(**overrides):
    record = {
        "timestamp": "2026-05-01T12:00:00Z",
        "source": "edge-01",
        "device": "workstation-01",
        "event_type": "connection",
        "action": "allowed",
        "direction": "outbound",
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "destination_port": 443,
        "bytes_out": 1024,
    }
    record.update(overrides)
    return record


class StructuredLogTests(unittest.TestCase):
    def test_normalizes_valid_json_and_marks_optional_fields_unavailable(self):
        normalized = parse_event_line(
            '{"timestamp":"2026-05-01T12:00:00Z","source":"edge-01",'
            '"device":"pc-01","event_type":"connection"}'
        )
        self.assertEqual(normalized["source_port"], None)
        self.assertEqual(normalized["source_ip"], None)
        self.assertEqual(normalized["direction"], None)
        self.assertEqual(len(normalized["event_id"]), 64)

    def test_rejects_missing_invalid_fields_and_malformed_json(self):
        cases = [
            ({**event(), "device": ""}, "device"),
            ({**event(), "event_type": None}, "event_type"),
            ({**event(), "timestamp": "yesterday"}, "timestamp"),
            ({**event(), "source_ip": "999.1.1.1"}, "source_ip"),
            ({**event(), "destination_port": 65536}, "destination_port"),
            ({**event(), "bytes_out": -1}, "bytes_out"),
        ]
        for record, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(ValueError, expected):
                    parse_event_line(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "valid JSON"):
            parse_event_line('{"timestamp":')

    def test_parses_rfc5424_json_message_and_rejects_malformed_syslog(self):
        line = (
            '<34>1 2026-05-01T12:00:00Z edge-01 firewall - - - '
            '{"event_type":"connection","action":"denied"}'
        )
        parsed = parse_event_line(line)
        self.assertEqual(parsed["source"], "edge-01")
        self.assertEqual(parsed["device"], "edge-01")
        self.assertEqual(parsed["action"], "denied")
        with self.assertRaisesRegex(ValueError, "RFC 5424"):
            parse_event_line("<34>bad syslog")
        with self.assertRaisesRegex(ValueError, "priority"):
            parse_event_line(
                '<999>1 2026-05-01T12:00:00Z edge-01 firewall - - - '
                '{"event_type":"connection"}'
            )

    def test_normalized_evidence_does_not_retain_unknown_payload_fields(self):
        normalized = parse_event_line(json.dumps({**event(), "payload": "not retained"}))
        self.assertNotIn("payload", normalized)
        self.assertNotIn("payload", normalized["raw_event"])

    def test_ingestion_sorts_deduplicates_and_reports_rejections(self):
        first = event(event_id="event-1", timestamp="2026-05-01T12:02:00Z")
        second = event(event_id="event-2", timestamp="2026-05-01T12:01:00Z")
        lines = "\n".join(json.dumps(item) for item in (first, first, second, {"timestamp": "bad"}))
        events, rejected, duplicates = ingest_event_text(lines)
        self.assertEqual([item["event_id"] for item in events], ["event-2", "event-1"])
        self.assertEqual(duplicates, 1)
        self.assertEqual(len(rejected), 1)
        self.assertIn("Line 4", rejected[0])


class AggregationTests(unittest.TestCase):
    def test_scoring_usable_counter_is_a_public_module_export(self):
        self.assertIn("count_scoring_usable_events", event_aggregation.__all__)
        self.assertIs(
            event_aggregation.count_scoring_usable_events,
            count_scoring_usable_events,
        )

    def test_event_category_fields_reach_scoring(self):
        records = [
            event(
                event_id="failed-summary",
                device="Test-Camera",
                event_type="connection_failed",
                action=None,
                failed_connections=12,
            ),
            event(
                event_id="external-summary",
                device="Test-Laptop",
                event_type="external_connection",
                action=None,
                external_connections=25,
            ),
            event(
                event_id="unusual-summary",
                device="Test-Sensor",
                event_type="unusual_port",
                action=None,
                unusual_port=1,
            ),
        ]
        events, rejected, duplicates = ingest_event_text(
            "\n".join(json.dumps(record) for record in records)
        )
        self.assertFalse(rejected)
        self.assertEqual(duplicates, 0)
        self.assertEqual(count_scoring_usable_events(events, [], set()), 3)

        summaries = aggregate_device_events(events, [], set())
        scored = analyse(
            pd.DataFrame(summaries).assign(_record_id=range(len(summaries)))[
                ["device", "failed_connections", "external_connections", "unusual_port", "bytes_out", "_record_id"]
            ]
        ).set_index("device")

        self.assertEqual(scored.loc["Test-Camera", "priority_score"], 30)
        self.assertEqual(scored.loc["Test-Laptop", "priority_score"], 25)
        self.assertEqual(scored.loc["Test-Sensor", "priority_score"], 25)
        self.assertIn("external_connections", scored.loc["Test-Camera", "invalid_fields"])

    def test_explicit_event_metrics_can_reach_combined_score_of_100(self):
        record = event(
            event_id="combined-score",
            event_type="connection_failed",
            action=None,
            direction=None,
            source_ip=None,
            destination_ip=None,
            destination_port=None,
            failed_connections=10,
            external_connections=20,
            unusual_port=1,
            bytes_out=5_000_001,
        )
        events, rejected, _ = ingest_event_text(json.dumps(record))
        self.assertFalse(rejected)

        summary = aggregate_device_events(events, [], set())[0]
        scored = analyse(
            pd.DataFrame([summary]).assign(_record_id=[0])[
                ["device", "failed_connections", "external_connections", "unusual_port", "bytes_out", "_record_id"]
            ]
        )
        self.assertEqual(scored.iloc[0]["priority_score"], 100)
        self.assertEqual(scored.iloc[0]["status"], "High-priority review")
        self.assertEqual(scored.iloc[0]["invalid_fields"], [])

    def test_missing_scoring_fields_remain_unknown_and_are_reported(self):
        events, rejected, _ = ingest_event_text(json.dumps({
            "timestamp": "2026-05-01T12:00:00Z",
            "source": "edge-01",
            "device": "partial-device",
            "event_type": "connection",
        }))
        self.assertFalse(rejected)
        summary = aggregate_device_events(events, [], set())[0]
        self.assertIsNone(summary["failed_connections"])
        self.assertIsNone(summary["external_connections"])
        self.assertIsNone(summary["unusual_port"])
        self.assertIsNone(summary["bytes_out"])

        scored = analyse(
            pd.DataFrame([summary]).assign(_record_id=[0])[
                ["device", "failed_connections", "external_connections", "unusual_port", "bytes_out", "_record_id"]
            ]
        )
        self.assertEqual(scored.iloc[0]["priority_score"], 0)
        self.assertEqual(
            set(scored.iloc[0]["invalid_fields"]),
            {"failed_connections", "external_connections", "unusual_port", "bytes_out"},
        )
        self.assertEqual(count_scoring_usable_events(events, [], set()), 0)

    def test_bytes_without_required_connection_direction_remain_unknown(self):
        events, rejected, _ = ingest_event_text(json.dumps(event(
            event_id="missing-direction",
            action=None,
            direction=None,
            bytes_out=5_000_001,
        )))
        self.assertFalse(rejected)
        summary = aggregate_device_events(events, [], set())[0]
        self.assertIsNone(summary["bytes_out"])
        self.assertEqual(count_scoring_usable_events(events, [], set()), 0)

    def test_invalid_numeric_score_fields_are_rejected_not_coerced(self):
        invalid_record = event(
            event_type="connection_failed",
            failed_connections="12",
        )
        events, rejected, _ = ingest_event_text(json.dumps(invalid_record))
        self.assertEqual(events, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn("failed_connections must be an integer", rejected[0])
        self.assertEqual(count_scoring_usable_events(events, [], set()), 0)

    def test_counts_failed_not_denied_and_derives_configured_fields(self):
        events, rejected, _ = ingest_event_text(
            "\n".join([
                json.dumps(event(event_id="allowed", action="allowed")),
                json.dumps(event(event_id="denied", action="denied")),
                json.dumps(event(event_id="failed", action="failed", destination_port=22)),
            ])
        )
        self.assertFalse(rejected)
        summary = aggregate_device_events(events, ["192.168.1.0/24"], {22})[0]
        self.assertEqual(summary["failed_connections"], 1)
        self.assertEqual(summary["external_connections"], 3)
        self.assertEqual(summary["unusual_port"], 1)
        self.assertEqual(summary["bytes_out"], 3072)

    def test_missing_aggregation_inputs_remain_unknown(self):
        events, _, _ = ingest_event_text(
            json.dumps(event(event_id="partial", direction=None, action=None, source_ip=None))
        )
        summary = aggregate_device_events(events, [], set())[0]
        self.assertIsNone(summary["failed_connections"])
        self.assertIsNone(summary["external_connections"])
        self.assertIsNone(summary["unusual_port"])
        self.assertIsNone(summary["bytes_out"])

    def test_denied_only_events_are_not_failed(self):
        events, _, _ = ingest_event_text(
            json.dumps(event(event_id="denied", action="denied"))
        )
        summary = aggregate_device_events(events, ["192.168.1.0/24"], {22})[0]
        self.assertEqual(summary["failed_connections"], 0)

    def test_upload_status_never_claims_a_live_connection(self):
        now = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(uploaded_batch_status(False, None, now, 60), "Configuration Required")
        self.assertEqual(
            uploaded_batch_status(True, now - timedelta(minutes=61), now, 60),
            "Stale",
        )
        self.assertEqual(uploaded_batch_status(True, now, now, 60), "Disconnected")


if __name__ == "__main__":
    unittest.main()
