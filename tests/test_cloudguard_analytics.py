import unittest
from datetime import date

from cloudguard_analytics import (
    build_event_frame,
    calculate_metrics,
    explain_event,
    filter_events,
    normalize_api_url,
    parse_api_payload,
    timeline_events,
    top_failed_ips,
)


class ApiPayloadTests(unittest.TestCase):
    def test_parses_current_api_gateway_envelope(self):
        events, malformed = parse_api_payload(
            {"statusCode": 200, "body": {"events": [{"event_id": "evt-1"}]}}
        )
        self.assertEqual(events, [{"event_id": "evt-1"}])
        self.assertEqual(malformed, 0)

    def test_parses_json_encoded_body_and_ignores_invalid_rows(self):
        events, malformed = parse_api_payload(
            {"statusCode": 200, "body": '{"events": [{"event_id": "evt-1"}, null, 4]}'}
        )
        self.assertEqual(events, [{"event_id": "evt-1"}])
        self.assertEqual(malformed, 2)

    def test_rejects_bad_status_body_and_shape(self):
        for payload in (
            {"statusCode": 503, "body": {"events": []}},
            {"statusCode": 200, "body": "not json"},
            {"statusCode": 200, "body": {"items": []}},
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                parse_api_payload(payload)

    def test_url_normalization_preserves_query_and_path(self):
        self.assertEqual(
            normalize_api_url("https://api.example/dev///?token=placeholder"),
            "https://api.example/dev?token=placeholder",
        )


class EventAnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.frame = build_event_frame(
            [
                {
                    "event_id": "evt-1",
                    "timestamp": "2026-10-19T09:00:00Z",
                    "severity": "High",
                    "status": "Failed",
                    "username": "alex",
                    "ip_address": "192.0.2.10",
                    "failed_attempts": "5",
                },
                {
                    "event_id": "evt-2",
                    "timestamp": "2026-10-19T10:00:00Z",
                    "severity": "Normal",
                    "status": "Success",
                    "username": "sam",
                    "ip_address": "192.0.2.11",
                    "failed_attempts": 0,
                },
                {
                    "event_id": "evt-3",
                    "timestamp": "not-a-date",
                    "severity": None,
                    "status": None,
                    "username": None,
                    "ip_address": None,
                },
            ]
        )

    def test_metrics_handle_missing_values_and_calculate_success_rate(self):
        metrics = calculate_metrics(self.frame)
        self.assertEqual(metrics["events"], 3)
        self.assertEqual(metrics["high_risk"], 1)
        self.assertEqual(metrics["failures"], 1)
        self.assertEqual(metrics["success_rate"], 50)
        self.assertEqual(metrics["users"], 2)
        self.assertEqual(metrics["source_ips"], 2)

    def test_success_rate_is_unavailable_without_known_outcomes(self):
        frame = build_event_frame([{"status": None}])
        self.assertIsNone(calculate_metrics(frame)["success_rate"])

    def test_event_sources_default_to_api_and_preserve_archive_source(self):
        frame = build_event_frame([{}, {"source": "S3 login simulator"}])
        self.assertEqual(frame["source"].tolist(), ["AWS API", "S3 login simulator"])

    def test_filters_combine_and_search_is_case_insensitive(self):
        filtered = filter_events(
            self.frame,
            search="ALEX",
            severities=["High"],
            statuses=["Failed"],
            date_range=(date(2026, 10, 19), date(2026, 10, 19)),
        )
        self.assertEqual(filtered["event_id"].tolist(), ["evt-1"])

    def test_default_full_date_range_keeps_bad_timestamps(self):
        filtered = filter_events(
            self.frame,
            date_range=(date(2026, 10, 19), date(2026, 10, 19)),
        )
        self.assertEqual(len(filtered), 3)

    def test_partial_date_range_selection_is_ignored_until_complete(self):
        filtered = filter_events(self.frame, date_range=(date(2026, 10, 19),))
        self.assertEqual(len(filtered), 3)

    def test_timeline_uses_fine_bins_and_handles_empty_timestamps(self):
        timeline, interval = timeline_events(self.frame)
        self.assertEqual(interval, "Minute")
        self.assertEqual(int(timeline["events"].sum()), 2)
        self.assertEqual(int(timeline["events"].gt(0).sum()), 2)

        empty = build_event_frame([{"timestamp": "invalid"}])
        empty_timeline, empty_interval = timeline_events(empty)
        self.assertTrue(empty_timeline.empty)
        self.assertEqual(empty_interval, "Unavailable")

    def test_explanation_and_top_failed_ips_are_transparent(self):
        event = self.frame.iloc[0].to_dict()
        explanation = explain_event(event)
        self.assertIn("at least 5 failed attempts", explanation)
        top_ips = top_failed_ips(self.frame)
        self.assertEqual(top_ips.iloc[0]["Source IP"], "192.0.2.10")


if __name__ == "__main__":
    unittest.main()