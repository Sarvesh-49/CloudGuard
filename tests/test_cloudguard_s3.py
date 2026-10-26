import json
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock

from cloudguard_s3 import S3_PREFIX, archive_login_event, load_archived_login_events


class S3ArchiveTests(unittest.TestCase):
    def test_archive_writes_only_event_metadata_with_encryption(self):
        client = Mock()
        event = {
            "event_id": "SIM-test-1",
            "timestamp": "2026-10-26T12:00:00+00:00",
            "severity": "High",
            "status": "Failed",
            "failed_attempts": 5,
        }

        key = archive_login_event(event, "private-bucket", s3_client=client)

        self.assertTrue(key.startswith(S3_PREFIX))
        self.assertTrue(key.endswith("/SIM-test-1.json"))
        request = client.put_object.call_args.kwargs
        self.assertEqual(request["Bucket"], "private-bucket")
        self.assertEqual(request["ServerSideEncryption"], "AES256")
        self.assertEqual(json.loads(request["Body"]), event)
        self.assertNotIn("password", request["Body"].decode("utf-8").casefold())

    def test_archive_drops_unapproved_secret_fields(self):
        client = Mock()
        event = {
            "event_id": "SIM-test-2",
            "severity": "High",
            "password": "must-not-be-stored",
            "credential": "must-not-be-stored",
        }

        archive_login_event(event, "private-bucket", s3_client=client)

        stored = json.loads(client.put_object.call_args.kwargs["Body"])
        self.assertEqual(stored, {"event_id": "SIM-test-2", "severity": "High"})

    def test_archive_requires_bucket_and_event_id(self):
        with self.assertRaises(ValueError):
            archive_login_event({"event_id": "SIM-1"}, " ", s3_client=Mock())
        with self.assertRaises(ValueError):
            archive_login_event({"severity": "High"}, "private-bucket", s3_client=Mock())

    def test_load_reads_only_prefixed_events_and_marks_their_source(self):
        client = Mock()
        key = f"{S3_PREFIX}2026/10/26/SIM-test-1.json"
        client.list_objects_v2.return_value = {
            "Contents": [{"Key": key, "LastModified": datetime.now(timezone.utc)}]
        }
        client.get_object.return_value = {
            "Body": Mock(read=lambda: b'{"event_id":"SIM-test-1","severity":"High"}')
        }

        events = load_archived_login_events("private-bucket", s3_client=client)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "S3 login simulator")
        client.list_objects_v2.assert_called_once_with(
            Bucket="private-bucket",
            Prefix=S3_PREFIX,
            MaxKeys=100,
        )

    def test_unconfigured_bucket_returns_no_archived_events(self):
        self.assertEqual(load_archived_login_events(""), [])


if __name__ == "__main__":
    unittest.main()