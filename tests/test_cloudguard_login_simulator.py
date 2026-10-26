import unittest

from cloudguard_login_simulator import (
    create_failed_login_event,
    severity_for_failed_attempts,
)


class LoginSimulatorTests(unittest.TestCase):
    def test_fifth_failed_attempt_is_high(self):
        self.assertEqual(severity_for_failed_attempts(1), "Normal")
        self.assertEqual(severity_for_failed_attempts(2), "Normal")
        self.assertEqual(severity_for_failed_attempts(3), "Medium")
        self.assertEqual(severity_for_failed_attempts(4), "Medium")
        self.assertEqual(severity_for_failed_attempts(5), "High")
        self.assertEqual(severity_for_failed_attempts(8), "High")

    def test_event_has_only_simulated_metadata_and_no_password(self):
        event = create_failed_login_event("demo-user", "192.0.2.10", 5)
        self.assertEqual(event["severity"], "High")
        self.assertEqual(event["status"], "Failed")
        self.assertEqual(event["source"], "Login simulator")
        self.assertNotIn("password", event)
        self.assertTrue(event["event_id"].startswith("SIM-"))

    def test_rejects_invalid_count_username_and_ip(self):
        for count in (0, -1, True, 1.5):
            with self.subTest(count=count), self.assertRaises(ValueError):
                severity_for_failed_attempts(count)
        with self.assertRaises(ValueError):
            create_failed_login_event("", "192.0.2.10", 1)
        with self.assertRaises(ValueError):
            create_failed_login_event("demo-user", "not-an-ip", 1)


if __name__ == "__main__":
    unittest.main()