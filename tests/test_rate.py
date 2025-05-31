import unittest
from detection.rate_detection import RateAnomalyDetector

from detection.config import ROLES

class TestRateAnomalyDetector(unittest.TestCase):

    def test_failed_login_admin(self):
        detector = RateAnomalyDetector(user_role="admin", device_id="deviceX")
        user_id = "admin_user"
        device_id = "deviceX"
        base_time = 1000000

        is_anomaly = False
        for i in range(11):  # Threshold is 10
            is_anomaly = detector.record_failed_login(user_id, device_id, base_time + i)
        self.assertTrue(is_anomaly)

    def test_control_command_guest(self):
        detector = RateAnomalyDetector(user_role="guest", device_id="deviceY")
        user_id = "guest_user"
        device_id = "deviceY"
        base_time = 2000000

        is_anomaly = False
        for i in range(6):  # Threshold is 5
            is_anomaly = detector.record_control_command(device_id, base_time + i)
        self.assertTrue(is_anomaly)

    def test_no_anomaly_for_user_login(self):
        detector = RateAnomalyDetector(user_role="user", device_id="deviceZ")
        user_id = "normal_user"
        device_id = "deviceZ"
        base_time = 3000000

        is_anomaly = False
        for i in range(4):  # Below threshold
            is_anomaly = detector.record_failed_login(user_id, device_id, base_time + i)
        self.assertFalse(is_anomaly)

    def test_no_anomaly_for_admin_commands(self):
        detector = RateAnomalyDetector(user_role="admin", device_id="deviceA")
        user_id = "admin1"
        device_id = "deviceA"
        base_time = 4000000

        for i in range(10):  # At threshold
            is_anomaly = detector.record_control_command(device_id, base_time + i)
        self.assertFalse(is_anomaly)  # Should not trigger yet

        is_anomaly = detector.record_control_command("deviceA", base_time + 29)
        self.assertTrue(is_anomaly)  # Should trigger


if __name__ == '__main__':
    unittest.main()
