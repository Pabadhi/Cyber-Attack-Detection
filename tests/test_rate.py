import unittest
from detection.rate_detection import detect_rate_anomalies
from detection.config import ROLES

class TestRateAnomalyDetector(unittest.TestCase):

    def test_failed_login_admin(self):
        role = "admin"
        user_id = "admin_user"
        device_id = "deviceX"
        base_time = 1000000

        # 11 failed logins within 1 min → threshold is 10
        is_anomaly = False
        for i in range(11):
            is_anomaly = detect_rate_anomalies(device_id, user_id, role, "login", base_time + i)
        self.assertTrue(is_anomaly)

    def test_control_command_guest(self):
        role = "guest"
        user_id = "guest_user"
        device_id = "deviceY"
        base_time = 2000000

        # 6 control commands within 30s → threshold is 5
        is_anomaly = False
        for i in range(6):
            is_anomaly = detect_rate_anomalies(device_id, user_id, role, "control_command", base_time + i)
        self.assertTrue(is_anomaly)

    def test_no_anomaly_for_user_login(self):
        role = "user"
        user_id = "normal_user"
        device_id = "deviceZ"
        base_time = 3000000

        # 4 logins → below threshold of 5
        is_anomaly = False
        for i in range(4):
            is_anomaly = detect_rate_anomalies(device_id, user_id, role, "login", base_time + i)
        self.assertFalse(is_anomaly)

    def test_no_anomaly_for_admin_commands(self):
        role = "admin"
        user_id = "admin1"
        device_id = "deviceA"
        base_time = 4000000

        # 10 control commands → equals threshold
        is_anomaly = False
        for i in range(10):
            is_anomaly = detect_rate_anomalies(device_id, user_id, role, "control_command", base_time + i)
        self.assertFalse(is_anomaly)  # Should not flag until 11th

        # 11th command causes anomaly
        is_anomaly = detect_rate_anomalies(device_id, user_id, role, "control_command", base_time + 29)
        self.assertTrue(is_anomaly)

if __name__ == '__main__':
    unittest.main()
