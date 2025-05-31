from detection.config import DEVICE_INFO, MODE_POWER_RANGES, ROLES
from detection.context import is_time_allowed, is_business_hours
from detection.logger_rate import log_event_to_json

import time
from collections import deque, defaultdict
import unittest

class RateAnomalyDetector:
    def __init__(self, user_role="guest", device_id=None):
        self.device_ID = device_id
        self.user = user_role
        self.failed_logins = defaultdict(deque)
        self.control_commands = defaultdict(deque)
        self.login_threshold = ROLES.get(self.user, {}).get("login_count_per_min")
        self.command_threshold = ROLES.get(self.user, {}).get("control_commands_per_min")

    def record_failed_login(self, user_id, device_id, timestamp=None):
        timestamp = timestamp or time.time()
        logins = self.failed_logins[user_id]
        logins.append(timestamp)
        # Keep only recent logins within 60s
        while logins and (timestamp - logins[0]) > 60:
            logins.popleft()
        is_detected = len(logins) > self.login_threshold
        if is_detected:
            # Log the event if anomaly is detected
            log_event_to_json(event_type="failed_login", device_id=device_id, value=str(self.login_threshold), message=f"User {user_id} exceeded login attempts in 60 seconds from device {device_id}. User role: {self.user} is not allowed to login more than {self.login_threshold} times in a minute.")
            print(f"User {user_id} exceeded login attempts in 60 seconds from device {device_id}. User role: {self.user} is not allowed to login more than {self.login_threshold} times in a minute.")
            return is_detected
        return False
    def record_control_command(self, device_id, timestamp=None):
        timestamp = timestamp or time.time()
        commands = self.control_commands[device_id]
        commands.append(timestamp)
        # Keep only recent commands within 30s
        while commands and (timestamp -     commands[0]) > 30:
            commands.popleft()
        is_detected = len(commands) > self.command_threshold
        if is_detected:
            # Log the event if anomaly is detected
            log_event_to_json(event_type="control_command", device_id=device_id, value=str(self.command_threshold), message=f"Device {device_id} exceeded control commands in 30 seconds. User role: {self.user} is not allowed to send more than {self.command_threshold} control commands in a 30s.")
            print(f"Device {device_id} exceeded control commands in 30 seconds. User role: {self.user} is not allowed to send more than {self.command_threshold} control commands in a 30s.")
            return is_detected
        return False

def detect_rate_anomalies(device_id, user_id, user_role, action_type, timestamp=None):
    detector = RateAnomalyDetector(user_role=user_role, device_id=device_id)
    detector.device_ID = device_id
    detector.user = user_role

    if action_type == "login":
        if detector.record_failed_login(user_id, timestamp):
            print(f"Rate anomaly detected for user {user_id} on device {device_id} at {timestamp}")
            log_event_to_json("rate_anomaly", device_id, "failed_login", 0, f"User {user_id} exceeded login attempts")
            return True
    elif action_type == "control_command":
        if detector.record_control_command(device_id, timestamp):
            print(f"Rate anomaly detected for device {device_id} at {timestamp}")
            log_event_to_json("rate_anomaly", device_id, "control_command", 0, f"Device {device_id} exceeded control commands")
            return True
    return False