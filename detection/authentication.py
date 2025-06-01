import json
from datetime import datetime, timedelta
from collections import defaultdict
import os

class AttackDetector:
    def __init__(self, log_file='suspicious_events.json'):
        self.failed_attempts = defaultdict(list)
        self.failed_attempts_by_ip = defaultdict(list)  # IP -> list of (timestamp, userId)
        self.log_file = log_file
        self.logged_events = []
        self._load_existing_log()

    def _load_existing_log(self):
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    self.logged_events = json.load(f)
            except json.JSONDecodeError:
                self.logged_events = []

    def _log_event(self, reason, event_name, user_role, user_id, source_id, timestamp, context):
        log_entry = {
            "alert": reason,
            "event": event_name,
            "userId": user_id,
            "sourceId": source_id,
            "timestamp": timestamp.isoformat(),
            "context": context,
            "flagged": True
        }
        self.logged_events.append(log_entry)
        self.save_logs()

    

    def instrument(self, event_name, user_role, user_id, source_id, timestamp, context):
        if event_name != "login_attempt":
            return False

        flagged = False
        reason = ""

        # Case 1: Too many failed login attempts by user
        if not context.get("success", True):
            self.failed_attempts[user_id].append(timestamp)
            self.failed_attempts[user_id] = [
                t for t in self.failed_attempts[user_id] if timestamp - t <= timedelta(seconds=60)
            ]
            if len(self.failed_attempts[user_id]) > 5:
                flagged = True
                reason = "Brute force detected"

            # Case 3: Username enumeration from same IP (3+ different users in 5 minutes)
            self.failed_attempts_by_ip[source_id].append((timestamp, user_id))
            self.failed_attempts_by_ip[source_id] = [
                (t, u) for (t, u) in self.failed_attempts_by_ip[source_id]
                if timestamp - t <= timedelta(minutes=5)
            ]
            unique_users = {u for (t, u) in self.failed_attempts_by_ip[source_id]}
            if len(unique_users) >= 3:
                flagged = True
                reason = "Multiple accounts targeted from same IP"

        # Case 2: Login at suspicious hours
        hour = timestamp.hour
        if hour < 5 or hour >= 24:
            flagged = True
            reason = "Login at suspicious time"

        if flagged:
            self._log_event(reason, event_name, user_role, user_id, source_id, timestamp, context)

        return flagged


    def save_logs(self):
        with open(self.log_file, 'w') as f:
            json.dump(self.logged_events, f, indent=2)