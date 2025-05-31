import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.authentication import AttackDetector
from datetime import datetime, timedelta

def run_tests():
    detector = AttackDetector()

    print("Test 1: Normal Login (should not flag):")
    now = datetime.now()
    flagged = detector.instrument(
        "login_attempt", "USER", "user123", "192.168.10.1",
        now,
        {"success": True}
    )
    print(f"Flagged: {flagged}")

    print("\nTest 2: Only 3 failed logins (no flag expected):")
    now = datetime.now()
    for i in range(3):
        flagged = detector.instrument(
            "login_attempt", "USER", "user123", "192.168.1.10",
            now + timedelta(seconds=i * 10),
            {"success": False}
        )
        print(f"Attempt {i+1}, Flagged: {flagged}")

    print("\nTest 3: Too Many Failed Logins (should flag after 6th):")
    now = datetime.now()
    for i in range(6):
        flagged = detector.instrument(
            "login_attempt", "USER", "u2", "192.168.1.11",
            now + timedelta(seconds=i * 8),
            {"success": False}
        )
        print(f"Attempt {i+1}, Flagged: {flagged}")

    print("\nTest 4: Login at Unusual Time (2:00 AM):")
    late_night = datetime.now().replace(hour=2, minute=0, second=0)
    flagged = detector.instrument(
        "login_attempt", "USER", "u3", "10.0.0.2",
        late_night,
        {"success": True}
    )
    print(f"Login at 2:00 AM, Flagged: {flagged}")

    print("\nTest 5: 5 Failures Followed by Success (no flag expected):")
    now = datetime.now()
    for i in range(5):
        flagged = detector.instrument(
            "login_attempt", "USER", "user999", "192.168.1.15",
            now + timedelta(seconds=i * 8),
            {"success": False}
        )
        print(f"Attempt {i+1} (Failed), Flagged: {flagged}")

    flagged = detector.instrument(
        "login_attempt", "USER", "user999", "192.168.1.15",
        now + timedelta(seconds=50),
        {"success": False}
    )
    print(f"Attempt 6 (Success), Flagged: {flagged}")

    # Save all flagged events
    detector.save_logs()

if __name__ == "__main__":
    run_tests()
