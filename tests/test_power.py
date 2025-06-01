import pytest
import datetime
from collections import deque
from unittest.mock import patch
from detection.logger import log_event_to_json as real_log_event_to_json
from detection.power_detection import (
    handle_power_reading,
    power_history,
    active_sessions,
    device_modes,
    MAX_HISTORY,
)

# ---- Simulate time context ----
class MockDateTime(datetime.datetime):
    forced_hour = None

    @classmethod
    def now(cls):
        now = super().now()
        if cls.forced_hour is not None:
            return now.replace(hour=cls.forced_hour)
        return now

datetime.datetime = MockDateTime  # Apply patch globally

# ---- Reset context before and after each test ----
@pytest.fixture(autouse=True)
def reset_context():
    power_history.clear()
    active_sessions.clear()
    device_modes.clear()
    MockDateTime.forced_hour = None
    yield
    power_history.clear()
    active_sessions.clear()
    device_modes.clear()

# ---- Shared sample history ----
def setup_sample_history(device_id="heater01", values=None):
    if values is None:
        values = [100, 105, 110, 108, 115]
    power_history[device_id] = deque(values, maxlen=MAX_HISTORY)

# ---- Parameterized detection tests ----

@pytest.mark.parametrize("desc,value,sessions,role,mode,force_time,should_flag,event_type", [
    # Normal behavior - should NOT be flagged
    ("Normal reading in range", 110, 2, "USER", "normal", None, False, None),

    # Invalid reading: zero
    ("Zero reading", 0, 1, "USER", "normal", None, True, "invalid_reading"),

    # Invalid reading: negative
    ("Negative reading", -10, 1, "USER", "normal", None, True, "invalid_reading"),

    # Power spike with low sessions and normal user
    ("Spike with low sessions and not admin", 2000, 1, "USER", "normal", None, True, "power_spike"),

    # Power spike with high session count – should NOT be flagged
    ("Spike with high sessions", 2000, 5, "USER", "boost", None, False, None),

    # Power spike by ADMIN – should NOT be flagged
    ("Spike by ADMIN", 2000, 1, "ADMIN", "normal", None, False, None),
    
    # Spike within mode range but suspicious context
    ("Spike inside mode range but outside time, low sessions", 1700, 1, "USER", "boost", 3, True, "power_spike"),
    
    # Spike inside mode range, allowed time — normal
    ("Spike inside mode range during allowed time", 1700, 1, "USER", "boost", 8, False, None),
    
    # Spike inside mode range, enough sessions — normal
    ("Spike inside mode range with high sessions", 1700, 5, "USER", "boost", 3, False, None),

    # Above max_expected
    ("Above max_expected", 2500, 1, "USER", "boost", None, True, "power_spike"),

    # Outside mode range
    ("Outside mode range", 1400, 1, "USER", "idle", None, True, "power_spike"),

    # Spike outside allowed time – should be flagged
    ("Spike outside allowed time", 2000, 1, "USER", "normal", 3, True, "power_spike"),

    # Spike inside allowed time – should NOT be flagged
    ("Spike inside allowed time", 2000, 1, "USER", "normal", 6, False, None),
])


@patch("detection.power_detection.log_event_to_json")
def test_power_detection_cases(mock_log, desc, value, sessions, role, mode, force_time, should_flag, event_type):
    """
    Generalized test that runs all intrusion and non-intrusion cases for power anomaly detection.
    It uses a mock to verify behavior AND logs the real data for screenshots.
    """
    # Setup mock to ALSO log to real file
    mock_log.side_effect = real_log_event_to_json

    device_id = "heater01"
    setup_sample_history(device_id)
    active_sessions[device_id] = sessions
    device_modes[device_id] = mode
    MockDateTime.forced_hour = force_time

    # Run the function under test
    handle_power_reading(device_id, value, user_role=role)

    # Assertions based on expected behavior
    if should_flag:
        assert mock_log.called, f"{desc} should have triggered a log"
        assert mock_log.call_args[0][0] == event_type, f"{desc} should log event type {event_type}"
    else:
        mock_log.assert_not_called(), f"{desc} should not have triggered any log"

# ---- Additional test: Initialization of power history ----

def test_history_initialization_for_new_device():
    """
    Tests that a new device ID initializes its power history correctly.
    """
    device_id = "new_device"
    value = 150
    user_role = "USER"

    if device_id in power_history:
        del power_history[device_id]

    handle_power_reading(device_id, value, user_role)

    assert device_id in power_history
    assert value in power_history[device_id]

