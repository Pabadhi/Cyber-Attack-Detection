import pytest
import datetime
from collections import deque
from detection.power_detection import handle_power_reading, power_history, active_sessions, device_modes, MAX_HISTORY

# Monkey-patch datetime to simulate time
class MockDateTime(datetime.datetime):
    forced_hour = None

    @classmethod
    def now(cls):
        now = super().now()
        if cls.forced_hour is not None:
            return now.replace(hour=cls.forced_hour)
        return now

# Inject the mock
datetime.datetime = MockDateTime

@pytest.mark.parametrize("desc,value,sessions,role,mode,force_time", [
    ("Normal reading in range", 110, 2, "USER", "normal", None),
    ("Zero reading", 0, 1, "USER", "normal", None),
    ("Negative reading", -10, 1, "USER", "normal", None),
    ("Spike with low sessions and not admin", 2000, 1, "USER", "normal", None),
    ("Spike with high sessions", 2000, 5, "USER", "boost", None),
    ("Spike by ADMIN", 2000, 1, "ADMIN", "normal", None),
    ("Above max_expected", 2500, 1, "USER", "boost", None),
    ("Outside mode range", 1400, 1, "USER", "idle", None),
    ("Spike outside allowed time", 2000, 1, "USER", "normal", 3),
    ("Spike inside allowed time", 2000, 1, "USER", "normal", 6)
])


def test_handle_power_reading(desc, value, sessions, role, mode, force_time):
    # Setup context
    sample_baseline = [100, 105, 110, 108, 115]
    power_history["heater01"] = deque(sample_baseline, maxlen=MAX_HISTORY)

    MockDateTime.forced_hour = force_time
    active_sessions["heater01"] = sessions
    device_modes["heater01"] = mode

    # Call the function (test passes if no exception is raised)
    handle_power_reading("heater01", value, user_role=role)

    # Optionally, you can assert log file contents or power_history if needed

@pytest.fixture(autouse=True)
def clear_power_history():
    power_history.clear()
    yield
    power_history.clear()

def test_history_initialization():
    device_id = "new_device"
    value = 150
    user_role = "USER"
    
    # Ensure it's not already in history
    if device_id in power_history:
        del power_history[device_id]
    
    handle_power_reading(device_id, value, user_role)
    
    assert device_id in power_history
    assert value in power_history[device_id]