from collections import deque
from detection.config import DEVICE_INFO, MODE_POWER_RANGES
from detection.context import is_time_allowed, is_business_hours
from detection.logger import log_event_to_json

MAX_HISTORY = 10
power_history = {}
active_sessions = {}
device_modes = {}

def handle_power_reading(device_id, value, user_role="USER"):
    if value <= 0:
        log_event_to_json("invalid_reading", device_id, value, 0, "Invalid power reading")
        return

    if device_id not in power_history:
        power_history[device_id] = deque(maxlen=MAX_HISTORY)

    history = power_history[device_id]
    avg = sum(history) / len(history) if history else 0

    # Context
    is_admin = user_role in ["ADMIN", "MANAGER"]
    time_allowed = is_time_allowed(device_id)
    business_hours = is_business_hours()
    device_info = DEVICE_INFO.get(device_id, {})
    max_expected = device_info.get("max_expected", float("inf"))
    sessions = active_sessions.get(device_id, 0)
    mode = device_modes.get(device_id, "normal")
    expected_range = MODE_POWER_RANGES.get(device_id, {}).get(mode, (0, float("inf")))

    # Detection
    spike = avg > 0 and value > 1.5 * avg
    exceeds_max = value > max_expected
    outside_mode_range = not (expected_range[0] <= value <= expected_range[1])

    if spike or exceeds_max or outside_mode_range:
        suspicious = not (is_admin or (time_allowed) or (sessions > 2 and not exceeds_max))
        if suspicious:
            reasons = []
            if spike: reasons.append("Significant spike")
            if exceeds_max: reasons.append(f"Exceeds max_expected ({max_expected})")
            if outside_mode_range: reasons.append(f"Outside mode range {expected_range}")
            if sessions <= 2: reasons.append(f"{sessions} active sessions")
            log_event_to_json("power_spike", device_id, value, avg, "; ".join(reasons))

    history.append(value)
