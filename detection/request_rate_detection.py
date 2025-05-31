"""
Detects bursts of *any* event (toggle, API call, login, …) that exceed a
reasonable rate.  Adapt WINDOW_SEC / MAX_REQ as needed.

Add one line in each hot-spot handler:

    request_rate_detection.track("heater01", user_id="bob")

The rest is automatic.
"""
from collections import deque
# from datetime import datetime, timezone
import datetime as dt
from detection.logger import log_event_to_json         # existing helper :contentReference[oaicite:0]{index=0}

# --- tunables ---------------------------------------------------------------
WINDOW_SEC = 60          # sliding window length
MAX_REQ    = 30          # >30 events in WINDOW_SEC triggers alert
HARD_CAP   = 100         # hard fail-safe to avoid memory blow-up
# ---------------------------------------------------------------------------

_history = {}             # device_id → deque[timestamps]


def _now():
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)


def track(device_id: str, user_id: str = "unknown") -> None:
    """
    Call this for *every* action you consider significant.
    Example: every REST request, MQTT message, or device toggle.
    """
    ts = _now()
    buf = _history.setdefault(device_id, deque())
    buf.append(ts)

    # prune old entries
    while buf and (ts - buf[0]).total_seconds() > WINDOW_SEC:
        buf.popleft()

    # protect against DoS filling RAM
    if len(buf) > HARD_CAP:
        buf.clear()

    if len(buf) > MAX_REQ:
        log_event_to_json(
            "request_burst",                   # event_type
            device_id,
            len(buf),                          # value = number of reqs
            MAX_REQ,                           # average slot reused for threshold
            f"{len(buf)} requests in {WINDOW_SEC}s by user '{user_id}' "
            f"(allowed ≤ {MAX_REQ})"
        )
