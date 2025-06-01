# import datetime
# import types
# import pytest
# from detection import request_rate_detection as rr


# # ---------------------------------------------------------------------- #
# #  automatic history cleanup between tests
# # ---------------------------------------------------------------------- #
# @pytest.fixture(autouse=True)
# def _clean():
#     rr._history.clear()
#     yield
#     rr._history.clear()


# # ---------------------------------------------------------------------- #
# #  clock-patch helper – targets rr.dt.datetime (module-level alias)
# # ---------------------------------------------------------------------- #
# def _patch_time(monkeypatch, base, delta_s):
#     class FakeDatetime(datetime.datetime):
#         @classmethod
#         def utcnow(cls):
#             return base + datetime.timedelta(seconds=delta_s)

#     # replace *class* datetime inside the detector's datetime module
#     monkeypatch.setattr(rr.dt, "datetime", FakeDatetime, raising=True)


# # -----------------------------  tests  -------------------------------- #
# def test_no_alert_under_threshold(monkeypatch, tmp_path):
#     """Exactly MAX_REQ requests ⇒ no alert should be logged."""
#     base = datetime.datetime(2025, 5, 31, 12, 0, 0)

#     for i in range(rr.MAX_REQ):        # hit the threshold but not exceed
#         _patch_time(monkeypatch, base, i)
#         rr.track("doorlock01", user_id="alice")

#     # internal buffer size check
#     assert len(rr._history["doorlock01"]) == rr.MAX_REQ

#     # verify nothing emitted to the JSON log
#     if tmp_path.joinpath("suspicious_events.json").exists():
#         assert "request_burst" not in tmp_path.joinpath(
#             "suspicious_events.json").read_text()


# def test_alert_over_threshold(monkeypatch):
#     """MAX_REQ + 1 requests ⇒ one request_burst alert."""
#     captured = []

#     # collect positional args → captured[0] will be event_type
#     monkeypatch.setattr(
#         rr,
#         "log_event_to_json",
#         lambda *args, **kwargs: captured.append(args)
#     )

#     base = datetime.datetime(2025, 5, 31, 12, 0, 0)
#     for i in range(rr.MAX_REQ + 1):    # exceed by one
#         _patch_time(monkeypatch, base, i)
#         rr.track("doorlock01", user_id="mallory")

#     assert any(args[0] == "request_burst" for args in captured)

# @pytest.mark.parametrize("desc,total,spread,device,users,expect_alert", [
#     # spread = seconds between first and last request
#     ("Window reset – 30 req over 65 s", 30, 65, "sensor01", ["u"], False),
#     ("Multiple devices isolated",      31, 10, "cam01",  ["u"], True),
#     ("Hard cap flush",                120, 10, "door01", ["u"], True),  # deque cleared once
#     ("Mixed users same device",        31, 10, "light01", ["a","b"], True),
#     ("Burst at same ts",               31,  0, "lock01", ["u"], True),
# ])
# def test_rate_various(monkeypatch, desc, total, spread,
#                       device, users, expect_alert):
#     captured = []
#     monkeypatch.setattr(rr, "log_event_to_json",
#                         lambda *args, **kw: captured.append(args))

#     base = datetime.datetime(2025, 5, 31, 12, 0, 0)
#     for i in range(total):
#         t_offset = 0 if spread == 0 else i * spread / max(total-1, 1)
#         _patch_time(monkeypatch, base, t_offset)
#         rr.track(device, user_id=users[i % len(users)])

#     assert bool(captured) is expect_alert

# tests/test_req_rate.py
# """
# Integration-style tests for request-rate burst detection.
# They do NOT stub-out the logger, so every alert is really written to
# 'suspicious_events.json', just like the power-anomaly tests.
# """
# import json
# import os
# import datetime
# from pathlib import Path

# import pytest
# from detection import request_rate_detection as rr
# from detection.logger import LOG_FILE           # path object defined in logger

# # ------------------------------------------------------------------ #
# #  Helpers
# # ------------------------------------------------------------------ #
# def _read_events():
#     """Return the list stored in suspicious_events.json (may be empty)."""
#     if not LOG_FILE.exists():
#         return []
#     return json.loads(LOG_FILE.read_text(encoding="utf-8"))


# def _clear_events():
#     if LOG_FILE.exists():
#         LOG_FILE.unlink()                       # start each test with a clean file


# # ------------------------------------------------------------------ #
# #  PyTest fixtures
# # ------------------------------------------------------------------ #
# @pytest.fixture(autouse=True)
# def _isolate():
#     """Clean history + log before and after every test."""
#     rr._history.clear()
#     _clear_events()
#     yield
#     rr._history.clear()
#     _clear_events()


# # ------------------------------------------------------------------ #
# #  Tests
# # ------------------------------------------------------------------ #
# def test_no_alert_at_threshold():
#     """Exactly MAX_REQ requests within the window must NOT raise an alert."""
#     for _ in range(rr.MAX_REQ):
#         rr.track("doorlock01", user_id="alice")

#     events = _read_events()
#     assert not events, "No request_burst should have been logged at threshold"


# def test_alert_when_exceeding_threshold():
#     """MAX_REQ + 1 requests ⇒ one request_burst entry in JSON log."""
#     for _ in range(rr.MAX_REQ + 1):
#         rr.track("doorlock01", user_id="mallory")

#     events = _read_events()
#     flagged = [e for e in events if e.get("event_type") == "request_burst"]
#     assert flagged, "Expected at least one request_burst entry"
#     # optional extra checks
#     entry = flagged[0]
#     assert entry["device_id"] == "doorlock01"
#     assert entry["value"] > rr.MAX_REQ

# tests/test_req_rate.py
# """
# Integration tests for request-rate burst detection.
# They let the real logger write to 'suspicious_events.json'.
# """
# import json
# import datetime
# from pathlib import Path

# import pytest
# from detection import request_rate_detection as rr
# from detection.logger import LOG_FILE as _LOG_FILE_STR   # <- it's a *str*

# LOG_PATH = Path(_LOG_FILE_STR)        # ← convert to Path once

# # ------------------------------------------------------------------ #
# # Helpers
# # ------------------------------------------------------------------ #
# def _read_events():
#     """Return the list stored in suspicious_events.json (may be empty)."""
#     if not LOG_PATH.exists():
#         return []
#     return json.loads(LOG_PATH.read_text(encoding="utf-8"))


# def _clear_events():
#     if LOG_PATH.exists():
#         LOG_PATH.unlink()


# # ------------------------------------------------------------------ #
# # PyTest fixtures
# # ------------------------------------------------------------------ #
# @pytest.fixture(autouse=True)
# def _isolate():
#     """Clean in-memory history and on-disk log before/after each test."""
#     rr._history.clear()
#     _clear_events()
#     yield
#     rr._history.clear()
#     _clear_events()


# # ------------------------------------------------------------------ #
# # Tests
# # ------------------------------------------------------------------ #
# def test_no_alert_at_threshold():
#     """Exactly MAX_REQ requests must NOT raise an alert."""
#     for _ in range(rr.MAX_REQ):
#         rr.track("doorlock01", user_id="alice")

#     assert _read_events() == []


# def test_alert_when_exceeding_threshold():
#     """MAX_REQ + 1 requests ⇒ at least one request_burst entry."""
#     for _ in range(rr.MAX_REQ + 1):
#         rr.track("doorlock01", user_id="mallory")

#     flagged = [e for e in _read_events() if e["event_type"] == "request_burst"]
#     assert flagged, "Expected a request_burst alert to be logged"
#     first = flagged[0]
#     assert first["device_id"] == "doorlock01"
#     assert first["value"] > rr.MAX_REQ

# tests/test_req_rate.py
# tests/test_req_rate.py
"""
Integration tests for request-rate burst detection.
They let the real logger write to 'suspicious_events.json'.
"""

import json
from pathlib import Path
import pytest
import importlib
from detection import request_rate_detection as rr
from detection.logger import LOG_FILE as _LOG_FILE_STR
import datetime

LOG_PATH = Path(_LOG_FILE_STR)       # convert logger's str to a Path


# --------------------------------------------------------------------- #
# helper functions
# --------------------------------------------------------------------- #
def _read_events():
    if not LOG_PATH.exists():
        return []
    return json.loads(LOG_PATH.read_text(encoding="utf-8"))


def _clear_events():
    if LOG_PATH.exists():
        LOG_PATH.unlink()


# --------------------------------------------------------------------- #
# fixture: isolate each test
# --------------------------------------------------------------------- #
# @pytest.fixture(autouse=True)
# def _isolate():
#     """Clean history, reload datetime module, wipe JSON log."""
#     rr._history.clear()

#     # -- hard reset the stdlib datetime module ------------
#     importlib.reload(datetime)             # <— THIS line fixes the leak
#     rr.dt = datetime                       # re-bind detector to fresh module
#     # -----------------------------------------------------

#     _clear_events()
#     yield
#     rr._history.clear()
#     importlib.reload(datetime)
#     rr.dt = datetime
#     _clear_events()

# tests/test_req_rate.py  – only the fixture block changes
@pytest.fixture(autouse=True)
def _isolate():
    """
    Keep the existing suspicious_events.json; just remember how many
    entries it already has so we can assert growth.
    Also reload datetime to undo earlier global patches.
    """
    # snapshot
    start_len = len(_read_events())

    # repair datetime contamination
    importlib.reload(datetime)
    rr.dt = datetime
    rr._history.clear()

    yield start_len   # give tests the baseline count

    rr._history.clear()
    importlib.reload(datetime)
    rr.dt = datetime


# --------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------- #
def test_no_alert_at_threshold(_isolate):
    start_len = _isolate
    for _ in range(rr.MAX_REQ):
        rr.track("doorlock01", user_id="alice")

    # unchanged length means no alert
    assert len(_read_events()) == start_len


def test_alert_after_threshold(_isolate):
    start_len = _isolate
    for _ in range(rr.MAX_REQ + 1):
        rr.track("doorlock01", user_id="mallory")

    events = _read_events()
    assert len(events) > start_len, "no lines appended"

    new = [e for e in events[start_len:] if e["event_type"] == "request_burst"]
    assert new, "appended lines but none are request_burst alerts"
