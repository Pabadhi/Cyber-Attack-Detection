import datetime
import types
import pytest
from detection import request_rate_detection as rr


# ---------------------------------------------------------------------- #
#  automatic history cleanup between tests
# ---------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def _clean():
    rr._history.clear()
    yield
    rr._history.clear()


# ---------------------------------------------------------------------- #
#  clock-patch helper – targets rr.dt.datetime (module-level alias)
# ---------------------------------------------------------------------- #
def _patch_time(monkeypatch, base, delta_s):
    class FakeDatetime(datetime.datetime):
        @classmethod
        def utcnow(cls):
            return base + datetime.timedelta(seconds=delta_s)

    # replace *class* datetime inside the detector's datetime module
    monkeypatch.setattr(rr.dt, "datetime", FakeDatetime, raising=True)


# -----------------------------  tests  -------------------------------- #
def test_no_alert_under_threshold(monkeypatch, tmp_path):
    """Exactly MAX_REQ requests ⇒ no alert should be logged."""
    base = datetime.datetime(2025, 5, 31, 12, 0, 0)

    for i in range(rr.MAX_REQ):        # hit the threshold but not exceed
        _patch_time(monkeypatch, base, i)
        rr.track("doorlock01", user_id="alice")

    # internal buffer size check
    assert len(rr._history["doorlock01"]) == rr.MAX_REQ

    # verify nothing emitted to the JSON log
    if tmp_path.joinpath("suspicious_events.json").exists():
        assert "request_burst" not in tmp_path.joinpath(
            "suspicious_events.json").read_text()


def test_alert_over_threshold(monkeypatch):
    """MAX_REQ + 1 requests ⇒ one request_burst alert."""
    captured = []

    # collect positional args → captured[0] will be event_type
    monkeypatch.setattr(
        rr,
        "log_event_to_json",
        lambda *args, **kwargs: captured.append(args)
    )

    base = datetime.datetime(2025, 5, 31, 12, 0, 0)
    for i in range(rr.MAX_REQ + 1):    # exceed by one
        _patch_time(monkeypatch, base, i)
        rr.track("doorlock01", user_id="mallory")

    assert any(args[0] == "request_burst" for args in captured)
