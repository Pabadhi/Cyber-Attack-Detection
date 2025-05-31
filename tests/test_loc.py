import pytest
import datetime
import types
from detection import location_jump_detection as loc_jump


@pytest.fixture(autouse=True)
def reset_login_map():
    loc_jump.last_login_map.clear()


def test_location_jump_flagged(monkeypatch):
    coords_map = {
        "1.1.1.1": (37.7749, -122.4194),  # SF
        "2.2.2.2": (40.7128, -74.0060),   # NY
    }
    monkeypatch.setattr(loc_jump, "get_coords", lambda ip: coords_map[ip])

    base_time = datetime.datetime(2025, 5, 30, 12, 0, 0)

    # First mocked datetime class
    class MockDateTime(datetime.datetime):
        @classmethod
        def now(cls):
            return base_time

    # Create fake datetime module
    fake_datetime = types.SimpleNamespace(datetime=MockDateTime)
    monkeypatch.setattr(loc_jump, "datetime", fake_datetime)

    loc_jump.jump_detection("user01", "1.1.1.1")

    # Second mocked datetime class, 30 seconds later
    class MockDateTimeLater(datetime.datetime):
        @classmethod
        def now(cls):
            return base_time + datetime.timedelta(seconds=30)

    # Update fake datetime module
    fake_datetime.datetime = MockDateTimeLater
    monkeypatch.setattr(loc_jump, "datetime", fake_datetime)

    logs = []
    monkeypatch.setattr(loc_jump, "log_event_to_json", lambda **kwargs: logs.append(kwargs))

    loc_jump.jump_detection("user01", "2.2.2.2")

    assert len(logs) == 1
    assert logs[0]["event_type"] == "location_jump"
    assert "user01" in logs[0]["message"]
    print(logs[0])


def test_location_jump_not_flagged_due_to_time(monkeypatch):
    coords_map = {
        "1.1.1.1": (37.7749, -122.4194),
        "2.2.2.2": (40.7128, -74.0060),
    }
    monkeypatch.setattr(loc_jump, "get_coords", lambda ip: coords_map[ip])

    base_time = datetime.datetime(2025, 5, 30, 12, 0, 0)
    monkeypatch.setattr(datetime, "datetime", type("MockDateTime", (datetime.datetime,), {
        "now": classmethod(lambda cls: base_time)
    }))

    loc_jump.jump_detection("user02", "1.1.1.1")

    # Now >60 seconds later (should NOT flag)
    datetime.datetime.now = classmethod(lambda cls: base_time + datetime.timedelta(seconds=120))

    logs = []
    monkeypatch.setattr(loc_jump, "log_event_to_json", lambda **kwargs: logs.append(kwargs))

    loc_jump.jump_detection("user02", "2.2.2.2")

    assert len(logs) == 0


def test_location_jump_not_flagged_due_to_distance(monkeypatch):
    coords_map = {
        "1.1.1.1": (37.7749, -122.4194),
        "1.1.1.2": (37.7750, -122.4195),  # Very close IP
    }
    monkeypatch.setattr(loc_jump, "get_coords", lambda ip: coords_map[ip])

    base_time = datetime.datetime(2025, 5, 30, 12, 0, 0)
    monkeypatch.setattr(datetime, "datetime", type("MockDateTime", (datetime.datetime,), {
        "now": classmethod(lambda cls: base_time)
    }))

    loc_jump.jump_detection("user03", "1.1.1.1")

    # 30s later, nearby IP
    datetime.datetime.now = classmethod(lambda cls: base_time + datetime.timedelta(seconds=30))

    logs = []
    monkeypatch.setattr(loc_jump, "log_event_to_json", lambda **kwargs: logs.append(kwargs))

    loc_jump.jump_detection("user03", "1.1.1.2")

    assert len(logs) == 0


def test_first_login_never_flags(monkeypatch):
    logs = []

    monkeypatch.setattr(loc_jump, "get_coords", lambda ip: (0, 0))  # Dummy
    monkeypatch.setattr(loc_jump, "log_event_to_json", lambda **kwargs: logs.append(kwargs))

    base_time = datetime.datetime(2025, 5, 30, 12, 0, 0)
    monkeypatch.setattr(datetime, "datetime", type("MockDateTime", (datetime.datetime,), {
        "now": classmethod(lambda cls: base_time)
    }))

    loc_jump.jump_detection("user01", "1.1.1.1")
    assert len(logs) == 0
