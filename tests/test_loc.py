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
    monkeypatch.setattr(loc_jump, "jump_logger", lambda user_id, last_ip, ip_address, distance_km, time_diff: logs.append({
    "event_type": "location_jump",
    "user_id": user_id,
    "from": last_ip,
    "to": ip_address,
    "distance_km": distance_km,
    "time_diff": time_diff,
    "message": f"User '{user_id}' jumped from {last_ip} to {ip_address}"
    }))



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
    monkeypatch.setattr(loc_jump, "jump_logger", lambda **kwargs: logs.append(kwargs))

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
    monkeypatch.setattr(loc_jump, "jump_logger", lambda **kwargs: logs.append(kwargs))

    loc_jump.jump_detection("user03", "1.1.1.2")

    assert len(logs) == 0


def test_location_jump_not_flagged_due_to_vpn(monkeypatch):
    coords_map = {
        "91.121.12.34": (48.8566, 2.3522),       # Paris (VPN)
        "2.2.2.2": (40.7128, -74.0060),          # New York
    }
    monkeypatch.setattr(loc_jump, "get_coords", lambda ip: coords_map[ip])

    # Mock known VPN check to match one IP
    monkeypatch.setattr(loc_jump, "is_known_vpn", lambda ip: ip == "91.121.12.34")

    # Setup mock time (30 seconds apart)
    base_time = datetime.datetime(2025, 5, 30, 12, 0, 0)

    # Mock time for first login
    monkeypatch.setattr(loc_jump, "datetime", types.SimpleNamespace(
        datetime=type("MockDateTime", (datetime.datetime,), {
            "now": classmethod(lambda cls: base_time)
        })
    ))
    loc_jump.jump_detection("user04", "91.121.12.34")

    # Mock time for second login 30s later
    monkeypatch.setattr(loc_jump, "datetime", types.SimpleNamespace(
        datetime=type("MockDateTimeLater", (datetime.datetime,), {
            "now": classmethod(lambda cls: base_time + datetime.timedelta(seconds=30))
        })
    ))

    logs = []
    monkeypatch.setattr(loc_jump, "jump_logger", lambda *args, **kwargs: logs.append(kwargs))

    loc_jump.jump_detection("user04", "2.2.2.2")

    # Should NOT be flagged due to known VPN
    assert len(logs) == 0


def test_first_login_never_flags(monkeypatch):
    logs = []

    monkeypatch.setattr(loc_jump, "get_coords", lambda ip: (0, 0))  # Dummy
    monkeypatch.setattr(loc_jump, "jump_logger", lambda **kwargs: logs.append(kwargs))

    base_time = datetime.datetime(2025, 5, 30, 12, 0, 0)
    monkeypatch.setattr(datetime, "datetime", type("MockDateTime", (datetime.datetime,), {
        "now": classmethod(lambda cls: base_time)
    }))

    loc_jump.jump_detection("user01", "1.1.1.1")
    assert len(logs) == 0
