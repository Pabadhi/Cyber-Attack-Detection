import pytest
import datetime

@pytest.fixture
def reset_login_map():
    from detection.location_jump_detection import last_login_map
    last_login_map.clear()

def test_location_jump_detection_flagged(monkeypatch, reset_login_map):
    from detection.location_jump_detection import jump_detection, last_login_map

    user_id = "test_user"
    ip1 = "192.168.1.1"
    ip2 = "10.0.0.2"
    base_time = datetime.datetime(2025, 5, 30, 12, 0, 0)

    class MockDateTime(datetime.datetime):
        @classmethod
        def now(cls):
            return base_time

    monkeypatch.setattr(datetime, "datetime", MockDateTime)

    jump_detection(user_id, ip1)

    # Simulate second login within 30 seconds from different IP
    MockDateTime.now = classmethod(lambda cls: base_time + datetime.timedelta(seconds=30))
    jump_detection(user_id, ip2)

    assert user_id in last_login_map

def test_location_jump_detection_not_flagged_same_ip(monkeypatch, reset_login_map):
    from detection.location_jump_detection import jump_detection, last_login_map

    user_id = "test_user"
    ip = "192.168.1.1"
    base_time = datetime.datetime(2025, 5, 30, 12, 0, 0)

    class MockDateTime(datetime.datetime):
        @classmethod
        def now(cls):
            return base_time

    monkeypatch.setattr(datetime, "datetime", MockDateTime)

    jump_detection(user_id, ip)

    # Second login from same IP within 30s should NOT trigger
    MockDateTime.now = classmethod(lambda cls: base_time + datetime.timedelta(seconds=30))
    jump_detection(user_id, ip)

    assert user_id in last_login_map

def test_location_jump_detection_not_flagged_after_window(monkeypatch, reset_login_map):
    from detection.location_jump_detection import jump_detection, last_login_map

    user_id = "test_user"
    ip1 = "192.168.1.1"
    ip2 = "10.0.0.2"
    base_time = datetime.datetime(2025, 5, 30, 12, 0, 0)

    class MockDateTime(datetime.datetime):
        @classmethod
        def now(cls):
            return base_time

    monkeypatch.setattr(datetime, "datetime", MockDateTime)

    jump_detection(user_id, ip1)

    # Simulate second login after 2 minutes (should NOT flag)
    MockDateTime.now = classmethod(lambda cls: base_time + datetime.timedelta(seconds=120))
    jump_detection(user_id, ip2)

    assert user_id in last_login_map
