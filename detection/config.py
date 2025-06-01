DEVICE_INFO = {
    "coffee_maker": {"max_expected": 1200, "allowed_times": (6, 9)},
    "fridge": {"max_expected": 500},
    "heater01": {"max_expected": 2000, "allowed_times": (5, 10)},
    "light01": {"max_expected": 100}
}

MODE_POWER_RANGES = {
    "heater01": {
        "idle": (0, 100),
        "normal": (100, 1500),
        "boost": (1500, 2000)
    }
}

ROLES = {
    "admin": {
        "can_view_logs": True,
        "can_manage_devices": True,
        "can_configure_network": True,
        "login_count_per_min": 10,
        "control_commands_per_min": 10
    },
    "user": {
        "can_view_logs": True,
        "can_manage_devices": True,
        "can_configure_network": False,
        "login_count_per_min": 5,
        "control_commands_per_min": 30        
    },
    "guest": {
        "can_view_logs": True,
        "can_manage_devices": False,
        "can_configure_network": False,
        "login_count_per_min": 2,
        "control_commands_per_min": 5
    }
}