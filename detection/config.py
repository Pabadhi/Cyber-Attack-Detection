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
        "boost": (1500, 2200)
    }
}
