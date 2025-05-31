import datetime
from detection.config import DEVICE_INFO

def is_business_hours():
    now = datetime.datetime.now()
    return now.weekday() < 5 and 8 <= now.hour <= 18

def is_time_allowed(device_id):
    now_hour = datetime.datetime.now().hour
    device = DEVICE_INFO.get(device_id, {})
    allowed_times = device.get("allowed_times")
    return allowed_times is None or allowed_times[0] <= now_hour <= allowed_times[1]
