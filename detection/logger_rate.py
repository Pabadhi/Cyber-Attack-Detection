import json
import os
import datetime

LOG_FILE = "suspicious_rate_events.json"

def log_event_to_json(event_type, device_id, value, avg, message):
    print(f"Logging event: {event_type}, Device ID: {device_id}, Value: {value}, Avg: {avg}, Message: {message}")
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": event_type,
        "device_id": device_id,
        "value": value,
        "average": avg,
        "message": message
    }
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r+") as f:
            data = json.load(f)
            data.append(log_entry)
            f.seek(0)
            json.dump(data, f, indent=4)
    else:
        with open(LOG_FILE, "w") as f:
            json.dump([log_entry], f, indent=4)
