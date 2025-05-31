import json
import os
import datetime

LOG_FILE = "suspicious_rate_events.json"

def log_event_to_json(event_type, device_id, value, message):
    print(f"Logging event: {event_type}, Device ID: {device_id}, Value: {value}, Message: {message}")
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": event_type,
        "device_id": device_id,
        "value": value,
        "message": message
    }

    # Ensure the file is not empty or invalid before loading
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r+", encoding='utf-8') as f:
            try:
                content = f.read().strip()
                data = json.loads(content) if content else []
            except json.JSONDecodeError:
                # Reset if file is corrupted
                data = []

            data.append(log_entry)
            f.seek(0)
            f.truncate()
            json.dump(data, f, indent=4)
    else:
        with open(LOG_FILE, "w", encoding='utf-8') as f:
            json.dump([log_entry], f, indent=4)
