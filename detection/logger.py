import json
import os
import datetime

import json
import os
import datetime

LOG_PATH_Power = "logs/power_detection.json"
os.makedirs(os.path.dirname(LOG_PATH_Power), exist_ok=True)

def log_event_to_json(event_type, device_id, value, avg, message):
    """
    Logs suspicious power-related events to a JSON file under logs/power_detection.json.
    """
    print(f"Logging event: {event_type}, Device ID: {device_id}, Value: {value}, Avg: {avg}, Message: {message}")
    
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": event_type,
        "device_id": device_id,
        "value": value,
        "average": avg,
        "message": message
    }

    # Create the log file if it doesn't exist
    if os.path.exists(LOG_PATH_Power):
        with open(LOG_PATH_Power, "r+", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
            data.append(log_entry)
            f.seek(0)
            f.truncate()
            json.dump(data, f, indent=4)
    else:
        with open(LOG_PATH_Power, "w", encoding="utf-8") as f:
            json.dump([log_entry], f, indent=4)




LOG_PATH_LOC = "logs/location_jump_log.json"
os.makedirs(os.path.dirname(LOG_PATH_LOC), exist_ok=True)

def jump_logger(user_id, old_ip, new_ip, distance_km, time_diff_seconds):
    """
    Logs a suspicious location jump where a user logs in from two distant locations
    within a short time window.
    """
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": "location_jump",
        "user_id": user_id,
        "previous_ip": old_ip,
        "current_ip": new_ip,
        "distance_km": round(distance_km, 2),
        "time_difference_seconds": round(time_diff_seconds, 2),
        "message": (
            f"User '{user_id}' logged in from two distant locations: "
            f"{old_ip} → {new_ip}, {distance_km:.2f} km apart in {time_diff_seconds:.1f}s"
        )
    }

    with open(LOG_PATH_LOC, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
