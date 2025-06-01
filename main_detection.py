import datetime
from detection.location_jump_detection import jump_detection
from detection.rate_detection import detect_rate_anomalies
from detection.authentication import AttackDetector
from detection.power_detection import handle_power_reading
from detection.logger import log_event_to_json
from detection.request_rate_detection import track as track_request_rate  # 🆕 Import burst detection

# Instantiate global detectors
attack_detector = AttackDetector()

def detect_anomalies(event):
    """
    Unified detection handler for various events.
    Event dict should contain:
        - event_name: str ("login_attempt", "device_power", etc.)
        - user_id: str
        - ip_address or source_id: str
        - device_id: str
        - user_role: str
        - timestamp: float (Unix time)
        - context: dict (optional additional info)
    """
    event_name = event.get("event_name")
    user_id = event.get("user_id", "unknown")
    user_role = event.get("user_role", "USER")
    source_id = event.get("source_id") or event.get("ip_address")
    device_id = event.get("device_id")
    context = event.get("context", {})
    timestamp = event.get("timestamp", datetime.datetime.now().timestamp())
    dt_obj = datetime.datetime.fromtimestamp(timestamp)

    # login_attempt checks
    if event_name == "login_attempt":
        if source_id:
            jump_detection(user_id, source_id)

        attack_detector.instrument(event_name, user_role, user_id, source_id, dt_obj, context)
        # Track login request frequency
        track_request_rate(source_id or user_id, user_id)

    # control_command checks
    elif event_name == "control_command":
        detect_rate_anomalies(device_id, user_id, user_role, event_name, timestamp)
    
    elif event_name=="api_request":
        track_request_rate(device_id,user_id)

    # device_power checks
    elif event_name == "device_power":
        value = context.get("value")
        if value is not None:
            handle_power_reading(device_id, value, user_role)
            # Track power request frequency
            track_request_rate(device_id, user_id)

    # Unknown events
    else:
        log_event_to_json("unknown_event", device_id or user_id, 0, 0, f"Unknown event: {event_name}")



# if __name__ == "__main__":
#     sample_login = {
#         "event_name": "login_attempt",
#         "user_id": "alice123",
#         "ip_address": "91.121.12.34",
#         "source_id": "91.121.12.34",
#         "user_role": "admin",
#         "timestamp": datetime.datetime.now().timestamp(),
#         "context": {
#             "success": False
#         }
#     }

#     sample_power = {
#         "event_name": "device_power",
#         "device_id": "dev001",
#         "user_id": "bob",
#         "user_role": "USER",
#         "timestamp": datetime.datetime.now().timestamp(),
#         "context": {
#             "value": 250
#         }
#     }

#     sample_control = {
#         "event_name": "control_command",
#         "user_id": "alice123",
#         "device_id": "dev001",
#         "user_role": "admin",
#         "timestamp": datetime.datetime.now().timestamp(),
#     }

#     detect_anomalies(sample_login)
#     detect_anomalies(sample_power)
#     detect_anomalies(sample_control)
