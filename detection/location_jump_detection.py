import geoip2.database
from geopy.distance import geodesic
import datetime
from detection.logger import log_event_to_json
import time

# Tracks the last login IP and time per user
last_login_map = {}

# Max time (in seconds) allowed between IP changes before flagging

GEOIP_DB_PATH = 'GeoLite2-City.mmdb'
reader = geoip2.database.Reader(GEOIP_DB_PATH)

GEO_DISTANCE_THRESHOLD_KM = 100  # example: 100km
LOCATION_JUMP_WINDOW = 60  # 60 seconds


def get_coords(ip):
    try:
        response = reader.city(ip)
        return (response.location.latitude, response.location.longitude)
    except:
        return None

def jump_detection(user_id, ip_address):
    print(f"Checking location jump for user '{user_id}' with IP '{ip_address}'")
    now = datetime.datetime.now()
    
    if user_id in last_login_map:
        last_ip, last_time = last_login_map[user_id]
        time_diff = (now - last_time).total_seconds()
        # print(time_diff)
        if time_diff <= LOCATION_JUMP_WINDOW:
            coord1 = get_coords(last_ip)
            coord2 = get_coords(ip_address)
            # print(coord1, coord2)
            if coord1 and coord2:
                distance_km = geodesic(coord1, coord2).km
                # print(f"Distance between {last_ip} and {ip_address}: {distance_km:.1f} km")
                if distance_km > GEO_DISTANCE_THRESHOLD_KM:
                    # print("Location jump detected!")
                    log_event_to_json(
                        event_type="location_jump",
                        device_id="N/A",
                        value="N/A",
                        avg="N/A",
                        message=(
                            f"User '{user_id}' logged in from two distant locations "
                            f"{last_ip} → {ip_address} ({distance_km:.1f} km apart) in {time_diff:.1f}s"
                        )
                    )

    last_login_map[user_id] = (ip_address, now)

