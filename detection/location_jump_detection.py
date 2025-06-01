import geoip2.database
from geopy.distance import geodesic
import datetime
from detection.logger import jump_logger
import time

# Tracks the last login IP and time per user
last_login_map = {}

# Max time (in seconds) allowed between IP changes before flagging

GEOIP_DB_PATH = 'GeoLite2-City.mmdb'
reader = geoip2.database.Reader(GEOIP_DB_PATH)

GEO_DISTANCE_THRESHOLD_KM = 100  # example: 100km
LOCATION_JUMP_WINDOW = 60  # 60 seconds

KNOWN_VPN_IPS = {
    "91.121.12.34",
    "185.107.56.210",
    "203.0.113.5"
}

def is_known_vpn(ip_address):
    return ip_address in KNOWN_VPN_IPS


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
        
        if time_diff <= LOCATION_JUMP_WINDOW:
            coord1 = get_coords(last_ip)
            coord2 = get_coords(ip_address)
            
            if coord1 and coord2:
                distance_km = geodesic(coord1, coord2).km
                
                if (
                    distance_km > GEO_DISTANCE_THRESHOLD_KM and
                    not is_known_vpn(ip_address) and
                    not is_known_vpn(last_ip)
                ):
                    jump_logger(user_id, last_ip, ip_address, distance_km, time_diff)

    last_login_map[user_id] = (ip_address, now)


