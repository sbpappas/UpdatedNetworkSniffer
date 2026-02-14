# key for common device IPs

from datetime import datetime

DEVICE_MAP = {
    "192.168.1.68": "My iPhone 13",
    "192.168.1.77": "Samsung Smart TV",
    "192.168.1.69": "My MacBook Pro",
    "192.168.1.254": "AT&T Router",
    "192.168.1.72": "Dell Work Laptop",
}


UNKNOWN_DEVICES = {}

def get_device_name(ip):
    
    # returns friendly device name.
    # tracks unknown devices automatically.

    if ip in DEVICE_MAP:
        return DEVICE_MAP[ip]

    # Track unknown device
    if ip not in UNKNOWN_DEVICES:
        UNKNOWN_DEVICES[ip] = {
            "first_seen": datetime.now(),
            "packet_count": 0
        }

    UNKNOWN_DEVICES[ip]["packet_count"] += 1

    return f"Unknown Device ({ip})"


def get_unknown_devices():
    return UNKNOWN_DEVICES