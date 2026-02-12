# key for common device IPs

DEVICE_MAP = {
    "192.168.0.1": "Router",
    "192.168.0.100": "Laptop 12",
    "192.168.0.101": "Jim's Samsung Galaxy",
}

def get_device_name(ip):
    return DEVICE_MAP.get(ip, f"Unknown Device ({ip})")