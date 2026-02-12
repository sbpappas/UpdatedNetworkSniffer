# key for common device IPs

DEVICE_MAP = {
    "192.168.1.68": "My iPhone 13",
    "192.168.1.77": "Samsung Smart TV",
    "192.168.1.69": "My MacBook Pro",
}

def get_device_name(ip):
    return DEVICE_MAP.get(ip, f"Unknown Device ({ip})")