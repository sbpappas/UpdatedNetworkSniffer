# key for common device IPs

DEVICE_MAP = {
    "192.168.1.68": "My iPhone 13",
    "192.168.1.77": "Samsung Smart TV",
    "192.168.1.69": "My MacBook Pro",
    "192.168.1.254": "AT&T Router",
    "192.168.1.72": "Dell Work Laptop",
}

def get_device_name(ip):
    return DEVICE_MAP.get(ip, f"Unknown Device ({ip})")