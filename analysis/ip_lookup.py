import socket

DNS_CACHE = {}

def reverse_dns_lookup(ip):

    # performs reverse DNS lookup, uuses caching to avoid repeated lookups


    if ip in DNS_CACHE:
        return DNS_CACHE[ip]

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = None

    DNS_CACHE[ip] = hostname
    return hostname

def get_ip_label(ip, mode="ip"):
    """
    mode:
        "ip" → returns raw IP
        "hostname" → returns reverse DNS hostname if available
    """

    if mode == "hostname": 
        hostname = reverse_dns_lookup(ip)
        if hostname:
            return hostname

    return ip
