from collections import defaultdict
from analysis.device_mappings import get_device_name

# run with 

def aggregate_by_ip(packets):
    # takes a bunch of packets and divides them by source IP
    
    features = defaultdict(lambda: { #lambda creates a new dict for each new key so we do not have key erros
        "packets_sent": 0,
        "packets_received": 0,
        "bytes_sent": 0,
        "bytes_received": 0,
        "unique_dst_ports": set(),
        "protocols_used": set(),
    })

    for pkt in packets:

        get_device_name(pkt["src_ip"])
        get_device_name(pkt["dst_ip"])

        src = pkt["src_ip"]
        dst = pkt["dst_ip"]
        length = pkt["length"]
        proto = pkt["protocol"]
        dst_port = pkt["dst_port"]

        # source IP behavior
        features[src]["packets_sent"] += 1
        features[src]["bytes_sent"] += length #see bytes sent
        if dst_port:
            features[src]["unique_dst_ports"].add(dst_port)
        if proto:
            features[src]["protocols_used"].add(proto)

        # destination IP behavior
        features[dst]["packets_received"] += 1
        features[dst]["bytes_received"] += length
        if proto:
            features[dst]["protocols_used"].add(proto)

        #TODO: add ability to track packets received ports?
        #TODO: match IP to machine 

    return features