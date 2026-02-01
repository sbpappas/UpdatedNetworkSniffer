from parser import parse_packets
from features import aggregate_by_ip

packets = list(parse_packets("data/traffic.pcap"))
features = aggregate_by_ip(packets)

for ip, data in list(features.items())[:5]: # elegant printing
    print(f"\nIP: {ip}")
    for k, v in data.items():
        if isinstance(v, set):
            print(f"  {k}: {len(v)}")
        else:
            print(f"  {k}: {v}")
