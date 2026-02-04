from parser import parse_packets
from features import aggregate_by_ip
from detections.port_scan import detect_port_scans

packets = list(parse_packets("data/traffic.pcap"))
features = aggregate_by_ip(packets)

alerts = detect_port_scans(features)

if not alerts:
    print("✅ No port scans detected.")
else:
    print("⚠️ Potential port scans detected:\n")
    for alert in alerts:
        print(f"Source IP: {alert['source_ip']}")
        print(f"  Unique ports: {alert['unique_ports']}")
        print(f"  Packets sent: {alert['packets_sent']}")
        print(f"  Severity: {alert['severity']}")
        print(f"  Description: {alert['description']}")
        print()