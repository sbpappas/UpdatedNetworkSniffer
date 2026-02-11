from analysis.parser import parse_packets
from analysis.time_windows import aggregate_by_window
from analysis.detections.port_scan_windowed import detect_windowed_port_scans

packets = list(parse_packets("data/traffic.pcap"))

windowed_features = aggregate_by_window(
    packets,
    window_size_seconds=30
)

alerts = detect_windowed_port_scans(
    windowed_features,
    port_threshold=8,
    packet_threshold=30
)

if alerts:
    for alert in alerts:
        print(
            f"[{alert['window_start']}] "
            f"{alert['source_ip']} → "
            f"{alert['unique_ports']} ports "
            f"({alert['packets_sent']} packets)"
        )
else:
    print("✅ No port scans detected in any time window.")

