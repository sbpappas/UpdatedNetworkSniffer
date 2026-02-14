#make the html report with charts and tables summarizing the detections and traffic patterns

import os
from analysis.parser import parse_packets
from analysis.time_windows import aggregate_by_window
from analysis.detections.port_scan_windowed import detect_windowed_port_scans
from analysis.device_mappings import get_unknown_devices


from reporting.traffic_charts import (
    plot_packets_sent_per_host,
    plot_unique_ports_per_host,
    plot_protocol_distribution, 
    plot_packet_size_distribution,
    plot_bytes_sent_received
)
from reporting.report_builder import build_html_report

OUTPUT_DIR = "reporting/output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

packets = list(parse_packets("data/traffic.pcap"))

windowed_features = aggregate_by_window(packets, 30)
alerts = detect_windowed_port_scans(
    windowed_features,
    port_threshold=8,
    packet_threshold=30
)

# for visualization, aggregate full dataset
from analysis.features import aggregate_by_ip
features = aggregate_by_ip(packets)

plot_packets_sent_per_host(
    features,
    alerts,
    save_path=os.path.join(OUTPUT_DIR, "packets_per_host.png")
)

plot_unique_ports_per_host(
    features,
    alerts,
    save_path=os.path.join(OUTPUT_DIR, "unique_ports.png")
)

plot_protocol_distribution(
    packets,
    save_path=os.path.join(OUTPUT_DIR, "protocol_distribution.png")
)

plot_packet_size_distribution(
    packets,
    save_path=os.path.join(OUTPUT_DIR, "packet_size_distribution.png")
)

plot_bytes_sent_received(
    features,
    save_path=os.path.join(OUTPUT_DIR, "bytes_sent_received.png")
)

unknown_devices = get_unknown_devices()



#build_html_report(alerts, unknown_devices, OUTPUT_DIR)

report_path = build_html_report(alerts, unknown_devices, OUTPUT_DIR)

print(f"\nReport generated: {report_path}")
