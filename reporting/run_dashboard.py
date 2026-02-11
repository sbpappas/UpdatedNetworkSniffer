# basically just shows the two charts

from analysis.parser import parse_packets
from analysis.features import aggregate_by_ip
from analysis.detections.port_scan import detect_port_scans
from reporting.traffic_charts import plot_packets_sent_per_host
from reporting.traffic_charts import plot_unique_ports_per_host

packets = list(parse_packets("data/traffic.pcap"))
features = aggregate_by_ip(packets)

alerts = detect_port_scans(
    features,
    port_threshold=10,      # tune as needed
    packet_threshold=50
)

plot_packets_sent_per_host(features, alerts)
plot_unique_ports_per_host(features, alerts)

# run with python3 -m reporting.run_dashboard
# that allows us to run the file as a module so that the imports work correctly. 
# If we just run python3 reporting/run_dashboard.py, the imports will fail because
# the current directory won't be in the module search path. By using -m, we ensure
# that the current directory is treated as a package and the imports work as expected.