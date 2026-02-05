from analysis.parser import parse_packets
from analysis.features import aggregate_by_ip
from reporting.traffic_charts import plot_packets_sent_per_host

packets = list(parse_packets("data/traffic.pcap"))
features = aggregate_by_ip(packets)

plot_packets_sent_per_host(features)

# run with python3 -m reporting.run_dashboard