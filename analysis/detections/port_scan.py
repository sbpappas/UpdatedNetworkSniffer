#make sure to run from the base directory NetworkSniffer

from collections import defaultdict

def detect_port_scans(features, port_threshold=2, packet_threshold=2):
    # parameters:
    # features (dict): Aggregated per-IP features
    # port_threshold (int): Unique destination ports threshold, so at least x ports contacted
    # packet_threshold (int): Minimum packets sent threshold, so at least y packets sent
    alerts = []

    for ip, data in features.items():
        unique_ports = len(data["unique_dst_ports"])
        packets_sent = data["packets_sent"]

        if unique_ports >= port_threshold and packets_sent >= packet_threshold:
            alerts.append({
                "type": "PORT_SCAN",
                "source_ip": ip,
                "unique_ports": unique_ports,
                "packets_sent": packets_sent,
                "severity": "HIGH" if unique_ports > port_threshold * 2 else "MEDIUM",
                "description": (
                    f"Host contacted {unique_ports} unique destination ports "
                    f"with {packets_sent} packets sent."
                )
            })
            #TODO - tell which ports were the unique ports
            #TODO - reference which machine this IP belongs to, if possible

    return alerts