import pyshark

PCAP_FILE = "data/traffic.pcap"

def parse_packets(pcap_file):
    cap = pyshark.FileCapture(
        pcap_file,
        keep_packets=False
    )

    for packet in cap:
        try:
            if "IP" not in packet:
                continue

            yield {
                "timestamp": packet.sniff_time,
                "src_ip": packet.ip.src,
                "dst_ip": packet.ip.dst,
                "protocol": packet.transport_layer,
                "length": int(packet.length),
                "src_port": getattr(packet[packet.transport_layer], "srcport", None)
                if packet.transport_layer else None,
                "dst_port": getattr(packet[packet.transport_layer], "dstport", None)
                if packet.transport_layer else None,
            }

        except Exception:
            continue
