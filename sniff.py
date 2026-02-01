import pyshark

cap = pyshark.FileCapture('traffic.pcap')

for packet in cap:
    if 'IP' in packet:
        src = packet.ip.src
        dst = packet.ip.dst
        proto = packet.transport_layer
        print(src + " to " + dst + " using " + str(proto))
