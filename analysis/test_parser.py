from parser import parse_packets

count = 0

for pkt in parse_packets("data/traffic.pcap"): # print first 100 packets using the parser and yield!
    print(pkt)
    count += 1
    if count == 100:
        break

print(f"\nParsed {count} packets successfully.")
