from collections import defaultdict
import statistics

MIN_CONNECTIONS = 5
STD_THRESHOLD = 2  # seconds tolerance


def detect_beaconing(packets):
    # detect periodic connections to the same ip, returns list of alert dicts

    connections = defaultdict(list)

    # get timestamps per src->dst
    for pkt in packets:
        src = pkt["src_ip"]
        dst = pkt["dst_ip"]
        timestamp = pkt["timestamp"]

        connections[(src, dst)].append(timestamp)

    alerts = []

    for (src, dst), timestamps in connections.items():

        if len(timestamps) < MIN_CONNECTIONS:
            continue

        timestamps.sort()

        intervals = [
            (timestamps[i] - timestamps[i - 1]).total_seconds()
            for i in range(1, len(timestamps))
        ]

        if len(intervals) < 2:
            continue

        std_dev = statistics.stdev(intervals)

        if std_dev < STD_THRESHOLD:
            alerts.append({
                "type": "BEACONING",
                "source_ip": src,
                "destination_ip": dst,
                "connection_count": len(timestamps),
                "interval_std_dev": round(std_dev, 2),
                "severity": "HIGH"
            })

    return alerts
