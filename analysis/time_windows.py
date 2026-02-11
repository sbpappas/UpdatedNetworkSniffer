from collections import defaultdict
from datetime import timedelta
from analysis.features import aggregate_by_ip

def window_packets(packets, window_size_seconds=30):
    # groups packets into fixed time windows.
    # returns dict: { window_start_time: [packets] }

    windows = defaultdict(list)

    for pkt in packets:
        ts = pkt["timestamp"]

        window_start = ts - timedelta(
            seconds=ts.second % window_size_seconds,
            microseconds=ts.microsecond
        )

        windows[window_start].append(pkt)
    return windows



def aggregate_by_window(packets, window_size_seconds=30):
    # aggregates traffic features per IP per time window.

    windows = window_packets(packets, window_size_seconds)
    windowed_features = {}

    for window_start, packets_in_window in windows.items():
        windowed_features[window_start] = aggregate_by_ip(packets_in_window)

    return windowed_features