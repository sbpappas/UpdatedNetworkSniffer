import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from collections import Counter
from analysis.device_mappings import get_device_name



def plot_packets_sent_per_host(features, alerts=None, save_path=None): # save path if we want to save the chart as an image instead of showing it
    
    #Displays packets sent per IP.
    #Highlights hosts flagged by detections.
    
    alerts = alerts or []
    flagged_ips = {alert["source_ip"] for alert in alerts}

    ips = []
    packets_sent = []
    colors = []

    for ip, data in features.items():
        ips.append(ip)
        packets_sent.append(data["packets_sent"])

        if ip in flagged_ips:
            colors.append("red")
        else:
            colors.append("blue")

    plt.figure()
    plt.bar(ips, packets_sent, color=colors)
    plt.xlabel("IP Address")
    plt.ylabel("Packets Sent")
    plt.title("Packets Sent per Host (Red = Port Scan Suspected)")
    plt.xticks(rotation=70)
    plt.tight_layout()
    if save_path:
        plt.savefig(save_path)
    else:
        plt.show()
    plt.close()



    #TODO - add more charts, like unique ports contacted, bytes sent, etc.
    #TODO - add ability to filter by time range
    #TODO - make the chart better looking on the axes - done

def plot_unique_ports_per_host(features, alerts=None, save_path=None):
    # Displays number of unique destination ports per IP.
    # Highlights hosts flagged by detections.


    alerts = alerts or []
    flagged_ips = {alert["source_ip"] for alert in alerts}

    ips = []
    unique_ports_counts = []
    colors = []

    for ip, data in features.items():
        ips.append(ip)
        unique_ports_counts.append(len(data["unique_dst_ports"]))

        if ip in flagged_ips:
            colors.append("red")
        else:
            colors.append("blue")

    fig, ax = plt.subplots()
    ax.bar(ips, unique_ports_counts, color=colors)

    ax.set_xlabel("IP Address")
    ax.set_ylabel("Unique Destination Ports")
    ax.set_title("Unique Destination Ports per Host (Red = Port Scan Suspected)")
    ax.xaxis.set_tick_params(rotation=70)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True)) # makes y-axis show only integer values
    plt.tight_layout()
    if save_path:
        plt.savefig(save_path)
    else:
        plt.show()
    plt.close()


def plot_protocol_distribution(packets, save_path=None):
    # pie chart of protocol usage.

    protocols = [pkt["protocol"] for pkt in packets if pkt["protocol"]]
    counts = Counter(protocols)

    labels = list(counts.keys())
    sizes = list(counts.values())

    plt.figure()
    plt.pie(sizes, labels=labels, autopct='%1.1f%%')
    plt.title("Protocol Distribution")

    if save_path:
        plt.savefig(save_path)
    else:
        plt.show()

    plt.close()

def plot_packet_size_distribution(packets, save_path=None):
    # chart of packet sizes

    sizes = [pkt["length"] for pkt in packets]

    plt.figure()
    plt.hist(sizes, bins=30)
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.title("Packet Size Distribution")

    if save_path:
        plt.savefig(save_path)
    else:
        plt.show()

    plt.close()

def plot_bytes_sent_received(features, save_path=None):
    # bar chart comparing bytes sent and received per host

    ips = []
    sent = []
    received = []

    for ip, data in features.items():
        ips.append(ip)
        sent.append(data["bytes_sent"])
        received.append(data["bytes_received"])

    x = range(len(ips))

    plt.figure()
    plt.bar(x, sent, label="Bytes Sent")
    plt.bar(x, received, bottom=sent, label="Bytes Received")

    plt.xticks(x, ips, rotation=45)
    plt.ylabel("Bytes")
    plt.title("Bytes Sent vs Received per Host")
    plt.legend()
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path)
    else:
        plt.show()

    plt.close()
