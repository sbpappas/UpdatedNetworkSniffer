import matplotlib.pyplot as plt

def plot_packets_sent_per_host(features):
    #packets per IP bar chart

    ips = []
    packets_sent = []

    for ip, data in features.items():
        ips.append(ip)
        packets_sent.append(data["packets_sent"])

    plt.figure()
    plt.bar(ips, packets_sent)
    plt.xlabel("IP Address")
    plt.ylabel("Packets Sent")
    plt.title("Packets Sent per Host")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
