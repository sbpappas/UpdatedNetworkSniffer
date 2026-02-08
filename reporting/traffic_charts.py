import matplotlib.pyplot as plt

def plot_packets_sent_per_host(features, alerts=None):
    
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
    plt.show()


    #TODO - add more charts, like unique ports contacted, bytes sent, etc.
    #TODO - add ability to filter by time range
    #TODO - make the chart better looking on the axes