def detect_data_exfiltration(features):
    # detect hosts sending disproportionally large amounts of outbound traffic

    alerts = []

    if not features:
        return alerts

    total_outbound = [data["bytes_sent"] for data in features.values()]
    avg_outbound = sum(total_outbound) / len(total_outbound)

    for ip, data in features.items():

        if data["bytes_sent"] > avg_outbound * 3: #kinda arbitrary
            alerts.append({
                "type": "DATA_EXFILTRATION",
                "source_ip": ip,
                "bytes_sent": data["bytes_sent"],
                "average_bytes_sent": int(avg_outbound),
                "severity": "HIGH"
            })

    return alerts
