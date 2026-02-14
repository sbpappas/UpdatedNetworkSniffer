import os
from datetime import datetime
from analysis.device_mappings import get_device_name


def build_html_report(alerts, unknown_devices, output_dir):
    html_path = os.path.join(output_dir, "report.html")

    alert_rows = ""
    for alert in alerts:
        alert_rows += f"""
        <tr>
            <td>{alert.get('window_start', 'N/A')}</td>
            <td>{get_device_name(alert['source_ip'])}</td>
            <td>{alert['unique_ports']}</td>
            <td>{alert['packets_sent']}</td>
            <td>{alert['severity']}</td>
        </tr>
        """

    if not alert_rows:
        alert_rows = "<tr><td colspan='5'>No alerts detected</td></tr>"

    unknown_rows = ""

    for ip, data in unknown_devices.items():
        unknown_rows += f"""
        <tr>
            <td>{ip}</td>
            <td>{data['first_seen']}</td>
            <td>{data['packet_count']}</td>
        </tr>
        """

    if not unknown_rows:
        unknown_rows = "<tr><td colspan='3'>No unknown devices detected</td></tr>"

    html_content = f"""
    <html>
    <head>
        <title>Network Sniffer Report</title>
        <style>
            body {{ font-family: Arial; margin: 40px; }}
            table {{ width: 100%; margin-bottom: 40px; }}
            table, th, td {{ border: 1px solid black; border-collapse: collapse; padding: 6px; }}
            th {{ background-color: #eee; }}
            img {{ margin-bottom: 40px; }}
            h2 {{ margin-top: 50px; }}
        </style>
    </head>
    <body>

        <h1>Network Traffic Report</h1>
        <p>Generated: {datetime.now()}</p>

        <h2>Packets Sent per Host</h2>
        <img src="packets_per_host.png" width="800">

        <h2>Unique Destination Ports per Host</h2>
        <img src="unique_ports.png" width="800">

        <h2>Protocol Distribution</h2>
        <img src="protocol_distribution.png" width="600">

        <h2>Packet Size Distribution</h2>
        <img src="packet_size_distribution.png" width="800">

        <h2>Bytes Sent vs Received</h2>
        <img src="bytes_sent_received.png" width="800">

        <h2>⚠ Unknown Devices Detected</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>First Seen</th>
                <th>Packets Observed</th>
            </tr>
            {unknown_rows}
        </table>

        <h2>Detected Alerts</h2>
        <table>
            <tr>
                <th>Window</th>
                <th>Source Device</th>
                <th>Unique Ports</th>
                <th>Packets Sent</th>
                <th>Severity</th>
            </tr>
            {alert_rows}
        </table>

    </body>
    </html>
    """

    with open(html_path, "w") as f:
        f.write(html_content)

    return html_path
