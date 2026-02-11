import os
from datetime import datetime

def build_html_report(alerts, output_dir):
    html_path = os.path.join(output_dir, "report.html")

    alert_rows = ""
    for alert in alerts:
        alert_rows += f"""
        <tr>
            <td>{alert.get('window_start', 'N/A')}</td>
            <td>{alert['source_ip']}</td>
            <td>{alert['unique_ports']}</td>
            <td>{alert['packets_sent']}</td>
            <td>{alert['severity']}</td>
        </tr>
        """

    html_content = f"""
    <html>
    <head>
        <title>Network Sniffer Report</title>
        <style>
            body {{ font-family: Arial; margin: 40px; }}
            table, th, td {{ border: 1px solid black; border-collapse: collapse; padding: 6px; }}
            th {{ background-color: #eee; }}
            img {{ margin-bottom: 40px; }}
        </style>
    </head>
    <body>
        <h1>Network Traffic Report</h1>
        <p>Generated: {datetime.now()}</p>

        <h2>Packets Sent per Host</h2>
        <img src="packets_per_host.png" width="800">

        <h2>Unique Destination Ports per Host</h2>
        <img src="unique_ports.png" width="800">

        <h2>Detected Alerts</h2>
        <table>
            <tr>
                <th>Window</th>
                <th>Source IP</th>
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
