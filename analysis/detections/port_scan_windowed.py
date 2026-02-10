from analysis.detections.port_scan import detect_port_scans

def detect_windowed_port_scans(windowed_features, **thresholds):
    # windowed_features - dict: { window_start_time: { ip: features } }
    # thresholds - same as detect_port_scans function, passed through here for flexibility
    #runs port scan detection independently per time window

    alerts = []

    for window_start, features in windowed_features.items():
        window_alerts = detect_port_scans(features, **thresholds)

        for alert in window_alerts:
            alert["window_start"] = window_start
            alert["type"] = "PORT_SCAN_WINDOWED"

            alerts.append(alert)

    return alerts
