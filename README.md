# Network Sniffer

An advanced network traffic analyzer that uses Wireshark (via pyshark) to capture and analyze network traffic for suspicious patterns. Features clean reporting and data visualization.

## Features

- **Live Packet Capture**: Capture packets from network interfaces in real-time
- **File-based Analysis**: Analyze existing pcap files
- **Suspicious Pattern Detection**:
  - Port scanning detection
  - Unusual protocol usage
  - Potential DDoS attacks
  - Multiple connection patterns
- **Clean Reporting**: Generate JSON reports with comprehensive statistics
- **Data Visualization**: Create charts and graphs from captured data
- **Configurable**: Customize detection thresholds and behavior

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. **Note**: pyshark requires tshark (Wireshark command-line tools) to be installed:
   - **macOS**: `brew install wireshark`
   - **Linux**: `sudo apt-get install tshark` (Ubuntu/Debian) or `sudo yum install wireshark` (RHEL/CentOS)
   - **Windows**: Download and install Wireshark from [wireshark.org](https://www.wireshark.org/)

## Usage

### Live Capture

Capture packets from your network interface:

```bash
python sniff.py
```

Capture from a specific interface:

```bash
python sniff.py -i en0
```

Capture a limited number of packets:

```bash
python sniff.py -c 1000
```

### File-based Analysis

Analyze packets from a pcap file:

```bash
python sniff.py -f traffic.pcap
```

### Generate Reports

Save a JSON report:

```bash
python sniff.py -f traffic.pcap -o report.json
```

### Verbose Output

Print detailed packet information:

```bash
python sniff.py -v
```

### Custom Detection Thresholds

Adjust port scan detection threshold:

```bash
python sniff.py --port-scan-threshold 20
```

### Visualization

Generate visualizations from a report:

```bash
python visualizer.py report.json
```

Save visualizations to a directory:

```bash
python visualizer.py report.json -o ./charts/
```

## Command Line Options

```
-i, --interface          Network interface to capture on (default: auto-detect)
-f, --file              Read packets from pcap file instead of live capture
-c, --count             Number of packets to capture (default: unlimited)
-v, --verbose           Print detailed packet information
-o, --output            Output file for JSON report
--port-scan-threshold   Port scan detection threshold (default: 10)
--no-summary            Skip printing summary at the end
```

## Output

The sniffer provides:

1. **Real-time Alerts**: Suspicious events are printed immediately with color-coded severity levels
2. **Summary Report**: Human-readable summary with statistics
3. **JSON Report**: Detailed JSON report with all captured data and statistics
4. **Visualizations**: Charts showing protocol distribution, top source IPs, traffic timeline, and suspicious events

## Example Output

```
[*] Starting live capture on interface: en0
[*] Press Ctrl+C to stop

[!] SUSPICIOUS EVENT DETECTED
    Type: PORT SCAN
    Severity: HIGH
    Source IP: 192.168.1.100
    Timestamp: 2026-01-26 10:30:45
    Ports Targeted: 15
    Protocol: TCP

============================================================
NETWORK SNIFFER SUMMARY
============================================================
Capture Duration: 120.50 seconds
Total Packets: 5432
Packets/Second: 45.08

Unique Source IPs: 23

Protocol Distribution:
  TCP: 4321 (79.6%)
  UDP: 987 (18.2%)
  ICMP: 124 (2.3%)

Suspicious Events: 3
  High Severity: 2
  Medium Severity: 1
============================================================
```

## Suspicious Pattern Detection

The sniffer detects several types of suspicious patterns:

1. **Port Scanning**: When a single source IP attempts to connect to many different ports
2. **Unusual Protocols**: Rare protocol usage that might indicate malicious activity
3. **Potential DDoS**: When a single source IP connects to many different destination IPs
4. **Connection Patterns**: Unusual connection patterns that deviate from normal traffic

## Requirements

- Python 3.7+
- pyshark
- matplotlib (for visualization)
- tshark (Wireshark command-line tools)

## License

MIT License
