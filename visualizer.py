#!/usr/bin/env python3

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from collections import Counter, defaultdict
import json
import sys


def plot_protocol_distribution(stats: dict, output_file: str = None):
    # makes a pie chart of protocols and their distribution
    protocol_dist = stats.get('protocol_distribution', {})
    if not protocol_dist:
        print("[!] No protocol data to visualize")
        return
    
    protocols = list(protocol_dist.keys())
    counts = list(protocol_dist.values())
    
    plt.figure(figsize=(10, 8))
    plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
    plt.title('Network Protocol Distribution', fontsize=16, fontweight='bold')
    plt.axis('equal')
    
    if output_file:
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"[*] Protocol distribution chart saved to {output_file}")
    else:
        plt.show()
    plt.close()


def plot_top_source_ips(stats: dict, top_n: int = 10, output_file: str = None):
    """Create a bar chart of top source IPs by connection count"""
    top_ips = stats.get('top_source_ips', {})
    if not top_ips:
        print("[!] No source IP data to visualize")
        return
    
    # Get top N IPs
    sorted_ips = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:top_n]
    ips = [ip for ip, _ in sorted_ips]
    counts = [count for _, count in sorted_ips]
    
    plt.figure(figsize=(12, 6))
    plt.barh(ips, counts, color='steelblue')
    plt.xlabel('Number of Unique Destinations', fontsize=12)
    plt.ylabel('Source IP Address', fontsize=12)
    plt.title(f'Top {top_n} Source IPs by Connection Count', fontsize=16, fontweight='bold')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    
    if output_file:
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"[*] Top source IPs chart saved to {output_file}")
    else:
        plt.show()
    plt.close()


def plot_traffic_timeline(packets: list, output_file: str = None):
    """Create a timeline of packet traffic"""
    if not packets:
        print("[!] No packet data to visualize")
        return
    
    # Group packets by time (round to nearest second)
    time_counts = defaultdict(int)
    for packet in packets:
        try:
            timestamp = datetime.fromisoformat(packet['timestamp'].replace('Z', '+00:00'))
            time_key = timestamp.replace(microsecond=0)
            time_counts[time_key] += 1
        except:
            continue
    
    if not time_counts:
        print("[!] Could not parse packet timestamps")
        return
    
    times = sorted(time_counts.keys())
    counts = [time_counts[t] for t in times]
    
    plt.figure(figsize=(14, 6))
    plt.plot(times, counts, linewidth=2, color='steelblue')
    plt.xlabel('Time', fontsize=12)
    plt.ylabel('Packets per Second', fontsize=12)
    plt.title('Network Traffic Timeline', fontsize=16, fontweight='bold')
    plt.grid(True, alpha=0.3)
    plt.gcf().autofmt_xdate()
    plt.tight_layout()
    
    if output_file:
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"[*] Traffic timeline chart saved to {output_file}")
    else:
        plt.show()
    plt.close()


def plot_suspicious_events_by_type(events: list, output_file: str = None):
    """Create a bar chart of suspicious events by type"""
    if not events:
        print("[!] No suspicious events to visualize")
        return
    
    event_types = Counter([e['type'] for e in events])
    
    types = list(event_types.keys())
    counts = list(event_types.values())
    
    plt.figure(figsize=(10, 6))
    colors = ['#d32f2f' if 'high' in str(e).lower() else '#f57c00' if 'medium' in str(e).lower() else '#388e3c' 
              for e in types]
    plt.bar(types, counts, color=colors)
    plt.xlabel('Event Type', fontsize=12)
    plt.ylabel('Count', fontsize=12)
    plt.title('Suspicious Events by Type', fontsize=16, fontweight='bold')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    if output_file:
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"[*] Suspicious events chart saved to {output_file}")
    else:
        plt.show()
    plt.close()


def visualize_report(report_file: str, output_dir: str = None):
    """Create all visualizations from a JSON report file"""
    try:
        with open(report_file, 'r') as f:
            report = json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: Report file '{report_file}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Error: Invalid JSON in report file: {e}")
        sys.exit(1)
    
    stats = report.get('statistics', {})
    events = report.get('suspicious_events', [])
    packets = report.get('packets', [])
    
    prefix = f"{output_dir}/" if output_dir else ""
    
    print("[*] Generating visualizations...")
    
    plot_protocol_distribution(stats, f"{prefix}protocol_distribution.png" if output_dir else None)
    plot_top_source_ips(stats, output_file=f"{prefix}top_source_ips.png" if output_dir else None)
    plot_suspicious_events_by_type(events, f"{prefix}suspicious_events.png" if output_dir else None)
    
    if packets:
        plot_traffic_timeline(packets, f"{prefix}traffic_timeline.png" if output_dir else None)
    
    print("[*] Visualization complete!")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Visualize network sniffer reports')
    parser.add_argument('report_file', type=str, help='JSON report file to visualize')
    parser.add_argument('-o', '--output-dir', type=str, help='Directory to save visualization images')
    
    args = parser.parse_args()
    visualize_report(args.report_file, args.output_dir)
