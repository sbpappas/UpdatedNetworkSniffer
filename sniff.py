import pyshark
import json
import argparse
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
import sys
import asyncio
import warnings

warnings.filterwarnings('ignore', message='.*Task exception was never retrieved.*')
warnings.filterwarnings('ignore', message='.*coroutine.*was never awaited.*')
#internet says those errors are harmless to me

class SuspiciousPatternDetector:
    # detect suspicious patterns in net traffic
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.port_scan_threshold = self.config.get('port_scan_threshold', 10)
        self.time_window = self.config.get('time_window', 60)  # seconds
        
        # Tracking structures
        self.connection_attempts = defaultdict(lambda: defaultdict(int))  # src_ip -> {dst_port: count}
        self.protocol_counts = defaultdict(int)
        self.ip_connections = defaultdict(set)  # src_ip -> set of dst_ips
        self.recent_packets = deque(maxlen=1000)  # Store recent packets for analysis
        self.suspicious_events = []
        
    def analyze_packet(self, packet) -> List[Dict]:
        # take and analyze a single packet, return any suspicious events 
        events = []
        
        if 'IP' not in packet:
            return events
            
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        
        # Track connection
        self.ip_connections[src_ip].add(dst_ip)
        
        # Track protocol
        if hasattr(packet, 'transport_layer') and packet.transport_layer:
            protocol = packet.transport_layer
            self.protocol_counts[protocol] += 1
            
            # Check for port scanning
            if protocol in ['TCP', 'UDP']:
                dst_port = None
                if hasattr(packet, protocol.lower()):
                    layer = getattr(packet, protocol.lower())
                    if hasattr(layer, 'dstport'):
                        dst_port = int(layer.dstport)
                
                if dst_port:
                    self.connection_attempts[src_ip][dst_port] += 1
                    
                    # Detect port scan (many different ports from same source)
                    if len(self.connection_attempts[src_ip]) >= self.port_scan_threshold:
                        event = {
                            'type': 'port_scan',
                            'severity': 'high',
                            'source_ip': src_ip,
                            'timestamp': str(packet.sniff_time),
                            'details': {
                                'ports_targeted': len(self.connection_attempts[src_ip]),
                                'protocol': protocol
                            }
                        }
                        events.append(event)
                        self.suspicious_events.append(event)
        
        # Check for unusual protocol usage
        if hasattr(packet, 'transport_layer') and packet.transport_layer:
            protocol = packet.transport_layer
            total_packets = sum(self.protocol_counts.values())
            if total_packets > 100:
                protocol_ratio = self.protocol_counts[protocol] / total_packets
                if protocol_ratio < 0.01 and protocol not in ['TCP', 'UDP']:  # Less than 1% and not common
                    event = {
                        'type': 'unusual_protocol',
                        'severity': 'medium',
                        'source_ip': src_ip,
                        'timestamp': str(packet.sniff_time),
                        'details': {
                            'protocol': protocol,
                            'usage_ratio': f"{protocol_ratio:.2%}"
                        }
                    }
                    events.append(event)
        
        # Check for potential DDoS (many connections from one IP)
        if len(self.ip_connections[src_ip]) >= 50:
            event = {
                'type': 'potential_ddos',
                'severity': 'high',
                'source_ip': src_ip,
                'timestamp': str(packet.sniff_time),
                'details': {
                    'unique_destinations': len(self.ip_connections[src_ip])
                }
            }
            events.append(event)
            self.suspicious_events.append(event)
        
        # Store packet info
        packet_info = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': getattr(packet, 'transport_layer', 'Unknown') if hasattr(packet, 'transport_layer') else 'Unknown',
            'timestamp': str(packet.sniff_time),
            'length': int(packet.length) if hasattr(packet, 'length') else 0
        }
        self.recent_packets.append(packet_info)
        
        return events
    
    def get_statistics(self) -> Dict:
        """Get current statistics about captured traffic"""
        return {
            'total_packets': len(self.recent_packets),
            'unique_source_ips': len(self.ip_connections),
            'protocol_distribution': dict(self.protocol_counts),
            'suspicious_events_count': len(self.suspicious_events),
            'top_source_ips': dict(sorted(
                [(ip, len(dests)) for ip, dests in self.ip_connections.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10])
        }


class NetworkSniffer:
    """Main network sniffer class"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.detector = SuspiciousPatternDetector(config)
        self.packet_count = 0
        self.start_time = datetime.now()
        
    def capture_live(self, interface: str = None, packet_count: int = None):
        # capture packets from live network 
        cap = None
        try:
            # Set up exception handler for pyshark's event loop
            _setup_asyncio_exception_handler()
            
            if interface:
                cap = pyshark.LiveCapture(interface=interface)
            else:
                cap = pyshark.LiveCapture()
            
            # Set exception handler again after pyshark might have created a new event loop
            _setup_asyncio_exception_handler()
            
            print(f"[*] Starting live capture on interface: {cap.interfaces[0] if cap.interfaces else 'default'}")
            print(f"[*] Press Ctrl+C to stop\n")
            
            for packet in cap.sniff_continuously(packet_count=packet_count):
                self.process_packet(packet)
                
        except KeyboardInterrupt:
            print("\n[*] Capture stopped by user")
        except Exception as e:
            print(f"[!] Error during capture: {e}")
            sys.exit(1)
        finally:
            # Properly close the capture to clean up background tasks
            # This helps prevent the "Task exception was never retrieved" warning
            if cap is not None:
                try:
                    cap.close()
                except (EOFError, OSError, AttributeError):
                    # These exceptions are expected when closing during interrupt
                    pass
                except Exception:
                    # Ignore any other cleanup errors
                    pass
    
    def capture_from_file(self, filename: str):
        """Capture packets from a pcap file"""
        try:
            print(f"[*] Reading packets from file: {filename}")
            cap = pyshark.FileCapture(filename)
            
            for packet in cap:
                self.process_packet(packet)
                
            cap.close()
            print(f"\n[*] Finished processing {self.packet_count} packets from file")
            
        except FileNotFoundError:
            print(f"[!] Error: File '{filename}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            sys.exit(1)
    
    def process_packet(self, packet):
        """Process a single packet"""
        self.packet_count += 1
        
        # Detect suspicious patterns
        events = self.detector.analyze_packet(packet)
        
        # Print suspicious events immediately
        for event in events:
            self.print_suspicious_event(event)
        
        # Print packet info if verbose
        if self.config.get('verbose', False):
            self.print_packet_info(packet)
    
    def print_packet_info(self, packet):
        """Print basic packet information"""
        if 'IP' in packet:
            src = packet.ip.src
            dst = packet.ip.dst
            proto = getattr(packet, 'transport_layer', 'Unknown') if hasattr(packet, 'transport_layer') else 'Unknown'
            print(f"[{self.packet_count}] {src} -> {dst} ({proto})")
    
    def print_suspicious_event(self, event: Dict):
        """Print suspicious event in a formatted way"""
        severity_colors = {
            'high': '\033[91m',  # Red
            'medium': '\033[93m',  # Yellow
            'low': '\033[92m'  # Green
        }
        reset = '\033[0m'
        color = severity_colors.get(event['severity'], '')
        
        print(f"\n{color}[!] SUSPICIOUS EVENT DETECTED{reset}")
        print(f"    Type: {event['type'].upper().replace('_', ' ')}")
        print(f"    Severity: {event['severity'].upper()}")
        print(f"    Source IP: {event['source_ip']}")
        print(f"    Timestamp: {event['timestamp']}")
        if 'details' in event:
            for key, value in event['details'].items():
                print(f"    {key.replace('_', ' ').title()}: {value}")
        print()
    
    def generate_report(self, output_file: Optional[str] = None) -> Dict:
        """Generate a comprehensive report"""
        stats = self.detector.get_statistics()
        duration = (datetime.now() - self.start_time).total_seconds()
        
        report = {
            'capture_info': {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': duration,
                'total_packets': self.packet_count
            },
            'statistics': stats,
            'suspicious_events': self.detector.suspicious_events,
            'summary': {
                'total_suspicious_events': len(self.detector.suspicious_events),
                'high_severity_events': len([e for e in self.detector.suspicious_events if e['severity'] == 'high']),
                'medium_severity_events': len([e for e in self.detector.suspicious_events if e['severity'] == 'medium']),
                'packets_per_second': self.packet_count / duration if duration > 0 else 0
            }
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[*] Report saved to {output_file}")
        else:
            print(json.dumps(report, indent=2))
        
        return report
    
    def print_summary(self):
        """Print a human-readable summary"""
        stats = self.detector.get_statistics()
        duration = (datetime.now() - self.start_time).total_seconds()
        
        print("\n" + "="*60)
        print("NETWORK SNIFFER SUMMARY")
        print("="*60)
        print(f"Capture Duration: {duration:.2f} seconds")
        print(f"Total Packets: {self.packet_count}")
        print(f"Packets/Second: {self.packet_count / duration:.2f}" if duration > 0 else "Packets/Second: N/A")
        print(f"\nUnique Source IPs: {stats['unique_source_ips']}")
        print(f"\nProtocol Distribution:")
        for protocol, count in sorted(stats['protocol_distribution'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
            print(f"  {protocol}: {count} ({percentage:.1f}%)")
        
        print(f"\nSuspicious Events: {stats['suspicious_events_count']}")
        print(f"  High Severity: {len([e for e in self.detector.suspicious_events if e['severity'] == 'high'])}")
        print(f"  Medium Severity: {len([e for e in self.detector.suspicious_events if e['severity'] == 'medium'])}")
        
        if stats['top_source_ips']:
            print(f"\nTop 10 Source IPs by Connection Count:")
            for ip, count in list(stats['top_source_ips'].items())[:10]:
                print(f"  {ip}: {count} unique destinations")
        
        print("="*60 + "\n")


def _setup_asyncio_exception_handler():
    """Set up asyncio exception handler to suppress expected EOFErrors from pyshark"""
    def exception_handler(loop, context):
        exception = context.get('exception')
        # Suppress EOFError which is expected when interrupting pyshark capture
        if isinstance(exception, EOFError):
            return
        # For other exceptions, use default handler if available
        try:
            default_handler = loop.default_exception_handler
            if default_handler:
                default_handler(context)
        except:
            # If no default handler, just print to stderr (but suppress EOFError)
            if not isinstance(exception, EOFError):
                print(f"Exception in asyncio task: {context}", file=sys.stderr)
    
    # Try to set handler on existing event loop
    try:
        loop = asyncio.get_event_loop()
        loop.set_exception_handler(exception_handler)
    except RuntimeError:
        # No event loop in current thread, will be set when pyshark creates one
        pass


def main():
    # Set up asyncio exception handler to suppress pyshark EOFError warnings
    _setup_asyncio_exception_handler()
    
    parser = argparse.ArgumentParser(
        description='Network Sniffer - Capture and analyze network traffic for suspicious patterns',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-i', '--interface', type=str, help='Network interface to capture on (default: auto-detect)')
    parser.add_argument('-f', '--file', type=str, help='Read packets from pcap file instead of live capture')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture (default: unlimited)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print detailed packet information')
    parser.add_argument('-o', '--output', type=str, help='Output file for JSON report')
    parser.add_argument('--port-scan-threshold', type=int, default=10, help='Port scan detection threshold (default: 10)')
    parser.add_argument('--no-summary', action='store_true', help='Skip printing summary at the end')
    
    args = parser.parse_args()
    
    config = {
        'verbose': args.verbose,
        'port_scan_threshold': args.port_scan_threshold
    }
    
    sniffer = NetworkSniffer(config)
    
    try:
        if args.file:
            sniffer.capture_from_file(args.file)
        else:
            # Set up exception handler again before live capture
            _setup_asyncio_exception_handler()
            sniffer.capture_live(interface=args.interface, packet_count=args.count)
    except KeyboardInterrupt:
        pass
    
    # Generate report
    if args.output:
        sniffer.generate_report(args.output)
    
    if not args.no_summary:
        sniffer.print_summary()


if __name__ == '__main__':
    main()
