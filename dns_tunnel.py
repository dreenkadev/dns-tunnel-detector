#!/usr/bin/env python3
"""
DNS Tunnel Detector - Detect DNS tunneling and data exfiltration attempts

Features:
- Monitor DNS queries in real-time
- Detect high-entropy subdomains
- Identify unusual query patterns
- TXT record abuse detection
- Query frequency analysis
- Known tunnel domain detection
- Alert generation
- JSON logging
"""

import argparse
import json
import math
import re
import socket
import struct
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Set

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


@dataclass
class DNSQuery:
    timestamp: str
    src_ip: str
    query_name: str
    query_type: str
    entropy: float
    subdomain_count: int
    label_length: int
    suspicious: bool
    reason: Optional[str] = None


@dataclass
class Alert:
    timestamp: str
    severity: str
    alert_type: str
    source_ip: str
    domain: str
    description: str
    indicators: Dict


# Known DNS tunneling domains
KNOWN_TUNNEL_DOMAINS = [
    'dnscat', 'dns2tcp', 'iodine', 'dnstt', 'dnscapy',
    'heyoka', 'ozyman', 'tuns', 'dns-tunnel'
]

# DNS query types
DNS_TYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
    15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'
}


class DNSTunnelDetector:
    def __init__(
        self,
        interface: str = "eth0",
        threshold_entropy: float = 3.5,
        threshold_length: int = 50,
        threshold_frequency: int = 100,
        alert_callback=None
    ):
        self.interface = interface
        self.threshold_entropy = threshold_entropy
        self.threshold_length = threshold_length
        self.threshold_frequency = threshold_frequency
        self.alert_callback = alert_callback
        
        self.queries: List[DNSQuery] = []
        self.alerts: List[Alert] = []
        self.query_counts: Dict[str, Counter] = defaultdict(Counter)
        self.suspicious_ips: Set[str] = set()
        self.domain_stats: Dict[str, Dict] = defaultdict(lambda: {
            'count': 0,
            'first_seen': None,
            'last_seen': None,
            'unique_subdomains': set(),
            'avg_entropy': 0
        })
        
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        freq = Counter(text.lower())
        length = len(text)
        entropy = 0.0
        
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def extract_subdomain(self, query_name: str) -> str:
        """Extract subdomain portion of query"""
        parts = query_name.rstrip('.').split('.')
        if len(parts) > 2:
            return '.'.join(parts[:-2])
        return ''
    
    def is_suspicious(self, query_name: str, query_type: str, src_ip: str) -> tuple:
        """Check if a DNS query is suspicious"""
        reasons = []
        subdomain = self.extract_subdomain(query_name)
        
        # High entropy subdomain
        entropy = self.calculate_entropy(subdomain) if subdomain else 0
        if entropy > self.threshold_entropy:
            reasons.append(f"High entropy subdomain ({entropy:.2f})")
        
        # Long labels
        labels = query_name.split('.')
        max_label = max(len(l) for l in labels) if labels else 0
        if max_label > 50:
            reasons.append(f"Unusually long label ({max_label} chars)")
        
        # Many subdomains
        subdomain_count = len(labels) - 2 if len(labels) > 2 else 0
        if subdomain_count > 5:
            reasons.append(f"Many subdomain levels ({subdomain_count})")
        
        # TXT record (commonly used for tunneling)
        if query_type == 'TXT' and subdomain and len(subdomain) > 30:
            reasons.append("Long TXT query (potential tunnel)")
        
        # NULL record
        if query_type == 'ANY':
            reasons.append("ANY query (reconnaissance/amplification)")
        
        # Known tunnel patterns
        for known in KNOWN_TUNNEL_DOMAINS:
            if known in query_name.lower():
                reasons.append(f"Known tunnel domain pattern: {known}")
        
        # Hexadecimal-like subdomain
        if subdomain and re.match(r'^[0-9a-f]{20,}$', subdomain.replace('.', ''), re.I):
            reasons.append("Hexadecimal subdomain (encoded data)")
        
        # Base64-like subdomain
        if subdomain and re.match(r'^[A-Za-z0-9+/=]{20,}$', subdomain.replace('.', '')):
            reasons.append("Base64-like subdomain (encoded data)")
        
        # Frequency analysis
        domain = '.'.join(labels[-2:]) if len(labels) >= 2 else query_name
        self.domain_stats[domain]['count'] += 1
        self.domain_stats[domain]['unique_subdomains'].add(subdomain)
        
        if len(self.domain_stats[domain]['unique_subdomains']) > 50:
            reasons.append(f"High unique subdomain count ({len(self.domain_stats[domain]['unique_subdomains'])})")
        
        return bool(reasons), '; '.join(reasons), entropy
    
    def create_alert(self, query: DNSQuery) -> Alert:
        """Create an alert for suspicious query"""
        severity = "medium"
        if query.entropy > 4.0 or "tunnel" in (query.reason or "").lower():
            severity = "high"
        if "Known tunnel" in (query.reason or ""):
            severity = "critical"
        
        alert = Alert(
            timestamp=query.timestamp,
            severity=severity,
            alert_type="DNS_TUNNEL_SUSPECTED",
            source_ip=query.src_ip,
            domain=query.query_name,
            description=query.reason or "Suspicious DNS activity",
            indicators={
                "entropy": query.entropy,
                "subdomain_count": query.subdomain_count,
                "query_type": query.query_type
            }
        )
        
        self.alerts.append(alert)
        return alert
    
    def parse_dns_packet(self, data: bytes) -> Optional[Dict]:
        """Parse DNS query from packet data"""
        try:
            # Skip IP header (20 bytes) and UDP header (8 bytes)
            dns_data = data[28:]
            
            if len(dns_data) < 12:
                return None
            
            # DNS header
            flags = struct.unpack('!H', dns_data[2:4])[0]
            is_response = (flags >> 15) & 1
            
            if is_response:
                return None  # Only interested in queries
            
            # Parse question section
            offset = 12
            labels = []
            
            while offset < len(dns_data):
                length = dns_data[offset]
                if length == 0:
                    offset += 1
                    break
                if length > 63:  # Compression pointer
                    break
                labels.append(dns_data[offset+1:offset+1+length].decode('utf-8', errors='ignore'))
                offset += length + 1
            
            if offset + 4 > len(dns_data):
                return None
            
            qtype, qclass = struct.unpack('!HH', dns_data[offset:offset+4])
            
            return {
                'query_name': '.'.join(labels),
                'query_type': DNS_TYPES.get(qtype, str(qtype))
            }
            
        except Exception:
            return None
    
    def analyze_pcap_line(self, line: str) -> Optional[DNSQuery]:
        """Analyze a line from tcpdump output"""
        # Parse tcpdump DNS output
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.\d+ > .+: .+ ([\w.]+)\. (\w+)\?', line)
        if not match:
            return None
        
        src_ip = match.group(1)
        query_name = match.group(2)
        query_type = match.group(3)
        
        is_susp, reason, entropy = self.is_suspicious(query_name, query_type, src_ip)
        
        subdomain = self.extract_subdomain(query_name)
        
        query = DNSQuery(
            timestamp=datetime.now().isoformat(),
            src_ip=src_ip,
            query_name=query_name,
            query_type=query_type,
            entropy=round(entropy, 2),
            subdomain_count=len(subdomain.split('.')) if subdomain else 0,
            label_length=max(len(l) for l in query_name.split('.')) if query_name else 0,
            suspicious=is_susp,
            reason=reason if is_susp else None
        )
        
        self.queries.append(query)
        
        if is_susp:
            self.suspicious_ips.add(src_ip)
            alert = self.create_alert(query)
            if self.alert_callback:
                self.alert_callback(alert)
        
        return query
    
    def print_query(self, query: DNSQuery):
        """Print query with highlighting"""
        if query.suspicious:
            color = Colors.RED if query.entropy > 4.0 else Colors.YELLOW
            print(f"{color}[!]{Colors.RESET} ", end="")
        else:
            print(f"{Colors.DIM}[*]{Colors.RESET} ", end="")
        
        print(f"{Colors.CYAN}{query.timestamp[11:19]}{Colors.RESET} ", end="")
        print(f"{query.src_ip:15} ", end="")
        print(f"{Colors.BOLD}{query.query_type:5}{Colors.RESET} ", end="")
        
        name = query.query_name
        if len(name) > 50:
            name = name[:47] + "..."
        print(f"{name}", end="")
        
        if query.suspicious:
            print(f" {Colors.RED}[E:{query.entropy:.1f}]{Colors.RESET}", end="")
        
        print()
    
    def print_alert(self, alert: Alert):
        """Print alert prominently"""
        color = {
            'critical': Colors.RED,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.CYAN
        }.get(alert.severity, Colors.RESET)
        
        print(f"\n{color}{'═' * 60}")
        print(f"  ALERT: {alert.alert_type}")
        print(f"  Severity: {alert.severity.upper()}")
        print(f"  Source: {alert.source_ip}")
        print(f"  Domain: {alert.domain}")
        print(f"  Reason: {alert.description}")
        print(f"{'═' * 60}{Colors.RESET}\n")
    
    def get_stats(self) -> Dict:
        """Get detection statistics"""
        return {
            'total_queries': len(self.queries),
            'suspicious_queries': sum(1 for q in self.queries if q.suspicious),
            'alerts': len(self.alerts),
            'unique_suspicious_ips': len(self.suspicious_ips),
            'top_suspicious_domains': [
                (domain, stats['count'])
                for domain, stats in sorted(
                    self.domain_stats.items(),
                    key=lambda x: len(x[1]['unique_subdomains']),
                    reverse=True
                )[:10]
            ]
        }


def print_banner():
    print(f"""{Colors.CYAN}
  ____  _   _ ____    _____                       _ 
 |  _ \| \ | / ___|  |_   _|   _ _ __  _ __   ___| |
 | | | |  \| \___ \    | || | | | '_ \| '_ \ / _ \ |
 | |_| | |\  |___) |   | || |_| | | | | | | |  __/ |
 |____/|_| \_|____/    |_| \__,_|_| |_|_| |_|\___|_|
                                                    
{Colors.RESET}  {Colors.BOLD}DNS Tunnel Detector{Colors.RESET} v{VERSION}
""")


def demo_mode(detector: DNSTunnelDetector):
    """Run demo with sample DNS queries"""
    print(f"{Colors.CYAN}Running demo mode with sample queries...{Colors.RESET}\n")
    
    sample_queries = [
        ("192.168.1.100", "google.com", "A"),
        ("192.168.1.100", "www.example.com", "A"),
        ("192.168.1.101", "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.tunnel.evil.com", "TXT"),
        ("192.168.1.102", "4a6f686e446f65.data.exfil.net", "A"),
        ("192.168.1.100", "github.com", "A"),
        ("192.168.1.103", "dnscat.malicious.domain.com", "TXT"),
        ("192.168.1.101", "deadbeef1234abcd5678.tunnel.attacker.com", "TXT"),
        ("192.168.1.100", "dns.google.com", "A"),
        ("192.168.1.104", "a" * 60 + ".suspicious.net", "A"),
        ("192.168.1.105", "iodine.tunnel.test.com", "NULL"),
    ]
    
    for src_ip, query_name, query_type in sample_queries:
        is_susp, reason, entropy = detector.is_suspicious(query_name, query_type, src_ip)
        subdomain = detector.extract_subdomain(query_name)
        
        query = DNSQuery(
            timestamp=datetime.now().isoformat(),
            src_ip=src_ip,
            query_name=query_name,
            query_type=query_type,
            entropy=round(entropy, 2),
            subdomain_count=len(subdomain.split('.')) if subdomain else 0,
            label_length=max(len(l) for l in query_name.split('.')) if query_name else 0,
            suspicious=is_susp,
            reason=reason if is_susp else None
        )
        
        detector.queries.append(query)
        detector.print_query(query)
        
        if is_susp:
            detector.suspicious_ips.add(src_ip)
            alert = detector.create_alert(query)
            detector.print_alert(alert)
        
        time.sleep(0.3)
    
    # Print summary
    stats = detector.get_stats()
    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary:{Colors.RESET}")
    print(f"  Total queries: {stats['total_queries']}")
    print(f"  Suspicious: {Colors.RED}{stats['suspicious_queries']}{Colors.RESET}")
    print(f"  Alerts: {Colors.YELLOW}{stats['alerts']}{Colors.RESET}")
    print(f"  Suspicious IPs: {len(stats['unique_suspicious_ips'])}")


def main():
    parser = argparse.ArgumentParser(description="DNS Tunnel Detector")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface")
    parser.add_argument("-e", "--entropy", type=float, default=3.5, help="Entropy threshold")
    parser.add_argument("-l", "--length", type=int, default=50, help="Label length threshold")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--demo", action="store_true", help="Run demo mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    print_banner()
    
    detector = DNSTunnelDetector(
        interface=args.interface,
        threshold_entropy=args.entropy,
        threshold_length=args.length,
        alert_callback=lambda a: detector.print_alert(a) if args.verbose else None
    )
    
    if args.demo:
        demo_mode(detector)
    else:
        print(f"{Colors.YELLOW}Live capture requires tcpdump and root privileges.")
        print(f"Use --demo for demonstration mode.{Colors.RESET}")
        print(f"\nExample with tcpdump:")
        print(f"  sudo tcpdump -i {args.interface} -l port 53 | python3 dns_tunnel.py --live")
    
    if args.output:
        output = {
            'stats': detector.get_stats(),
            'alerts': [asdict(a) for a in detector.alerts],
            'suspicious_queries': [asdict(q) for q in detector.queries if q.suspicious]
        }
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\n{Colors.GREEN}Results saved to: {args.output}{Colors.RESET}")


if __name__ == "__main__":
    main()
