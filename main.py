#!/usr/bin/env python3
"""DNS Tunnel Detector - Entry point"""

import argparse
import json
import time
from dataclasses import asdict
from datetime import datetime

from src import (
    VERSION, Colors, DNSTunnelDetector, DNSQuery,
    print_banner, print_query, print_alert, print_stats
)


def demo_mode(detector: DNSTunnelDetector):
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
        print_query(query)
        
        if is_susp:
            detector.suspicious_ips.add(src_ip)
            alert = detector.create_alert(query)
            print_alert(alert)
        
        time.sleep(0.3)
    
    stats = detector.get_stats()
    print_stats(stats)


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
        alert_callback=lambda a: print_alert(a) if args.verbose else None
    )
    
    if args.demo:
        demo_mode(detector)
    else:
        print(f"{Colors.YELLOW}Live capture requires tcpdump and root privileges.")
        print(f"Use --demo for demonstration mode.{Colors.RESET}")
        print(f"\nExample with tcpdump:")
        print(f"  sudo tcpdump -i {args.interface} -l port 53 | python3 main.py --live")
    
    if args.output:
        output = {
            'stats': detector.get_stats(),
            'alerts': [asdict(a) for a in detector.alerts],
            'suspicious_queries': [asdict(q) for q in detector.queries if q.suspicious]
        }
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2, default=list)
        print(f"\n{Colors.GREEN}Results saved to: {args.output}{Colors.RESET}")


if __name__ == "__main__":
    main()
