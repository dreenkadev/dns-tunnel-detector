"""DNS Tunnel Detector - Core detection engine"""

import math
import re
import struct
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set

from .constants import KNOWN_TUNNEL_DOMAINS, DNS_TYPES
from .models import DNSQuery, Alert


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
        parts = query_name.rstrip('.').split('.')
        if len(parts) > 2:
            return '.'.join(parts[:-2])
        return ''
    
    def is_suspicious(self, query_name: str, query_type: str, src_ip: str) -> tuple:
        reasons = []
        subdomain = self.extract_subdomain(query_name)
        
        entropy = self.calculate_entropy(subdomain) if subdomain else 0
        if entropy > self.threshold_entropy:
            reasons.append(f"High entropy subdomain ({entropy:.2f})")
        
        labels = query_name.split('.')
        max_label = max(len(l) for l in labels) if labels else 0
        if max_label > 50:
            reasons.append(f"Unusually long label ({max_label} chars)")
        
        subdomain_count = len(labels) - 2 if len(labels) > 2 else 0
        if subdomain_count > 5:
            reasons.append(f"Many subdomain levels ({subdomain_count})")
        
        if query_type == 'TXT' and subdomain and len(subdomain) > 30:
            reasons.append("Long TXT query (potential tunnel)")
        
        if query_type == 'ANY':
            reasons.append("ANY query (reconnaissance/amplification)")
        
        for known in KNOWN_TUNNEL_DOMAINS:
            if known in query_name.lower():
                reasons.append(f"Known tunnel domain pattern: {known}")
        
        if subdomain and re.match(r'^[0-9a-f]{20,}$', subdomain.replace('.', ''), re.I):
            reasons.append("Hexadecimal subdomain (encoded data)")
        
        if subdomain and re.match(r'^[A-Za-z0-9+/=]{20,}$', subdomain.replace('.', '')):
            reasons.append("Base64-like subdomain (encoded data)")
        
        domain = '.'.join(labels[-2:]) if len(labels) >= 2 else query_name
        self.domain_stats[domain]['count'] += 1
        self.domain_stats[domain]['unique_subdomains'].add(subdomain)
        
        if len(self.domain_stats[domain]['unique_subdomains']) > 50:
            reasons.append(f"High unique subdomain count ({len(self.domain_stats[domain]['unique_subdomains'])})")
        
        return bool(reasons), '; '.join(reasons), entropy
    
    def create_alert(self, query: DNSQuery) -> Alert:
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
        try:
            dns_data = data[28:]
            
            if len(dns_data) < 12:
                return None
            
            flags = struct.unpack('!H', dns_data[2:4])[0]
            is_response = (flags >> 15) & 1
            
            if is_response:
                return None
            
            offset = 12
            labels = []
            
            while offset < len(dns_data):
                length = dns_data[offset]
                if length == 0:
                    offset += 1
                    break
                if length > 63:
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
    
    def get_stats(self) -> Dict:
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
