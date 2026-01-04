"""DNS Tunnel Detector - Data models"""

from dataclasses import dataclass
from typing import Dict, Optional


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
