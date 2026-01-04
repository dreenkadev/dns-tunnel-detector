"""DNS Tunnel Detector - Constants and patterns"""

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
