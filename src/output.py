"""DNS Tunnel Detector - Output formatting"""

from .constants import Colors, VERSION
from .models import DNSQuery, Alert


def print_banner():
    print(f"""{Colors.CYAN}
  ____  _   _ ____    _____                       _ 
 |  _ \| \ | / ___|  |_   _|   _ _ __  _ __   ___| |
 | | | |  \| \___ \    | || | | | '_ \| '_ \ / _ \ |
 | |_| | |\  |___) |   | || |_| | | | | | | |  __/ |
 |____/|_| \_|____/    |_| \__,_|_| |_|_| |_|\___|_|
                                                    
{Colors.RESET}  {Colors.BOLD}DNS Tunnel Detector{Colors.RESET} v{VERSION}
""")


def print_query(query: DNSQuery):
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


def print_alert(alert: Alert):
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


def print_stats(stats: dict):
    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary:{Colors.RESET}")
    print(f"  Total queries: {stats['total_queries']}")
    print(f"  Suspicious: {Colors.RED}{stats['suspicious_queries']}{Colors.RESET}")
    print(f"  Alerts: {Colors.YELLOW}{stats['alerts']}{Colors.RESET}")
    print(f"  Suspicious IPs: {stats['unique_suspicious_ips']}")
