#!/usr/bin/env python3
"""
Subdomain Enumerator - Purple Team Security Suite
MITRE ATT&CK: T1596.002 (Search Open Technical Databases)

Discovers subdomains via passive certificate transparency logs (crt.sh)
and DNS brute force enumeration.

Ethical Use: Only enumerate domains you own or have explicit permission to test.
Unauthorized access is illegal.
"""

import sys
import os
import json
import socket
import argparse
from datetime import datetime
from collections import defaultdict
from pathlib import Path

# Try to import requests, fall back to urllib if not available
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False


# ANSI Colors and Styling
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


def print_banner():
    """Display the tool banner."""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    🔍 SUBDOMAIN ENUMERATOR 🔍                  ║
║                   Purple Team Security Suite                   ║
║                   MITRE ATT&CK: T1596.002                      ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def detect_environment():
    """Detect if running on Termux or desktop."""
    try:
        if os.path.exists('/data/data/com.termux'):
            return 'termux'
    except:
        pass
    return 'desktop'


def get_output_directory():
    """Determine output directory based on environment."""
    env = detect_environment()

    if env == 'termux':
        base_dir = os.path.expanduser('~/Termux_Purple_Team/reports')
    else:
        base_dir = '/tmp/purple_team_reports'

    os.makedirs(base_dir, exist_ok=True)
    return base_dir


def passive_enumeration(domain):
    """
    Perform passive subdomain enumeration using crt.sh certificate transparency logs.

    Args:
        domain: Target domain to enumerate

    Returns:
        Set of discovered subdomains
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    print(f"\n{Colors.BLUE}[*] Starting passive enumeration via crt.sh...{Colors.RESET}")

    try:
        if HAS_REQUESTS:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
        else:
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode())

        if isinstance(data, list):
            for entry in data:
                if 'name_value' in entry:
                    names = entry['name_value'].split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name and not name.startswith('*.'):
                            subdomains.add(name)

        print(f"{Colors.GREEN}[+] Found {len(subdomains)} subdomains via crt.sh{Colors.RESET}")

    except Exception as e:
        print(f"{Colors.RED}[-] crt.sh enumeration failed: {str(e)}{Colors.RESET}")

    return subdomains


def dns_brute_force(domain):
    """
    Perform DNS brute force enumeration using common subdomain prefixes.

    Args:
        domain: Target domain to enumerate

    Returns:
        Set of discovered subdomains
    """
    subdomains = set()

    # Common subdomain prefixes
    wordlist = [
        'www', 'mail', 'ftp', 'admin', 'staging', 'dev', 'api', 'app',
        'test', 'beta', 'portal', 'vpn', 'remote', 'cloud', 'cdn',
        'backup', 'ns1', 'ns2', 'dns', 'mx', 'webmail', 'smtp',
        'pop3', 'imap', 'autodiscover', 'autoconfig', 'control',
        'panel', 'dashboard', 'console', 'terminal', 'shell',
        'git', 'svn', 'gitlab', 'github', 'jenkins', 'docker',
        'kubernetes', 'k8s', 'mongo', 'mysql', 'postgres', 'redis',
        'cache', 'db', 'database', 'server', 'host', 'node',
        'worker', 'batch', 'job', 'queue', 'message', 'event',
        'stream', 'socket', 'websocket', 'ws', 'api-v1', 'api-v2',
        'v1', 'v2', 'v3', 'graphql', 'rest', 'soap', 'xml',
        'json', 'rpc', 'grpc', 'gateway', 'proxy', 'load-balancer',
        'lb', 'firewall', 'router', 'switch', 'vpn', 'ipsec',
        'staging-api', 'dev-api', 'test-api', 'prod', 'production',
        'build', 'release', 'deploy', 'ci', 'cd', 'monitoring',
        'metrics', 'logs', 'kibana', 'grafana', 'prometheus',
        'alertmanager', 'splunk', 'datadog', 'newrelic', 'sentry',
        'slack', 'teams', 'zoom', 'jira', 'confluence', 'wiki',
        'docs', 'documentation', 'support', 'help', 'contact',
        'sales', 'marketing', 'hr', 'finance', 'accounting',
        'legal', 'compliance', 'security', 'privacy', 'gdpr',
        'status', 'health', 'ping', 'heartbeat', 'uptime',
        'archive', 'legacy', 'old', 'beta', 'staging', 'uat',
        'qat', 'qa', 'sandbox', 'test-env', 'demo', 'trial',
        'internal', 'private', 'external', 'public', 'partner',
        'affiliate', 'reseller', 'distributor', 'integrations',
        'plugins', 'extensions', 'addons', 'modules', 'components',
        'microservices', 'services', 'platform', 'base', 'core',
        'utils', 'tools', 'utilities', 'common', 'shared',
        'assets', 'static', 'media', 'images', 'videos',
        'download', 'upload', 'transfer', 'storage', 'backup',
        'sync', 'replicate', 'mirror', 'clone', 'copy',
        'export', 'import', 'migrate', 'upgrade', 'patch',
    ]

    print(f"\n{Colors.BLUE}[*] Starting DNS brute force with {len(wordlist)} prefixes...{Colors.RESET}")

    for prefix in wordlist:
        subdomain = f"{prefix}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            subdomains.add(subdomain)
        except socket.gaierror:
            pass
        except Exception as e:
            pass

    print(f"{Colors.GREEN}[+] Found {len(subdomains)} subdomains via DNS brute force{Colors.RESET}")

    return subdomains


def resolve_subdomain(subdomain):
    """
    Resolve a subdomain to IP address(es).

    Args:
        subdomain: Subdomain to resolve

    Returns:
        List of IP addresses or empty list if resolution fails
    """
    ips = []
    try:
        result = socket.gethostbyname_ex(subdomain)
        ips = result[2]
    except socket.gaierror:
        pass
    except Exception:
        pass

    return ips


def detect_wildcard(domain):
    """
    Detect if domain has wildcard DNS configured.

    Args:
        domain: Target domain

    Returns:
        Tuple of (has_wildcard, wildcard_ip)
    """
    try:
        wildcard_ip = socket.gethostbyname(f"nonexistent-{datetime.now().timestamp()}.{domain}")
        return True, wildcard_ip
    except socket.gaierror:
        return False, None
    except Exception:
        return False, None


def calculate_risk(subdomain, ips):
    """
    Calculate risk level for discovered subdomain.

    Args:
        subdomain: Subdomain name
        ips: List of resolved IPs

    Returns:
        Risk level ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') and reasoning
    """
    subdomain_lower = subdomain.lower()

    # CRITICAL indicators
    if any(x in subdomain_lower for x in ['admin', 'root', 'superuser']):
        return 'CRITICAL', 'Admin panel detected'

    # HIGH risk indicators
    if any(x in subdomain_lower for x in ['staging', 'dev', 'test', 'uat', 'qa', 'sandbox', 'internal']):
        return 'HIGH', 'Development/staging environment detected'

    if any(x in subdomain_lower for x in ['backup', 'archive', 'old', 'legacy']):
        return 'HIGH', 'Backup/archive system detected'

    if any(x in subdomain_lower for x in ['mail', 'smtp', 'pop3', 'imap', 'webmail']):
        return 'HIGH', 'Email service detected'

    if any(x in subdomain_lower for x in ['vpn', 'remote', 'ssh', 'rdp', 'terminal']):
        return 'HIGH', 'Remote access service detected'

    # MEDIUM risk indicators
    if any(x in subdomain_lower for x in ['api', 'graphql', 'rest', 'soap', 'ws', 'websocket']):
        return 'MEDIUM', 'API endpoint detected'

    if any(x in subdomain_lower for x in ['jenkins', 'gitlab', 'github', 'docker', 'kubernetes']):
        return 'MEDIUM', 'CI/CD or container infrastructure detected'

    if any(x in subdomain_lower for x in ['monitoring', 'grafana', 'kibana', 'prometheus']):
        return 'MEDIUM', 'Monitoring infrastructure detected'

    if any(x in subdomain_lower for x in ['database', 'db', 'mongo', 'mysql', 'postgres', 'redis']):
        return 'MEDIUM', 'Database service detected'

    # LOW risk indicators
    return 'LOW', 'Standard service'


def group_by_ip(results):
    """
    Group subdomains by IP address to identify shared hosting.

    Args:
        results: List of result dictionaries

    Returns:
        Dictionary mapping IPs to subdomains
    """
    ip_groups = defaultdict(list)

    for result in results:
        for ip in result['ips']:
            ip_groups[ip].append(result['subdomain'])

    return dict(ip_groups)


def generate_report(domain, results, output_dir):
    """
    Generate JSON report and save to file.

    Args:
        domain: Target domain
        results: List of discovered subdomains with metadata
        output_dir: Output directory path

    Returns:
        Path to saved report
    """
    timestamp = datetime.now().isoformat()
    report = {
        'domain': domain,
        'timestamp': timestamp,
        'total_subdomains': len(results),
        'subdomains': results,
        'ip_groups': group_by_ip(results),
        'risk_summary': {
            'CRITICAL': len([r for r in results if r['risk'] == 'CRITICAL']),
            'HIGH': len([r for r in results if r['risk'] == 'HIGH']),
            'MEDIUM': len([r for r in results if r['risk'] == 'MEDIUM']),
            'LOW': len([r for r in results if r['risk'] == 'LOW']),
        }
    }

    filename = f"subdomain_enum_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, 'w') as f:
        json.dump(report, f, indent=2)

    return filepath


def display_results(domain, results, wildcard_ip=None):
    """
    Display results in formatted console output.

    Args:
        domain: Target domain
        results: List of discovered subdomains with metadata
        wildcard_ip: IP of wildcard DNS if present
    """
    print(f"\n{Colors.BOLD}{Colors.CYAN}╔════ Enumeration Results ════╗{Colors.RESET}")
    print(f"{Colors.CYAN}║ Domain: {domain}{Colors.RESET}")
    print(f"{Colors.CYAN}║ Total Subdomains: {len(results)}{Colors.RESET}")

    if wildcard_ip:
        print(f"{Colors.YELLOW}║ ⚠️  Wildcard DNS detected: {wildcard_ip}{Colors.RESET}")

    print(f"{Colors.CYAN}╚══════════════════════════╝{Colors.RESET}\n")

    # Group by risk level
    risk_colors = {
        'CRITICAL': Colors.RED,
        'HIGH': Colors.YELLOW,
        'MEDIUM': Colors.CYAN,
        'LOW': Colors.GREEN,
    }

    for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        filtered = [r for r in results if r['risk'] == risk_level]

        if not filtered:
            continue

        color = risk_colors[risk_level]
        print(f"{color}{Colors.BOLD}[{risk_level}]{Colors.RESET} ({len(filtered)} found)")

        for result in filtered:
            ip_str = ', '.join(result['ips']) if result['ips'] else 'unresolved'
            print(f"  • {Colors.BOLD}{result['subdomain']}{Colors.RESET}")
            print(f"    └─ IPs: {ip_str}")
            print(f"    └─ Risk: {result['reason']}")

        print()


def interactive_mode():
    """Run tool in interactive mode."""
    print_banner()

    domain = input(f"\n{Colors.BOLD}Enter domain to enumerate:{Colors.RESET} ").strip()

    if not domain:
        print(f"{Colors.RED}[-] Domain cannot be empty{Colors.RESET}")
        sys.exit(1)

    # Remove www. prefix if present
    if domain.startswith('www.'):
        domain = domain[4:]

    print(f"\n{Colors.BLUE}[*] Starting enumeration for {domain}...{Colors.RESET}")

    # Detect wildcard
    has_wildcard, wildcard_ip = detect_wildcard(domain)
    if has_wildcard:
        print(f"{Colors.YELLOW}[!] Wildcard DNS detected ({wildcard_ip}){Colors.RESET}")

    # Run passive enumeration
    passive_subs = passive_enumeration(domain)

    # Run DNS brute force
    dns_subs = dns_brute_force(domain)

    # Combine results
    all_subdomains = passive_subs.union(dns_subs)

    print(f"\n{Colors.BLUE}[*] Resolving {len(all_subdomains)} subdomains...{Colors.RESET}")

    results = []
    for subdomain in sorted(all_subdomains):
        ips = resolve_subdomain(subdomain)
        risk, reason = calculate_risk(subdomain, ips)

        results.append({
            'subdomain': subdomain,
            'ips': ips,
            'risk': risk,
            'reason': reason,
            'resolved': len(ips) > 0
        })

    # Display results
    display_results(domain, results, wildcard_ip)

    # Save report
    output_dir = get_output_directory()
    report_path = generate_report(domain, results, output_dir)

    print(f"{Colors.GREEN}[+] Report saved to: {report_path}{Colors.RESET}\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Subdomain Enumerator - Purple Team Security Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python subdomain_enumerator.py --domain example.com
  python subdomain_enumerator.py --domain example.com --output /custom/path
  python subdomain_enumerator.py  # Interactive mode
        '''
    )

    parser.add_argument('--domain', '-d', help='Target domain to enumerate')
    parser.add_argument('--output', '-o', help='Custom output directory')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress banner')

    args = parser.parse_args()

    if not args.quiet:
        print_banner()

    # Interactive mode if no domain provided
    if not args.domain:
        interactive_mode()
        return

    domain = args.domain

    # Remove www. prefix if present
    if domain.startswith('www.'):
        domain = domain[4:]

    print(f"\n{Colors.BLUE}[*] Starting enumeration for {domain}...{Colors.RESET}")

    # Detect wildcard
    has_wildcard, wildcard_ip = detect_wildcard(domain)
    if has_wildcard:
        print(f"{Colors.YELLOW}[!] Wildcard DNS detected ({wildcard_ip}){Colors.RESET}")

    # Run passive enumeration
    passive_subs = passive_enumeration(domain)

    # Run DNS brute force
    dns_subs = dns_brute_force(domain)

    # Combine results
    all_subdomains = passive_subs.union(dns_subs)

    print(f"\n{Colors.BLUE}[*] Resolving {len(all_subdomains)} subdomains...{Colors.RESET}")

    results = []
    for subdomain in sorted(all_subdomains):
        ips = resolve_subdomain(subdomain)
        risk, reason = calculate_risk(subdomain, ips)

        results.append({
            'subdomain': subdomain,
            'ips': ips,
            'risk': risk,
            'reason': reason,
            'resolved': len(ips) > 0
        })

    # Display results
    display_results(domain, results, wildcard_ip)

    # Save report
    if args.output:
        output_dir = args.output
    else:
        output_dir = get_output_directory()

    os.makedirs(output_dir, exist_ok=True)
    report_path = generate_report(domain, results, output_dir)

    print(f"{Colors.GREEN}[+] Report saved to: {report_path}{Colors.RESET}\n")


if __name__ == '__main__':
    main()
