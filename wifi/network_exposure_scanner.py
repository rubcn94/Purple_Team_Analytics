#!/usr/bin/env python3
"""
📡 NETWORK EXPOSURE SCANNER - Guest WiFi Network Vulnerability Assessment
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Comprehensive assessment of what's exposed on internal network from guest WiFi.
Detects POS terminals, cameras, databases, file servers accessible to customers.
PCI DSS compliance violations and critical security gaps.
Part of Purple Team Security Suite.

MITRE ATT&CK: T1046 (Network Service Discovery), T1135 (Network Share Discovery)

⚠️  ETHICAL DISCLAIMER:
This tool is designed ONLY for authorized security testing on networks you own
or have explicit written permission to test. Unauthorized network scanning is illegal.
Use only as part of authorized security assessments.
"""

import json
import subprocess
import sys
import os
import re
import socket
import ipaddress
import threading
import time
from datetime import datetime
from pathlib import Path

# ────────────────────────────────────────────────────────────
# ENVIRONMENT DETECTION
# ────────────────────────────────────────────────────────────

def is_termux():
    """Detect if running in Termux environment."""
    return os.path.exists('/data/data/com.termux') or 'TERMUX_VERSION' in os.environ

def get_environment():
    """Return execution environment info."""
    return {
        'platform': 'Termux' if is_termux() else 'Linux',
        'timestamp': datetime.now().isoformat(),
    }

# ────────────────────────────────────────────────────────────
# NETWORK DISCOVERY
# ────────────────────────────────────────────────────────────

def get_local_ip_and_subnet():
    """Get local IP and subnet information."""
    try:
        if is_termux():
            result = subprocess.run(
                ['termux-wifi-connectioninfo'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                ip = data.get('ip_address', '')
                if ip:
                    return ip, 24
    except Exception:
        pass

    try:
        result = subprocess.run(
            ['ip', 'addr', 'show'],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'inet ' in line and not '127.0.0.1' in line:
                match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if match:
                    return match.group(1), int(match.group(2))
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip, 24
    except Exception:
        return None, None

def get_subnet_range(ip, prefix_length):
    """Get all IPs in subnet."""
    try:
        network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
        return [str(ip) for ip in list(network.hosts())]
    except Exception:
        return []

# ────────────────────────────────────────────────────────────
# PORT SCANNING
# ────────────────────────────────────────────────────────────

def check_port(host, port, timeout=0.3):
    """Check if port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_banner(host, port, timeout=1):
    """Get service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:200]
    except Exception:
        return None

# Service classification
SERVICES = {
    21: {'name': 'FTP', 'description': 'FTP (transferencia SIN CIFRADO)', 'risk': 'CRITICAL', 'category': 'UNENCRYPTED'},
    22: {'name': 'SSH', 'description': 'SSH (shell remoto)', 'risk': 'HIGH', 'category': 'REMOTE_ACCESS'},
    23: {'name': 'Telnet', 'description': 'Telnet (SIN CIFRADO)', 'risk': 'CRITICAL', 'category': 'UNENCRYPTED'},
    25: {'name': 'SMTP', 'description': 'SMTP (correo saliente)', 'risk': 'MEDIUM', 'category': 'EMAIL'},
    80: {'name': 'HTTP', 'description': 'Servidor web', 'risk': 'MEDIUM', 'category': 'WEB'},
    139: {'name': 'NetBIOS', 'description': 'File sharing (NetBIOS)', 'risk': 'HIGH', 'category': 'FILE_SHARING'},
    443: {'name': 'HTTPS', 'description': 'Servidor web seguro', 'risk': 'LOW', 'category': 'WEB_SECURE'},
    445: {'name': 'SMB', 'description': 'Almacenamiento de red (SMB)', 'risk': 'CRITICAL', 'category': 'FILE_SHARING'},
    554: {'name': 'RTSP', 'description': 'Cámara IP (posible CCTV)', 'risk': 'HIGH', 'category': 'CAMERA'},
    631: {'name': 'IPP', 'description': 'Impresora de red', 'risk': 'MEDIUM', 'category': 'PRINTER'},
    3306: {'name': 'MySQL', 'description': 'Base de datos MySQL', 'risk': 'CRITICAL', 'category': 'DATABASE'},
    3389: {'name': 'RDP', 'description': 'Escritorio remoto Windows', 'risk': 'CRITICAL', 'category': 'REMOTE_ACCESS'},
    5432: {'name': 'PostgreSQL', 'description': 'Base de datos PostgreSQL', 'risk': 'CRITICAL', 'category': 'DATABASE'},
    5900: {'name': 'VNC', 'description': 'Escritorio remoto VNC', 'risk': 'CRITICAL', 'category': 'REMOTE_ACCESS'},
    8080: {'name': 'HTTP-Alt', 'description': 'Puerto HTTP alternativo', 'risk': 'MEDIUM', 'category': 'WEB'},
    8443: {'name': 'HTTPS-Alt', 'description': 'Puerto HTTPS alternativo', 'risk': 'LOW', 'category': 'WEB_SECURE'},
    9100: {'name': 'JetDirect', 'description': 'TPV / Impresora de recibos', 'risk': 'CRITICAL', 'category': 'POS'},
}

def scan_host_comprehensive(host, ports=None):
    """Comprehensive port scan of a host."""
    if ports is None:
        ports = list(SERVICES.keys())

    open_ports = []
    for port in ports:
        if check_port(host, port):
            banner = get_banner(host, port)
            open_ports.append({
                'port': port,
                'service': SERVICES.get(port, {}).get('name', 'Unknown'),
                'description': SERVICES.get(port, {}).get('description', ''),
                'risk': SERVICES.get(port, {}).get('risk', 'UNKNOWN'),
                'category': SERVICES.get(port, {}).get('category', 'OTHER'),
                'banner': banner,
            })

    return open_ports

def classify_device_detailed(open_ports):
    """Detailed device classification."""
    if not open_ports:
        return {'type': 'UNKNOWN', 'categories': []}

    categories = set()
    device_indicators = {}

    for port_info in open_ports:
        cat = port_info['category']
        categories.add(cat)

        if cat == 'POS':
            device_indicators['POS'] = device_indicators.get('POS', 0) + 10
        elif cat == 'CAMERA':
            device_indicators['CAMERA'] = device_indicators.get('CAMERA', 0) + 8
        elif cat == 'FILE_SHARING':
            device_indicators['FILE_SHARING'] = device_indicators.get('FILE_SHARING', 0) + 7
        elif cat == 'DATABASE':
            device_indicators['DATABASE'] = device_indicators.get('DATABASE', 0) + 9
        elif cat == 'REMOTE_ACCESS':
            device_indicators['REMOTE_ACCESS'] = device_indicators.get('REMOTE_ACCESS', 0) + 8
        elif cat == 'PRINTER':
            device_indicators['PRINTER'] = device_indicators.get('PRINTER', 0) + 6
        elif cat == 'WEB':
            device_indicators['WEB'] = device_indicators.get('WEB', 0) + 2

    primary_type = max(device_indicators, key=device_indicators.get) if device_indicators else 'UNKNOWN'

    return {
        'primary_type': primary_type,
        'categories': sorted(list(categories)),
        'score': device_indicators.get(primary_type, 0)
    }

# ────────────────────────────────────────────────────────────
# NETWORK SCANNING WITH THREADING
# ────────────────────────────────────────────────────────────

def scan_subnet_comprehensive(subnet_range, timeout=45):
    """Fast subnet scan using threading."""
    devices = []
    lock = threading.Lock()
    checked = [0]

    def worker(host):
        try:
            ports = list(SERVICES.keys())
            open_ports = scan_host_comprehensive(host, ports)
            if open_ports:
                classification = classify_device_detailed(open_ports)
                device = {
                    'ip': host,
                    'open_ports': open_ports,
                    'device_type': classification['primary_type'],
                    'categories': classification['categories'],
                    'score': classification['score'],
                }
                with lock:
                    devices.append(device)
                    checked[0] += 1
        except Exception:
            pass

    threads = []
    start_time = time.time()

    for host in subnet_range:
        if time.time() - start_time > timeout:
            break

        t = threading.Thread(target=worker, args=(host,), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=0.5)

    return devices

# ────────────────────────────────────────────────────────────
# PCI DSS ANALYSIS
# ────────────────────────────────────────────────────────────

def analyze_pci_dss_compliance(devices, local_ip):
    """Analyze PCI DSS violations."""
    violations = []

    for device in devices:
        ports = [p['port'] for p in device['open_ports']]

        # PCI DSS 1.3: Prohibit direct public access to card data
        if 'POS' in device['categories'] or any(p == 9100 for p in ports):
            violations.append({
                'ip': device['ip'],
                'severity': 'CRITICAL',
                'violation': 'PCI DSS 1.3: Payment device visible from guest network',
                'detail': 'Point-of-Sale terminals should never be accessible from customer networks',
                'ports': ports,
                'remediation': 'Isolate POS systems on separate VLAN restricted from guest access'
            })

        # PCI DSS 1.2: Restrict inbound traffic
        if 'DATABASE' in device['categories'] or any(p in [3306, 5432] for p in ports):
            violations.append({
                'ip': device['ip'],
                'severity': 'CRITICAL',
                'violation': 'PCI DSS 1.2: Database accessible from untrusted network',
                'detail': 'Databases containing cardholder data should not be accessible from guest networks',
                'ports': ports,
                'remediation': 'Block all inbound connections to databases from guest/customer networks'
            })

        # PCI DSS 2.1: Default credentials
        if 'REMOTE_ACCESS' in device['categories']:
            violations.append({
                'ip': device['ip'],
                'severity': 'HIGH',
                'violation': 'PCI DSS 2.1: Remote access exposed without authentication requirement visible',
                'detail': 'Remote access services (RDP, SSH, VNC) should require strong authentication',
                'ports': ports,
                'remediation': 'Disable unnecessary remote services; use VPN for authorized access only'
            })

        # Unencrypted protocols
        for port_info in device['open_ports']:
            if port_info['category'] == 'UNENCRYPTED':
                violations.append({
                    'ip': device['ip'],
                    'severity': 'HIGH',
                    'violation': f"PCI DSS 4.1: {port_info['service']} (unencrypted) in use",
                    'detail': f"Port {port_info['port']} uses unencrypted protocol",
                    'ports': [port_info['port']],
                    'remediation': f"Disable {port_info['service']}; use encrypted alternatives (SFTP for FTP, SSH for Telnet)"
                })

    return violations

# ────────────────────────────────────────────────────────────
# DEMO MODE
# ────────────────────────────────────────────────────────────

def get_demo_data():
    """Return sample network exposure data."""
    return {
        'environment': get_environment(),
        'network_info': {
            'local_ip': '192.168.1.50',
            'subnet': '192.168.1.0/24',
            'scan_duration': 45,
            'timestamp': datetime.now().isoformat(),
        },
        'scan_summary': {
            'hosts_scanned': 254,
            'hosts_with_open_ports': 12,
            'critical_risk_services': 15,
            'pci_dss_violations': 8,
        },
        'devices_found': [
            {
                'ip': '192.168.1.100',
                'open_ports': [
                    {'port': 9100, 'service': 'JetDirect', 'description': 'TPV / Impresora de recibos', 'risk': 'CRITICAL', 'category': 'POS', 'banner': None},
                ],
                'device_type': 'POS',
                'categories': ['POS'],
                'score': 10,
            },
            {
                'ip': '192.168.1.101',
                'open_ports': [
                    {'port': 445, 'service': 'SMB', 'description': 'Almacenamiento de red', 'risk': 'CRITICAL', 'category': 'FILE_SHARING', 'banner': 'Samba 4.13'},
                    {'port': 139, 'service': 'NetBIOS', 'description': 'File sharing (NetBIOS)', 'risk': 'HIGH', 'category': 'FILE_SHARING', 'banner': None},
                ],
                'device_type': 'FILE_SHARING',
                'categories': ['FILE_SHARING'],
                'score': 7,
            },
            {
                'ip': '192.168.1.102',
                'open_ports': [
                    {'port': 3306, 'service': 'MySQL', 'description': 'Base de datos MySQL', 'risk': 'CRITICAL', 'category': 'DATABASE', 'banner': 'MySQL 5.7.32'},
                ],
                'device_type': 'DATABASE',
                'categories': ['DATABASE'],
                'score': 9,
            },
            {
                'ip': '192.168.1.103',
                'open_ports': [
                    {'port': 3389, 'service': 'RDP', 'description': 'Escritorio remoto Windows', 'risk': 'CRITICAL', 'category': 'REMOTE_ACCESS', 'banner': None},
                ],
                'device_type': 'REMOTE_ACCESS',
                'categories': ['REMOTE_ACCESS'],
                'score': 8,
            },
            {
                'ip': '192.168.1.104',
                'open_ports': [
                    {'port': 23, 'service': 'Telnet', 'description': 'Telnet (SIN CIFRADO)', 'risk': 'CRITICAL', 'category': 'UNENCRYPTED', 'banner': 'Telnet Server'},
                ],
                'device_type': 'UNENCRYPTED',
                'categories': ['UNENCRYPTED'],
                'score': 5,
            },
            {
                'ip': '192.168.1.105',
                'open_ports': [
                    {'port': 21, 'service': 'FTP', 'description': 'FTP (transferencia SIN CIFRADO)', 'risk': 'CRITICAL', 'category': 'UNENCRYPTED', 'banner': 'FTP Server'},
                ],
                'device_type': 'UNENCRYPTED',
                'categories': ['UNENCRYPTED'],
                'score': 5,
            },
            {
                'ip': '192.168.1.106',
                'open_ports': [
                    {'port': 554, 'service': 'RTSP', 'description': 'Cámara IP (posible CCTV)', 'risk': 'HIGH', 'category': 'CAMERA', 'banner': None},
                ],
                'device_type': 'CAMERA',
                'categories': ['CAMERA'],
                'score': 8,
            },
            {
                'ip': '192.168.1.107',
                'open_ports': [
                    {'port': 5900, 'service': 'VNC', 'description': 'Escritorio remoto VNC', 'risk': 'CRITICAL', 'category': 'REMOTE_ACCESS', 'banner': 'VNC'},
                ],
                'device_type': 'REMOTE_ACCESS',
                'categories': ['REMOTE_ACCESS'],
                'score': 8,
            },
        ],
        'pci_dss_violations': [
            {
                'ip': '192.168.1.100',
                'severity': 'CRITICAL',
                'violation': 'PCI DSS 1.3: Payment device visible from guest network',
                'detail': 'Point-of-Sale terminals should never be accessible from customer networks',
                'ports': [9100],
                'remediation': 'Isolate POS systems on separate VLAN restricted from guest access'
            },
            {
                'ip': '192.168.1.101',
                'severity': 'CRITICAL',
                'violation': 'PCI DSS 1.2: File storage accessible from untrusted network',
                'detail': 'Network storage containing business data should not be accessible from guest networks',
                'ports': [445, 139],
                'remediation': 'Block all inbound connections to file storage from guest/customer networks'
            },
            {
                'ip': '192.168.1.102',
                'severity': 'CRITICAL',
                'violation': 'PCI DSS 1.2: Database accessible from untrusted network',
                'detail': 'Databases containing cardholder data should not be accessible from guest networks',
                'ports': [3306],
                'remediation': 'Block all inbound connections to databases from guest/customer networks'
            },
        ],
        'findings': {
            'critical_services_exposed': 8,
            'unencrypted_protocols': 2,
            'databases_exposed': 1,
            'pos_systems_exposed': 1,
            'remote_access_exposed': 2,
            'total_pci_dss_violations': 3,
        },
        'door_opener': {
            'headline': '🚨 CRITICAL: Your Internal Network Is Visible From Customer WiFi',
            'summary': 'From a customer WiFi connection, we were able to directly access your most sensitive business systems.',
            'findings_summary': [
                '✗ POS terminal exposed: Payment system accessible from guest network',
                '✗ Database exposed: MySQL database (containing customer/payment data?) visible to customers',
                '✗ File storage exposed: Network storage accessible without authentication',
                '✗ Unencrypted protocols: Telnet and FTP without encryption in use',
                '✗ Remote access: Windows RDP and VNC exposed to customer network',
                '✗ CCTV cameras: IP cameras visible from guest WiFi',
                '✗ Multiple PCI DSS violations: Payment processing systems not properly segmented',
            ],
            'customer_impact': [
                'A customer could directly intercept payment transactions at your POS terminal',
                'Complete access to your database without any password required',
                'All files on your network storage could be copied or deleted',
                'Credentials sent over Telnet/FTP could be captured and credentials reused',
                'Remote access could give attacker full control of Windows systems',
                'Surveillance cameras could be accessed or disabled',
            ],
            'recommended_actions': [
                '1. IMMEDIATE: Isolate all internal systems on a separate VLAN from guest WiFi',
                '2. Enable AP Isolation (Client Isolation) on your guest network',
                '3. Configure firewall rules to block all traffic between guest and business VLANs',
                '4. Move POS systems to hardwired network away from WiFi',
                '5. Disable Telnet and FTP completely - they have no place in modern networks',
                '6. Require strong authentication on all remote access (RDP, SSH, VNC)',
                '7. Schedule a professional network segmentation audit',
            ],
            'business_impact': 'Your business violates PCI DSS compliance requirements. This puts you at legal risk and could result in fines from payment processors.'
        }
    }

# ────────────────────────────────────────────────────────────
# REPORT GENERATION
# ────────────────────────────────────────────────────────────

def generate_report(findings, demo=False):
    """Generate human-readable report."""
    report = []
    report.append("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    report.append("┃ 📡 NETWORK EXPOSURE SCANNER - Audit Report        ┃")
    report.append("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    report.append("")

    if demo:
        report.append("[DEMO MODE - Sample Data]")
        report.append("")

    if 'network_info' in findings:
        ni = findings['network_info']
        report.append("NETWORK SCAN INFORMATION:")
        report.append(f"  Local IP: {ni['local_ip']}")
        report.append(f"  Subnet: {ni['subnet']}")
        report.append(f"  Duration: {ni['scan_duration']}s")
        report.append("")

    if 'scan_summary' in findings:
        ss = findings['scan_summary']
        report.append("SCAN SUMMARY:")
        report.append(f"  Hosts Scanned: {ss['hosts_scanned']}")
        report.append(f"  Hosts with Open Ports: {ss['hosts_with_open_ports']}")
        report.append(f"  Critical Risk Services: {ss['critical_risk_services']}")
        report.append("")

    devices = findings.get('devices_found', [])
    if devices:
        report.append(f"DEVICES FOUND ({len(devices)}):")
        for device in sorted(devices, key=lambda d: d['score'], reverse=True):
            report.append(f"  • {device['ip']} - {device['device_type']}")
            for port in device['open_ports']:
                report.append(f"    {port['port']:5d}/tcp - {port['service']:15s} {port['risk']}")
        report.append("")

    violations = findings.get('pci_dss_violations', [])
    if violations:
        report.append(f"🚫 PCI DSS VIOLATIONS ({len(violations)}):")
        for v in violations:
            report.append(f"  • [{v['severity']}] {v['ip']}")
            report.append(f"    {v['violation']}")

    return '\n'.join(report)

# ────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ────────────────────────────────────────────────────────────

def main():
    """Main execution."""
    import argparse

    parser = argparse.ArgumentParser(
        description='📡 Network Exposure Scanner - Comprehensive Guest WiFi Security Assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 network_exposure_scanner.py        # Live scan
  python3 network_exposure_scanner.py --demo # Demo mode
  python3 network_exposure_scanner.py --json # JSON output
        """
    )
    parser.add_argument('--demo', action='store_true', help='Run with demo data')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--subnet', help='Override subnet (e.g., 192.168.1.0/24)')
    args = parser.parse_args()

    if args.demo:
        findings = get_demo_data()
    else:
        print("[*] Detecting local network...", file=sys.stderr)
        local_ip, prefix_len = get_local_ip_and_subnet()

        if not local_ip:
            print("[!] Could not detect network. Try --demo", file=sys.stderr)
            sys.exit(1)

        print(f"[+] Local IP: {local_ip}/{prefix_len}", file=sys.stderr)

        if args.subnet:
            subnet_range = get_subnet_range(args.subnet.split('/')[0], int(args.subnet.split('/')[1]))
        else:
            subnet_range = get_subnet_range(local_ip, prefix_len)

        print(f"[*] Scanning {len(subnet_range)} hosts...", file=sys.stderr)
        devices = scan_subnet_comprehensive(subnet_range, timeout=45)

        print(f"[+] Found {len(devices)} devices with open ports", file=sys.stderr)

        violations = analyze_pci_dss_compliance(devices, local_ip)

        # Analyze findings
        critical_count = len([d for d in devices for p in d['open_ports'] if p['risk'] == 'CRITICAL'])
        pos_count = len([d for d in devices if 'POS' in d['categories']])
        db_count = len([d for d in devices if 'DATABASE' in d['categories']])

        findings = {
            'environment': get_environment(),
            'network_info': {
                'local_ip': local_ip,
                'subnet': f"{local_ip}/{prefix_len}",
                'scan_duration': 45,
                'timestamp': datetime.now().isoformat(),
            },
            'scan_summary': {
                'hosts_scanned': len(subnet_range),
                'hosts_with_open_ports': len(devices),
                'critical_risk_services': critical_count,
                'pci_dss_violations': len(violations),
            },
            'devices_found': devices,
            'pci_dss_violations': violations,
            'findings': {
                'critical_services_exposed': critical_count,
                'databases_exposed': db_count,
                'pos_systems_exposed': pos_count,
                'total_pci_dss_violations': len(violations),
            },
            'door_opener': {
                'headline': '🚨 Critical Network Exposure Detected' if violations else '⚠️  Network Exposure Analysis Complete',
                'summary': f'Found {len(devices)} devices with exposed services on the guest network.',
            }
        }

    if args.json or args.output:
        json_output = json.dumps(findings, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(json_output)
            print(f"[+] JSON report saved to {args.output}")
        else:
            print(json_output)
    else:
        report = generate_report(findings, demo=args.demo)
        print(report)

        reports_dir = Path.home() / 'purple_team_reports'
        reports_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = reports_dir / f'network_exposure_scanner_{timestamp}.json'
        with open(json_path, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"\n[+] JSON report saved to {json_path}")

if __name__ == '__main__':
    main()
