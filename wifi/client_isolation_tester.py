#!/usr/bin/env python3
"""
🔗 CLIENT ISOLATION TESTER - Network Segmentation Vulnerability Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests if client isolation is enabled on the current WiFi network.
Detects exposed POS terminals, printers, cameras, and NAS devices.
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
from datetime import datetime
from pathlib import Path
import threading
import time
import struct

# ────────────────────────────────────────────────────────────
# CONSTANTS
# ────────────────────────────────────────────────────────────

# Maximum concurrent scan threads — keeps Termux stable
MAX_THREADS = 20

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
                    return ip, 24  # Assume /24 for WiFi
    except Exception:
        pass

    # Fallback: use ip command
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

    # Last resort: socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip, 24
    except Exception:
        return None, None

def get_gateway():
    """Get default gateway IP."""
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
                gateway = data.get('gateway_ip', '')
                if gateway:
                    return gateway
    except Exception:
        pass

    # Fallback: parse routing table
    try:
        result = subprocess.run(
            ['ip', 'route', 'show'],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'default via' in line:
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    return match.group(1)
    except Exception:
        pass

    return None

def get_subnet_range(ip, prefix_length):
    """Get all IPs in subnet using ipaddress module."""
    try:
        network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
        return [str(addr) for addr in network.hosts()]
    except Exception:
        return []

# ────────────────────────────────────────────────────────────
# ARP TABLE — fast host pre-discovery
# ────────────────────────────────────────────────────────────

KNOWN_OUI = {
    'e8:65:d4': 'Xiaomi', 'f4:f2:6d': 'Apple', '14:cc:20': 'TP-Link',
    '50:c7:bf': 'TP-Link', '18:a6:f7': 'Huawei', '04:a1:51': 'Asus',
    'c8:3a:35': 'Tenda', '08:86:3b': 'Netgear', 'd8:07:b6': 'D-Link',
    'a8:96:8a': 'Ubiquiti', 'b4:75:0e': 'Cisco', '60:a4:b7': 'Aruba',
    '00:1a:11': 'Google', 'cc:2d:e0': 'Fiberhome', 'e4:5f:01': 'Fiberhome',
    '6c:72:20': 'Mitrastar', '2c:f0:5d': 'Samsung', 'b8:27:eb': 'Raspberry Pi',
    'dc:a6:32': 'Raspberry Pi', '00:50:56': 'VMware', '08:00:27': 'VirtualBox',
}

def get_vendor(mac: str) -> str:
    """Look up device vendor from MAC OUI prefix."""
    if not mac or len(mac) < 8:
        return ''
    prefix = mac[:8].lower()
    return KNOWN_OUI.get(prefix, '')

def get_arp_table():
    """
    Read the ARP table to get already-discovered hosts on the subnet.
    Returns dict: {ip: mac}. Much faster than pinging every host.
    """
    arp_map = {}

    # Method 1: ip neigh (Linux/Termux)
    try:
        result = subprocess.run(
            ['ip', 'neigh', 'show'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            # Example: 192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+.*?lladdr\s+([0-9a-f:]{17})', line, re.I)
            if m:
                arp_map[m.group(1)] = m.group(2).lower()
        if arp_map:
            return arp_map
    except Exception:
        pass

    # Method 2: arp -a (fallback)
    try:
        result = subprocess.run(
            ['arp', '-a'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            # Example: hostname (192.168.1.5) at aa:bb:cc:dd:ee:ff [ether] on wlan0
            m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})', line, re.I)
            if m:
                arp_map[m.group(1)] = m.group(2).lower()
    except Exception:
        pass

    return arp_map

def ping_host(host, timeout=0.8):
    """Fast ICMP reachability check using system ping."""
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', str(int(timeout)), host],
            capture_output=True, timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        return False

def reverse_dns(ip, timeout=1):
    """Try reverse DNS lookup for an IP."""
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return None

# ────────────────────────────────────────────────────────────
# PORT SCANNING (PURE PYTHON - NO NMAP)
# ────────────────────────────────────────────────────────────

def check_port(host, port, timeout=0.5):
    """Check if a port is open on a host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_banner(host, port, timeout=1):
    """Try to grab a banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:100]  # First 100 chars
    except Exception:
        return None

# Device classification ports
DEVICE_PORTS = {
    9100: {'device': 'POS_PRINTER', 'name': 'Impresora de recibos (posible TPV)', 'risk': 'CRITICAL'},
    8080: {'device': 'HTTP_ALT', 'name': 'Puerto HTTP alternativo (web admin)', 'risk': 'HIGH'},
    554: {'device': 'IP_CAMERA', 'name': 'Cámara IP (RTSP)', 'risk': 'HIGH'},
    445: {'device': 'NAS_SMB', 'name': 'Almacenamiento de red (SMB)', 'risk': 'CRITICAL'},
    139: {'device': 'SMB_NBT', 'name': 'File sharing (NetBIOS)', 'risk': 'HIGH'},
    548: {'device': 'AFP', 'name': 'File sharing (AFP - Mac)', 'risk': 'HIGH'},
    3389: {'device': 'RDP', 'name': 'Escritorio remoto Windows', 'risk': 'CRITICAL'},
    5900: {'device': 'VNC', 'name': 'Escritorio remoto VNC', 'risk': 'CRITICAL'},
    23: {'device': 'TELNET', 'name': 'Telnet (SIN CIFRADO)', 'risk': 'CRITICAL'},
    21: {'device': 'FTP', 'name': 'FTP (transferencia SIN CIFRADO)', 'risk': 'CRITICAL'},
    3306: {'device': 'MYSQL', 'name': 'Base de datos MySQL', 'risk': 'CRITICAL'},
    5432: {'device': 'POSTGRES', 'name': 'Base de datos PostgreSQL', 'risk': 'CRITICAL'},
    631: {'device': 'IPP_PRINTER', 'name': 'Impresora de red (IPP)', 'risk': 'HIGH'},
    22: {'device': 'SSH', 'name': 'SSH (shell remoto)', 'risk': 'HIGH'},
    80: {'device': 'HTTP', 'name': 'Servidor web', 'risk': 'MEDIUM'},
    443: {'device': 'HTTPS', 'name': 'Servidor web seguro', 'risk': 'LOW'},
}

def scan_host(host, ports=None):
    """Scan a host for open ports."""
    if ports is None:
        ports = list(DEVICE_PORTS.keys())

    open_ports = []
    for port in ports:
        if check_port(host, port):
            banner = get_banner(host, port)
            open_ports.append({
                'port': port,
                'banner': banner,
                'device_info': DEVICE_PORTS.get(port, {})
            })

    return open_ports

def classify_device(open_ports):
    """Classify device type based on open ports."""
    if not open_ports:
        return {'type': 'UNKNOWN', 'confidence': 'LOW'}

    # Scoring system
    scores = {}

    for port_info in open_ports:
        port = port_info['port']
        device_info = DEVICE_PORTS.get(port, {})

        if not device_info:
            continue

        device_type = device_info['device']

        if device_type not in scores:
            scores[device_type] = 0

        # Weight certain ports higher
        if port == 9100:
            scores[device_type] += 10  # Strong indicator
        elif port in [445, 139]:
            scores[device_type] += 8
        elif port in [3389, 5900]:
            scores[device_type] += 9
        elif port in [21, 23]:
            scores[device_type] += 7
        else:
            scores[device_type] += 1

    if not scores:
        return {'type': 'UNKNOWN', 'confidence': 'LOW'}

    best_device = max(scores, key=scores.get)
    return {
        'type': best_device,
        'confidence': 'HIGH' if scores[best_device] >= 10 else 'MEDIUM',
        'score': scores[best_device]
    }

# ────────────────────────────────────────────────────────────
# SUBNET SCANNING WITH THREADING
# ────────────────────────────────────────────────────────────

def scan_subnet(subnet_range, timeout=60, arp_map=None):
    """
    Scan all hosts in subnet for open ports.

    Uses a Semaphore to cap concurrent threads at MAX_THREADS (default 20),
    preventing Termux from running out of memory/FDs on a /24 subnet.

    Optimisation: hosts already seen in the ARP table are scanned first;
    unknown hosts get a quick ping check to filter out dead IPs before
    the full port scan.
    """
    devices = []
    lock = threading.Lock()
    semaphore = threading.Semaphore(MAX_THREADS)

    arp_map = arp_map or {}
    # Build priority order: ARP-known hosts first (almost certainly alive)
    known_ips = set(arp_map.keys())
    ordered = [h for h in subnet_range if h in known_ips] + \
              [h for h in subnet_range if h not in known_ips]

    total = len(ordered)
    scanned = [0]          # mutable counter shared across threads
    start_time = time.time()

    def worker(host):
        try:
            # If host is NOT in ARP table, do a quick ping first
            if host not in known_ips:
                if not ping_host(host, timeout=0.6):
                    return

            open_ports = scan_host(host)
            if open_ports:
                device_class = classify_device(open_ports)
                mac = arp_map.get(host, '')
                vendor = get_vendor(mac) if mac else ''
                hostname = reverse_dns(host)
                device = {
                    'ip': host,
                    'mac': mac,
                    'vendor': vendor,
                    'hostname': hostname,
                    'open_ports': open_ports,
                    'device_type': device_class['type'],
                    'confidence': device_class.get('confidence', 'LOW'),
                }
                with lock:
                    devices.append(device)
        finally:
            with lock:
                scanned[0] += 1
                done = scanned[0]
            semaphore.release()
            # Progress indicator every 10 hosts
            if done % 10 == 0 or done == total:
                elapsed = time.time() - start_time
                pct = (done / total) * 100
                print(f"\r  [*] Escaneando... {done}/{total} ({pct:.0f}%)  {elapsed:.0f}s",
                      end='', flush=True, file=sys.stderr)

    threads = []
    for host in ordered:
        if time.time() - start_time > timeout:
            print(f"\n  [!] Timeout de {timeout}s alcanzado, deteniendo escaneo.", file=sys.stderr)
            break
        semaphore.acquire()          # blocks when MAX_THREADS active
        t = threading.Thread(target=worker, args=(host,), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=2)

    print(file=sys.stderr)  # newline after progress line
    return devices

# ────────────────────────────────────────────────────────────
# ANALYSIS & REPORTING
# ────────────────────────────────────────────────────────────

def analyze_exposure(devices, gateway):
    """Analyze exposure risks from detected devices."""
    findings = {
        'client_isolation_enabled': True,
        'reachable_devices': len(devices),
        'critical_devices': [],
        'high_risk_services': [],
        'pos_terminals_exposed': [],
        'pci_dss_violations': [],
    }

    # Check for exposed devices
    for device in devices:
        if device['ip'] == gateway:
            continue  # Skip gateway

        device_type = device['device_type']
        open_ports = device['open_ports']

        # Critical device types
        if device_type in ['POS_PRINTER', 'RDP', 'VNC', 'MYSQL', 'POSTGRES', 'TELNET', 'FTP', 'NAS_SMB']:
            findings['client_isolation_enabled'] = False

            # POS system detection
            if device_type == 'POS_PRINTER' or any(p['port'] == 9100 for p in open_ports):
                findings['pos_terminals_exposed'].append({
                    'ip': device['ip'],
                    'type': device_type,
                    'ports': [p['port'] for p in open_ports],
                    'risk': 'CRITICAL - POS terminal visible from customer WiFi'
                })
                findings['pci_dss_violations'].append({
                    'ip': device['ip'],
                    'violation': 'PCI DSS 1.3: Prohibited traffic between guest/customer networks and internal payment systems',
                    'ports': [p['port'] for p in open_ports]
                })

            # High-risk service exposure
            for port_info in open_ports:
                port = port_info['port']
                if port in [23, 21, 3306, 5432, 445, 3389, 5900]:
                    findings['high_risk_services'].append({
                        'ip': device['ip'],
                        'port': port,
                        'service': DEVICE_PORTS[port]['name'],
                        'risk': DEVICE_PORTS[port]['risk'],
                        'banner': port_info.get('banner', 'N/A')
                    })

            findings['critical_devices'].append(device)

    return findings

# ────────────────────────────────────────────────────────────
# DEMO MODE
# ────────────────────────────────────────────────────────────

def get_demo_data():
    """Return sample client isolation test data."""
    return {
        'environment': get_environment(),
        'network_info': {
            'local_ip': '192.168.1.50',
            'subnet': '192.168.1.0/24',
            'gateway': '192.168.1.1',
            'timestamp': datetime.now().isoformat(),
        },
        'scan_results': {
            'hosts_scanned': 254,
            'hosts_reachable': 8,
            'scan_duration_seconds': 45,
        },
        'devices_found': [
            {
                'ip': '192.168.1.100',
                'open_ports': [
                    {'port': 9100, 'banner': None, 'device_info': {'device': 'POS_PRINTER', 'name': 'Impresora de recibos', 'risk': 'CRITICAL'}},
                ],
                'device_type': 'POS_PRINTER',
                'confidence': 'HIGH',
            },
            {
                'ip': '192.168.1.101',
                'open_ports': [
                    {'port': 445, 'banner': 'SMB Signing: Disabled', 'device_info': {'device': 'NAS_SMB', 'name': 'Almacenamiento de red', 'risk': 'CRITICAL'}},
                    {'port': 139, 'banner': None, 'device_info': {'device': 'SMB_NBT', 'name': 'File sharing', 'risk': 'HIGH'}},
                ],
                'device_type': 'NAS_SMB',
                'confidence': 'HIGH',
            },
            {
                'ip': '192.168.1.102',
                'open_ports': [
                    {'port': 3389, 'banner': None, 'device_info': {'device': 'RDP', 'name': 'Escritorio remoto', 'risk': 'CRITICAL'}},
                ],
                'device_type': 'RDP',
                'confidence': 'HIGH',
            },
            {
                'ip': '192.168.1.103',
                'open_ports': [
                    {'port': 23, 'banner': 'Telnet Server', 'device_info': {'device': 'TELNET', 'name': 'Telnet (SIN CIFRADO)', 'risk': 'CRITICAL'}},
                ],
                'device_type': 'TELNET',
                'confidence': 'HIGH',
            },
            {
                'ip': '192.168.1.104',
                'open_ports': [
                    {'port': 21, 'banner': 'FTP Server Ready', 'device_info': {'device': 'FTP', 'name': 'FTP (transferencia SIN CIFRADO)', 'risk': 'CRITICAL'}},
                ],
                'device_type': 'FTP',
                'confidence': 'HIGH',
            },
            {
                'ip': '192.168.1.105',
                'open_ports': [
                    {'port': 3306, 'banner': 'MySQL 5.7', 'device_info': {'device': 'MYSQL', 'name': 'Base de datos MySQL', 'risk': 'CRITICAL'}},
                ],
                'device_type': 'MYSQL',
                'confidence': 'HIGH',
            },
            {
                'ip': '192.168.1.106',
                'open_ports': [
                    {'port': 5900, 'banner': None, 'device_info': {'device': 'VNC', 'name': 'Escritorio remoto VNC', 'risk': 'CRITICAL'}},
                ],
                'device_type': 'VNC',
                'confidence': 'HIGH',
            },
            {
                'ip': '192.168.1.107',
                'open_ports': [
                    {'port': 554, 'banner': None, 'device_info': {'device': 'IP_CAMERA', 'name': 'Cámara IP', 'risk': 'HIGH'}},
                ],
                'device_type': 'IP_CAMERA',
                'confidence': 'MEDIUM',
            },
        ],
        'findings': {
            'client_isolation_enabled': False,
            'reachable_devices': 8,
            'critical_devices': 7,
            'high_risk_services': [
                {'ip': '192.168.1.100', 'port': 9100, 'service': 'POS Printer', 'risk': 'CRITICAL'},
                {'ip': '192.168.1.101', 'port': 445, 'service': 'SMB File Sharing', 'risk': 'CRITICAL'},
                {'ip': '192.168.1.102', 'port': 3389, 'service': 'RDP', 'risk': 'CRITICAL'},
                {'ip': '192.168.1.103', 'port': 23, 'service': 'Telnet', 'risk': 'CRITICAL'},
                {'ip': '192.168.1.104', 'port': 21, 'service': 'FTP', 'risk': 'CRITICAL'},
                {'ip': '192.168.1.105', 'port': 3306, 'service': 'MySQL', 'risk': 'CRITICAL'},
                {'ip': '192.168.1.106', 'port': 5900, 'service': 'VNC', 'risk': 'CRITICAL'},
            ],
            'pos_terminals_exposed': [
                {'ip': '192.168.1.100', 'type': 'POS_PRINTER', 'ports': [9100], 'risk': 'CRITICAL - POS visible from customer WiFi'}
            ],
            'pci_dss_violations': [
                {'ip': '192.168.1.100', 'violation': 'PCI DSS 1.3: Prohibited traffic between guest and payment systems', 'ports': [9100]}
            ],
        },
        'door_opener': {
            'headline': '🚨 CRITICAL: Your Customer WiFi Can Reach Sensitive Business Systems',
            'summary': 'Your WiFi does not have client isolation enabled. This means anyone on your guest WiFi can directly access internal devices.',
            'findings_summary': [
                '✗ POS Terminal exposed: Payment device (192.168.1.100) visible to customers',
                '✗ Network storage exposed: File server accessible from guest WiFi (192.168.1.101)',
                '✗ Unencrypted services: Telnet, FTP, and unencrypted databases exposed',
                '✗ Remote access enabled: Windows RDP, VNC accessible from customer network',
                '✗ PCI DSS violation: Guest network can reach payment-processing systems',
            ],
            'customer_impact': [
                'A customer on your WiFi could directly connect to your POS terminal and intercept transactions',
                'Network storage with customer data is accessible without authentication',
                'Unencrypted protocols allow credential sniffing',
                'Remote desktop access could give attackers full system control',
            ],
            'recommended_actions': [
                '1. IMMEDIATE: Enable AP Isolation (Client Isolation) on all guest networks in your router settings',
                '2. Move all internal business devices to a separate VLAN (virtual network)',
                '3. Disable Telnet, FTP, and unencrypted services - use SSH and SFTP instead',
                '4. Change all default credentials and disable unnecessary services on open ports',
                '5. Set up a proper firewall between guest WiFi and business network',
                '6. Schedule a full network segmentation audit',
            ],
            'next_steps': 'Enable AP Isolation now - it takes 5 minutes and immediately prevents this risk.'
        }
    }

# ────────────────────────────────────────────────────────────
# REPORT GENERATION
# ────────────────────────────────────────────────────────────

def generate_report(findings, demo=False):
    """Generate human-readable report."""
    W = 64
    report = []
    report.append("┏" + "━" * W + "┓")
    report.append("┃" + " 🔗 CLIENT ISOLATION TESTER — Purple Team Security Suite".ljust(W) + "┃")
    report.append("┗" + "━" * W + "┛")
    report.append("")

    if demo:
        report.append("  ⚠️  [MODO DEMO — Datos de ejemplo para presentación]")
        report.append("")

    ni = findings.get('network_info', {})
    if ni:
        report.append(f"  🌐 Red: {ni.get('subnet', 'N/A')}  |  Gateway: {ni.get('gateway', 'N/A')}")
        report.append(f"  📱 IP local: {ni.get('local_ip', 'N/A')}")
        report.append("")

    sr = findings.get('scan_results', {})
    if sr:
        report.append(f"  📊 Hosts escaneados: {sr.get('hosts_scanned', 0)}  |  Alcanzables: {sr.get('hosts_reachable', 0)}  |  Tiempo: {sr.get('scan_duration_seconds', '?')}s")
        report.append("")

    fd = findings.get('findings', {})
    isolation = fd.get('client_isolation_enabled', True)
    if isolation:
        report.append("  ✅ AISLAMIENTO DE CLIENTES: ACTIVO")
    else:
        report.append("  🔴 AISLAMIENTO DE CLIENTES: DESACTIVADO — RIESGO CRÍTICO")
    report.append("")

    devices = findings.get('devices_found', [])
    if devices:
        report.append(f"  📡 DISPOSITIVOS ENCONTRADOS ({len(devices)}):")
        report.append("  " + "─" * (W - 2))
        for d in devices:
            risk_ports = [p for p in d['open_ports'] if p.get('device_info', {}).get('risk') in ('CRITICAL', 'HIGH')]
            icon = '🔴' if risk_ports else '🟡'
            mac_info = f"  MAC: {d.get('mac', 'N/A')}"
            vendor_info = f"  [{d.get('vendor', '')}]" if d.get('vendor') else ''
            hostname_info = f"  ({d.get('hostname', '')})" if d.get('hostname') else ''
            report.append(f"  {icon} {d['ip']}{vendor_info}{hostname_info}  [{d['device_type']}]")
            if d.get('mac'):
                report.append(f"     {mac_info}")
            ports_str = ', '.join(str(p['port']) for p in d['open_ports'])
            report.append(f"     Puertos: {ports_str}")
            report.append("")

    critical_svcs = fd.get('high_risk_services', [])
    if critical_svcs:
        report.append(f"  🚨 SERVICIOS CRÍTICOS EXPUESTOS ({len(critical_svcs)}):")
        report.append("  " + "─" * (W - 2))
        for svc in critical_svcs:
            banner = f"  banner: {svc['banner'][:40]}" if svc.get('banner') else ''
            report.append(f"  🔴 [{svc['risk']}] {svc['ip']}:{svc['port']} — {svc['service']}{banner}")
        report.append("")

    pci = fd.get('pci_dss_violations', [])
    if pci:
        report.append(f"  🚫 VIOLACIONES PCI DSS ({len(pci)}):")
        for v in pci:
            report.append(f"  ✗ {v['ip']}: {v['violation']}")
        report.append("")

    door = findings.get('door_opener', {})
    if door.get('headline'):
        report.append("  " + "─" * (W - 2))
        report.append(f"  {door['headline']}")
        report.append(f"  {door['summary']}")

    return '\n'.join(report)

# ────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ────────────────────────────────────────────────────────────

def main():
    """Main execution."""
    import argparse

    parser = argparse.ArgumentParser(
        description='🔗 Client Isolation Tester - Network Segmentation Test',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 client_isolation_tester.py        # Live scan of current WiFi
  python3 client_isolation_tester.py --demo # Demo mode with sample data
  python3 client_isolation_tester.py --json # JSON output only
        """
    )
    parser.add_argument('--demo', action='store_true', help='Run with demo data')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--subnet', help='Override subnet range (e.g., 192.168.1.0/24)')
    args = parser.parse_args()

    # Get data
    if args.demo:
        findings = get_demo_data()
    else:
        print("[*] Detecting local network...", file=sys.stderr)
        local_ip, prefix_len = get_local_ip_and_subnet()
        gateway = get_gateway()

        if not local_ip:
            print("[!] Could not detect network. Try --demo for sample output.", file=sys.stderr)
            sys.exit(1)

        print(f"[+] Local IP: {local_ip}/{prefix_len}", file=sys.stderr)
        print(f"[+] Gateway: {gateway}", file=sys.stderr)

        # Get subnet range
        if args.subnet:
            subnet_range = get_subnet_range(args.subnet.split('/')[0], int(args.subnet.split('/')[1]))
        else:
            subnet_range = get_subnet_range(local_ip, prefix_len)

        # Collect ARP table for fast pre-filtering
        print(f"[*] Leyendo tabla ARP...", file=sys.stderr)
        arp_map = get_arp_table()
        print(f"[+] {len(arp_map)} hosts en tabla ARP", file=sys.stderr)

        print(f"[*] Escaneando {len(subnet_range)} hosts (max {MAX_THREADS} hilos simultáneos)...", file=sys.stderr)
        devices = scan_subnet(subnet_range, timeout=60, arp_map=arp_map)

        print(f"[+] Found {len(devices)} active devices", file=sys.stderr)

        analysis = analyze_exposure(devices, gateway)

        findings = {
            'environment': get_environment(),
            'network_info': {
                'local_ip': local_ip,
                'subnet': f"{local_ip}/{prefix_len}",
                'gateway': gateway,
                'timestamp': datetime.now().isoformat(),
            },
            'scan_results': {
                'hosts_scanned': len(subnet_range),
                'hosts_reachable': len(devices),
                'scan_duration_seconds': 30,
            },
            'devices_found': devices,
            'findings': analysis,
            'door_opener': {
                'headline': '🚨 WiFi Network Segmentation Issue' if not analysis['client_isolation_enabled'] else '✓ WiFi Properly Segmented',
                'summary': 'Network access control analysis complete.',
            } if devices else {}
        }

    # Output
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

        # Also save JSON
        reports_dir = Path.home() / 'purple_team_reports'
        reports_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = reports_dir / f'client_isolation_tester_{timestamp}.json'
        with open(json_path, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"\n[+] JSON report saved to {json_path}")

if __name__ == '__main__':
    main()
