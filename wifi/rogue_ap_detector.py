#!/usr/bin/env python3
"""
🔍 ROGUE AP DETECTOR - Evil Twin & Malicious WiFi Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detects potential Evil Twin / Rogue AP attacks targeting SMB networks.
Part of Purple Team Security Suite.

MITRE ATT&CK: T1557.002 (ARP Cache Poisoning), T1040 (Traffic Sniffing)

⚠️  ETHICAL DISCLAIMER:
This tool is designed ONLY for authorized security testing on networks you own
or have explicit written permission to test. Unauthorized network testing is illegal.
Use only as part of authorized security assessments.
"""

import json
import subprocess
import sys
import os
import re
from datetime import datetime
from pathlib import Path
import socket

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
# WIFI SCANNING FUNCTIONS
# ────────────────────────────────────────────────────────────

# ────────────────────────────────────────────────────────────
# OUI VENDOR LOOKUP (MAC prefix → manufacturer)
# ────────────────────────────────────────────────────────────

KNOWN_OUI = {
    'e8:65:d4': 'Xiaomi', 'f4:f2:6d': 'Apple', '14:cc:20': 'TP-Link',
    '50:c7:bf': 'TP-Link', 'a4:2b:b0': 'TP-Link', '98:da:c4': 'TP-Link',
    '18:a6:f7': 'Huawei', 'b4:f8:83': 'Huawei', '54:89:98': 'Huawei',
    '00:50:f2': 'Microsoft', '00:1a:11': 'Google', 'f4:f5:e8': 'Google',
    '04:a1:51': 'Asus', '2c:4d:54': 'Asus', 'ac:84:c9': 'Asus',
    'c8:3a:35': 'Tenda', '00:26:5a': 'Tenda', 'e8:94:f6': 'Tenda',
    '08:86:3b': 'Netgear', 'c0:ff:d4': 'Netgear', '9c:3d:cf': 'Netgear',
    '00:17:f2': 'Apple', 'f0:18:98': 'Apple', 'a4:c3:f0': 'Apple',
    'a8:96:8a': 'Ubiquiti', 'e0:63:da': 'Ubiquiti', '44:d9:e7': 'Ubiquiti',
    'b4:75:0e': 'Cisco', '00:1b:2b': 'Cisco', '58:97:bd': 'Cisco',
    '60:a4:b7': 'Aruba', 'd8:c7:c8': 'Aruba', '00:24:6c': 'Aruba',
    '74:da:38': 'Edimax', '80:1f:02': 'Edimax',
    'd8:07:b6': 'D-Link', '14:d6:4d': 'D-Link', '28:10:7b': 'D-Link',
    '00:90:4c': 'Epigram', 'cc:2d:e0': 'Fiberhome', 'e4:5f:01': 'Fiberhome',
    '6c:72:20': 'Mitrastar', '48:8d:36': 'Mitrastar',
}

def get_vendor(bssid: str) -> str:
    """Look up router vendor from MAC OUI prefix."""
    prefix = bssid[:8].lower()
    if prefix in KNOWN_OUI:
        return KNOWN_OUI[prefix]
    prefix6 = bssid[:6].lower().replace(':', '')
    for oui, vendor in KNOWN_OUI.items():
        if oui.replace(':', '') == prefix6:
            return vendor
    return ''

def parse_capabilities(caps: str) -> dict:
    """Extract security protocol and WPS status from capabilities string."""
    caps_upper = caps.upper()
    if 'WPA3' in caps_upper or 'SAE' in caps_upper:
        protocol = 'WPA3'
        risk = 'BAJO'
    elif 'WPA2' in caps_upper:
        protocol = 'WPA2'
        risk = 'BAJO'
    elif 'WPA' in caps_upper:
        protocol = 'WPA'
        risk = 'MEDIO'
    elif 'WEP' in caps_upper:
        protocol = 'WEP'
        risk = 'CRÍTICO'
    else:
        protocol = 'OPEN'
        risk = 'CRÍTICO'
    wps = 'WPS' in caps_upper
    return {'protocol': protocol, 'risk': risk, 'wps': wps}


def get_aps_termux():
    """Scan WiFi networks using Termux termux-wifi-scaninfo.
    termux-wifi-scaninfo returns a single JSON array with lowercase keys:
    ssid, bssid, level, frequency, capabilities
    """
    try:
        result = subprocess.run(
            ['termux-wifi-scaninfo'],
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode != 0:
            return []

        raw = result.stdout.strip()
        if not raw:
            return []

        # Parse as a single JSON array (NOT line by line)
        data = json.loads(raw)
        if not isinstance(data, list):
            data = [data]

        aps = []
        for ap in data:
            caps_str = ap.get('capabilities', '')
            sec = parse_capabilities(caps_str)
            bssid = ap.get('bssid', '')
            aps.append({
                'ssid': ap.get('ssid', ''),
                'bssid': bssid,
                'level': ap.get('level', 0),
                'frequency': ap.get('frequency', 0),
                'capabilities': caps_str,
                'protocol': sec['protocol'],
                'security_risk': sec['risk'],
                'wps': sec['wps'],
                'vendor': get_vendor(bssid),
            })
        return aps
    except json.JSONDecodeError as e:
        print(f"[!] JSON parse error from termux-wifi-scaninfo: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] Termux scan error: {e}", file=sys.stderr)
        return []

def get_aps_linux():
    """Scan WiFi networks using nmcli (terse mode) or iwlist on Linux/Kali."""
    aps = []

    # Try nmcli terse mode — avoids column-width alignment issues
    try:
        result = subprocess.run(
            ['nmcli', '-t', '-f', 'BSSID,SSID,FREQ,SIGNAL,SECURITY', 'dev', 'wifi', 'list', '--rescan', 'yes'],
            capture_output=True,
            text=True,
            timeout=20
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                # nmcli -t separates fields with ':' and escapes literal ':' as '\:'
                # Replace escaped colons temporarily
                parts = re.split(r'(?<!\\):', line)
                parts = [p.replace('\\:', ':') for p in parts]
                if len(parts) < 5:
                    continue
                bssid, ssid, freq_str, signal_str, security = parts[0], parts[1], parts[2], parts[3], parts[4]
                # freq: "2437 MHz" or "5180 MHz"
                freq_match = re.search(r'(\d+)', freq_str)
                freq = int(freq_match.group(1)) if freq_match else 0
                try:
                    level = int(signal_str) - 110  # nmcli signal is 0-100; convert to rough dBm
                except ValueError:
                    level = 0
                caps_str = security.strip()
                sec = parse_capabilities(caps_str)
                aps.append({
                    'ssid': ssid,
                    'bssid': bssid,
                    'level': level,
                    'frequency': freq,
                    'capabilities': caps_str,
                    'protocol': sec['protocol'],
                    'security_risk': sec['risk'],
                    'wps': sec['wps'],
                    'vendor': get_vendor(bssid),
                })
            if aps:
                return aps
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # Fallback: iwlist scan
    try:
        result = subprocess.run(
            ['iwlist', 'scan'],
            capture_output=True,
            text=True,
            timeout=20
        )
        if result.returncode == 0:
            current_ap: dict = {}
            for line in result.stdout.split('\n'):
                stripped = line.strip()
                if 'Cell' in stripped and 'Address:' in stripped:
                    if current_ap.get('bssid'):
                        _finalize_ap(current_ap, aps)
                    match = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', stripped)
                    current_ap = {'bssid': match.group(1).upper() if match else '', 'capabilities': ''}
                elif stripped.startswith('ESSID:'):
                    m = re.search(r'ESSID:"(.*?)"', stripped)
                    current_ap['ssid'] = m.group(1) if m else ''
                elif 'Frequency:' in stripped:
                    m = re.search(r'Frequency:([\d.]+)', stripped)
                    if m:
                        current_ap['frequency'] = int(float(m.group(1)) * 1000)
                elif 'Signal level=' in stripped:
                    m = re.search(r'Signal level=(-?\d+)', stripped)
                    current_ap['level'] = int(m.group(1)) if m else 0
                elif 'Encryption key:' in stripped:
                    current_ap['_enc'] = 'on' in stripped.lower()
                elif 'IE:' in stripped or 'WPA' in stripped.upper():
                    current_ap['capabilities'] += ' ' + stripped
            if current_ap.get('bssid'):
                _finalize_ap(current_ap, aps)
    except FileNotFoundError:
        pass
    except Exception:
        pass

    return aps

def _finalize_ap(current_ap: dict, aps: list):
    """Finalize an AP dict from iwlist parsing and append to aps list."""
    caps_str = current_ap.get('capabilities', '')
    # If no WPA in caps but encryption is on, likely WEP
    if not caps_str.strip() and current_ap.get('_enc'):
        caps_str = 'WEP'
    sec = parse_capabilities(caps_str)
    bssid = current_ap.get('bssid', '')
    aps.append({
        'ssid': current_ap.get('ssid', ''),
        'bssid': bssid,
        'level': current_ap.get('level', 0),
        'frequency': current_ap.get('frequency', 0),
        'capabilities': caps_str.strip(),
        'protocol': sec['protocol'],
        'security_risk': sec['risk'],
        'wps': sec['wps'],
        'vendor': get_vendor(bssid),
    })

def get_aps():
    """Get list of visible APs, auto-detecting environment."""
    if is_termux():
        return get_aps_termux()
    else:
        return get_aps_linux()

# ────────────────────────────────────────────────────────────
# ROGUE AP DETECTION LOGIC
# ────────────────────────────────────────────────────────────

def detect_evil_twins(aps):
    """
    Detect Evil Twin APs:
    - Same SSID with different BSSIDs (Evil Twin / rogue AP)
    - Same SSID with different security protocols (downgrade attack)
    """
    ssid_groups = {}

    for ap in aps:
        ssid = ap.get('ssid', '').strip()
        if not ssid:
            continue
        ssid_groups.setdefault(ssid, []).append(ap)

    suspicious = []

    for ssid, ap_list in ssid_groups.items():
        unique_bssids = {ap['bssid'] for ap in ap_list if ap.get('bssid')}

        if len(unique_bssids) > 1:
            levels = [ap.get('level', 0) for ap in ap_list]
            signal_diff = max(levels) - min(levels)

            # Check for security downgrade: same SSID, different protocols
            protocols = {ap.get('protocol', 'OPEN') for ap in ap_list}
            downgrade_note = ''
            if len(protocols) > 1:
                downgrade_note = f' | ⚠️ DOWNGRADE: diferentes protocolos detectados: {", ".join(protocols)}'

            # Vendor info per BSSID
            ap_detail = []
            for ap in ap_list:
                vendor = ap.get('vendor', '')
                proto = ap.get('protocol', 'OPEN')
                freq = ap.get('frequency', 0)
                band = '5GHz' if freq > 4000 else '2.4GHz'
                ap_detail.append({
                    'bssid': ap['bssid'],
                    'signal': ap.get('level', 0),
                    'frequency': freq,
                    'band': band,
                    'protocol': proto,
                    'vendor': vendor,
                    'wps': ap.get('wps', False),
                })

            suspicious.append({
                'type': 'EVIL_TWIN',
                'risk': 'CRITICAL',
                'ssid': ssid,
                'count': len(ap_list),
                'bssids': list(unique_bssids),
                'signal_variance': signal_diff,
                'protocols_detected': list(protocols),
                'detail': f"SSID '{ssid}' detectado en {len(unique_bssids)} BSSIDs distintos{downgrade_note}",
                'explanation': 'Un atacante puede estar ejecutando una copia falsa de tu red WiFi. Los clientes que se conecten a la red errónea podrían ser interceptados.',
                'aps': ap_detail,
            })

    return suspicious


def detect_weak_security(aps):
    """Detect APs with weak/no encryption or WPS enabled."""
    findings = []
    for ap in aps:
        proto = ap.get('protocol', 'OPEN')
        wps = ap.get('wps', False)
        ssid = ap.get('ssid', '[oculta]') or '[oculta]'

        if proto == 'OPEN':
            findings.append({
                'type': 'OPEN_NETWORK',
                'risk': 'CRÍTICO',
                'ssid': ssid,
                'bssid': ap.get('bssid', ''),
                'vendor': ap.get('vendor', ''),
                'detail': f"Red ABIERTA sin cifrado: '{ssid}'",
                'explanation': 'Cualquier persona puede conectarse y ver todo el tráfico en texto plano.',
            })
        elif proto == 'WEP':
            findings.append({
                'type': 'WEAK_ENCRYPTION',
                'risk': 'CRÍTICO',
                'ssid': ssid,
                'bssid': ap.get('bssid', ''),
                'vendor': ap.get('vendor', ''),
                'detail': f"Cifrado WEP (obsoleto y roto) en: '{ssid}'",
                'explanation': 'WEP se puede descifrar en menos de 60 segundos con herramientas gratuitas.',
            })
        elif proto == 'WPA' and not wps:
            findings.append({
                'type': 'WEAK_ENCRYPTION',
                'risk': 'ALTO',
                'ssid': ssid,
                'bssid': ap.get('bssid', ''),
                'vendor': ap.get('vendor', ''),
                'detail': f"Cifrado WPA1 (antiguo) en: '{ssid}'",
                'explanation': 'WPA1 tiene vulnerabilidades conocidas. Actualizar a WPA2/WPA3.',
            })

        if wps and proto not in ('WPA3',):
            findings.append({
                'type': 'WPS_ENABLED',
                'risk': 'ALTO',
                'ssid': ssid,
                'bssid': ap.get('bssid', ''),
                'vendor': ap.get('vendor', ''),
                'detail': f"WPS activado en: '{ssid}' [{proto}]",
                'explanation': 'WPS PIN puede crackearse en horas (Pixie Dust, fuerza bruta). Desactivar en el router.',
            })

    return findings

def detect_hidden_ssid_conflicts(aps):
    """Detect hidden SSIDs on same channel as legitimate networks."""
    channel_map = {}

    for ap in aps:
        # Rough frequency-to-channel conversion (2.4 GHz)
        freq = ap.get('frequency', 0)
        if 2400 <= freq <= 2500:
            channel = int((freq - 2407) / 5)
        elif 5000 <= freq <= 6000:
            channel = int((freq - 5000) / 5)
        else:
            channel = 0

        ssid = ap.get('ssid', '').strip()
        if ssid:
            if channel not in channel_map:
                channel_map[channel] = {'named': [], 'hidden': []}
            channel_map[channel]['named'].append(ap)
        else:
            if channel not in channel_map:
                channel_map[channel] = {'named': [], 'hidden': []}
            channel_map[channel]['hidden'].append(ap)

    suspicious = []
    for channel, networks in channel_map.items():
        if networks['hidden'] and networks['named']:
            suspicious.append({
                'type': 'HIDDEN_SSID_CONFLICT',
                'risk': 'HIGH',
                'channel': channel,
                'hidden_count': len(networks['hidden']),
                'named_count': len(networks['named']),
                'detail': f"Hidden network(s) detected on same channel as legitimate SSID(s)",
                'explanation': 'A hidden WiFi network on the same channel as your network could be an attacker jamming or capturing traffic.',
                'legitimate_ssids': [ap['ssid'] for ap in networks['named']],
            })

    return suspicious

# ────────────────────────────────────────────────────────────
# DEMO MODE
# ────────────────────────────────────────────────────────────

def get_demo_data():
    """Return sample rogue AP detection data for demonstrations."""
    return {
        'environment': get_environment(),
        'scan_results': {
            'timestamp': datetime.now().isoformat(),
            'total_aps_found': 7,
            'aps_scanned': [
                {'ssid': 'FreeWiFi_Public', 'bssid': 'AA:BB:CC:DD:EE:01', 'level': -45, 'frequency': 2442},
                {'ssid': 'FreeWiFi_Public', 'bssid': 'AA:BB:CC:DD:EE:02', 'level': -72, 'frequency': 2442},
                {'ssid': 'RestaurantGuest', 'bssid': '00:11:22:33:44:55', 'level': -30, 'frequency': 2437},
                {'ssid': 'RestaurantGuest_5G', 'bssid': '00:11:22:33:44:66', 'level': -55, 'frequency': 5180},
                {'ssid': '', 'bssid': 'FF:FF:FF:FF:FF:FF', 'level': -85, 'frequency': 2442},
                {'ssid': 'admin', 'bssid': '11:22:33:44:55:66', 'level': -60, 'frequency': 2437},
                {'ssid': 'admin', 'bssid': '11:22:33:44:55:77', 'level': -88, 'frequency': 2437},
            ]
        },
        'findings': {
            'evil_twins': [
                {
                    'type': 'EVIL_TWIN',
                    'risk': 'CRITICAL',
                    'ssid': 'FreeWiFi_Public',
                    'count': 2,
                    'bssids': ['AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:02'],
                    'signal_variance': 27,
                    'detail': "Same SSID 'FreeWiFi_Public' detected with 2 different BSSIDs",
                    'explanation': 'An attacker may be running a fake copy of your WiFi network outside your business. Customers connecting to the wrong one could be intercepted.',
                    'protocols_detected': ['WPA2', 'OPEN'],
                    'aps': [
                        {'bssid': 'AA:BB:CC:DD:EE:01', 'signal': -45, 'frequency': 2442, 'band': '2.4GHz', 'protocol': 'WPA2', 'vendor': 'TP-Link', 'wps': False},
                        {'bssid': 'AA:BB:CC:DD:EE:02', 'signal': -72, 'frequency': 2442, 'band': '2.4GHz', 'protocol': 'OPEN', 'vendor': '', 'wps': False},
                    ]
                },
                {
                    'type': 'EVIL_TWIN',
                    'risk': 'CRITICAL',
                    'ssid': 'admin',
                    'count': 2,
                    'bssids': ['11:22:33:44:55:66', '11:22:33:44:55:77'],
                    'signal_variance': 28,
                    'detail': "SSID 'admin' detectado en 2 BSSIDs distintos",
                    'explanation': 'Red interna duplicada — posible rogue AP imitando la red del personal.',
                    'protocols_detected': ['WPA2'],
                    'aps': [
                        {'bssid': '11:22:33:44:55:66', 'signal': -60, 'frequency': 2437, 'band': '2.4GHz', 'protocol': 'WPA2', 'vendor': 'Huawei', 'wps': True},
                        {'bssid': '11:22:33:44:55:77', 'signal': -88, 'frequency': 2437, 'band': '2.4GHz', 'protocol': 'WPA2', 'vendor': '', 'wps': False},
                    ]
                }
            ],
            'hidden_conflicts': [
                {
                    'type': 'HIDDEN_SSID_CONFLICT',
                    'risk': 'HIGH',
                    'channel': 6,
                    'hidden_count': 1,
                    'named_count': 2,
                    'detail': 'Hidden network(s) detected on same channel as legitimate SSID(s)',
                    'explanation': 'A hidden WiFi network on the same channel as your network could be an attacker jamming or capturing traffic.',
                    'legitimate_ssids': ['FreeWiFi_Public', 'admin'],
                }
            ],
            'total_risks': 3,
            'critical_count': 2,
        },
        'door_opener': {
            'headline': '🚨 CRITICAL: We Detected Active Rogue WiFi Networks Targeting Your Business',
            'summary': 'While scanning the WiFi environment around your restaurant, we discovered 2 CRITICAL vulnerabilities - someone may be running fake copies of your WiFi network right outside your door.',
            'findings_summary': [
                '✗ FAKE "FreeWiFi_Public": Same name as your network, but from a different device (Evil Twin). Customers could accidentally connect to the attacker\'s network instead of yours.',
                '✗ FAKE "admin" network: Your internal staff network is being impersonated by an unauthorized device.',
                '✗ Hidden network interference: An unlabeled WiFi network is operating on the same channel, likely jamming legitimate connections.',
            ],
            'customer_impact': [
                'Customers\' payment card data could be intercepted while they think they\'re on your safe network',
                'Login credentials for apps and accounts could be captured',
                'Personal device data could be exposed (photos, messages, location)',
            ],
            'recommended_actions': [
                '1. Change your main WiFi network name (SSID) to something unique that only your business would use',
                '2. Enable WiFi encryption (WPA3 or at minimum WPA2-AES)',
                '3. Disable the broadcast of your staff network name or move to 5 GHz only',
                '4. Reboot your router immediately - this may clear the rogue APs from the area',
                '5. Schedule a full network audit to identify any compromised devices',
            ],
            'next_steps': 'We recommend quarterly WiFi audits to catch these threats early.'
        }
    }

# ────────────────────────────────────────────────────────────
# REPORT GENERATION
# ────────────────────────────────────────────────────────────

def generate_report(findings, demo=False):
    """Generate human-readable report."""
    W = 60
    report = []
    report.append("┏" + "━" * W + "┓")
    report.append("┃" + " 🔍 ROGUE AP DETECTOR — Purple Team Security Suite".ljust(W) + "┃")
    report.append("┗" + "━" * W + "┛")
    report.append("")

    if demo:
        report.append("  ⚠️  [MODO DEMO — Datos de ejemplo para presentación]")
        report.append("")

    env = findings.get('environment', {})
    report.append(f"  📅 Fecha: {env.get('timestamp', 'N/A')}")
    report.append(f"  🖥️  Plataforma: {env.get('platform', 'N/A')}")

    scan = findings.get('scan_results', {})
    if scan:
        report.append(f"  📡 Redes escaneadas: {scan.get('total_aps_found', 0)}")
    report.append("")

    fd = findings.get('findings', {})
    evil_twins    = fd.get('evil_twins', [])
    hidden        = fd.get('hidden_conflicts', [])
    weak_sec      = fd.get('weak_security', [])
    total         = fd.get('total_risks', 0)
    critical      = fd.get('critical_count', 0)

    risk_bar = f"  ⚠️  Total hallazgos: {total}  |  Críticos: {critical}"
    report.append(risk_bar)
    report.append("")

    # Evil Twins
    if evil_twins:
        report.append("  🚨 EVIL TWIN / ROGUE AP (CRÍTICO):")
        report.append("  " + "─" * (W - 2))
        for et in evil_twins:
            report.append(f"  • SSID: '{et['ssid']}'  ({et['count']} APs)")
            for ap in et.get('aps', []):
                vendor = f" [{ap['vendor']}]" if ap.get('vendor') else ''
                wps_tag = ' ⚡WPS' if ap.get('wps') else ''
                report.append(f"    ↳ {ap['bssid']}{vendor}  {ap['protocol']}  {ap['band']}  {ap['signal']} dBm{wps_tag}")
            report.append(f"    💬 {et['explanation']}")
            report.append("")
    else:
        report.append("  ✅ Sin Evil Twins detectados")
        report.append("")

    # Hidden conflicts
    if hidden:
        report.append("  🕵️  REDES OCULTAS EN CONFLICTO (ALTO):")
        report.append("  " + "─" * (W - 2))
        for hc in hidden:
            report.append(f"  • Canal {hc['channel']}: {hc['hidden_count']} red(es) oculta(s)")
            report.append(f"    SSIDs legítimos: {', '.join(hc['legitimate_ssids'])}")
            report.append(f"    💬 {hc['explanation']}")
            report.append("")

    # Weak security
    if weak_sec:
        report.append("  🔓 SEGURIDAD DÉBIL:")
        report.append("  " + "─" * (W - 2))
        for ws in weak_sec:
            icon = '🔴' if ws['risk'] in ('CRÍTICO', 'CRITICAL') else '🟠'
            vendor = f" [{ws['vendor']}]" if ws.get('vendor') else ''
            report.append(f"  {icon} [{ws['risk']}] {ws['detail']}")
            report.append(f"     BSSID: {ws['bssid']}{vendor}")
            report.append(f"     💬 {ws['explanation']}")
            report.append("")

    # Door opener summary
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
        description='🔍 Rogue AP Detector - Evil Twin & Malicious WiFi Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 rogue_ap_detector.py              # Live scan (requires WiFi scanning permissions)
  python3 rogue_ap_detector.py --demo       # Demo mode with sample data
  python3 rogue_ap_detector.py --json       # Output JSON only
        """
    )
    parser.add_argument('--demo', action='store_true', help='Run with demo data')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    parser.add_argument('--output', help='Output file path')
    args = parser.parse_args()

    # Get data
    if args.demo:
        findings = get_demo_data()
    else:
        print("[*] Scanning for WiFi networks...", file=sys.stderr)
        aps = get_aps()

        if not aps:
            print("[!] No WiFi networks found. Try --demo for sample output.", file=sys.stderr)
            sys.exit(1)

        evil_twins = detect_evil_twins(aps)
        hidden_conflicts = detect_hidden_ssid_conflicts(aps)
        weak_security = detect_weak_security(aps)

        all_findings = evil_twins + hidden_conflicts + weak_security
        critical_count = len([x for x in all_findings if x.get('risk') in ('CRITICAL', 'CRÍTICO')])

        findings = {
            'environment': get_environment(),
            'scan_results': {
                'timestamp': datetime.now().isoformat(),
                'total_aps_found': len(aps),
                'aps_scanned': aps,
            },
            'findings': {
                'evil_twins': evil_twins,
                'hidden_conflicts': hidden_conflicts,
                'weak_security': weak_security,
                'total_risks': len(all_findings),
                'critical_count': critical_count,
            },
            'door_opener': {
                'headline': '🚨 Vulnerabilidades WiFi detectadas en tu red',
                'summary': f'Análisis completado: {len(aps)} redes escaneadas, {len(all_findings)} hallazgos ({critical_count} críticos).',
                'findings_summary': [x['detail'] for x in all_findings],
            } if all_findings else {
                'headline': '✅ No se detectaron anomalías WiFi',
                'summary': f'{len(aps)} redes escaneadas. Sin Evil Twins ni redes débiles detectadas.',
                'findings_summary': [],
            }
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
        json_path = reports_dir / f'rogue_ap_detector_{timestamp}.json'
        with open(json_path, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"\n[+] JSON report saved to {json_path}")

if __name__ == '__main__':
    main()
