#!/usr/bin/env python3
"""
🔐 ROUTER DEFAULT CHECKER - Default Credentials & Exposed Admin Panels
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detects routers with exposed admin interfaces and tests default credentials.
Identifies vulnerable router brands and configurations.
Part of Purple Team Security Suite.

MITRE ATT&CK: T1078.001 (Default Accounts), T1133 (External Remote Services)

⚠️  ETHICAL DISCLAIMER:
This tool is designed ONLY for authorized security testing on networks you own
or have explicit written permission to test. Unauthorized access attempts are illegal.
Use only as part of authorized security assessments.
"""

import json
import subprocess
import sys
import os
import re
import socket
from datetime import datetime
from pathlib import Path
import urllib.parse
import base64

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

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
# GATEWAY DETECTION
# ────────────────────────────────────────────────────────────

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

    return '192.168.1.1'  # Default fallback

# ────────────────────────────────────────────────────────────
# ROUTER DETECTION & CREDENTIAL TESTING
# ────────────────────────────────────────────────────────────

ROUTER_BRANDS = {
    'tp-link': {
        'names': ['TP-Link', 'tplink', 'TP_Link'],
        'ports': [80, 8080],
        'login_paths': ['/'],
        'form_fields': {'username': 'username', 'password': 'password'},
        'credentials': [
            ('admin', 'admin'), ('admin', 'tplink'), ('admin', 'password'), ('admin', '1234'),
        ],
    },
    'asus': {
        'names': ['ASUS', 'AsusWrt', 'asuswrt'],
        'ports': [80, 8080, 443, 8443],
        'login_paths': ['/Main_Login.asp', '/'],
        'form_fields': {'username': 'login_username', 'password': 'login_passwd'},
        'credentials': [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'),
        ],
    },
    'vodafone': {
        'names': ['Vodafone', 'vodafone', 'Hitachi', 'OpenWrt'],
        'ports': [80, 8080],
        'login_paths': ['/login.html', '/'],
        'form_fields': {'username': 'loginUsername', 'password': 'loginPassword'},
        'credentials': [
            ('admin', '1234'), ('admin', 'admin'), ('vodafone', 'vodafone'),
            ('admin', 'password'), ('admin', 'vodafone1'),
        ],
    },
    'movistar': {
        'names': ['Movistar', 'Telefonica', 'telefonica', 'Mitrastar', 'mitrastar'],
        'ports': [80, 8080],
        'login_paths': ['/login.html', '/index.html', '/'],
        'form_fields': {'username': 'admin_name', 'password': 'admin_password'},
        'credentials': [
            ('admin', '1234'), ('admin', 'admin'), ('1234', '1234'),
            ('admin', 'movistar'), ('root', '1234'),
        ],
    },
    'orange': {
        'names': ['Orange', 'Livebox', 'livebox', 'Sagem', 'Arcadyan'],
        'ports': [80, 8080],
        'login_paths': ['/login.html', '/'],
        'form_fields': {'username': 'login', 'password': 'password'},
        'credentials': [
            ('admin', 'admin'), ('admin', '1234'), ('admin', 'orange'),
            ('orange', 'orange'), ('admin', ''),
        ],
    },
    'jazztel': {
        'names': ['Jazztel', 'jazztel', 'Comtrend', 'comtrend'],
        'ports': [80, 8080],
        'login_paths': ['/'],
        'form_fields': {'username': 'username', 'password': 'password'},
        'credentials': [
            ('admin', 'admin'), ('admin', '1234'), ('jazztel', 'jazztel'),
            ('admin', 'password'),
        ],
    },
    'masmovil': {
        'names': ['MasMovil', 'masmovil', 'Lowi', 'lowi', 'Pepephone', 'pepephone', 'Yoigo', 'yoigo'],
        'ports': [80, 8080],
        'login_paths': ['/login.html', '/'],
        'form_fields': {'username': 'username', 'password': 'password'},
        'credentials': [
            ('admin', 'admin'), ('admin', '1234'), ('admin', 'masmovil'),
            ('admin', 'password'), ('1234', '1234'),
        ],
    },
    'xiaomi': {
        'names': ['Xiaomi', 'MiRouter', 'mi router', 'Redmi'],
        'ports': [80, 8080],
        'login_paths': ['/cgi-bin/luci/web/home'],
        'form_fields': {'username': 'username', 'password': 'password'},
        'credentials': [
            ('admin', 'admin'), ('admin', 'password'), ('root', 'root'),
        ],
    },
    'd-link': {
        'names': ['D-Link', 'DLink', 'd-link'],
        'ports': [80, 8080],
        'login_paths': ['/login.asp', '/'],
        'form_fields': {'username': 'username', 'password': 'password'},
        'credentials': [
            ('admin', ''), ('Admin', 'Admin'), ('admin', 'admin'), ('admin', '1234'),
        ],
    },
    'netgear': {
        'names': ['Netgear', 'NETGEAR', 'netgear'],
        'ports': [80, 443, 8080],
        'login_paths': ['/index.html', '/'],
        'form_fields': {'username': 'username', 'password': 'password'},
        'credentials': [
            ('admin', 'password'), ('admin', 'admin'), ('admin', '1234'),
        ],
    },
    'huawei': {
        'names': ['Huawei', 'HuaweiHG', 'HUAWEI'],
        'ports': [80, 8080],
        'login_paths': ['/html/index.html', '/'],
        'form_fields': {'username': 'Username', 'password': 'Password'},
        'credentials': [
            ('admin', 'admin'), ('root', 'admin'), ('admin', 'password'),
            ('telecomadmin', 'admintelecom'),
        ],
    },
    'zte': {
        'names': ['ZTE', 'ZXHN', 'Zxhn'],
        'ports': [80, 8080],
        'login_paths': ['/'],
        'form_fields': {'username': 'Username', 'password': 'Password'},
        'credentials': [
            ('admin', 'admin'), ('admin', 'zte'), ('admin', '1234'),
            ('root', 'root'), ('admin', 'telecom'),
        ],
    },
    'fiberhome': {
        'names': ['FiberHome', 'Fiberhome', 'fiberhome', 'AN5506'],
        'ports': [80, 8080],
        'login_paths': ['/'],
        'form_fields': {'username': 'Username', 'password': 'Password'},
        'credentials': [
            ('admin', 'admin'), ('admin', 'password'), ('telecomadmin', 'admintelecom'),
        ],
    },
}

# Generic credentials tested on unknown/undetected routers
GENERIC_CREDENTIALS = [
    ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'), ('admin', ''),
    ('root', 'root'), ('root', 'password'), ('root', '1234'),
    ('user', 'user'), ('admin', '0000'), ('admin', 'admin123'),
]

# Common login page paths to probe
LOGIN_PATHS = [
    '/', '/login', '/login.html', '/login.asp', '/login.cgi',
    '/admin', '/admin/', '/cgi-bin/luci', '/webpages/index.html',
]

def _raw_http_get(host, port, path='/', headers=None, timeout=5):
    """
    Pure-stdlib HTTP GET via raw socket.
    Returns (status_code: int, headers: dict, body: str) or None on error.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        base_headers = {
            'Host': host,
            'User-Agent': 'Mozilla/5.0 (Purple Team Scanner)',
            'Connection': 'close',
            'Accept': 'text/html,*/*',
        }
        if headers:
            base_headers.update(headers)
        header_str = ''.join(f'{k}: {v}\r\n' for k, v in base_headers.items())
        request = f'GET {path} HTTP/1.1\r\n{header_str}\r\n'
        sock.sendall(request.encode())
        raw = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()
        text = raw.decode('utf-8', errors='ignore')
        # Parse status line
        lines = text.split('\r\n')
        status_line = lines[0] if lines else ''
        m = re.search(r'HTTP/[\d.]+ (\d+)', status_line)
        status = int(m.group(1)) if m else 0
        # Parse response headers
        resp_headers = {}
        body_start = text.find('\r\n\r\n')
        header_block = text[:body_start] if body_start >= 0 else text
        for line in header_block.split('\r\n')[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                resp_headers[k.strip().lower()] = v.strip()
        body = text[body_start + 4:] if body_start >= 0 else ''
        return status, resp_headers, body
    except Exception:
        return None


def _raw_http_post(host, port, path='/', data=None, extra_headers=None, timeout=5):
    """
    Pure-stdlib HTTP POST via raw socket.
    Returns (status_code: int, headers: dict, body: str) or None on error.
    """
    try:
        payload = urllib.parse.urlencode(data or {}).encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        base_headers = {
            'Host': host,
            'User-Agent': 'Mozilla/5.0 (Purple Team Scanner)',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': str(len(payload)),
            'Connection': 'close',
        }
        if extra_headers:
            base_headers.update(extra_headers)
        header_str = ''.join(f'{k}: {v}\r\n' for k, v in base_headers.items())
        request = f'POST {path} HTTP/1.1\r\n{header_str}\r\n'
        sock.sendall(request.encode() + payload)
        raw = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()
        text = raw.decode('utf-8', errors='ignore')
        lines = text.split('\r\n')
        status_line = lines[0] if lines else ''
        m = re.search(r'HTTP/[\d.]+ (\d+)', status_line)
        status = int(m.group(1)) if m else 0
        resp_headers = {}
        body_start = text.find('\r\n\r\n')
        header_block = text[:body_start] if body_start >= 0 else text
        for line in header_block.split('\r\n')[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                resp_headers[k.strip().lower()] = v.strip()
        body = text[body_start + 4:] if body_start >= 0 else ''
        return status, resp_headers, body
    except Exception:
        return None


def detect_http_response(host, port, path='/', extra_headers=None, timeout=5):
    """Get HTTP response using requests (if available) or raw socket."""
    if REQUESTS_AVAILABLE:
        try:
            import warnings
            warnings.filterwarnings('ignore')
            resp = requests.get(
                f'http://{host}:{port}{path}',
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers=extra_headers or {},
            )
            return {
                'status_code': resp.status_code,
                'headers': {k.lower(): v for k, v in resp.headers.items()},
                'text': resp.text,
                'url': resp.url,
            }
        except Exception:
            pass
    result = _raw_http_get(host, port, path, extra_headers, timeout)
    if result:
        status, headers, body = result
        return {'status_code': status, 'headers': headers, 'text': body, 'url': f'http://{host}:{port}{path}'}
    return None


def detect_router_brand(http_response):
    """Detect router brand from HTTP response headers and body."""
    if not http_response:
        return None, 'UNKNOWN'

    text = http_response.get('text', '').lower()
    headers = http_response.get('headers', {})

    # Strong signals from Server header
    server = headers.get('server', '').lower()
    brand_server_map = {
        'tplink': 'tp-link', 'realtek': 'tp-link', 'asus': 'asus',
        'huawei': 'huawei', 'zte': 'zte', 'fiberhome': 'fiberhome',
        'arcadyan': 'orange', 'sagem': 'orange', 'comtrend': 'jazztel',
    }
    for keyword, brand_key in brand_server_map.items():
        if keyword in server:
            info = ROUTER_BRANDS.get(brand_key, {})
            return info.get('names', [brand_key])[0], 'HIGH'

    # Check page body and title
    for brand_key, info in ROUTER_BRANDS.items():
        for name in info['names']:
            if name.lower() in text:
                return name, 'MEDIUM'

    # Generic fallback
    if any(kw in text for kw in ['admin', 'password', 'login', 'router', 'gateway']):
        return 'Generic Router', 'LOW'

    return None, 'UNKNOWN'


def _login_success(status, headers, body, path_before):
    """
    Determine if a login attempt succeeded.
    Success = 200 with admin content, OR redirect (302/303) to a non-login page.
    Avoids false positives from 302 back to the same login page.
    """
    if status == 200:
        # Check for typical post-login indicators
        body_lower = body.lower()
        success_keywords = ['logout', 'sign out', 'dashboard', 'wireless', 'lan', 'wan',
                            'status', 'configuration', 'setup', 'management', 'reboot']
        login_page_keywords = ['incorrect', 'invalid', 'wrong password', 'login failed',
                               'error', 'login again', '<form', 'username', 'password']
        has_success = any(kw in body_lower for kw in success_keywords)
        has_login_form = any(kw in body_lower for kw in login_page_keywords)
        return has_success and not has_login_form
    if status in (301, 302, 303, 307):
        location = headers.get('location', '')
        # Redirect must be to a DIFFERENT page (not back to login)
        login_indicators = ['login', 'index', 'signin']
        is_redirect_away = location and not any(li in location.lower() for li in login_indicators)
        return is_redirect_away
    return False


def test_basic_auth(host, port, path, username, password, timeout=5):
    """Test HTTP Basic Auth on a given path."""
    auth_string = f"{username}:{password}"
    encoded_auth = base64.b64encode(auth_string.encode()).decode()
    extra = {'Authorization': f'Basic {encoded_auth}'}

    if REQUESTS_AVAILABLE:
        try:
            import warnings; warnings.filterwarnings('ignore')
            resp = requests.get(
                f'http://{host}:{port}{path}',
                auth=(username, password),
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            return _login_success(resp.status_code,
                                  {k.lower(): v for k, v in resp.headers.items()},
                                  resp.text, path)
        except Exception:
            pass

    result = _raw_http_get(host, port, path, extra, timeout)
    if result:
        status, headers, body = result
        return _login_success(status, headers, body, path)
    return False


def test_form_auth(host, port, path, username, password, form_fields, timeout=5):
    """Test form-based (POST) login on a given path."""
    user_field = form_fields.get('username', 'username')
    pass_field = form_fields.get('password', 'password')
    data = {user_field: username, pass_field: password}

    if REQUESTS_AVAILABLE:
        try:
            import warnings; warnings.filterwarnings('ignore')
            resp = requests.post(
                f'http://{host}:{port}{path}',
                data=data,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            return _login_success(resp.status_code,
                                  {k.lower(): v for k, v in resp.headers.items()},
                                  resp.text, path)
        except Exception:
            pass

    result = _raw_http_post(host, port, path, data, timeout=timeout)
    if result:
        status, headers, body = result
        return _login_success(status, headers, body, path)
    return False


def check_upnp(host, timeout=3):
    """Check for exposed UPnP SSDP on UDP 1900."""
    findings = []
    try:
        msg = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 1\r\n'
            'ST: ssdp:all\r\n\r\n'
        ).encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(msg, (host, 1900))
        try:
            data, _ = sock.recvfrom(2048)
            response = data.decode('utf-8', errors='ignore')
            findings.append({
                'type': 'UPNP_EXPOSED',
                'risk': 'ALTO',
                'host': host,
                'port': 1900,
                'detail': 'UPnP/SSDP expuesto — permite reconfiguración remota del router',
                'response_snippet': response[:200],
            })
        except socket.timeout:
            pass
        sock.close()
    except Exception:
        pass

    # Also check TCP port 5000 (UPnP control)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((host, 5000)) == 0:
            findings.append({
                'type': 'UPNP_TCP',
                'risk': 'ALTO',
                'host': host,
                'port': 5000,
                'detail': 'Puerto UPnP TCP 5000 abierto — posible control remoto UPnP',
            })
        s.close()
    except Exception:
        pass

    return findings


def check_router_access(host, port=80, timeout=5):
    """Check if router admin is accessible and test credentials (Basic + Form)."""
    results = {
        'host': host,
        'port': port,
        'accessible': False,
        'brand': None,
        'brand_key': None,
        'brand_confidence': 'UNKNOWN',
        'auth_type': None,
        'credentials_tested': [],
        'default_password_vulnerable': False,
        'authenticated_as': None,
        'working_password': None,
        'login_path': None,
        'firmware_hint': None,
    }

    # Check if port is open
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) != 0:
            sock.close()
            return results
        sock.close()
    except Exception:
        return results

    results['accessible'] = True

    # Get HTTP response from root
    http_response = detect_http_response(host, port, '/', timeout=timeout)
    brand_name, confidence = detect_router_brand(http_response)
    results['brand'] = brand_name
    results['brand_confidence'] = confidence

    # Try to extract firmware version from headers or body
    if http_response:
        server_hdr = http_response.get('headers', {}).get('server', '')
        if server_hdr:
            results['firmware_hint'] = server_hdr[:80]
        # Look for version strings in body
        body = http_response.get('text', '')
        m = re.search(r'[Vv]ersion[:\s]+([0-9]+\.[0-9]+[.\-\w]*)', body)
        if m and not results['firmware_hint']:
            results['firmware_hint'] = m.group(0)[:60]

    # Identify brand config block
    brand_config = None
    brand_key_found = None
    if brand_name:
        for bkey, binfo in ROUTER_BRANDS.items():
            if brand_name.lower() in [n.lower() for n in binfo['names']] or \
               brand_name.lower() in bkey:
                brand_config = binfo
                brand_key_found = bkey
                break
    results['brand_key'] = brand_key_found

    # Build credentials list: brand-specific first, then generic
    creds_to_try = list(brand_config['credentials'] if brand_config else []) + list(GENERIC_CREDENTIALS)
    # Deduplicate while preserving order
    seen = set()
    creds_unique = []
    for c in creds_to_try:
        if c not in seen:
            seen.add(c)
            creds_unique.append(c)

    # Determine login paths to try
    login_paths = list(brand_config.get('login_paths', LOGIN_PATHS[:3])) if brand_config else LOGIN_PATHS[:4]
    form_fields  = brand_config.get('form_fields', {'username': 'username', 'password': 'password'}) if brand_config else {'username': 'username', 'password': 'password'}

    # Phase 1: Try Basic Auth
    for username, password in creds_unique:
        for path in login_paths:
            if test_basic_auth(host, port, path, username, password, timeout):
                results['authenticated_as'] = username
                results['working_password'] = password
                results['default_password_vulnerable'] = True
                results['auth_type'] = 'HTTP Basic Auth'
                results['login_path'] = path
                results['credentials_tested'].append(
                    {'username': username, 'password': password, 'method': 'basic', 'success': True})
                return results
            else:
                results['credentials_tested'].append(
                    {'username': username, 'password': password, 'method': 'basic', 'success': False})
        if len(results['credentials_tested']) >= 20:  # Cap to avoid huge lists
            break

    # Phase 2: Try Form-based POST login
    results['credentials_tested'] = []  # Reset for form attempts
    for username, password in creds_unique:
        for path in login_paths:
            if test_form_auth(host, port, path, username, password, form_fields, timeout):
                results['authenticated_as'] = username
                results['working_password'] = password
                results['default_password_vulnerable'] = True
                results['auth_type'] = 'Form Login (POST)'
                results['login_path'] = path
                results['credentials_tested'].append(
                    {'username': username, 'password': password, 'method': 'form', 'success': True})
                return results
            else:
                results['credentials_tested'].append(
                    {'username': username, 'password': password, 'method': 'form', 'success': False})
        if len(results['credentials_tested']) >= 20:
            break

    return results

# ────────────────────────────────────────────────────────────
# DEMO MODE
# ────────────────────────────────────────────────────────────

def get_demo_data():
    """Return sample router checker data."""
    return {
        'environment': get_environment(),
        'scan_results': {
            'gateway': '192.168.1.1',
            'ports_scanned': [80, 443, 8080, 8443, 8888],
            'timestamp': datetime.now().isoformat(),
        },
        'routers_found': [
            {
                'host': '192.168.1.1', 'port': 80, 'accessible': True,
                'brand': 'TP-Link', 'brand_confidence': 'HIGH',
                'default_password_vulnerable': True, 'authenticated_as': 'admin',
                'working_password': 'admin', 'auth_type': 'Form Login (POST)',
                'login_path': '/', 'firmware_hint': 'TP-LINK Technologies',
                'credentials_tested': [{'username': 'admin', 'password': 'admin', 'method': 'form', 'success': True}],
            },
            {
                'host': '192.168.1.1', 'port': 8080, 'accessible': True,
                'brand': 'TP-Link', 'brand_confidence': 'MEDIUM',
                'default_password_vulnerable': True, 'authenticated_as': 'admin',
                'working_password': 'tplink', 'auth_type': 'HTTP Basic Auth',
                'login_path': '/', 'firmware_hint': '',
                'credentials_tested': [{'username': 'admin', 'password': 'tplink', 'method': 'basic', 'success': True}],
            },
        ],
        'upnp_findings': [
            {
                'type': 'UPNP_EXPOSED', 'risk': 'ALTO', 'host': '192.168.1.1', 'port': 1900,
                'detail': 'UPnP/SSDP expuesto — permite reconfiguración remota del router',
                'response_snippet': 'HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:TP-Link-Router',
            }
        ],
        'findings': {
            'total_routers_found': 2,
            'vulnerable_routers': 2,
            'upnp_exposed': [],
            'default_credentials_found': [
                {
                    'router': '192.168.1.1:80',
                    'brand': 'TP-Link',
                    'auth_type': 'Form Login (POST)',
                    'login_path': '/',
                    'username': 'admin',
                    'password': 'admin',
                    'firmware_hint': 'TP-LINK Technologies',
                    'risk': 'CRÍTICO',
                },
                {
                    'router': '192.168.1.1:8080',
                    'brand': 'TP-Link',
                    'auth_type': 'HTTP Basic Auth',
                    'login_path': '/',
                    'username': 'admin',
                    'password': 'tplink',
                    'firmware_hint': '',
                    'risk': 'CRÍTICO',
                },
            ],
            'exposed_admin_interfaces': 2,
            'critical_count': 2,
        },
        'door_opener': {
            'headline': '🚨 CRITICAL: Your Router Uses Default Admin Password',
            'summary': 'We were able to log into your router admin panel using the default password that came from the manufacturer.',
            'findings_summary': [
                '✗ Admin panel accessible: Port 80 and 8080 respond to HTTP requests',
                '✗ Default credentials work: Username "admin" / password "admin" logs in',
                '✗ TP-Link router detected: Brand identified from HTTP response',
                '✗ No access control: Anyone on the network can reach the admin panel',
            ],
            'customer_impact': [
                'An attacker with access to your WiFi can change your WiFi password and lock you out',
                'Network configuration can be changed to redirect traffic to malicious sites',
                'DNS settings can be hijacked to intercept all internet traffic',
                'WiFi encryption can be downgraded to allow password cracking',
            ],
            'recommended_actions': [
                '1. Log into your router admin panel immediately (192.168.1.1 or 192.168.0.1)',
                '2. Change the admin password to a strong, unique password (16+ characters)',
                '3. Enable WPA3 encryption (or WPA2-AES if WPA3 not available)',
                '4. Disable remote management access',
                '5. Disable WPS (WiFi Protected Setup) - it has known vulnerabilities',
                '6. Update router firmware to the latest version',
                '7. Restrict admin panel access to wired connections only if possible',
            ],
            'next_steps': 'Changing the admin password takes 2 minutes and secures your entire network.'
        }
    }

# ────────────────────────────────────────────────────────────
# REPORT GENERATION
# ────────────────────────────────────────────────────────────

def generate_report(findings, demo=False):
    """Generate human-readable report."""
    W = 62
    report = []
    report.append("┏" + "━" * W + "┓")
    report.append("┃" + " 🔐 ROUTER DEFAULT CHECKER — Purple Team Security Suite".ljust(W) + "┃")
    report.append("┗" + "━" * W + "┛")
    report.append("")

    if demo:
        report.append("  ⚠️  [MODO DEMO — Datos de ejemplo para presentación]")
        report.append("")

    env = findings.get('environment', {})
    report.append(f"  📅 {env.get('timestamp', 'N/A')}  |  🖥️  {env.get('platform', 'N/A')}")

    sr = findings.get('scan_results', {})
    if sr:
        report.append(f"  🌐 Gateway: {sr.get('gateway', 'N/A')}  |  Puertos: {', '.join(map(str, sr.get('ports_scanned', [])))} ")
    report.append("")

    fd = findings.get('findings', {})
    critical = fd.get('critical_count', 0)
    report.append(f"  ⚠️  Interfaces admin detectadas: {fd.get('total_routers_found', 0)}  |  Críticos: {critical}")
    report.append("")

    routers = findings.get('routers_found', [])
    for r in routers:
        icon = '🔴' if r['default_password_vulnerable'] else '🟡'
        brand = r.get('brand') or 'Desconocido'
        conf = r.get('brand_confidence', '')
        report.append(f"  {icon} {r['host']}:{r['port']}  [{brand}]  confianza:{conf}")
        if r.get('firmware_hint'):
            report.append(f"     Firmware/Server: {r['firmware_hint']}")
        if r['default_password_vulnerable']:
            report.append(f"     🔓 CREDENCIALES FUNCIONAN — usuario: {r['authenticated_as']}  pass: {r.get('working_password', '?')}")
            report.append(f"     Método: {r.get('auth_type', 'N/A')}  |  Ruta: {r.get('login_path', '/')}")
        else:
            report.append(f"     ✅ Sin credenciales por defecto detectadas")
        report.append("")

    # UPnP
    upnp = findings.get('upnp_findings', [])
    if upnp:
        report.append("  📡 UPnP EXPUESTO:")
        report.append("  " + "─" * (W - 2))
        for u in upnp:
            report.append(f"  🟠 [{u['risk']}] {u['detail']}")
            if u.get('response_snippet'):
                snippet = u['response_snippet'].replace('\r\n', ' ')[:80]
                report.append(f"     Respuesta: {snippet}")
        report.append("")

    # Default creds table
    creds_list = fd.get('default_credentials_found', [])
    if creds_list:
        report.append("  🔓 CREDENCIALES POR DEFECTO ENCONTRADAS:")
        report.append("  " + "─" * (W - 2))
        for c in creds_list:
            report.append(f"  🔴 {c['router']}  [{c['brand']}]  {c['auth_type']}")
            report.append(f"     usuario: {c['username']}  contraseña: {c['password']}")
            report.append(f"     Ruta: {c.get('login_path', '/')}  Firmware: {c.get('firmware_hint', 'N/A')}")
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
        description='🔐 Router Default Checker - Admin Interface & Credential Test',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 router_default_checker.py        # Test default gateway
  python3 router_default_checker.py --demo # Demo mode with sample data
  python3 router_default_checker.py --json # JSON output only
  python3 router_default_checker.py --host 192.168.0.1  # Test specific host
        """
    )
    parser.add_argument('--demo', action='store_true', help='Run with demo data')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--host', help='Override gateway IP')
    args = parser.parse_args()

    # Get data
    if args.demo:
        findings = get_demo_data()
    else:
        gateway = args.host or get_gateway()
        print(f"[*] Testing router at {gateway}...", file=sys.stderr)

        ports_to_test = [80, 443, 8080, 8443, 8888]
        routers_found = []

        for port in ports_to_test:
            print(f"  [*] Comprobando puerto {port}...", file=sys.stderr)
            result = check_router_access(gateway, port)
            if result['accessible']:
                routers_found.append(result)
                if result['default_password_vulnerable']:
                    print(f"  [!] CREDENCIALES POR DEFECTO funcionan en puerto {port}! ({result['auth_type']})", file=sys.stderr)

        # UPnP check
        print(f"  [*] Comprobando UPnP...", file=sys.stderr)
        upnp_findings = check_upnp(gateway)
        if upnp_findings:
            print(f"  [!] UPnP expuesto en {gateway}", file=sys.stderr)

        print(f"[+] Interfaces de admin encontradas: {len(routers_found)}", file=sys.stderr)

        default_creds = [r for r in routers_found if r['default_password_vulnerable']]
        critical_count = len(default_creds) + len(upnp_findings)

        findings = {
            'environment': get_environment(),
            'scan_results': {
                'gateway': gateway,
                'ports_scanned': ports_to_test,
                'timestamp': datetime.now().isoformat(),
            },
            'routers_found': routers_found,
            'upnp_findings': upnp_findings,
            'findings': {
                'total_routers_found': len(routers_found),
                'vulnerable_routers': len(default_creds),
                'default_credentials_found': [
                    {
                        'router': f"{r['host']}:{r['port']}",
                        'brand': r['brand'] or 'UNKNOWN',
                        'auth_type': r.get('auth_type', 'N/A'),
                        'login_path': r.get('login_path', '/'),
                        'username': r['authenticated_as'] or 'unknown',
                        'password': r.get('working_password', 'unknown'),
                        'firmware_hint': r.get('firmware_hint', ''),
                        'risk': 'CRÍTICO',
                    }
                    for r in default_creds
                ],
                'upnp_exposed': upnp_findings,
                'exposed_admin_interfaces': len(routers_found),
                'critical_count': critical_count,
            },
            'door_opener': {
                'headline': '🚨 Panel de administración del router expuesto' if routers_found else '✅ Sin interfaces admin detectadas',
                'summary': (
                    f"{len(routers_found)} interfaz(ces) admin encontrada(s). "
                    f"{len(default_creds)} con credenciales por defecto. "
                    f"{'UPnP expuesto.' if upnp_findings else ''}"
                ),
            } if routers_found or upnp_findings else {},
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
        json_path = reports_dir / f'router_default_checker_{timestamp}.json'
        with open(json_path, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"\n[+] JSON report saved to {json_path}")

if __name__ == '__main__':
    main()
