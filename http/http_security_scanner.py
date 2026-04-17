#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔒 HTTP SECURITY SCANNER — Purple Team Security Suite
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Analiza headers HTTP de seguridad, cookies, TLS, detección de CMS
y paneles de administración. Sin dependencias externas — 100% stdlib.

MITRE ATT&CK: T1190 (Exploit Public-Facing App), T1592.002 (Software)

⚠️  ETHICAL DISCLAIMER:
Usar únicamente en sitios propios o con permiso escrito explícito.
"""

import sys
import os
import re
import json
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from pathlib import Path

# ────────────────────────────────────────────────────────────
# ENVIRONMENT
# ────────────────────────────────────────────────────────────

def is_termux():
    return os.path.exists('/data/data/com.termux') or 'TERMUX_VERSION' in os.environ

def get_output_path():
    if is_termux():
        p = Path.home() / 'storage' / 'shared' / 'Documents' / 'purple_team_reports'
    else:
        p = Path.home() / 'purple_team_reports'
    p.mkdir(parents=True, exist_ok=True)
    return p

# ────────────────────────────────────────────────────────────
# HTTP FETCH (stdlib only — works in Termux without pip)
# ────────────────────────────────────────────────────────────

def fetch_url(url, timeout=10, method='GET', follow_redirects=True):
    """
    Fetch a URL using urllib (no requests dependency).
    Returns dict with status_code, headers (lowercased keys),
    body (str), final_url, set_cookie_headers (list of raw strings).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'Mozilla/5.0 (Purple Team Scanner; Security Audit)'},
        method=method,
    )

    try:
        if follow_redirects:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(65536).decode('utf-8', errors='ignore')
                headers = {k.lower(): v for k, v in resp.headers.items()}
                # urllib collapses duplicate headers — grab raw Set-Cookie list
                set_cookies = resp.headers.get_all('Set-Cookie') or []
                return {
                    'status_code': resp.status,
                    'headers': headers,
                    'body': body,
                    'final_url': resp.url,
                    'set_cookie_headers': set_cookies,
                    'error': None,
                }
        else:
            # No-redirect handler
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            opener.addheaders = [('User-Agent', 'Mozilla/5.0 (Purple Team Scanner)')]
            try:
                with opener.open(req, timeout=timeout) as resp:
                    body = resp.read(16384).decode('utf-8', errors='ignore')
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    set_cookies = resp.headers.get_all('Set-Cookie') or []
                    return {
                        'status_code': resp.status,
                        'headers': headers,
                        'body': body,
                        'final_url': resp.url,
                        'set_cookie_headers': set_cookies,
                        'error': None,
                    }
            except urllib.error.HTTPError as e:
                body = e.read(4096).decode('utf-8', errors='ignore')
                headers = {k.lower(): v for k, v in e.headers.items()}
                set_cookies = e.headers.get_all('Set-Cookie') or []
                return {
                    'status_code': e.code,
                    'headers': headers,
                    'body': body,
                    'final_url': url,
                    'set_cookie_headers': set_cookies,
                    'error': None,
                }
    except urllib.error.URLError as e:
        return {'status_code': 0, 'headers': {}, 'body': '', 'final_url': url,
                'set_cookie_headers': [], 'error': str(e.reason)}
    except socket.timeout:
        return {'status_code': 0, 'headers': {}, 'body': '', 'final_url': url,
                'set_cookie_headers': [], 'error': 'Timeout'}
    except Exception as e:
        return {'status_code': 0, 'headers': {}, 'body': '', 'final_url': url,
                'set_cookie_headers': [], 'error': str(e)}

# ────────────────────────────────────────────────────────────
# SECURITY HEADERS DEFINITIONS
# ────────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    'strict-transport-security': {
        'display': 'Strict-Transport-Security',
        'description': 'HSTS — fuerza HTTPS, evita downgrade a HTTP',
        'severity': 'HIGH',
        'recommendation': 'max-age=31536000; includeSubDomains; preload',
        'validator': lambda v: 'max-age' in v.lower(),
        'validator_msg': 'Debe incluir max-age',
    },
    'content-security-policy': {
        'display': 'Content-Security-Policy',
        'description': 'CSP — mitiga XSS e inyección de contenido',
        'severity': 'HIGH',
        'recommendation': "default-src 'self'; script-src 'self'",
        'validator': lambda v: 'default-src' in v.lower() or 'script-src' in v.lower(),
        'validator_msg': 'Debe incluir default-src',
    },
    'x-frame-options': {
        'display': 'X-Frame-Options',
        'description': 'Clickjacking — evita embeber en iframes maliciosos',
        'severity': 'MEDIUM',
        'recommendation': 'DENY o SAMEORIGIN',
        'validator': lambda v: v.upper() in ('DENY', 'SAMEORIGIN'),
        'validator_msg': 'Usar DENY o SAMEORIGIN',
    },
    'x-content-type-options': {
        'display': 'X-Content-Type-Options',
        'description': 'MIME-sniffing — evita ejecución de tipos incorrectos',
        'severity': 'MEDIUM',
        'recommendation': 'nosniff',
        'validator': lambda v: v.lower() == 'nosniff',
        'validator_msg': 'Debe ser exactamente "nosniff"',
    },
    'referrer-policy': {
        'display': 'Referrer-Policy',
        'description': 'Controla información enviada en cabecera Referer',
        'severity': 'LOW',
        'recommendation': 'no-referrer o strict-origin-when-cross-origin',
        'validator': lambda v: any(x in v.lower() for x in
                                   ['no-referrer', 'strict-origin', 'same-origin']),
        'validator_msg': 'Usar no-referrer o strict-origin-when-cross-origin',
    },
    'permissions-policy': {
        'display': 'Permissions-Policy',
        'description': 'Controla acceso a APIs del navegador (cámara, GPS…)',
        'severity': 'LOW',
        'recommendation': 'geolocation=(), camera=(), microphone=()',
        'validator': lambda v: len(v) > 5,
        'validator_msg': 'Definir restricciones de permisos',
    },
    'x-xss-protection': {
        'display': 'X-XSS-Protection',
        'description': 'XSS auditor (navegadores legacy)',
        'severity': 'LOW',
        'recommendation': '1; mode=block',
        'validator': lambda v: '1' in v,
        'validator_msg': 'Usar "1; mode=block"',
    },
    'cross-origin-embedder-policy': {
        'display': 'Cross-Origin-Embedder-Policy',
        'description': 'Aísla el contexto de navegación de recursos cross-origin',
        'severity': 'LOW',
        'recommendation': 'require-corp',
        'validator': lambda v: 'require-corp' in v.lower() or 'unsafe-none' not in v.lower(),
        'validator_msg': 'Usar require-corp',
    },
}

# ────────────────────────────────────────────────────────────
# COOKIE SECURITY ANALYSIS
# ────────────────────────────────────────────────────────────

def parse_set_cookie(raw_header):
    """Parse a raw Set-Cookie header string into a structured dict."""
    parts = [p.strip() for p in raw_header.split(';')]
    if not parts:
        return None
    name_val = parts[0]
    name = name_val.split('=')[0].strip() if '=' in name_val else name_val.strip()
    attrs = {p.split('=')[0].strip().lower() for p in parts[1:]}
    samesite_val = ''
    for p in parts[1:]:
        if p.strip().lower().startswith('samesite'):
            samesite_val = p.split('=')[-1].strip().lower() if '=' in p else ''
    return {
        'name': name,
        'secure': 'secure' in attrs,
        'httponly': 'httponly' in attrs,
        'samesite': samesite_val or ('samesite' in attrs),
        'raw': raw_header[:120],
    }

def analyze_cookies(set_cookie_headers):
    """Return list of cookie security findings."""
    findings = []
    for raw in set_cookie_headers:
        c = parse_set_cookie(raw)
        if not c:
            continue
        if not c['secure']:
            findings.append({
                'type': 'INSECURE_COOKIE',
                'severity': 'HIGH',
                'cookie': c['name'],
                'issue': 'Flag Secure ausente — cookie enviada en HTTP plano',
                'recommendation': 'Añadir flag Secure (solo HTTPS)',
            })
        if not c['httponly']:
            findings.append({
                'type': 'INSECURE_COOKIE',
                'severity': 'HIGH',
                'cookie': c['name'],
                'issue': 'Flag HttpOnly ausente — cookie accesible vía JavaScript (riesgo XSS)',
                'recommendation': 'Añadir flag HttpOnly a cookies de sesión',
            })
        if not c['samesite']:
            findings.append({
                'type': 'INSECURE_COOKIE',
                'severity': 'MEDIUM',
                'cookie': c['name'],
                'issue': 'Atributo SameSite ausente — riesgo CSRF',
                'recommendation': 'Añadir SameSite=Lax o SameSite=Strict',
            })
    return findings

# ────────────────────────────────────────────────────────────
# CMS & TECHNOLOGY DETECTION
# ────────────────────────────────────────────────────────────

CMS_SIGNATURES = {
    'WordPress': {
        'patterns': [r'/wp-content/', r'/wp-includes/', r'wordpress', r'wp-json'],
        'version_re': r'<meta[^>]+generator[^>]+WordPress\s+([\d.]+)',
        'admin_paths': ['/wp-admin/', '/wp-login.php', '/xmlrpc.php'],
        'risk_note': 'Mantener actualizado; xmlrpc.php debe deshabilitarse si no se usa',
    },
    'Joomla': {
        'patterns': [r'/components/com_', r'joomla', r'/media/jui/'],
        'version_re': r'<meta[^>]+generator[^>]+Joomla[!]?\s*([\d.]+)',
        'admin_paths': ['/administrator/', '/administrator/index.php'],
        'risk_note': 'Panel admin en /administrator/ debe protegerse con IP allowlist',
    },
    'Drupal': {
        'patterns': [r'/sites/default/', r'drupal', r'Drupal.settings'],
        'version_re': r'Drupal\s+([\d.]+)',
        'admin_paths': ['/user/login', '/admin/'],
        'risk_note': 'Aplicar parches de seguridad; Drupalgeddon vulnerabilidades conocidas',
    },
    'PrestaShop': {
        'patterns': [r'prestashop', r'/modules/ps_', r'PrestaShop'],
        'version_re': r'PrestaShop\s+([\d.]+)',
        'admin_paths': ['/admin/', '/adminXXX/'],
        'risk_note': 'Renombrar carpeta /admin/ es esencial en PrestaShop',
    },
    'Magento': {
        'patterns': [r'magento', r'/skin/frontend/', r'Mage.Cookies'],
        'version_re': r'Magento\s*/?v?([\d.]+)',
        'admin_paths': ['/admin/', '/index.php/admin/'],
        'risk_note': 'Asegurar panel admin; parches críticos (PCI DSS scope)',
    },
    'phpMyAdmin': {
        'patterns': [r'phpMyAdmin', r'phpmyadmin', r'pma_'],
        'version_re': r'phpMyAdmin\s+([\d.]+)',
        'admin_paths': ['/phpmyadmin/', '/pma/', '/mysql/'],
        'risk_note': 'phpMyAdmin nunca debe estar expuesto sin autenticación fuerte',
    },
}

def detect_cms(body, headers):
    """Detect CMS and version from body and response headers."""
    results = []
    body_lower = body.lower()

    for cms_name, sig in CMS_SIGNATURES.items():
        for pattern in sig['patterns']:
            if re.search(pattern, body, re.I):
                version = ''
                m = re.search(sig['version_re'], body, re.I)
                if m:
                    version = m.group(1)
                results.append({
                    'cms': cms_name,
                    'version': version,
                    'risk_note': sig['risk_note'],
                    'admin_paths': sig['admin_paths'],
                })
                break  # Only one match per CMS

    # Check X-Powered-By / Generator header
    for header_name in ('x-powered-by', 'x-generator', 'x-cms'):
        val = headers.get(header_name, '')
        if val:
            results.append({
                'cms': f'Header disclosure ({header_name})',
                'version': val[:60],
                'risk_note': 'Eliminar cabeceras que revelan tecnología usada',
                'admin_paths': [],
            })

    return results

# ────────────────────────────────────────────────────────────
# ADMIN PATH DISCOVERY
# ────────────────────────────────────────────────────────────

COMMON_ADMIN_PATHS = [
    '/admin/', '/admin/login', '/administrator/', '/wp-admin/',
    '/panel/', '/cpanel/', '/webadmin/', '/manager/',
    '/phpmyadmin/', '/pma/', '/db/', '/mysql/',
    '/login', '/login.php', '/signin',
    '/console', '/actuator', '/actuator/env', '/actuator/health',
    '/.env', '/.git/', '/config.php', '/web.config',
    '/debug', '/test', '/backup/', '/dump.sql',
]

def check_admin_paths(base_url, paths=None, timeout=5):
    """Probe common admin/sensitive paths for accessible responses."""
    found = []
    paths = paths or COMMON_ADMIN_PATHS

    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in paths:
        url = origin + path
        result = fetch_url(url, timeout=timeout, follow_redirects=False)
        if result['error']:
            continue
        code = result['status_code']
        # Interesting: 200, 401 (exists but protected), 403 (exists but forbidden)
        if code in (200, 401, 403):
            note = {
                200: '🔴 ACCESIBLE — panel/archivo expuesto sin auth',
                401: '🟡 Requiere autenticación (existe)',
                403: '🟡 Acceso prohibido (existe)',
            }.get(code, '')
            found.append({
                'path': path,
                'status': code,
                'note': note,
                'severity': 'CRITICAL' if code == 200 else 'MEDIUM',
            })

    return found

# ────────────────────────────────────────────────────────────
# INFORMATION DISCLOSURE
# ────────────────────────────────────────────────────────────

def check_info_disclosure(headers, body):
    findings = []

    for hdr in ('server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
                'x-generator', 'x-runtime'):
        val = headers.get(hdr, '')
        if val:
            findings.append({
                'type': 'INFO_DISCLOSURE',
                'severity': 'LOW',
                'header': hdr,
                'value': val[:80],
                'recommendation': f'Eliminar o genericizar cabecera {hdr}',
            })

    # Common sensitive patterns in body
    sensitive_patterns = [
        (r'(?i)(mysql_connect|mysqli_connect|pg_connect)\s*\(', 'DB credentials in source', 'CRITICAL'),
        (r'(?i)Exception\s+in\s+thread|stack\s*trace|at\s+[\w\.]+\([\w\.]+:\d+\)', 'Stack trace / debug info', 'HIGH'),
        (r'(?i)phpinfo\(\)', 'phpinfo() call exposed', 'HIGH'),
        (r'(?i)<!--\s*(debug|todo|fixme|password|secret|key|token)', 'Sensitive HTML comment', 'MEDIUM'),
        (r'(?i)(api[_-]?key|api[_-]?secret|access[_-]?token)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{8,}', 'API key/token in body', 'CRITICAL'),
    ]
    for pattern, desc, severity in sensitive_patterns:
        if re.search(pattern, body[:20000]):
            findings.append({
                'type': 'SENSITIVE_DATA_EXPOSURE',
                'severity': severity,
                'description': desc,
                'recommendation': 'Eliminar información sensible del código fuente / respuestas',
            })

    return findings

# ────────────────────────────────────────────────────────────
# TLS / HTTPS CHECKS
# ────────────────────────────────────────────────────────────

def check_tls(host, port=443, timeout=5):
    """Check TLS configuration details."""
    result = {
        'tls_available': False,
        'protocol_version': None,
        'cert_subject': None,
        'cert_expiry': None,
        'cert_expired': False,
        'findings': [],
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result['tls_available'] = True
                result['protocol_version'] = ssock.version()
                cert = ssock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    result['cert_subject'] = subject.get('commonName', '')
                    not_after = cert.get('notAfter', '')
                    result['cert_expiry'] = not_after
                    if not_after:
                        try:
                            expiry_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            result['cert_expired'] = expiry_dt < datetime.utcnow()
                        except Exception:
                            pass

        # Warn on old TLS versions
        proto = result.get('protocol_version', '')
        if proto in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
            result['findings'].append({
                'type': 'WEAK_TLS',
                'severity': 'HIGH',
                'description': f'Protocolo TLS obsoleto: {proto}',
                'recommendation': 'Deshabilitar TLS < 1.2; usar TLS 1.2 y TLS 1.3',
            })
        if result['cert_expired']:
            result['findings'].append({
                'type': 'EXPIRED_CERT',
                'severity': 'CRITICAL',
                'description': f'Certificado TLS expirado: {result["cert_expiry"]}',
                'recommendation': 'Renovar certificado SSL/TLS inmediatamente',
            })
    except Exception:
        pass
    return result

# ────────────────────────────────────────────────────────────
# MAIN SCANNER CLASS
# ────────────────────────────────────────────────────────────

class HTTPSecurityScanner:
    def __init__(self):
        self.output_dir = get_output_path()

    def scan(self, url, check_paths=False, json_output=False):
        """Full scan of a URL. Returns findings dict."""

        # Normalise URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        if not json_output:
            print("━" * 70)
            print("🔒  HTTP SECURITY SCANNER — Purple Team")
            print("━" * 70)
            print(f"Target: {url}\n")

        # ── Fetch main page ──────────────────────────────────
        resp = fetch_url(url, timeout=12)
        if resp['error']:
            msg = f"❌ Error al conectar: {resp['error']}"
            if not json_output:
                print(msg)
            return {'error': resp['error'], 'url': url}

        headers = resp['headers']
        body    = resp['body']
        final_url = resp['final_url']
        is_https  = final_url.startswith('https://')

        all_findings = []
        score = 0
        max_score = len(SECURITY_HEADERS)

        # ── Security headers ─────────────────────────────────
        if not json_output:
            print("━" * 70)
            print("📋  SECURITY HEADERS")
            print("━" * 70)

        header_results = {}
        for key, info in SECURITY_HEADERS.items():
            val = headers.get(key, '')
            present = bool(val)
            valid = present and info['validator'](val)

            if present and valid:
                score += 1
                status = '✅'
                issue = None
            elif present and not valid:
                score += 0.5
                status = '🟡'
                issue = info.get('validator_msg', 'Valor incorrecto')
            else:
                status = '❌'
                issue = 'Cabecera ausente'

            header_results[key] = {'present': present, 'valid': valid, 'value': val}

            if not json_output:
                icon_sev = {'HIGH': '🔴', 'MEDIUM': '🟠', 'LOW': '⚪'}.get(info['severity'], '⚪')
                if present:
                    print(f"  {status} {info['display']}: {val[:60]}")
                else:
                    print(f"  {status} {icon_sev} {info['display']} — AUSENTE")
                    print(f"     {info['description']}")
                    print(f"     Recomendación: {info['recommendation']}")

            if issue:
                all_findings.append({
                    'type': 'MISSING_HEADER' if not present else 'WEAK_HEADER',
                    'severity': info['severity'],
                    'header': info['display'],
                    'description': info['description'],
                    'recommendation': info['recommendation'],
                    'current_value': val or '(ausente)',
                })

        # ── Information disclosure ───────────────────────────
        if not json_output:
            print(f"\n{'━' * 70}\n🔍  INFORMATION DISCLOSURE\n{'━' * 70}")

        info_findings = check_info_disclosure(headers, body)
        all_findings.extend(info_findings)
        if not json_output:
            for f in info_findings:
                print(f"  ⚠️  {f.get('header', f.get('description', ''))}: {f.get('value', '')}")
            if not info_findings:
                print("  ✅ Sin cabeceras de information disclosure detectadas")

        # ── Cookie security ──────────────────────────────────
        if not json_output:
            print(f"\n{'━' * 70}\n🍪  COOKIE SECURITY\n{'━' * 70}")

        cookie_findings = analyze_cookies(resp['set_cookie_headers'])
        all_findings.extend(cookie_findings)
        if not json_output:
            if resp['set_cookie_headers']:
                cookie_names_seen = set()
                for raw in resp['set_cookie_headers']:
                    c = parse_set_cookie(raw)
                    if c and c['name'] not in cookie_names_seen:
                        cookie_names_seen.add(c['name'])
                        flags = []
                        flags.append('✅Secure' if c['secure'] else '🔴Secure:MISSING')
                        flags.append('✅HttpOnly' if c['httponly'] else '🔴HttpOnly:MISSING')
                        flags.append(f"✅SameSite={c['samesite']}" if c['samesite'] else '🟡SameSite:MISSING')
                        print(f"  🍪 {c['name']}: {' | '.join(flags)}")
            else:
                print("  ℹ️  Sin cookies detectadas en esta respuesta")

        # ── TLS ──────────────────────────────────────────────
        if not json_output:
            print(f"\n{'━' * 70}\n🔐  TLS / HTTPS\n{'━' * 70}")

        if is_https:
            tls_info = check_tls(host, 443)
            all_findings.extend(tls_info.get('findings', []))
            if not json_output:
                print(f"  ✅ HTTPS activo — protocolo: {tls_info.get('protocol_version', 'N/A')}")
                if tls_info.get('cert_subject'):
                    print(f"  📜 Certificado: {tls_info['cert_subject']}  expira: {tls_info.get('cert_expiry', 'N/A')}")
                if tls_info.get('cert_expired'):
                    print(f"  🔴 CERTIFICADO EXPIRADO")
                for f in tls_info.get('findings', []):
                    print(f"  🟠 {f['description']}")
        else:
            all_findings.append({
                'type': 'NO_HTTPS',
                'severity': 'CRITICAL',
                'description': 'Sitio sirve HTTP sin cifrado',
                'recommendation': 'Implementar HTTPS con certificado válido (Let\'s Encrypt es gratuito)',
            })
            if not json_output:
                print("  🔴 HTTP SIN CIFRADO — todo el tráfico es interceptable")

        # ── HTTP→HTTPS redirect check ─────────────────────────
        if is_https:
            http_check = fetch_url(url.replace('https://', 'http://'), timeout=5, follow_redirects=False)
            if http_check.get('status_code', 0) not in (301, 302, 307, 308):
                all_findings.append({
                    'type': 'NO_HTTPS_REDIRECT',
                    'severity': 'HIGH',
                    'description': 'HTTP no redirige a HTTPS automáticamente',
                    'recommendation': 'Añadir redireccionamiento 301 de HTTP a HTTPS',
                })
                if not json_output:
                    print("  🟠 HTTP no redirige a HTTPS — usuarios pueden quedar en HTTP")

        # ── CMS Detection ────────────────────────────────────
        if not json_output:
            print(f"\n{'━' * 70}\n🏷️   CMS / TECNOLOGÍA\n{'━' * 70}")

        cms_results = detect_cms(body, headers)
        if not json_output:
            if cms_results:
                for c in cms_results:
                    ver = f" v{c['version']}" if c.get('version') else ''
                    print(f"  🔎 Detectado: {c['cms']}{ver}")
                    print(f"     ⚠️  {c['risk_note']}")
                    if c.get('admin_paths'):
                        print(f"     Rutas admin: {', '.join(c['admin_paths'])}")
            else:
                print("  ℹ️  Sin CMS conocido detectado")

        # ── Admin paths ──────────────────────────────────────
        admin_findings = []
        if check_paths:
            if not json_output:
                print(f"\n{'━' * 70}\n🚪  ADMIN / RUTAS SENSIBLES\n{'━' * 70}")
            # Include CMS-specific paths
            extra_paths = []
            for c in cms_results:
                extra_paths.extend(c.get('admin_paths', []))
            paths_to_check = list(dict.fromkeys(COMMON_ADMIN_PATHS + extra_paths))
            admin_findings = check_admin_paths(url, paths_to_check, timeout=5)
            if not json_output:
                for af in admin_findings:
                    print(f"  {af['note']}  {af['path']}  [{af['status']}]")
                if not admin_findings:
                    print("  ✅ Sin rutas sensibles accesibles detectadas")

        all_findings.extend([
            {'type': 'EXPOSED_ADMIN', 'severity': af['severity'],
             'path': af['path'], 'status': af['status'], 'description': af['note']}
            for af in admin_findings
        ])

        # ── Score ─────────────────────────────────────────────
        percentage = (score / max_score) * 100 if max_score else 0
        if percentage >= 80:   grade, label = 'A', '✅ EXCELENTE'
        elif percentage >= 60: grade, label = 'B', '🟢 BUENA'
        elif percentage >= 40: grade, label = 'C', '🟡 MEDIA'
        elif percentage >= 20: grade, label = 'D', '🟠 POBRE'
        else:                  grade, label = 'F', '🔴 MUY POBRE'

        critical_count = len([f for f in all_findings if f.get('severity') == 'CRITICAL'])
        high_count     = len([f for f in all_findings if f.get('severity') == 'HIGH'])

        if not json_output:
            print(f"\n{'━' * 70}\n📊  SECURITY SCORE\n{'━' * 70}")
            print(f"  Puntuación: {score:.1f}/{max_score} ({percentage:.0f}%) — Nota: {grade} {label}")
            print(f"  🔴 Críticos: {critical_count}  🟠 Altos: {high_count}  Total hallazgos: {len(all_findings)}")

        result = {
            'url': url,
            'final_url': final_url,
            'timestamp': datetime.now().isoformat(),
            'is_https': is_https,
            'score': round(score, 1),
            'max_score': max_score,
            'percentage': round(percentage, 1),
            'grade': grade,
            'critical_count': critical_count,
            'high_count': high_count,
            'findings': all_findings,
            'cms_detected': cms_results,
            'admin_paths_found': admin_findings,
            'header_results': header_results,
        }

        self._save_report(result)
        return result

    def _save_report(self, result):
        """Save JSON and text reports to output directory."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = urllib.parse.urlparse(result['url']).netloc.replace(':', '_')
        domain = re.sub(r'[^\w\-.]', '', domain)[:40]

        # JSON report
        json_path = self.output_dir / f'http_security_{domain}_{timestamp}.json'
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        print(f"\n💾 Reporte guardado: {json_path}")

# ────────────────────────────────────────────────────────────
# DEMO DATA
# ────────────────────────────────────────────────────────────

def get_demo_data():
    return {
        'url': 'https://ejemplo-restaurante.es',
        'final_url': 'https://ejemplo-restaurante.es/',
        'timestamp': datetime.now().isoformat(),
        'is_https': True,
        'score': 2.0,
        'max_score': 8,
        'percentage': 25.0,
        'grade': 'D',
        'critical_count': 1,
        'high_count': 3,
        'findings': [
            {'type': 'NO_HTTPS_REDIRECT', 'severity': 'HIGH',
             'description': 'HTTP no redirige a HTTPS automáticamente'},
            {'type': 'MISSING_HEADER', 'severity': 'HIGH', 'header': 'Content-Security-Policy',
             'description': 'CSP — mitiga XSS e inyección de contenido',
             'recommendation': "default-src 'self'"},
            {'type': 'MISSING_HEADER', 'severity': 'HIGH', 'header': 'Strict-Transport-Security',
             'description': 'HSTS — fuerza HTTPS', 'recommendation': 'max-age=31536000; includeSubDomains'},
            {'type': 'INSECURE_COOKIE', 'severity': 'HIGH', 'cookie': 'session_id',
             'issue': 'Flag Secure ausente', 'recommendation': 'Añadir flag Secure'},
            {'type': 'INSECURE_COOKIE', 'severity': 'HIGH', 'cookie': 'session_id',
             'issue': 'Flag HttpOnly ausente', 'recommendation': 'Añadir flag HttpOnly'},
            {'type': 'INFO_DISCLOSURE', 'severity': 'LOW', 'header': 'x-powered-by',
             'value': 'PHP/7.4.3', 'recommendation': 'Eliminar X-Powered-By'},
            {'type': 'EXPOSED_ADMIN', 'severity': 'CRITICAL', 'path': '/wp-admin/',
             'status': 200, 'description': '🔴 ACCESIBLE — panel admin WordPress expuesto'},
        ],
        'cms_detected': [
            {'cms': 'WordPress', 'version': '6.2', 'risk_note': 'Mantener actualizado; deshabilitar xmlrpc.php',
             'admin_paths': ['/wp-admin/', '/wp-login.php', '/xmlrpc.php']},
        ],
        'admin_paths_found': [
            {'path': '/wp-admin/', 'status': 200, 'note': '🔴 ACCESIBLE sin auth', 'severity': 'CRITICAL'},
            {'path': '/wp-login.php', 'status': 200, 'note': '🔴 Login expuesto', 'severity': 'CRITICAL'},
        ],
    }

# ────────────────────────────────────────────────────────────
# MAIN
# ────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='🔒 HTTP Security Scanner — Purple Team (sin dependencias externas)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 http_security_scanner.py --url https://miempresa.es
  python3 http_security_scanner.py --url https://tienda.es --paths
  python3 http_security_scanner.py --demo
  python3 http_security_scanner.py --url https://sitio.es --json
        """
    )
    parser.add_argument('--url', help='URL objetivo a analizar')
    parser.add_argument('--demo', action='store_true', help='Mostrar datos de demo')
    parser.add_argument('--json', action='store_true', help='Salida en JSON')
    parser.add_argument('--paths', action='store_true', help='Comprobar rutas admin/sensibles')
    parser.add_argument('--output', help='Guardar JSON en archivo')
    args = parser.parse_args()

    scanner = HTTPSecurityScanner()

    if args.demo:
        data = get_demo_data()
        if args.json or args.output:
            out = json.dumps(data, indent=2, ensure_ascii=False)
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(out)
                print(f"[+] Demo guardado en {args.output}")
            else:
                print(out)
        else:
            # Pretty-print demo
            print("━" * 70)
            print("🔒  HTTP SECURITY SCANNER — MODO DEMO")
            print("━" * 70)
            print(f"Target: {data['url']}")
            print(f"Nota: {data['grade']}  Score: {data['percentage']:.0f}%")
            print(f"Críticos: {data['critical_count']}  Altos: {data['high_count']}")
            print(f"\nCMS detectado: {data['cms_detected'][0]['cms']} v{data['cms_detected'][0]['version']}")
            print(f"\nHallazgos:")
            for f in data['findings']:
                icon = '🔴' if f['severity'] == 'CRITICAL' else '🟠' if f['severity'] == 'HIGH' else '🟡'
                desc = f.get('description') or f.get('issue') or f.get('header', '')
                print(f"  {icon} [{f['severity']}] {desc}")
        return

    if args.url:
        result = scanner.scan(args.url, check_paths=args.paths, json_output=args.json)
        if args.json or args.output:
            out = json.dumps(result, indent=2, ensure_ascii=False)
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(out)
                print(f"[+] JSON guardado en {args.output}")
            else:
                print(out)
        return

    # Interactive mode (backward compatible)
    print("━" * 70)
    print("  🔒 HTTP Security Scanner — Purple Team Edition")
    print("━" * 70)
    print("Analiza headers de seguridad y vulnerabilidades OWASP")
    print("(sin dependencias externas — funciona en Termux)\n")

    try:
        while True:
            url = input("🎯 URL objetivo (o 'q' para salir): ").strip()
            if url.lower() in ('q', 'quit', 'exit', 'salir'):
                print("👋 Hasta luego!")
                break
            if not url:
                print("❌ URL vacía\n")
                continue
            check_p = input("¿Comprobar rutas admin/sensibles? (s/N): ").strip().lower() == 's'
            print()
            scanner.scan(url, check_paths=check_p)
            print("\n" + "━" * 70 + "\n")
            cont = input("¿Escanear otra URL? (S/n): ").strip().lower()
            if cont in ('n', 'no'):
                print("👋 Hasta luego!")
                break
    except KeyboardInterrupt:
        print("\n\n👋 Interrumpido por usuario")

if __name__ == '__main__':
    main()
