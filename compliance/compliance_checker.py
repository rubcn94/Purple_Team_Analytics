# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║       PURPLE TEAM SUITE - COMPLIANCE CHECKER                 ║
║       RGPD · ENS · ISO 27001 · PCI DSS · LOPD               ║
║                                                              ║
║  Evalúa el cumplimiento normativo del cliente y genera       ║
║  informe de brechas de compliance con referencias legales    ║
║  y multas aplicables.                                        ║
║                                                              ║
║  Uso:                                                        ║
║    python compliance/compliance_checker.py --url https://empresa.com ║
║    python compliance/compliance_checker.py --url https://web.com --framework rgpd ║
║    python compliance/compliance_checker.py --url https://web.com --full  ║
╚══════════════════════════════════════════════════════════════╝
"""

import ssl
import sys
import json
import socket
import argparse
import re
import urllib.request
import urllib.parse
from datetime import datetime
from pathlib import Path

# ── Colores ───────────────────────────────────────────────────────────────────
class C:
    PURPLE = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN  = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    BOLD   = '\033[1m';  DIM = '\033[2m'; END = '\033[0m'

def ok(m):    print(f"{C.GREEN}  ✅  {m}{C.END}")
def warn(m):  print(f"{C.YELLOW}  ⚠️   {m}{C.END}")
def fail(m):  print(f"{C.RED}  ❌  {m}{C.END}")
def crit(m):  print(f"{C.RED}  🚨  {m}{C.END}")
def info(m):  print(f"{C.CYAN}  ℹ️   {m}{C.END}")
def hdr(m):   print(f"\n{C.PURPLE}{C.BOLD}  ╔══ {m} ══╗{C.END}\n")

BANNER = f"""
{C.PURPLE}{C.BOLD}
  ╔══════════════════════════════════════════════════╗
  ║   🟣  PURPLE TEAM — COMPLIANCE CHECKER           ║
  ║        RGPD · ENS · ISO 27001 · PCI DSS           ║
  ╚══════════════════════════════════════════════════╝
{C.END}"""

# ─── Base de datos de normativas ─────────────────────────────────────────────

RGPD_CHECKS = {
    "Política de privacidad visible": {
        "description": "El sitio debe mostrar política de privacidad accesible",
        "check_type": "content",
        "patterns": [r"pol[íi]tica de privacidad", r"privacy policy", r"aviso legal"],
        "severity": "critical",
        "article": "Art. 13 y 14 RGPD",
        "fine_range": "hasta 20.000.000€ o 4% facturación global",
        "remediation": "Añadir página de Política de Privacidad enlazada desde el footer"
    },
    "Banner de cookies": {
        "description": "Debe existir consentimiento explícito para cookies",
        "check_type": "content",
        "patterns": [r"cookie", r"galeta", r"consentimiento", r"consent"],
        "severity": "high",
        "article": "Art. 7 RGPD + Art. 22 LSSI",
        "fine_range": "hasta 30.000€ (AEPD)",
        "remediation": "Implementar banner de cookies con opciones Aceptar/Rechazar/Personalizar"
    },
    "Formulario con checkbox de consentimiento": {
        "description": "Los formularios deben tener checkbox de aceptación explícita",
        "check_type": "content",
        "patterns": [r'type=["\']checkbox["\'].*(?:acepto|privacidad|rgpd|gdpr)',
                     r'(?:acepto|privacidad|rgpd|gdpr).*type=["\']checkbox["\']'],
        "severity": "high",
        "article": "Art. 7 RGPD",
        "fine_range": "hasta 20.000.000€",
        "remediation": "Añadir checkbox desmarcado con texto del consentimiento en formularios de contacto"
    },
    "HTTPS obligatorio": {
        "description": "Todo el sitio debe servirse por HTTPS",
        "check_type": "https",
        "severity": "critical",
        "article": "Art. 32 RGPD — medidas técnicas de seguridad",
        "fine_range": "hasta 10.000.000€ o 2% facturación",
        "remediation": "Implementar certificado SSL y redirigir HTTP → HTTPS (301)"
    },
    "Headers de seguridad HTTP": {
        "description": "Cabeceras de seguridad básicas deben estar presentes",
        "check_type": "headers",
        "required_headers": {
            "Strict-Transport-Security": "HSTS — fuerza HTTPS",
            "X-Content-Type-Options": "Previene MIME sniffing",
            "X-Frame-Options": "Previene clickjacking",
            "Content-Security-Policy": "Controla carga de recursos",
        },
        "severity": "medium",
        "article": "Art. 32 RGPD",
        "fine_range": "hasta 10.000.000€ o 2% facturación",
        "remediation": "Añadir headers de seguridad en servidor web (nginx/apache)"
    },
    "Información de contacto del DPO o responsable": {
        "description": "Debe indicarse responsable del tratamiento de datos",
        "check_type": "content",
        "patterns": [r"responsable.*datos", r"delegado.*protecci[oó]n", r"DPO", r"data protection officer"],
        "severity": "medium",
        "article": "Art. 13.1 RGPD",
        "fine_range": "hasta 10.000.000€",
        "remediation": "Incluir datos del responsable del tratamiento en la política de privacidad"
    },
}

PCI_DSS_CHECKS = {
    "HTTPS en páginas de pago": {
        "description": "Todas las páginas de pago deben usar HTTPS/TLS 1.2+",
        "check_type": "https",
        "severity": "critical",
        "requirement": "PCI DSS Req. 4.1",
        "remediation": "Implementar TLS 1.2 o superior en todo el flujo de pago"
    },
    "Formularios de pago seguros": {
        "description": "Los formularios de pago deben ser PCI-compliant",
        "check_type": "content",
        "patterns": [r'type=["\'](?:number|tel)["\'][^>]*(?:card|tarjeta|visa|mastercard)',
                     r'(?:card|tarjeta)[^>]*type=["\'](?:number|tel)["\']'],
        "severity": "critical",
        "requirement": "PCI DSS Req. 6.4",
        "remediation": "Usar pasarelas de pago certificadas PCI (Stripe, Redsys). NO almacenar datos de tarjeta."
    },
    "Cabecera CSP presente": {
        "description": "Content-Security-Policy para prevenir skimming de datos",
        "check_type": "header_check",
        "header": "Content-Security-Policy",
        "severity": "high",
        "requirement": "PCI DSS Req. 6.4.3",
        "remediation": "Implementar CSP restrictiva: default-src 'self'; script-src 'self'"
    },
    "Sin datos de tarjeta en localStorage": {
        "description": "No deben almacenarse datos de tarjeta en el navegador",
        "check_type": "content",
        "patterns": [r'localStorage.*(?:card|tarjeta|cvv|pan)',
                     r'sessionStorage.*(?:card|tarjeta|cvv|pan)'],
        "severity": "critical",
        "requirement": "PCI DSS Req. 3.2",
        "remediation": "NUNCA almacenar datos de tarjeta en localStorage/sessionStorage/cookies"
    },
}

ENS_CHECKS = {
    "Certificado SSL válido": {
        "description": "El certificado digital debe ser válido y no expirado",
        "check_type": "ssl_valid",
        "severity": "critical",
        "control": "ENS mp.com.2 — Cifrado de comunicaciones",
        "remediation": "Renovar certificado SSL. Recomendado: Let's Encrypt (gratuito)"
    },
    "TLS versión segura (1.2+)": {
        "description": "No deben usarse versiones obsoletas de TLS/SSL",
        "check_type": "tls_version",
        "severity": "high",
        "control": "ENS mp.com.2",
        "remediation": "Deshabilitar SSLv3, TLS 1.0, TLS 1.1 en configuración del servidor"
    },
    "Cabecera HSTS configurada": {
        "description": "HSTS previene downgrade attacks",
        "check_type": "header_check",
        "header": "Strict-Transport-Security",
        "severity": "high",
        "control": "ENS mp.com.2",
        "remediation": "Añadir: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Sin información de versión en cabeceras": {
        "description": "No deben exponerse versiones de software",
        "check_type": "no_version_headers",
        "severity": "medium",
        "control": "ENS op.exp.2 — Gestión de configuración",
        "remediation": "Deshabilitar cabeceras Server y X-Powered-By en el servidor"
    },
    "Redirección HTTPS activa": {
        "description": "HTTP debe redirigir a HTTPS",
        "check_type": "http_redirect",
        "severity": "high",
        "control": "ENS mp.com.2",
        "remediation": "Configurar redirección 301 de HTTP a HTTPS"
    },
}

ISO27001_CONTROLS = {
    "A.14.1.2 — Seguridad servicios en red": {
        "description": "Servicios web deben ser seguros por diseño",
        "checks": ["https", "security_headers"],
        "severity": "high",
        "clause": "ISO 27001:2022 A.8.24",
    },
    "A.18.1.4 — Privacidad y PII": {
        "description": "Protección de información personal identificable",
        "checks": ["privacy_policy", "cookie_banner"],
        "severity": "critical",
        "clause": "ISO 27001:2022 A.5.34",
    },
    "A.12.6.1 — Gestión de vulnerabilidades técnicas": {
        "description": "Gestión de actualizaciones y parches",
        "checks": ["no_version_headers", "security_headers"],
        "severity": "medium",
        "clause": "ISO 27001:2022 A.8.8",
    },
}

SECTOR_REQUIREMENTS = {
    "clinica": {
        "name": "Clínica / Centro de Salud",
        "frameworks": ["RGPD", "ENS", "ISO27001"],
        "extra": [
            ("LOPD-GDD Art. 9", "Datos de salud — categoría especial", "Requiere consentimiento explícito y DPO obligatorio"),
            ("LOPDGDD Art. 28", "Notificación de brechas en 72h", "Sistema de gestión de incidentes de seguridad"),
        ],
        "fine_multiplier": 2.0,
        "note": "Datos de salud tienen protección reforzada — multas x2"
    },
    "educacion": {
        "name": "Academia / Centro Educativo",
        "frameworks": ["RGPD", "ENS"],
        "extra": [
            ("LOPD Art. 7", "Menores de edad", "Datos de menores requieren consentimiento parental"),
            ("RD 203/2021", "Accesibilidad web", "Obligatoria para centros que reciben subvenciones"),
        ],
        "fine_multiplier": 1.5,
        "note": "Tratamiento de datos de menores — riesgo elevado"
    },
    "ecommerce": {
        "name": "Tienda Online",
        "frameworks": ["RGPD", "PCI_DSS", "LSSI"],
        "extra": [
            ("LSSI Art. 10", "Información obligatoria en web", "NIF, domicilio, precios con IVA"),
            ("PCI DSS v4.0", "Seguridad datos de pago", "Si procesas pagos con tarjeta"),
        ],
        "fine_multiplier": 1.0,
        "note": "Cumplimiento doble: RGPD + PCI DSS"
    },
    "restaurante": {
        "name": "Restaurante / Bar",
        "frameworks": ["RGPD", "LSSI"],
        "extra": [
            ("RGPD Art. 13", "Formulario de reservas online", "Debe tener política de privacidad y checkbox"),
            ("LSSI Art. 22", "WiFi con formulario de acceso", "Si el WiFi requiere datos, aplica RGPD"),
        ],
        "fine_multiplier": 0.8,
        "note": "PYMEs con menor facturación — multas proporcionales pero impacto alto"
    },
    "gimnasio": {
        "name": "Gimnasio / Centro Deportivo",
        "frameworks": ["RGPD", "ENS"],
        "extra": [
            ("RGPD Art. 9", "Datos biométricos", "Si usa control de acceso biométrico"),
            ("LSSI Art. 22", "WiFi clientes", "Registro de usuarios WiFi sujeto a RGPD"),
        ],
        "fine_multiplier": 0.9,
        "note": "Si usa control de acceso o cámaras — datos especiales"
    },
}


class ComplianceChecker:
    def __init__(self, url, domain=None, sector=None):
        self.url = url.rstrip('/')
        self.domain = domain or urllib.parse.urlparse(url).netloc
        self.sector = sector
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.site_content = ""
        self.site_headers = {}
        self.is_https = url.startswith("https://")
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "url": url,
            "domain": self.domain,
            "sector": sector,
            "rgpd": {"findings": [], "score": 0},
            "pci_dss": {"findings": [], "score": 0},
            "ens": {"findings": [], "score": 0},
            "overall_compliance": 0,
            "critical_issues": [],
            "total_fines_exposure": "No calculable sin contexto de facturación",
        }

    def _fetch_site(self):
        """Descarga el contenido del sitio."""
        try:
            req = urllib.request.Request(self.url)
            req.add_header('User-Agent', 'Mozilla/5.0 (compatible; ComplianceAudit/1.0)')
            with urllib.request.urlopen(req, timeout=15, context=self.ctx) as r:
                self.site_content = r.read(50000).decode('utf-8', errors='ignore').lower()
                self.site_headers = dict(r.info())
            return True
        except Exception as e:
            warn(f"No se pudo obtener contenido: {e}")
            return False

    def _check_ssl(self):
        """Verifica certificado SSL."""
        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=self.domain)
            conn.settimeout(10)
            conn.connect((self.domain, 443))
            cert = conn.getpeercert()
            conn.close()
            expire_str = cert.get('notAfter', '')
            if expire_str:
                expire_dt = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expire_dt - datetime.now()).days
                return True, days_left, cert
            return True, 999, cert
        except ssl.SSLError as e:
            return False, 0, str(e)
        except Exception as e:
            return False, 0, str(e)

    def _check_http_redirect(self):
        """Verifica redirección HTTP → HTTPS."""
        http_url = self.url.replace("https://", "http://")
        try:
            req = urllib.request.Request(http_url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            # No seguir redirect
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
            with opener.open(req, timeout=5) as r:
                return False  # Si llega aquí sin redirect, no redirige
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                location = e.headers.get('Location', '')
                return 'https://' in location
            return False
        except Exception:
            return False

    # ──────────────────────────────────────────────────────────────────────────
    def check_rgpd(self):
        """Evalúa cumplimiento RGPD."""
        hdr("📋 EVALUACIÓN RGPD / LOPD-GDD")
        findings = []
        passed = 0
        total = len(RGPD_CHECKS)

        for check_name, check in RGPD_CHECKS.items():
            result = False
            detail = ""

            if check["check_type"] == "content":
                if self.site_content:
                    for pattern in check["patterns"]:
                        if re.search(pattern, self.site_content, re.IGNORECASE):
                            result = True
                            break
                detail = "Presente en contenido" if result else "No encontrado en página"

            elif check["check_type"] == "https":
                result = self.is_https
                detail = "HTTPS activo" if result else "Sitio en HTTP sin cifrar"

            elif check["check_type"] == "headers":
                missing = []
                for header, desc in check["required_headers"].items():
                    if header.lower() not in {k.lower() for k in self.site_headers}:
                        missing.append(f"{header} ({desc})")
                result = len(missing) == 0
                detail = f"Faltan: {', '.join(missing)}" if missing else "Todos los headers presentes"

            elif check["check_type"] == "header_check":
                result = check.get("header", "").lower() in {k.lower() for k in self.site_headers}

            if result:
                ok(f"{check_name}")
                passed += 1
            else:
                sev = check.get("severity", "medium")
                icon = {"critical": "🚨", "high": "🔴", "medium": "🟡"}.get(sev, "⚠️")
                print(f"  {C.RED}  {icon}  INCUMPLIMIENTO: {check_name}{C.END}")
                print(f"       {C.DIM}↳ Artículo: {check.get('article', '')}{C.END}")
                print(f"       {C.DIM}↳ Multa potencial: {check.get('fine_range', '')}{C.END}")
                print(f"       {C.DIM}↳ Remediación: {check.get('remediation', '')}{C.END}")
                findings.append({
                    "check": check_name,
                    "severity": sev,
                    "article": check.get("article", ""),
                    "fine_range": check.get("fine_range", ""),
                    "detail": detail,
                    "remediation": check.get("remediation", "")
                })
                if sev == "critical":
                    self.results["critical_issues"].append(check_name)

        score = int((passed / total) * 100)
        color = C.GREEN if score >= 80 else (C.YELLOW if score >= 60 else C.RED)
        print(f"\n  {color}{C.BOLD}  RGPD Score: {passed}/{total} ({score}%){C.END}")
        self.results["rgpd"] = {"findings": findings, "score": score, "passed": passed, "total": total}
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    def check_pci_dss(self):
        """Evalúa cumplimiento PCI DSS básico."""
        hdr("💳 EVALUACIÓN PCI DSS (Datos de Pago)")
        findings = []
        passed = 0
        total = len(PCI_DSS_CHECKS)

        # Detectar si hay formularios de pago
        has_payment = any(kw in self.site_content for kw in
                         ['tarjeta', 'card', 'visa', 'mastercard', 'pago', 'checkout', 'payment'])

        if not has_payment:
            info("No se detectaron formularios de pago — PCI DSS aplicable solo si procesa tarjetas")

        for check_name, check in PCI_DSS_CHECKS.items():
            result = False
            detail = ""

            if check["check_type"] == "https":
                result = self.is_https
            elif check["check_type"] == "content":
                if self.site_content:
                    result = not any(re.search(p, self.site_content, re.IGNORECASE)
                                   for p in check["patterns"])
                    detail = "Sin evidencia de almacenamiento inseguro" if result else "Posible almacenamiento inseguro detectado"
                else:
                    result = True  # No content = no found
            elif check["check_type"] == "header_check":
                result = check.get("header", "").lower() in {k.lower() for k in self.site_headers}

            if result:
                ok(f"{check_name}")
                passed += 1
            else:
                sev = check.get("severity", "high")
                icon = {"critical": "🚨", "high": "🔴"}.get(sev, "⚠️")
                print(f"  {C.RED}  {icon}  FALLO PCI DSS: {check_name}{C.END}")
                print(f"       {C.DIM}↳ Requisito: {check.get('requirement', '')}{C.END}")
                print(f"       {C.DIM}↳ Remediación: {check.get('remediation', '')}{C.END}")
                findings.append({
                    "check": check_name,
                    "severity": sev,
                    "requirement": check.get("requirement", ""),
                    "remediation": check.get("remediation", "")
                })

        score = int((passed / total) * 100)
        color = C.GREEN if score >= 80 else (C.YELLOW if score >= 60 else C.RED)
        print(f"\n  {color}{C.BOLD}  PCI DSS Score: {passed}/{total} ({score}%){C.END}")
        self.results["pci_dss"] = {"findings": findings, "score": score}
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    def check_ens(self):
        """Evalúa cumplimiento ENS (Esquema Nacional de Seguridad)."""
        hdr("🏛️ EVALUACIÓN ENS (Esquema Nacional de Seguridad)")
        findings = []
        passed = 0
        total = len(ENS_CHECKS)

        for check_name, check in ENS_CHECKS.items():
            result = False
            detail = ""

            if check["check_type"] == "ssl_valid":
                valid, days, cert = self._check_ssl()
                result = valid and days > 0
                if valid:
                    detail = f"Certificado válido — expira en {days} días"
                    if days < 30:
                        result = False
                        detail = f"¡ATENCIÓN! Certificado expira en {days} días"
                else:
                    detail = f"Certificado inválido: {cert}"

            elif check["check_type"] == "tls_version":
                # Intentar conexión con TLS 1.0 (si funciona, hay problema)
                try:
                    ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx_old.minimum_version = ssl.TLSVersion.TLSv1
                    ctx_old.maximum_version = ssl.TLSVersion.TLSv1
                    ctx_old.check_hostname = False
                    ctx_old.verify_mode = ssl.CERT_NONE
                    s = socket.socket()
                    s.settimeout(5)
                    ssl_s = ctx_old.wrap_socket(s, server_hostname=self.domain)
                    ssl_s.connect((self.domain, 443))
                    ssl_s.close()
                    result = False  # TLS 1.0 funciona = problema
                    detail = "TLS 1.0 soportado — versión obsoleta"
                except Exception:
                    result = True  # No soporta TLS 1.0 = bien
                    detail = "TLS 1.0 no soportado ✓"

            elif check["check_type"] == "header_check":
                result = check.get("header", "").lower() in {k.lower() for k in self.site_headers}
                hdr_val = self.site_headers.get(check["header"], "")
                detail = f"Valor: {hdr_val}" if result else "Header no presente"

            elif check["check_type"] == "no_version_headers":
                server = self.site_headers.get("Server", "")
                powered = self.site_headers.get("X-Powered-By", "")
                has_version = bool(re.search(r'\d+\.\d+', server + powered))
                result = not has_version
                detail = f"Server: {server} | X-Powered-By: {powered}" if not result else "No expone versiones"

            elif check["check_type"] == "http_redirect":
                result = self._check_http_redirect()
                detail = "HTTP redirige a HTTPS" if result else "HTTP no redirige a HTTPS"

            if result:
                ok(f"{check_name} — {detail}")
                passed += 1
            else:
                sev = check.get("severity", "medium")
                icon = {"critical": "🚨", "high": "🔴", "medium": "🟡"}.get(sev, "⚠️")
                print(f"  {C.RED}  {icon}  FALLO ENS: {check_name}{C.END}")
                print(f"       {C.DIM}↳ Control: {check.get('control', '')}{C.END}")
                if detail:
                    print(f"       {C.DIM}↳ Detalle: {detail}{C.END}")
                print(f"       {C.DIM}↳ Remediación: {check.get('remediation', '')}{C.END}")
                findings.append({
                    "check": check_name,
                    "severity": sev,
                    "control": check.get("control", ""),
                    "detail": detail,
                    "remediation": check.get("remediation", "")
                })

        score = int((passed / total) * 100)
        color = C.GREEN if score >= 80 else (C.YELLOW if score >= 60 else C.RED)
        print(f"\n  {color}{C.BOLD}  ENS Score: {passed}/{total} ({score}%){C.END}")
        self.results["ens"] = {"findings": findings, "score": score}
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    def sector_specific_checks(self):
        """Muestra requerimientos específicos según sector."""
        if not self.sector or self.sector not in SECTOR_REQUIREMENTS:
            return
        sector_data = SECTOR_REQUIREMENTS[self.sector]
        hdr(f"🏢 REQUISITOS ESPECÍFICOS — {sector_data['name'].upper()}")
        print(f"  {C.DIM}{sector_data['note']}{C.END}\n")

        for req_name, description, action in sector_data["extra"]:
            warn(f"{req_name}: {description}")
            print(f"       {C.DIM}↳ Acción: {action}{C.END}")

        print(f"\n  {C.CYAN}  Frameworks aplicables: {', '.join(sector_data['frameworks'])}{C.END}")

    # ──────────────────────────────────────────────────────────────────────────
    def generate_summary(self):
        """Genera resumen ejecutivo de compliance."""
        hdr("📊 RESUMEN EJECUTIVO DE COMPLIANCE")

        rgpd_score = self.results["rgpd"].get("score", 0)
        pci_score = self.results["pci_dss"].get("score", 0)
        ens_score = self.results["ens"].get("score", 0)
        overall = int((rgpd_score + ens_score) / 2)
        self.results["overall_compliance"] = overall

        print(f"  {'Normativa':<30} {'Score':>8}  {'Estado':>10}")
        print(f"  {'-'*52}")

        for name, score in [("RGPD / LOPD-GDD", rgpd_score), ("ENS", ens_score), ("PCI DSS", pci_score)]:
            if score >= 80:
                status = f"{C.GREEN}CONFORME{C.END}"
            elif score >= 60:
                status = f"{C.YELLOW}PARCIAL{C.END}"
            else:
                status = f"{C.RED}NO CONFORME{C.END}"
            bar = "█" * (score // 10) + "░" * (10 - score // 10)
            print(f"  {name:<30} {score:>5}%  {bar}  {status}")

        # Issues críticos
        critical = self.results["critical_issues"]
        if critical:
            print(f"\n  {C.RED}{C.BOLD}  🚨 INCUMPLIMIENTOS CRÍTICOS (acción inmediata):{C.END}")
            for issue in critical:
                print(f"  {C.RED}    • {issue}{C.END}")

        color = C.GREEN if overall >= 80 else (C.YELLOW if overall >= 60 else C.RED)
        icon = "✅" if overall >= 80 else ("⚠️" if overall >= 60 else "🚨")
        print(f"\n{C.PURPLE}{'═'*52}{C.END}")
        print(f"{color}{C.BOLD}  {icon}  COMPLIANCE GLOBAL: {overall}%{C.END}")
        print(f"{C.PURPLE}{'═'*52}{C.END}")

        # Impacto económico estimado
        rgpd_failures = len(self.results["rgpd"].get("findings", []))
        if rgpd_failures > 0:
            print(f"\n  {C.RED}  💶 EXPOSICIÓN ECONÓMICA ESTIMADA (RGPD):")
            print(f"       • {rgpd_failures} incumplimientos detectados")
            print(f"       • Multas leves: hasta 10.000.000€ o 2% facturación global")
            print(f"       • Multas graves: hasta 20.000.000€ o 4% facturación global")
            print(f"       • Multas AEPD por cookies: 3.000€ – 30.000€ (PYMEs){C.END}")

    # ──────────────────────────────────────────────────────────────────────────
    def save_results(self, output_dir=None):
        """Guarda resultados."""
        if output_dir is None:
            base = Path.home() / "Documents" / "purple_team_reports" / "compliance"
        else:
            base = Path(output_dir) / "compliance"
        base.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_clean = self.domain.replace('.', '_').replace(':', '_')
        out_file = base / f"compliance_{domain_clean}_{ts}.json"
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        ok(f"Resultados de compliance guardados: {out_file}")
        return str(out_file)

    # ──────────────────────────────────────────────────────────────────────────
    def run(self, framework="all"):
        """Ejecuta la evaluación de compliance completa."""
        print(BANNER)
        info(f"Objetivo: {self.url}")
        info(f"Framework: {framework.upper()}")
        print()

        info("Obteniendo contenido del sitio web...")
        self._fetch_site()

        if framework in ("all", "rgpd"):
            self.check_rgpd()
        if framework in ("all", "pci"):
            self.check_pci_dss()
        if framework in ("all", "ens"):
            self.check_ens()

        self.sector_specific_checks()
        self.generate_summary()
        return self.save_results()


# ─── Entry point ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Compliance Checker — RGPD, ENS, PCI DSS, ISO 27001")
    parser.add_argument("--url", required=True, help="URL del sitio a evaluar")
    parser.add_argument("--domain", help="Dominio (si difiere del URL)")
    parser.add_argument("--sector",
                        choices=list(SECTOR_REQUIREMENTS.keys()),
                        help="Sector del cliente para checks específicos")
    parser.add_argument("--framework",
                        choices=["all", "rgpd", "pci", "ens"],
                        default="all",
                        help="Framework de compliance a evaluar")
    parser.add_argument("--output", help="Directorio de salida")
    args = parser.parse_args()

    checker = ComplianceChecker(
        url=args.url,
        domain=args.domain,
        sector=args.sector
    )
    checker.run(framework=args.framework)


if __name__ == "__main__":
    main()
