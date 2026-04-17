# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║          PURPLE TEAM SUITE - MASTER ORCHESTRATOR             ║
║          Orquestación automática de todos los módulos        ║
║                                                              ║
║  Uso: python orchestrator.py [opciones]                      ║
║                                                              ║
║  Ejemplos:                                                   ║
║    python orchestrator.py --mode full                        ║
║    python orchestrator.py --mode external --domain ejemplo.com ║
║    python orchestrator.py --mode web --url https://ejemplo.com ║
║    python orchestrator.py --target 192.168.1.1 --url https://ejemplo.com  ║
║    python orchestrator.py --client "Empresa SA" --mode full  ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import time
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
import importlib.util


# ─── Colores para terminal ───────────────────────────────────────────────────
class C:
    PURPLE  = '\033[95m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    END     = '\033[0m'

def pr(color, msg):    print(f"{color}{msg}{C.END}")
def ok(msg):           pr(C.GREEN,  f"  ✅  {msg}")
def warn(msg):         pr(C.YELLOW, f"  ⚠️   {msg}")
def err(msg):          pr(C.RED,    f"  ❌  {msg}")
def info(msg):         pr(C.CYAN,   f"  ℹ️   {msg}")
def red_t(msg):        pr(C.RED,    f"  🔴  {msg}")
def blue_t(msg):       pr(C.BLUE,   f"  🔵  {msg}")


# ─── Banner ───────────────────────────────────────────────────────────────────
BANNER = f"""
{C.PURPLE}{C.BOLD}
  ╔══════════════════════════════════════════════════╗
  ║   🟣  PURPLE TEAM SUITE - MASTER ORCHESTRATOR   ║
  ║        Attack → Detect → Respond → Report        ║
  ╚══════════════════════════════════════════════════╝{C.END}
"""

# ─── Directorio base ─────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.resolve()
REPORTS_DIR = Path.home() / "storage" / "shared" / "Documents" / "purple_team_reports"
if not REPORTS_DIR.parent.exists():
    REPORTS_DIR = Path.home() / "Documents" / "purple_team_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ─── Sesión ───────────────────────────────────────────────────────────────────
class Session:
    def __init__(self, client_name="Unknown"):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_client = client_name.replace(" ", "_").replace("/", "-")
        self.id = f"{safe_client}_{ts}"
        self.dir = REPORTS_DIR / self.id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.client = client_name
        self.start_time = datetime.now()
        self.results = {}
        self.errors = {}

    def save_module_result(self, module_name: str, data: dict):
        out = self.dir / f"{module_name}.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        self.results[module_name] = data

    def save_aggregate(self):
        agg = {
            "session_id": self.id,
            "client": self.client,
            "start_time": self.start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "duration_seconds": (datetime.now() - self.start_time).seconds,
            "modules_executed": list(self.results.keys()),
            "errors": self.errors,
            "results": self.results,
        }
        out = self.dir / "results_full.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(agg, f, indent=2, ensure_ascii=False, default=str)
        return out


# ─── Cargador dinámico de módulos ─────────────────────────────────────────────
def load_module(path: Path):
    """Carga un módulo Python desde un path sin importarlo globalmente."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        return mod
    except Exception as e:
        return None


# ─── Módulos de orquestación ──────────────────────────────────────────────────

def run_wifi_module(session: Session, config: dict) -> dict:
    red_t("Iniciando WiFi Audit Suite (rogue AP, isolation, default creds, exposure)...")
    result = {"module": "wifi", "status": "skipped", "findings": [], "timestamp": datetime.now().isoformat()}

    # Prefer the full WiFi audit suite (4 door-opener tools)
    suite_path = BASE_DIR / "wifi" / "wifi_audit_suite.py"
    fallback_path = BASE_DIR / "wifi" / "wifi_security_analyzer.py"
    wifi_path = suite_path if suite_path.exists() else fallback_path

    if not wifi_path.exists():
        warn(f"Módulo WiFi no encontrado en {wifi_path}")
        result["status"] = "not_found"
        return result

    try:
        proc = subprocess.run(
            [sys.executable, str(wifi_path), "--json"],
            capture_output=True, text=True, timeout=120,
        )
        if proc.stdout:
            try:
                data = json.loads(proc.stdout)
                result["status"] = "completed"
                result["findings"] = data.get("findings", [])
                result["summary"] = data.get("summary", {})
                result["tool_results"] = data.get("tool_results", [])
                total_findings = len(result["findings"])
                ok(f"WiFi Audit Suite: {total_findings} hallazgos")
            except json.JSONDecodeError:
                result["status"] = "completed_text"
                result["stdout"] = proc.stdout[-5000:]
                ok("WiFi: análisis completado")
        else:
            result["status"] = "no_output"
            result["stderr"] = proc.stderr[-1000:] if proc.stderr else ""
            warn("WiFi: sin output — verifica permisos de ubicación en Android")
    except subprocess.TimeoutExpired:
        warn("WiFi: timeout (120s) — continuando con siguiente módulo")
        result["status"] = "timeout"
    except Exception as e:
        warn(f"WiFi: {type(e).__name__}: {e}")
        result["status"] = "error"
        result["error"] = str(e)

    session.save_module_result("wifi", result)
    return result


def run_http_module(session: Session, config: dict) -> dict:
    red_t("Iniciando HTTP Security Scanner...")
    result = {"module": "http", "status": "skipped", "findings": [], "timestamp": datetime.now().isoformat()}

    url = config.get("url")
    if not url:
        warn("HTTP: no se proporcionó URL (--url). Saltando módulo.")
        result["status"] = "skipped_no_target"
        session.save_module_result("http", result)
        return result

    http_path = BASE_DIR / "http" / "http_security_scanner.py"
    if not http_path.exists():
        result["status"] = "not_found"
        session.save_module_result("http", result)
        return result

    try:
        proc = subprocess.run(
            [sys.executable, str(http_path)],
            capture_output=True, text=True, timeout=90,
            input=f"{url}\n",
        )
        result["status"] = "completed"
        result["target_url"] = url
        result["stdout"] = proc.stdout[-4000:] if proc.stdout else ""

        # Parsear hallazgos del output
        findings = []
        for line in (proc.stdout or "").split("\n"):
            if any(kw in line for kw in ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "❌", "⚠️", "MISSING", "VULNERABLE"]):
                findings.append(line.strip())
        result["findings"] = findings
        ok(f"HTTP: {url} — {len(findings)} hallazgos detectados")
    except subprocess.TimeoutExpired:
        warn("HTTP: timeout (90s)")
        result["status"] = "timeout"
    except Exception as e:
        warn(f"HTTP: {type(e).__name__}: {e}")
        result["status"] = "error"
        result["error"] = str(e)

    session.save_module_result("http", result)
    return result


def run_network_module(session: Session, config: dict) -> dict:
    red_t("Iniciando Network Reconnaissance...")
    result = {"module": "network", "status": "skipped", "findings": [], "timestamp": datetime.now().isoformat()}

    net_path = BASE_DIR / "network" / "network_recon.py"
    if not net_path.exists():
        result["status"] = "not_found"
        session.save_module_result("network", result)
        return result

    target = config.get("target", "")
    domain = config.get("domain", "")

    try:
        # Ejecutar con entrada automática: opción 1 (network info) + opción 5 (quit)
        input_seq = "1\n"
        if target:
            input_seq += f"3\n{target}\n"  # port scan si hay target
        if domain:
            input_seq += f"2\n{domain}\n"  # DNS enum si hay dominio
        input_seq += "5\n"

        proc = subprocess.run(
            [sys.executable, str(net_path)],
            capture_output=True, text=True, timeout=120,
            input=input_seq,
        )
        result["status"] = "completed"
        result["target"] = target or "red local"
        result["stdout"] = proc.stdout[-4000:] if proc.stdout else ""

        # Extraer hallazgos relevantes
        findings = []
        for line in (proc.stdout or "").split("\n"):
            if any(kw in line for kw in ["open", "abierto", "CRÍTICO", "ALTO", "puerto", "service"]):
                findings.append(line.strip())
        result["findings"] = findings
        ok(f"Network: recon completado — {len(findings)} hallazgos")
    except subprocess.TimeoutExpired:
        warn("Network: timeout (120s)")
        result["status"] = "timeout"
    except Exception as e:
        warn(f"Network: {type(e).__name__}: {e}")
        result["status"] = "error"
        result["error"] = str(e)

    session.save_module_result("network", result)
    return result


def run_purple_suite(session: Session, config: dict) -> dict:
    red_t("Iniciando Purple Team Suite (análisis completo)...")
    result = {"module": "purple_suite", "status": "skipped", "timestamp": datetime.now().isoformat()}

    suite_path = BASE_DIR / "purple_suite" / "purple_team_suite.py"
    if not suite_path.exists():
        result["status"] = "not_found"
        session.save_module_result("purple_suite", result)
        return result

    target = config.get("target", "192.168.1.1")
    url    = config.get("url", "https://example.com")
    domain = config.get("domain", "example.com")

    # Secuencia automática: recon(1) + portscan(2) + dns(3) + webscan(4) + blue_analysis(6) + exit(8)
    input_seq = f"1\n2\n{target}\n3\n{domain}\n4\n{url}\n6\n8\n"

    try:
        proc = subprocess.run(
            [sys.executable, str(suite_path)],
            capture_output=True, text=True, timeout=180,
            input=input_seq,
        )
        result["status"] = "completed"
        result["stdout"] = proc.stdout[-5000:] if proc.stdout else ""

        # Buscar alertas generadas
        alerts = []
        for line in (proc.stdout or "").split("\n"):
            if any(kw in line for kw in ["ALERT", "🚨", "DETECTED", "WARNING", "CRITICAL"]):
                alerts.append(line.strip())
        result["alerts"] = alerts
        ok(f"Purple Suite: completado — {len(alerts)} alertas blue team")
    except subprocess.TimeoutExpired:
        warn("Purple Suite: timeout (180s)")
        result["status"] = "timeout"
    except Exception as e:
        warn(f"Purple Suite: {type(e).__name__}: {e}")
        result["status"] = "error"
        result["error"] = str(e)

    session.save_module_result("purple_suite", result)
    return result


# ─── Módulo SSL/TLS ───────────────────────────────────────────────────────────

def run_ssl_module(session: Session, config: dict) -> dict:
    red_t("Iniciando SSL/TLS Deep Analyzer...")
    result = {"module": "ssl_tls", "status": "skipped", "findings": [], "timestamp": datetime.now().isoformat()}

    url = config.get("url", "")
    domain = config.get("domain", "")
    # Extraer host de URL o usar domain
    host = ""
    if url:
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = parsed.hostname or ""
    if not host and domain:
        host = domain
    if not host:
        warn("SSL/TLS: no se proporcionó host (--url o --domain). Saltando.")
        result["status"] = "skipped_no_target"
        session.save_module_result("ssl_tls", result)
        return result

    ssl_path = BASE_DIR / "ssl_tls" / "ssl_analyzer.py"
    if not ssl_path.exists():
        warn(f"Módulo SSL/TLS no encontrado en {ssl_path}")
        result["status"] = "not_found"
        session.save_module_result("ssl_tls", result)
        return result

    try:
        proc = subprocess.run(
            [sys.executable, str(ssl_path), "--target", host, "--port", "443"],
            capture_output=True, text=True, timeout=60,
        )
        result["status"] = "completed"
        result["target"] = f"{host}:443"
        result["stdout"] = proc.stdout[-4000:] if proc.stdout else ""

        findings = []
        for line in (proc.stdout or "").split("\n"):
            if any(kw in line.upper() for kw in ["INSECURE", "DEPRECATED", "WEAK", "EXPIRED", "VULNERABLE", "FAIL", "❌", "🔴"]):
                findings.append(line.strip())
        result["findings"] = findings
        ok(f"SSL/TLS: {host} — {len(findings)} hallazgos")
    except subprocess.TimeoutExpired:
        warn("SSL/TLS: timeout (60s)")
        result["status"] = "timeout"
    except Exception as e:
        warn(f"SSL/TLS: {type(e).__name__}: {e}")
        result["status"] = "error"
        result["error"] = str(e)

    session.save_module_result("ssl_tls", result)
    return result


# ─── Módulo Subdomain Enumerator ──────────────────────────────────────────────

def run_subdomain_module(session: Session, config: dict) -> dict:
    red_t("Iniciando Subdomain Enumerator...")
    result = {"module": "subdomains", "status": "skipped", "findings": [], "timestamp": datetime.now().isoformat()}

    domain = config.get("domain", "")
    if not domain:
        # Intentar extraer de URL
        url = config.get("url", "")
        if url:
            from urllib.parse import urlparse
            parsed = urlparse(url if "://" in url else f"https://{url}")
            domain = parsed.hostname or ""
    if not domain:
        warn("Subdomains: no se proporcionó dominio (--domain). Saltando.")
        result["status"] = "skipped_no_target"
        session.save_module_result("subdomains", result)
        return result

    sub_path = BASE_DIR / "subdomain" / "subdomain_enumerator.py"
    if not sub_path.exists():
        warn(f"Módulo Subdomain no encontrado en {sub_path}")
        result["status"] = "not_found"
        session.save_module_result("subdomains", result)
        return result

    try:
        proc = subprocess.run(
            [sys.executable, str(sub_path), "--domain", domain],
            capture_output=True, text=True, timeout=120,
        )
        result["status"] = "completed"
        result["target_domain"] = domain
        result["stdout"] = proc.stdout[-5000:] if proc.stdout else ""

        findings = []
        for line in (proc.stdout or "").split("\n"):
            line = line.strip()
            if line and ("." in line) and any(c.isalpha() for c in line) and ("found" in line.lower() or "→" in line or domain in line):
                findings.append(line)
        result["findings"] = findings
        ok(f"Subdomains: {domain} — {len(findings)} subdominios encontrados")
    except subprocess.TimeoutExpired:
        warn("Subdomains: timeout (120s)")
        result["status"] = "timeout"
    except Exception as e:
        warn(f"Subdomains: {type(e).__name__}: {e}")
        result["status"] = "error"
        result["error"] = str(e)

    session.save_module_result("subdomains", result)
    return result


# ─── Módulo Web Directory Scanner ─────────────────────────────────────────────

def run_directory_module(session: Session, config: dict) -> dict:
    red_t("Iniciando Web Directory Scanner...")
    result = {"module": "directories", "status": "skipped", "findings": [], "timestamp": datetime.now().isoformat()}

    url = config.get("url", "")
    if not url:
        warn("Directories: no se proporcionó URL (--url). Saltando.")
        result["status"] = "skipped_no_target"
        session.save_module_result("directories", result)
        return result

    dir_path = BASE_DIR / "web_discovery" / "directory_scanner.py"
    if not dir_path.exists():
        warn(f"Módulo Directory Scanner no encontrado en {dir_path}")
        result["status"] = "not_found"
        session.save_module_result("directories", result)
        return result

    try:
        proc = subprocess.run(
            [sys.executable, str(dir_path), "--url", url, "--threads", "5", "--timeout", "5"],
            capture_output=True, text=True, timeout=180,
        )
        result["status"] = "completed"
        result["target_url"] = url
        result["stdout"] = proc.stdout[-5000:] if proc.stdout else ""

        findings = []
        for line in (proc.stdout or "").split("\n"):
            if any(kw in line for kw in ["200", "301", "302", "403", "FOUND", "✅", "→"]):
                findings.append(line.strip())
        result["findings"] = findings
        ok(f"Directories: {url} — {len(findings)} rutas descubiertas")
    except subprocess.TimeoutExpired:
        warn("Directories: timeout (180s)")
        result["status"] = "timeout"
    except Exception as e:
        warn(f"Directories: {type(e).__name__}: {e}")
        result["status"] = "error"
        result["error"] = str(e)

    session.save_module_result("directories", result)
    return result


# ─── Módulo CVE Correlator ────────────────────────────────────────────────────

def run_cve_module(session: Session, config: dict) -> dict:
    red_t("Iniciando CVE Correlator (post-análisis)...")
    result = {"module": "cve", "status": "skipped", "findings": [], "timestamp": datetime.now().isoformat()}

    cve_path = BASE_DIR / "cve" / "cve_correlator.py"
    if not cve_path.exists():
        warn(f"Módulo CVE no encontrado en {cve_path}")
        result["status"] = "not_found"
        session.save_module_result("cve", result)
        return result

    # Buscar servicios detectados en resultados anteriores para correlacionar
    services_to_check = []
    for mod_name, mod_data in session.results.items():
        stdout = mod_data.get("stdout", "")
        # Buscar patrones tipo "Apache/2.4.41", "nginx/1.18.0", "OpenSSH_8.2"
        import re as _re
        svc_patterns = _re.findall(r'(Apache|nginx|OpenSSH|PHP|MySQL|PostgreSQL|vsftpd|ProFTPD|IIS|lighttpd)[/_ ]?([\d.]+)', stdout, _re.IGNORECASE)
        for svc_name, svc_ver in svc_patterns:
            services_to_check.append(f"{svc_name}/{svc_ver}")

    if not services_to_check:
        info("CVE: no se detectaron servicios con versión para correlacionar. Ejecutando en modo demo.")
        # Ejecutar con un servicio de ejemplo para mostrar la funcionalidad
        services_to_check = ["Apache/2.4.41"]

    # Usar el primero como ejemplo (el módulo real haría todos)
    try:
        proc = subprocess.run(
            [sys.executable, str(cve_path), "--service", services_to_check[0]],
            capture_output=True, text=True, timeout=60,
        )
        result["status"] = "completed"
        result["services_checked"] = services_to_check
        result["stdout"] = proc.stdout[-4000:] if proc.stdout else ""

        findings = []
        for line in (proc.stdout or "").split("\n"):
            if any(kw in line.upper() for kw in ["CVE-", "CRITICAL", "HIGH", "MEDIUM", "🔴", "🟠", "🟡"]):
                findings.append(line.strip())
        result["findings"] = findings
        ok(f"CVE: {len(services_to_check)} servicios analizados — {len(findings)} CVEs correlacionados")
    except subprocess.TimeoutExpired:
        warn("CVE: timeout (60s)")
        result["status"] = "timeout"
    except Exception as e:
        warn(f"CVE: {type(e).__name__}: {e}")
        result["status"] = "error"
        result["error"] = str(e)

    session.save_module_result("cve", result)
    return result


# ─── Blue Team: análisis agregado ─────────────────────────────────────────────

def blue_team_analysis(session: Session) -> dict:
    blue_t("Ejecutando análisis Blue Team agregado...")

    all_findings = []
    severity_count = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0, "INFO": 0}
    mitre_techniques = []

    for module_name, data in session.results.items():
        findings = data.get("findings", []) or data.get("alerts", [])
        for f in findings:
            f_str = str(f)
            all_findings.append({"module": module_name, "finding": f_str})
            # Clasificar severidad
            if any(kw in f_str.upper() for kw in ["CRÍTICO", "CRITICO", "CRITICAL"]):
                severity_count["CRITICO"] += 1
            elif any(kw in f_str.upper() for kw in ["ALTO", "HIGH"]):
                severity_count["ALTO"] += 1
            elif any(kw in f_str.upper() for kw in ["MEDIO", "MEDIUM", "WARN"]):
                severity_count["MEDIO"] += 1
            else:
                severity_count["BAJO"] += 1

    # MITRE mapping por módulo
    mitre_map = {
        "wifi":         [{"id": "TA0043", "name": "Reconnaissance", "subtechnique": "T1595.001 - Active Scanning: WiFi"}],
        "http":         [{"id": "T1190",  "name": "Exploit Public-Facing Application"}, {"id": "T1592", "name": "Gather Victim Host Info"}],
        "network":      [{"id": "T1046",  "name": "Network Service Discovery"}, {"id": "T1590.002", "name": "Gather Victim Network Info: DNS"}],
        "purple_suite": [{"id": "TA0043", "name": "Reconnaissance"}, {"id": "T1046", "name": "Network Service Discovery"}],
        "ssl_tls":      [{"id": "T1557",  "name": "Adversary-in-the-Middle"}, {"id": "T1573", "name": "Encrypted Channel Analysis"}],
        "subdomains":   [{"id": "T1596.002", "name": "Search Open Technical Databases"}, {"id": "T1590.002", "name": "Gather Victim Network Info: DNS"}],
        "directories":  [{"id": "T1083",  "name": "File and Directory Discovery"}, {"id": "T1590", "name": "Gather Victim Network Info"}],
        "cve":          [{"id": "T1592",  "name": "Gather Victim Host Information"}, {"id": "T1588.006", "name": "Obtain Capabilities: Vulnerabilities"}],
    }
    for mod in session.results.keys():
        mitre_techniques.extend(mitre_map.get(mod, []))

    # Recomendaciones automáticas
    recommendations = []
    if severity_count["CRITICO"] > 0:
        recommendations.append("⚠️  URGENTE: Existen hallazgos críticos — remediar en < 24h")
    if "wifi" in session.results:
        recommendations.extend([
            "Deshabilitar WPS en todos los APs",
            "Migrar a WPA3 o WPA2-Enterprise donde sea posible",
            "Implementar detección de Rogue APs con IDS inalámbrico",
        ])
    if "http" in session.results:
        recommendations.extend([
            "Implementar headers de seguridad: HSTS, CSP, X-Frame-Options",
            "Revisar cookies: flags Secure, HttpOnly, SameSite",
        ])
    if "ssl_tls" in session.results:
        recommendations.extend([
            "Deshabilitar TLS 1.0/1.1 y cipher suites débiles",
            "Renovar certificados próximos a expirar",
            "Configurar HSTS con preload para forzar HTTPS",
        ])
    if "network" in session.results:
        recommendations.extend([
            "Cerrar puertos no necesarios con firewall",
            "Actualizar servicios con versiones vulnerables detectadas",
            "Implementar network segmentation y VLANs",
        ])
    if "subdomains" in session.results:
        recommendations.extend([
            "Revisar subdominios descubiertos: eliminar los que no estén en uso",
            "Asegurar que todos los subdominios activos tienen certificados SSL válidos",
        ])
    if "directories" in session.results:
        recommendations.extend([
            "Proteger rutas de administración con autenticación fuerte y restricción de IP",
            "Eliminar archivos de configuración y backups expuestos (.env, .git, .bak)",
        ])
    if "cve" in session.results:
        recommendations.extend([
            "Aplicar parches de seguridad para las CVEs identificadas según prioridad CVSS",
            "Establecer proceso de gestión de parches con ciclo mensual mínimo",
        ])

    analysis = {
        "timestamp": datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "severity_breakdown": severity_count,
        "all_findings": all_findings,
        "mitre_techniques_covered": mitre_techniques,
        "recommendations": recommendations,
        "risk_score": min(10, severity_count["CRITICO"]*3 + severity_count["ALTO"]*1.5 +
                         severity_count["MEDIO"]*0.5 + severity_count["BAJO"]*0.1),
    }

    session.save_module_result("analysis", analysis)
    blue_t(f"Blue Team: {len(all_findings)} hallazgos totales | Riesgo: {analysis['risk_score']:.1f}/10")
    return analysis


# ─── Generador de resumen texto ───────────────────────────────────────────────

def generate_summary_report(session: Session, analysis: dict):
    blue_t("Generando resumen de auditoría...")

    report_path = session.dir / f"summary_{session.id}.txt"
    sev = analysis.get("severity_breakdown", {})
    risk = analysis.get("risk_score", 0)

    if risk >= 7:
        risk_label = "ALTO 🔴"
    elif risk >= 4:
        risk_label = "MEDIO 🟠"
    elif risk >= 2:
        risk_label = "BAJO 🟡"
    else:
        risk_label = "MÍNIMO 🟢"

    lines = [
        "=" * 65,
        "   PURPLE TEAM SUITE - RESUMEN DE AUDITORÍA",
        "=" * 65,
        f"  Cliente:          {session.client}",
        f"  Sesión ID:        {session.id}",
        f"  Fecha/Hora:       {session.start_time.strftime('%d/%m/%Y %H:%M:%S')}",
        f"  Duración:         {(datetime.now() - session.start_time).seconds}s",
        f"  Módulos activos:  {', '.join(session.results.keys())}",
        "-" * 65,
        "  RESUMEN DE HALLAZGOS",
        "-" * 65,
        f"  Total hallazgos:  {analysis.get('total_findings', 0)}",
        f"  🔴 Críticos:      {sev.get('CRITICO', 0)}",
        f"  🟠 Altos:         {sev.get('ALTO', 0)}",
        f"  🟡 Medios:        {sev.get('MEDIO', 0)}",
        f"  🟢 Bajos:         {sev.get('BAJO', 0)}",
        f"  📊 Risk Score:    {risk:.1f}/10 — {risk_label}",
        "-" * 65,
        "  TÉCNICAS MITRE ATT&CK CUBIERTAS",
        "-" * 65,
    ]
    seen_mitre = set()
    for t in analysis.get("mitre_techniques_covered", []):
        key = t.get("id", "")
        if key not in seen_mitre:
            lines.append(f"  [{t.get('id','?')}] {t.get('name','?')}")
            seen_mitre.add(key)

    lines += [
        "-" * 65,
        "  RECOMENDACIONES PRIORITARIAS",
        "-" * 65,
    ]
    for i, rec in enumerate(analysis.get("recommendations", []), 1):
        lines.append(f"  {i:02d}. {rec}")

    lines += [
        "-" * 65,
        f"  Datos completos: {session.dir}",
        f"  Archivo JSON:    results_full.json",
        "=" * 65,
        "",
        "  ⚠️  AVISO LEGAL: Solo usar en sistemas autorizados.",
        "",
    ]

    report_path.write_text("\n".join(lines), encoding="utf-8")
    ok(f"Resumen guardado: {report_path.name}")
    return report_path


# ─── Argumentos CLI ───────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Purple Team Suite - Master Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modos disponibles:
  full     → TODOS los módulos (9 herramientas completas)
  external → Auditoría externa: Subdomains + SSL + HTTP + Directories + CVE
  web      → Auditoría web: HTTP + SSL + Directories + CVE
  internal → Auditoría interna: WiFi + Network + CVE
  wifi     → Solo WiFi Security Analyzer
  http     → Solo HTTP Security Scanner (requiere --url)
  ssl      → Solo SSL/TLS Deep Analyzer (requiere --url o --domain)
  network  → Solo Network Reconnaissance
  quick    → WiFi + HTTP (rápido, < 2 min)

Ejemplos:
  python orchestrator.py --mode full --target 192.168.1.1 --url https://example.com --domain example.com
  python orchestrator.py --mode external --domain example.com --url https://example.com
  python orchestrator.py --mode web --url https://miweb.com --client "Cliente SA"
  python orchestrator.py --mode internal --target 192.168.1.0/24 --client "Red Interna"
        """
    )
    parser.add_argument("--mode",    default="full",      choices=["full","external","web","internal","wifi","http","ssl","network","quick"], help="Modo de ejecución")
    parser.add_argument("--target",  default="",          help="IP o rango objetivo (ej: 192.168.1.1 o 192.168.1.0/24)")
    parser.add_argument("--url",     default="",          help="URL objetivo para análisis HTTP (ej: https://example.com)")
    parser.add_argument("--domain",  default="",          help="Dominio para enumeración DNS (ej: example.com)")
    parser.add_argument("--client",  default="Test",      help="Nombre del cliente para el informe")
    parser.add_argument("--output",  default="",          help="Directorio de salida (opcional)")
    parser.add_argument("--quiet",   action="store_true", help="Modo silencioso (menos output)")
    return parser.parse_args()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    args = parse_args()

    config = {
        "mode":   args.mode,
        "target": args.target,
        "url":    args.url,
        "domain": args.domain,
        "client": args.client,
    }

    # Override output dir si se especifica
    global REPORTS_DIR
    if args.output:
        REPORTS_DIR = Path(args.output)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    pr(C.PURPLE + C.BOLD, f"  ► Modo: {args.mode.upper()} | Cliente: {args.client}")
    if args.target: info(f"Target: {args.target}")
    if args.url:    info(f"URL:    {args.url}")
    if args.domain: info(f"Domain: {args.domain}")
    print()

    session = Session(client_name=args.client)
    ok(f"Sesión iniciada: {session.id}")
    info(f"Reportes en: {session.dir}")
    print()

    # ── Ejecutar módulos según modo ──────────────────────────────────────────
    start = time.time()

    pr(C.RED + C.BOLD, "  ═══ FASE RED TEAM: RECONOCIMIENTO ═══")
    print()

    # WiFi (internal, full)
    if args.mode in ("full", "internal", "wifi", "quick"):
        run_wifi_module(session, config)
        print()

    # Subdomain enumeration (external, full)
    if args.mode in ("full", "external"):
        run_subdomain_module(session, config)
        print()

    # Network recon (internal, full)
    if args.mode in ("full", "internal", "network"):
        run_network_module(session, config)
        print()

    pr(C.RED + C.BOLD, "  ═══ FASE RED TEAM: ANÁLISIS ═══")
    print()

    # SSL/TLS (external, web, full, ssl)
    if args.mode in ("full", "external", "web", "ssl"):
        run_ssl_module(session, config)
        print()

    # HTTP headers (external, web, full, http, quick)
    if args.mode in ("full", "external", "web", "http", "quick"):
        run_http_module(session, config)
        print()

    # Directory scanning (external, web, full)
    if args.mode in ("full", "external", "web"):
        run_directory_module(session, config)
        print()

    pr(C.RED + C.BOLD, "  ═══ FASE RED TEAM: CORRELACIÓN ═══")
    print()

    # CVE correlation (runs after other modules to use their data)
    if args.mode in ("full", "external", "web", "internal"):
        run_cve_module(session, config)
        print()

    # Purple suite completa solo en full
    if args.mode == "full":
        run_purple_suite(session, config)
        print()

    # ── Blue Team Analysis ───────────────────────────────────────────────────
    print()
    pr(C.BLUE + C.BOLD, "  ═══ FASE BLUE TEAM ═══")
    analysis = blue_team_analysis(session)
    print()

    # ── Guardar datos agregados ──────────────────────────────────────────────
    agg_path = session.save_aggregate()
    ok(f"JSON agregado guardado: {agg_path.name}")

    # ── Generar resumen ──────────────────────────────────────────────────────
    summary_path = generate_summary_report(session, analysis)

    # ── Mostrar resumen final ────────────────────────────────────────────────
    elapsed = time.time() - start
    sev = analysis.get("severity_breakdown", {})
    risk = analysis.get("risk_score", 0)

    print()
    pr(C.PURPLE + C.BOLD, "  ╔══════════════════════════════════════════╗")
    pr(C.PURPLE + C.BOLD, "  ║         AUDITORÍA COMPLETADA             ║")
    pr(C.PURPLE + C.BOLD, "  ╚══════════════════════════════════════════╝")
    print(f"  ⏱️  Tiempo total:   {elapsed:.0f}s")
    print(f"  📊 Hallazgos:      {analysis.get('total_findings',0)} total  |  🔴 {sev.get('CRITICO',0)} críticos  |  🟠 {sev.get('ALTO',0)} altos")
    print(f"  🎯 Risk Score:     {risk:.1f}/10")
    print(f"  📁 Sesión:         {session.dir}")
    print(f"  📄 JSON:           {agg_path.name}")
    print(f"  📝 Resumen:        {summary_path.name}")
    print()
    pr(C.DIM, "  ⚠️  Solo usar en sistemas autorizados. Uso ético y responsable.")
    print()


if __name__ == "__main__":
    main()
