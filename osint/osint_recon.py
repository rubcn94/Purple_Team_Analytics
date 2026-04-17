# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║         PURPLE TEAM SUITE - OSINT RECONNAISSANCE             ║
║         Google Dorks · Brechas · Metadatos · WHOIS           ║
║                                                              ║
║  Módulo de inteligencia en fuentes abiertas:                 ║
║  Recolecta información pública sobre el objetivo             ║
║  para construir el perfil de ataque.                         ║
║                                                              ║
║  Uso:                                                        ║
║    python osint/osint_recon.py --domain empresa.com          ║
║    python osint/osint_recon.py --email info@empresa.com      ║
║    python osint/osint_recon.py --company "Empresa SA"        ║
║    python osint/osint_recon.py --domain empresa.com --full   ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import ssl
import json
import socket
import argparse
import re
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from pathlib import Path

# ── Colores ───────────────────────────────────────────────────────────────────
class C:
    PURPLE = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN  = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    BOLD   = '\033[1m';  DIM = '\033[2m'; END = '\033[0m'

def ok(m):    print(f"{C.GREEN}  ✅  {m}{C.END}")
def warn(m):  print(f"{C.YELLOW}  ⚠️   {m}{C.END}")
def found(m): print(f"{C.RED}  🔍  {m}{C.END}")
def info(m):  print(f"{C.CYAN}  ℹ️   {m}{C.END}")
def hdr(m):   print(f"\n{C.PURPLE}{C.BOLD}  ╔══ {m} ══╗{C.END}\n")

BANNER = f"""
{C.PURPLE}{C.BOLD}
  ╔══════════════════════════════════════════════════╗
  ║   🟣  PURPLE TEAM — OSINT RECONNAISSANCE         ║
  ║        Fuentes Abiertas · Inteligencia Pasiva     ║
  ╚══════════════════════════════════════════════════╝
{C.END}"""


# ─── Google Dorks para PYMES ─────────────────────────────────────────────────
GOOGLE_DORKS = {
    "Archivos sensibles expuestos": [
        'site:{domain} ext:pdf | ext:doc | ext:xls | ext:xlsx filetype:pdf "confidencial" OR "interno"',
        'site:{domain} ext:sql | ext:bak | ext:log | ext:conf',
        'site:{domain} ext:env | ext:cfg | ext:ini',
    ],
    "Paneles de administración": [
        'site:{domain} inurl:admin | inurl:login | inurl:panel | inurl:dashboard',
        'site:{domain} intitle:"admin" | intitle:"login" | intitle:"panel de control"',
        'site:{domain} inurl:wp-admin | inurl:administrator | inurl:phpmyadmin',
    ],
    "Errores y debug info": [
        'site:{domain} intext:"error" | intext:"warning" | intext:"mysql_error" | intext:"syntax error"',
        'site:{domain} intext:"stack trace" | intext:"exception" | intext:"traceback"',
    ],
    "Directorios abiertos": [
        'site:{domain} intitle:"index of" | intitle:"directory listing"',
        'site:{domain} intitle:"index of /" -html -htm',
    ],
    "Información corporativa sensible": [
        'site:{domain} intext:"password" | intext:"contraseña" | intext:"clave"',
        'site:{domain} filetype:pdf "NIF" | "CIF" | "nómina" | "factura"',
        'site:linkedin.com "{company}" empleados',
    ],
    "APIs y endpoints": [
        'site:{domain} inurl:api | inurl:v1 | inurl:v2 | inurl:swagger',
        'site:{domain} inurl:.json | inurl:.xml | inurl:rest',
    ],
    "Tecnología expuesta": [
        'site:{domain} intext:"Powered by" | intext:"Built with" | intext:"WordPress"',
        'site:{domain} intext:"PHP/" | intext:"Apache/" | intext:"nginx/"',
    ],
}

# ─── Brechas conocidas por servicio ──────────────────────────────────────────
BREACH_INDICATORS = {
    "HaveIBeenPwned": "https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
    "DeHashed": "https://api.dehashed.com/search?query={email}",
}

# ─── Shodan dorks para servicios PYME ────────────────────────────────────────
SHODAN_DORKS = [
    'hostname:{domain} port:3306',           # MySQL expuesto
    'hostname:{domain} port:27017',          # MongoDB expuesto
    'hostname:{domain} port:6379',           # Redis expuesto
    'hostname:{domain} "X-Powered-By" apache',
    'hostname:{domain} http.title:"phpMyAdmin"',
    'org:"{company}" port:22',
    'org:"{company}" "default password"',
    'net:{ip} vuln:ms17-010',               # EternalBlue
]


class OsintRecon:
    def __init__(self, domain=None, email=None, company=None, ip=None):
        self.domain = domain
        self.email = email
        self.company = company
        self.ip = ip
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "target": {"domain": domain, "email": email, "company": company, "ip": ip},
            "whois_info": {},
            "dns_records": {},
            "email_breaches": [],
            "google_dorks": {},
            "shodan_dorks": [],
            "exposed_assets": [],
            "technology_stack": [],
            "people_intel": [],
            "risk_score": 0,
        }
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _http_get(self, url, headers=None, timeout=10):
        """HTTP GET con manejo de errores."""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (compatible; SecurityAudit/1.0)')
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
                return r.read().decode('utf-8', errors='ignore')
        except Exception:
            return ""

    # ──────────────────────────────────────────────────────────────────────────
    def whois_lookup(self):
        """Consulta WHOIS del dominio."""
        if not self.domain:
            return {}
        hdr("🌐 WHOIS & REGISTRO DE DOMINIO")
        info(f"Consultando WHOIS para {self.domain}...")

        result = {}
        try:
            import subprocess
            whois_out = subprocess.run(
                ["whois", self.domain], capture_output=True, text=True, timeout=15
            ).stdout
        except Exception:
            whois_out = ""

        # También consultar RDAP (reemplaza WHOIS, más estructurado)
        rdap_url = f"https://rdap.org/domain/{self.domain}"
        rdap_data = self._http_get(rdap_url)
        if rdap_data:
            try:
                rdap = json.loads(rdap_data)
                # Fechas de registro
                for event in rdap.get("events", []):
                    action = event.get("eventAction", "")
                    date = event.get("eventDate", "")
                    if "registration" in action:
                        result["registered"] = date
                        info(f"Fecha de registro: {date[:10]}")
                    elif "expiration" in action:
                        result["expires"] = date
                        info(f"Fecha de expiración: {date[:10]}")

                # Nameservers
                ns_list = [ns.get("ldhName", "") for ns in rdap.get("nameservers", [])]
                if ns_list:
                    result["nameservers"] = ns_list
                    info(f"Nameservers: {', '.join(ns_list[:4])}")

                # Entidades (registrante, contacto)
                for entity in rdap.get("entities", []):
                    roles = entity.get("roles", [])
                    vcard = entity.get("vcardArray", [None, []])
                    if isinstance(vcard, list) and len(vcard) > 1:
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) >= 4:
                                if item[0] == "fn":
                                    name = item[3]
                                    found(f"Entidad ({', '.join(roles)}): {name}")
                                    result[f"entity_{roles[0] if roles else 'unknown'}"] = name
                                    self.results["risk_score"] += 5
            except Exception:
                pass

        # Fallback: parsear texto WHOIS
        if whois_out and not result:
            patterns = {
                "registrant": r'Registrant[^:]*:\s*(.+)',
                "registrar": r'Registrar:\s*(.+)',
                "created": r'Creation Date:\s*(.+)',
                "expires": r'Expiry Date:\s*(.+)',
                "emails": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            }
            for key, pattern in patterns.items():
                if key == "emails":
                    emails = list(set(re.findall(pattern, whois_out)))
                    if emails:
                        result["contact_emails"] = emails
                        for email in emails[:3]:
                            found(f"Email en WHOIS: {email}")
                else:
                    match = re.search(pattern, whois_out, re.IGNORECASE)
                    if match:
                        result[key] = match.group(1).strip()

        self.results["whois_info"] = result
        return result

    # ──────────────────────────────────────────────────────────────────────────
    def dns_enumeration(self):
        """Enumeración DNS completa."""
        if not self.domain:
            return {}
        hdr("🗺️ ENUMERACIÓN DNS")
        dns_results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

        for rtype in record_types:
            try:
                import subprocess
                out = subprocess.run(
                    ["dig", "+short", rtype, self.domain],
                    capture_output=True, text=True, timeout=10
                ).stdout.strip()
                if out:
                    records = [r for r in out.splitlines() if r]
                    dns_results[rtype] = records
                    for r in records[:3]:
                        info(f"  {rtype}: {r}")
                    if rtype == 'A':
                        self.ip = records[0] if records else self.ip
            except Exception:
                try:
                    # Fallback socket
                    if rtype == 'A':
                        ip = socket.gethostbyname(self.domain)
                        dns_results['A'] = [ip]
                        info(f"  A: {ip}")
                        self.ip = ip
                    elif rtype == 'MX':
                        mx = socket.getaddrinfo(f"mail.{self.domain}", None)
                        if mx:
                            dns_results['MX'] = [str(mx[0][4][0])]
                except Exception:
                    pass

        # Verificar SPF/DMARC (protección anti-phishing)
        spf_found = False
        dmarc_found = False
        if 'TXT' in dns_results:
            for record in dns_results['TXT']:
                if 'v=spf1' in record:
                    spf_found = True
                if 'DMARC' in record.upper():
                    dmarc_found = True

        if not spf_found:
            warn("Sin registro SPF — dominio vulnerable a suplantación de email")
            self.results["exposed_assets"].append({
                "type": "missing_spf",
                "severity": "high",
                "detail": "Sin registro SPF — phishing y spoofing de email posible",
                "risk": "Atacante puede enviar emails desde el dominio de la empresa"
            })
            self.results["risk_score"] += 15
        else:
            ok("SPF configurado — protección anti-phishing presente")

        try:
            dmarc_out = subprocess.run(
                ["dig", "+short", "TXT", f"_dmarc.{self.domain}"],
                capture_output=True, text=True, timeout=10
            ).stdout.strip()
            if 'v=DMARC1' in dmarc_out:
                dmarc_found = True
        except Exception:
            pass

        if not dmarc_found:
            warn("Sin registro DMARC — emails fraudulentos no serán rechazados")
            self.results["exposed_assets"].append({
                "type": "missing_dmarc",
                "severity": "medium",
                "detail": "Sin política DMARC",
                "risk": "Emails de phishing en nombre de la empresa llegan a destinatarios"
            })
            self.results["risk_score"] += 10
        else:
            ok("DMARC configurado")

        self.results["dns_records"] = dns_results
        return dns_results

    # ──────────────────────────────────────────────────────────────────────────
    def check_email_breaches(self):
        """Verifica si el email o dominio aparece en brechas conocidas."""
        if not self.email and not self.domain:
            return []
        hdr("🔓 VERIFICACIÓN DE BRECHAS DE DATOS")
        breaches = []

        # HIBP - HaveIBeenPwned (sin API key, consulta pública limitada)
        targets = []
        if self.email:
            targets.append(self.email)
        if self.domain:
            # Emails genéricos comunes del dominio
            common_prefixes = ['info', 'admin', 'contact', 'hola', 'soporte', 'ventas']
            targets.extend([f"{prefix}@{self.domain}" for prefix in common_prefixes])

        # BreachDirectory API (pública)
        breach_db_url = "https://breachdirectory.org/api/?func=auto&term={target}"

        for target in targets[:3]:  # Limitar para no sobrecargar
            info(f"Verificando {target} en bases de datos de brechas...")

            # Intentar BreachDirectory
            url = breach_db_url.format(target=urllib.parse.quote(target))
            data = self._http_get(url)
            if data:
                try:
                    parsed = json.loads(data)
                    if parsed.get("success") and parsed.get("result"):
                        for r in parsed["result"][:5]:
                            found(f"¡BRECHA ENCONTRADA! {target} en: {r.get('sources', 'desconocido')}")
                            breaches.append({
                                "email": target,
                                "source": r.get("sources", ""),
                                "has_password": r.get("has_password", False),
                                "severity": "critical" if r.get("has_password") else "high"
                            })
                            self.results["risk_score"] += 20
                except Exception:
                    pass
            time.sleep(0.5)  # Rate limiting

        # Verifica dominios conocidos en Have I Been Pwned (endpoint de dominio)
        if self.domain:
            hibp_domain_url = f"https://haveibeenpwned.com/unifiedsearch/{urllib.parse.quote(self.domain)}"
            data = self._http_get(hibp_domain_url, headers={"hibp-api-key": ""})
            if data and '"Name"' in data:
                try:
                    parsed = json.loads(data)
                    for breach in parsed[:5]:
                        name = breach.get("Name", "")
                        date = breach.get("BreachDate", "")
                        found(f"Dominio en brecha: {name} ({date})")
                        breaches.append({
                            "email": f"@{self.domain}",
                            "source": name,
                            "date": date,
                            "severity": "high"
                        })
                        self.results["risk_score"] += 15
                except Exception:
                    pass

        if not breaches:
            ok("No se encontraron brechas conocidas para los targets consultados")
        else:
            warn(f"{len(breaches)} brechas encontradas — credenciales potencialmente comprometidas")

        self.results["email_breaches"] = breaches
        return breaches

    # ──────────────────────────────────────────────────────────────────────────
    def generate_google_dorks(self):
        """Genera lista de Google Dorks específicos para el objetivo."""
        if not self.domain and not self.company:
            return {}
        hdr("🔎 GOOGLE DORKS GENERADOS")
        print(f"  {C.DIM}Copia y pega estos dorks en Google para buscar información expuesta:{C.END}\n")

        dorks_output = {}
        for category, templates in GOOGLE_DORKS.items():
            print(f"  {C.PURPLE}{C.BOLD}  ► {category}{C.END}")
            dorks_output[category] = []
            for template in templates:
                dork = template.replace("{domain}", self.domain or "").replace(
                    "{company}", self.company or "")
                print(f"  {C.DIM}    {dork}{C.END}")
                dorks_output[category].append(dork)
            print()

        # Shodan dorks
        print(f"  {C.BLUE}{C.BOLD}  ► SHODAN DORKS (shodan.io){C.END}")
        for template in SHODAN_DORKS:
            dork = template.replace("{domain}", self.domain or "").replace(
                "{company}", self.company or "").replace(
                "{ip}", self.ip or "")
            print(f"  {C.DIM}    {dork}{C.END}")
        print()

        self.results["google_dorks"] = dorks_output
        self.results["shodan_dorks"] = [
            d.replace("{domain}", self.domain or "").replace("{company}", self.company or "")
            for d in SHODAN_DORKS
        ]
        return dorks_output

    # ──────────────────────────────────────────────────────────────────────────
    def document_metadata(self, url=None):
        """Busca y analiza metadatos de documentos públicos del dominio."""
        if not self.domain:
            return []
        hdr("📄 ANÁLISIS DE METADATOS DE DOCUMENTOS")
        metadata_findings = []

        # Buscar PDFs mediante certificados (crt.sh lista documentos)
        info(f"Buscando documentos públicos en {self.domain}...")

        # Google Cache: busca PDFs con autor expuesto
        pdf_dork = f"site:{self.domain} filetype:pdf"
        info(f"Dork para buscar PDFs: {pdf_dork}")

        # Intentar obtener PDF del sitio web
        if url:
            data = self._http_get(url)
            if data:
                # Buscar links a documentos
                doc_exts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt']
                for ext in doc_exts:
                    links = re.findall(rf'href=["\']([^"\']+{re.escape(ext)})["\']', data, re.IGNORECASE)
                    for link in links[:5]:
                        if not link.startswith('http'):
                            link = f"https://{self.domain}{link}"
                        found(f"Documento expuesto: {link}")
                        metadata_findings.append({
                            "type": "exposed_document",
                            "url": link,
                            "extension": ext,
                            "severity": "medium",
                            "detail": "Documento accesible públicamente — puede contener metadatos de autor/empresa"
                        })
                        self.results["risk_score"] += 5

        # Información de tecnología del sitio
        target_url = url or f"https://{self.domain}"
        info(f"Analizando tecnología de {target_url}...")
        headers_data = ""
        try:
            req = urllib.request.Request(target_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (compatible; SecurityAudit/1.0)')
            with urllib.request.urlopen(req, timeout=10, context=self.ctx) as r:
                headers_data = dict(r.info())
                body = r.read(10000).decode('utf-8', errors='ignore')

            # Detectar tecnologías
            tech_indicators = {
                "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
                "Joomla": [r"Joomla", r"/components/com_"],
                "Drupal": [r"Drupal", r"/sites/default/"],
                "PrestaShop": [r"PrestaShop", r"/themes/default-bootstrap/"],
                "Magento": [r"Magento", r"/skin/frontend/"],
                "PHP": [r"\.php", r"X-Powered-By.*PHP"],
                "Apache": [r"Apache/\d", r"Server.*Apache"],
                "nginx": [r"nginx/\d", r"Server.*nginx"],
                "IIS": [r"IIS/\d", r"Server.*Microsoft-IIS"],
            }

            tech_found = []
            combined = body + str(headers_data)
            for tech, patterns in tech_indicators.items():
                for pattern in patterns:
                    if re.search(pattern, combined, re.IGNORECASE):
                        tech_found.append(tech)
                        info(f"Tecnología detectada: {C.BOLD}{tech}{C.END}")
                        break

            self.results["technology_stack"] = list(set(tech_found))

            # Versiones expuestas en cabeceras
            server_header = headers_data.get("Server", "")
            if re.search(r'\d+\.\d+', server_header):
                warn(f"Versión de servidor expuesta: {server_header}")
                self.results["exposed_assets"].append({
                    "type": "server_version_exposed",
                    "severity": "medium",
                    "detail": f"Header Server: {server_header}",
                    "risk": "Facilita búsqueda de exploits para versión específica"
                })
                self.results["risk_score"] += 8

            x_powered = headers_data.get("X-Powered-By", "")
            if x_powered:
                warn(f"X-Powered-By expuesto: {x_powered}")
                self.results["exposed_assets"].append({
                    "type": "tech_header_exposed",
                    "severity": "low",
                    "detail": f"X-Powered-By: {x_powered}"
                })

        except Exception as e:
            warn(f"No se pudo conectar a {target_url}")

        self.results["exposed_assets"].extend(metadata_findings)
        return metadata_findings

    # ──────────────────────────────────────────────────────────────────────────
    def certificate_transparency(self):
        """Busca subdominios y assets via Certificate Transparency logs."""
        if not self.domain:
            return []
        hdr("🔐 CERTIFICATE TRANSPARENCY LOGS")
        info(f"Buscando certificados emitidos para *.{self.domain}...")

        subdomains = []
        crtsh_url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        data = self._http_get(crtsh_url, timeout=20)

        if data:
            try:
                entries = json.loads(data)
                seen = set()
                for entry in entries[:50]:
                    name = entry.get("name_value", "")
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and sub not in seen and self.domain in sub:
                            seen.add(sub)
                            subdomains.append(sub)
                            info(f"Subdominio encontrado: {C.BOLD}{sub}{C.END}")
                            # Detectar subdomains interesantes
                            for keyword in ['admin', 'dev', 'test', 'staging', 'vpn', 'mail',
                                          'api', 'internal', 'intranet', 'old', 'backup']:
                                if keyword in sub:
                                    found(f"  ↳ Subdominio sensible: {sub} [{keyword.upper()}]")
                                    self.results["exposed_assets"].append({
                                        "type": "sensitive_subdomain",
                                        "severity": "medium",
                                        "subdomain": sub,
                                        "keyword": keyword,
                                        "detail": f"Subdominio con keyword sensible: {keyword}"
                                    })
                                    self.results["risk_score"] += 8
                                    break

                info(f"Total subdominios encontrados: {len(subdomains)}")
            except Exception:
                warn("No se pudo parsear respuesta de crt.sh")
        else:
            warn("No se pudo contactar crt.sh — verificar conexión")

        return subdomains

    # ──────────────────────────────────────────────────────────────────────────
    def calculate_risk_score(self):
        """Calcula y muestra el Risk Score OSINT."""
        score = min(100, self.results["risk_score"])
        if score >= 70:
            level = "CRÍTICO"; color = C.RED; icon = "🚨"
        elif score >= 45:
            level = "ALTO"; color = C.RED; icon = "🔴"
        elif score >= 20:
            level = "MEDIO"; color = C.YELLOW; icon = "🟡"
        else:
            level = "BAJO"; color = C.GREEN; icon = "🟢"

        print(f"\n{C.PURPLE}{'═'*52}{C.END}")
        print(f"{color}{C.BOLD}  {icon}  OSINT RISK SCORE: {score}/100 — Exposición {level}{C.END}")
        total_assets = len(self.results["exposed_assets"])
        total_breaches = len(self.results["email_breaches"])
        print(f"  {C.DIM}  Assets expuestos: {total_assets}  |  Brechas encontradas: {total_breaches}{C.END}")
        print(f"{C.PURPLE}{'═'*52}{C.END}\n")
        self.results["risk_level"] = level
        return score

    # ──────────────────────────────────────────────────────────────────────────
    def save_results(self, output_dir=None):
        """Guarda resultados en JSON."""
        if output_dir is None:
            base = Path.home() / "Documents" / "purple_team_reports"
        else:
            base = Path(output_dir)
        out_dir = base / "osint"
        out_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_name = (self.domain or self.company or "target").replace('.', '_')
        out_file = out_dir / f"osint_{target_name}_{ts}.json"
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        ok(f"Resultados OSINT guardados: {out_file}")
        return str(out_file)

    # ──────────────────────────────────────────────────────────────────────────
    def run(self, full=False, url=None):
        """Ejecuta el reconocimiento OSINT completo."""
        print(BANNER)
        target_str = " | ".join(filter(None, [
            f"Dominio: {self.domain}" if self.domain else "",
            f"Email: {self.email}" if self.email else "",
            f"Empresa: {self.company}" if self.company else "",
        ]))
        print(f"  {C.BOLD}{target_str}{C.END}\n")

        if self.domain:
            self.whois_lookup()
            self.dns_enumeration()
            self.certificate_transparency()
            self.document_metadata(url=url)

        self.check_email_breaches()
        self.generate_google_dorks()
        self.calculate_risk_score()
        return self.save_results()


# ─── Entry point ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="OSINT Reconnaissance — Inteligencia en fuentes abiertas")
    parser.add_argument("--domain", help="Dominio objetivo (ej: empresa.com)")
    parser.add_argument("--email",  help="Email objetivo")
    parser.add_argument("--company", help="Nombre de la empresa")
    parser.add_argument("--url",    help="URL del sitio web del objetivo")
    parser.add_argument("--full",   action="store_true", help="Análisis completo")
    parser.add_argument("--output", help="Directorio de salida")
    args = parser.parse_args()

    if not any([args.domain, args.email, args.company]):
        parser.print_help()
        sys.exit(1)

    recon = OsintRecon(
        domain=args.domain,
        email=args.email,
        company=args.company,
    )
    recon.run(full=args.full, url=args.url)


if __name__ == "__main__":
    main()
