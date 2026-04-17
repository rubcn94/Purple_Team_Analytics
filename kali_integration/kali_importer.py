# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║       PURPLE TEAM SUITE - KALI LINUX RESULTS IMPORTER        ║
║       Importador profesional de herramientas Kali             ║
║                                                              ║
║  Formatos soportados:                                        ║
║    - Nmap XML (-oX output)                                   ║
║    - Nessus/OpenVAS XML (.nessus)                            ║
║    - Burp Suite XML                                          ║
║    - Metasploit XML (db_export)                              ║
║    - Nikto CSV/JSON                                          ║
║    - Masscan JSON                                            ║
║    - CrackMapExec/NetExec output                             ║
║                                                              ║
║  Uso:                                                        ║
║    python kali_importer.py                                   ║
║      → modo interactivo                                      ║
║                                                              ║
║    python kali_importer.py --file scan.xml                   ║
║      → importa un archivo                                    ║
║                                                              ║
║    python kali_importer.py --directory /path/to/scans/       ║
║      → importa todos los archivos de un directorio           ║
║                                                              ║
║    python kali_importer.py --file nmap.xml --file nessus.nessus ║
║      → merge múltiples archivos en un único reporte          ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import csv
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import xml.etree.ElementTree as ET
from collections import defaultdict
import re


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


# ─── MITRE ATT&CK Mapping ────────────────────────────────────────────────────
MITRE_MAPPING = {
    'network_scanning': 'T1046',
    'port_scanning': 'T1046',
    'service_enumeration': 'T1046',
    'web_application': 'T1190',
    'web_vulnerability': 'T1190',
    'sql_injection': 'T1190',
    'cross_site_scripting': 'T1190',
    'weak_authentication': 'T1110',
    'brute_force': 'T1110',
    'default_credentials': 'T1110.004',
    'weak_encryption': 'T1556',
    'missing_patch': 'T1548',
    'privilege_escalation': 'T1548',
    'lateral_movement': 'T1570',
    'active_directory': 'T1087',
    'kerberoasting': 'T1558.004',
    'smb': 'T1021.002',
    'dns': 'T1584.002',
    'credential_dumping': 'T1003',
    'information_disclosure': 'T1041',
}

def get_mitre_from_keyword(keyword: str) -> str:
    """Obtiene MITRE ATT&CK ID basado en palabras clave"""
    keyword_lower = keyword.lower().replace(' ', '_').replace('/', '_')
    for key, mitre in MITRE_MAPPING.items():
        if key in keyword_lower:
            return mitre
    return 'T1046'  # Default: Network Service Scanning


# ─── Esquema normalizado ─────────────────────────────────────────────────────
def create_finding(
    host: str,
    port: str = '',
    service: str = '',
    version: str = '',
    finding_type: str = '',
    severity: str = 'INFO',
    cvss: float = 0.0,
    description: str = '',
    evidence: str = '',
    recommendation: str = '',
    tool_source: str = '',
    mitre_id: str = ''
) -> Dict[str, Any]:
    """Crea un hallazgo normalizado en el esquema de Purple Team"""

    if not mitre_id:
        mitre_id = get_mitre_from_keyword(finding_type)

    return {
        'timestamp': datetime.now().isoformat(),
        'host': host,
        'port': port,
        'service': service,
        'version': version,
        'finding_type': finding_type,
        'severity': severity.upper(),
        'cvss': round(cvss, 1),
        'description': description,
        'evidence': evidence,
        'recommendation': recommendation,
        'tool_source': tool_source,
        'mitre_id': mitre_id,
    }


# ─── Parser base ─────────────────────────────────────────────────────────────
class KaliResultsParser:
    """Clase base para parsers de resultados Kali"""

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.findings: List[Dict[str, Any]] = []

    def parse(self) -> List[Dict[str, Any]]:
        """Parsea el archivo y retorna hallazgos normalizados"""
        raise NotImplementedError("Subclasses must implement parse()")

    def _normalize_severity(self, sev: str) -> str:
        """Normaliza valores de severidad a nuestro esquema"""
        sev_map = {
            'critical': 'CRITICO',
            'high': 'ALTO',
            'medium': 'MEDIO',
            'low': 'BAJO',
            'info': 'INFO',
            'informational': 'INFO',
            'none': 'INFO',
            '0': 'INFO',
            '1': 'BAJO',
            '2': 'MEDIO',
            '3': 'ALTO',
            '4': 'CRITICO',
        }
        return sev_map.get(str(sev).lower().strip(), 'INFO')

    def _parse_cvss(self, cvss_str: str) -> float:
        """Extrae valor numérico de CVSS"""
        try:
            match = re.search(r'(\d+\.?\d*)', str(cvss_str))
            if match:
                val = float(match.group(1))
                return min(10.0, max(0.0, val))
        except (ValueError, TypeError):
            pass
        return 0.0


# ─── Nmap XML Parser ─────────────────────────────────────────────────────────
class NmapParser(KaliResultsParser):
    """Parser para salidas XML de Nmap"""

    def parse(self) -> List[Dict[str, Any]]:
        """Parsea XML de Nmap"""
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            err(f"Error parsing Nmap XML: {e}")
            return []

        self.findings = []

        for host_elem in root.findall('host'):
            # Obtener IP del host
            ip_elem = host_elem.find('address[@addrtype="ipv4"]')
            if ip_elem is None:
                ip_elem = host_elem.find('address[@addrtype="ipv6"]')
            if ip_elem is None:
                continue

            ip = ip_elem.get('addr', '')

            # Obtener OS detection
            os_elem = host_elem.find('os')
            os_info = ''
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    os_info = osmatch.get('name', '')

            # Si hay OS detection, crear hallazgo
            if os_info:
                self.findings.append(create_finding(
                    host=ip,
                    finding_type='OS Detection',
                    severity='INFO',
                    description=f"Detected OS: {os_info}",
                    evidence=os_info,
                    tool_source='nmap',
                ))

            # Parsear puertos abiertos
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_num = port_elem.get('portid', '')
                    protocol = port_elem.get('protocol', 'tcp')

                    state_elem = port_elem.find('state')
                    port_state = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'

                    if port_state != 'open':
                        continue

                    # Obtener servicio
                    service_elem = port_elem.find('service')
                    service_name = ''
                    service_version = ''
                    if service_elem is not None:
                        service_name = service_elem.get('name', '')
                        service_version = service_elem.get('version', '')
                        product = service_elem.get('product', '')
                        extrainfo = service_elem.get('extrainfo', '')

                        if product:
                            service_version = f"{product} {service_version}".strip()
                        if extrainfo:
                            service_version = f"{service_version} ({extrainfo})".strip()

                    self.findings.append(create_finding(
                        host=ip,
                        port=port_num,
                        service=service_name,
                        version=service_version,
                        finding_type='Open Port',
                        severity='INFO',
                        description=f"Port {port_num}/{protocol} is open ({service_name})",
                        evidence=f"Port: {port_num}/{protocol}, Service: {service_name}, Version: {service_version}",
                        tool_source='nmap',
                    ))

                    # Parsear NSE scripts
                    for script_elem in port_elem.findall('script'):
                        script_id = script_elem.get('id', '')
                        script_output = script_elem.get('output', '')

                        if script_output:
                            self.findings.append(create_finding(
                                host=ip,
                                port=port_num,
                                service=service_name,
                                finding_type=f'NSE Script: {script_id}',
                                severity='INFO',
                                description=f"NSE script {script_id} output",
                                evidence=script_output[:500],
                                tool_source='nmap',
                            ))

        ok(f"Parsed {len(self.findings)} findings from Nmap")
        return self.findings


# ─── Nessus/OpenVAS Parser ──────────────────────────────────────────────────
class NessusParser(KaliResultsParser):
    """Parser para archivos Nessus XML"""

    def parse(self) -> List[Dict[str, Any]]:
        """Parsea XML de Nessus"""
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            err(f"Error parsing Nessus XML: {e}")
            return []

        self.findings = []

        for report_host in root.findall('.//ReportHost'):
            host_ip = report_host.get('name', '')

            for report_item in report_host.findall('ReportItem'):
                plugin_id = report_item.get('pluginID', '')
                plugin_name = report_item.get('pluginName', '')
                severity = report_item.get('severity', '0')
                port = report_item.get('port', '')
                protocol = report_item.get('protocol', 'tcp')
                service = report_item.get('svc_name', '')

                description = self._get_elem_text(report_item, 'description')
                cvss_base = self._get_elem_text(report_item, 'cvss_base_score')
                cvss_temp = self._get_elem_text(report_item, 'cvss_temporal_score')
                solution = self._get_elem_text(report_item, 'solution')
                synopsis = self._get_elem_text(report_item, 'synopsis')

                cvss = self._parse_cvss(cvss_base or cvss_temp or '0')
                severity_normalized = self._severity_from_cvss(cvss)

                self.findings.append(create_finding(
                    host=host_ip,
                    port=port,
                    service=service,
                    finding_type=plugin_name,
                    severity=severity_normalized,
                    cvss=cvss,
                    description=description or synopsis or plugin_name,
                    evidence=f"Plugin ID: {plugin_id}, Port: {port}/{protocol}",
                    recommendation=solution or 'See Nessus plugin documentation',
                    tool_source='nessus',
                ))

        ok(f"Parsed {len(self.findings)} findings from Nessus")
        return self.findings

    def _get_elem_text(self, parent: ET.Element, tag: str) -> str:
        """Obtiene texto de elemento XML"""
        elem = parent.find(tag)
        return (elem.text or '').strip() if elem is not None else ''

    def _severity_from_cvss(self, cvss: float) -> str:
        """Convierte CVSS a severidad"""
        if cvss >= 9.0:
            return 'CRITICO'
        elif cvss >= 7.0:
            return 'ALTO'
        elif cvss >= 4.0:
            return 'MEDIO'
        elif cvss > 0:
            return 'BAJO'
        return 'INFO'


# ─── Burp Suite XML Parser ──────────────────────────────────────────────────
class BurpParser(KaliResultsParser):
    """Parser para XML de Burp Suite"""

    def parse(self) -> List[Dict[str, Any]]:
        """Parsea XML de Burp"""
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            err(f"Error parsing Burp XML: {e}")
            return []

        self.findings = []

        for issue in root.findall('.//Issue'):
            name = self._get_elem_text(issue, 'Name')
            url = self._get_elem_text(issue, 'Url')
            severity = self._get_elem_text(issue, 'Severity')
            confidence = self._get_elem_text(issue, 'Confidence')
            issue_background = self._get_elem_text(issue, 'IssueBackground')
            remediation = self._get_elem_text(issue, 'RemediationBackground')

            # Extraer host y path de URL
            host = ''
            port = ''
            if url:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    host = parsed.hostname or ''
                    port = str(parsed.port) if parsed.port else ''
                except:
                    pass

            cvss = 0.0
            if confidence.lower() == 'certain':
                cvss = 7.0 if severity.lower() == 'high' else 5.0

            self.findings.append(create_finding(
                host=host,
                port=port,
                finding_type=name,
                severity=self._normalize_severity(severity),
                cvss=cvss,
                description=issue_background or name,
                evidence=f"URL: {url}, Confidence: {confidence}",
                recommendation=remediation or 'See Burp issue details',
                tool_source='burp',
            ))

        ok(f"Parsed {len(self.findings)} findings from Burp")
        return self.findings

    def _get_elem_text(self, parent: ET.Element, tag: str) -> str:
        """Obtiene texto de elemento XML"""
        elem = parent.find(tag)
        return (elem.text or '').strip() if elem is not None else ''


# ─── Metasploit XML Parser ──────────────────────────────────────────────────
class MetasploitParser(KaliResultsParser):
    """Parser para XML de db_export de Metasploit"""

    def parse(self) -> List[Dict[str, Any]]:
        """Parsea XML de Metasploit"""
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            err(f"Error parsing Metasploit XML: {e}")
            return []

        self.findings = []

        # Parsear hosts
        for host in root.findall('.//host'):
            host_ip = host.get('address', '')

            # Servicios
            for service in host.findall('service'):
                port = service.get('port', '')
                proto = service.get('proto', 'tcp')
                state = service.get('state', '')
                name = service.get('name', '')

                if state == 'open':
                    self.findings.append(create_finding(
                        host=host_ip,
                        port=port,
                        service=name,
                        finding_type='Open Service',
                        severity='INFO',
                        description=f"Open {proto}/{port} service: {name}",
                        evidence=f"Service: {name}, State: {state}",
                        tool_source='metasploit',
                    ))

            # Vulnerabilidades
            for vuln in host.findall('vuln'):
                vuln_name = vuln.get('name', '')
                vuln_refs = vuln.findall('ref')
                refs = [ref.text for ref in vuln_refs if ref.text]

                self.findings.append(create_finding(
                    host=host_ip,
                    finding_type=vuln_name,
                    severity='ALTO',
                    description=f"Vulnerability: {vuln_name}",
                    evidence=f"References: {', '.join(refs)}",
                    recommendation='See Metasploit module details',
                    tool_source='metasploit',
                ))

        ok(f"Parsed {len(self.findings)} findings from Metasploit")
        return self.findings


# ─── Nikto Parser ──────────────────────────────────────────────────────────
class NiktoParser(KaliResultsParser):
    """Parser para Nikto (CSV o JSON)"""

    def parse(self) -> List[Dict[str, Any]]:
        """Parsea resultados de Nikto"""
        self.findings = []

        if str(self.file_path).endswith('.json'):
            return self._parse_json()
        else:
            return self._parse_csv()

    def _parse_json(self) -> List[Dict[str, Any]]:
        """Parsea JSON de Nikto"""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            err(f"Error parsing Nikto JSON: {e}")
            return []

        results = data.get('vulnerabilities', data) if isinstance(data, dict) else data
        if not isinstance(results, list):
            results = [results]

        for vuln in results:
            if isinstance(vuln, dict):
                host = vuln.get('host', vuln.get('ip', ''))
                port = str(vuln.get('port', ''))
                description = vuln.get('description', vuln.get('msg', ''))
                severity = vuln.get('severity', 'INFO')

                self.findings.append(create_finding(
                    host=host,
                    port=port,
                    finding_type='Web Vulnerability',
                    severity=self._normalize_severity(severity),
                    description=description,
                    evidence=json.dumps(vuln, indent=2)[:500],
                    tool_source='nikto',
                ))

        ok(f"Parsed {len(self.findings)} findings from Nikto JSON")
        return self.findings

    def _parse_csv(self) -> List[Dict[str, Any]]:
        """Parsea CSV de Nikto"""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                if reader.fieldnames is None:
                    err("Nikto CSV tiene encabezado inválido")
                    return []

                for row in reader:
                    host = row.get('ip', row.get('host', ''))
                    port = row.get('port', '')
                    description = row.get('description', row.get('msg', ''))
                    severity = row.get('severity', 'INFO')

                    self.findings.append(create_finding(
                        host=host,
                        port=port,
                        finding_type='Web Vulnerability',
                        severity=self._normalize_severity(severity),
                        description=description,
                        evidence=str(row)[:500],
                        tool_source='nikto',
                    ))
        except (IOError, csv.Error) as e:
            err(f"Error parsing Nikto CSV: {e}")
            return []

        ok(f"Parsed {len(self.findings)} findings from Nikto CSV")
        return self.findings


# ─── Masscan JSON Parser ──────────────────────────────────────────────────
class MasscanParser(KaliResultsParser):
    """Parser para Masscan JSON"""

    def parse(self) -> List[Dict[str, Any]]:
        """Parsea JSON de Masscan"""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            err(f"Error parsing Masscan JSON: {e}")
            return []

        self.findings = []

        results = data if isinstance(data, list) else data.get('results', [])

        for result in results:
            if isinstance(result, dict):
                ip = result.get('ip', '')
                ports = result.get('ports', [])

                for port_info in ports:
                    port = port_info.get('port', '')
                    proto = port_info.get('proto', 'tcp')
                    status = port_info.get('status', 'open')
                    service = port_info.get('service', '')

                    if status == 'open':
                        self.findings.append(create_finding(
                            host=ip,
                            port=str(port),
                            service=service,
                            finding_type='Open Port',
                            severity='INFO',
                            description=f"Port {port}/{proto} detected by Masscan",
                            evidence=f"Service: {service}",
                            tool_source='masscan',
                        ))

        ok(f"Parsed {len(self.findings)} findings from Masscan")
        return self.findings


# ─── CrackMapExec/NetExec Parser ─────────────────────────────────────────
class CMEParser(KaliResultsParser):
    """Parser para salidas de CrackMapExec/NetExec"""

    def parse(self) -> List[Dict[str, Any]]:
        """Parsea JSON de CME"""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            err(f"Error parsing CME JSON: {e}")
            return []

        self.findings = []

        hosts = data.get('hosts', []) if isinstance(data, dict) else data

        for host in hosts:
            if isinstance(host, dict):
                ip = host.get('ip', '')
                os = host.get('os', '')
                domain = host.get('domain', '')

                if os:
                    self.findings.append(create_finding(
                        host=ip,
                        finding_type='OS Identification',
                        severity='INFO',
                        description=f"Detected OS: {os}",
                        evidence=os,
                        tool_source='crackmapexec',
                    ))

                # Credenciales válidas
                valid_creds = host.get('valid_credentials', [])
                for cred in valid_creds:
                    self.findings.append(create_finding(
                        host=ip,
                        finding_type='Valid Credentials Found',
                        severity='ALTO',
                        description=f"Valid credentials discovered during CME scan",
                        evidence=f"Domain: {domain or 'N/A'}, Credential found: Yes",
                        recommendation='Implement strong password policies and MFA',
                        tool_source='crackmapexec',
                    ))

                # Usuarios sin contraseña
                blank_pwd_users = host.get('blank_password_users', [])
                for user in blank_pwd_users:
                    self.findings.append(create_finding(
                        host=ip,
                        finding_type='User with Blank Password',
                        severity='CRITICO',
                        description=f"User {user} has no password set",
                        evidence=f"Username: {user}",
                        recommendation='Set password for all user accounts',
                        tool_source='crackmapexec',
                    ))

        ok(f"Parsed {len(self.findings)} findings from CME")
        return self.findings


# ─── Gestor de importación ──────────────────────────────────────────────────
class KaliImportManager:
    """Gestiona la importación de múltiples archivos"""

    PARSERS = {
        '.xml': [NmapParser, NessusParser, BurpParser, MetasploitParser],
        '.nessus': NessusParser,
        '.json': [NiktoParser, MasscanParser, CMEParser],
        '.csv': NiktoParser,
    }

    def __init__(self):
        self.all_findings: List[Dict[str, Any]] = []
        self.import_stats = {
            'total_files': 0,
            'successful_imports': 0,
            'failed_imports': 0,
            'total_findings': 0,
        }

    def detect_format(self, file_path: Path) -> Optional[KaliResultsParser]:
        """Auto-detecta formato de archivo y retorna parser apropiado"""
        suffix = file_path.suffix.lower()

        if suffix in self.PARSERS:
            parser_classes = self.PARSERS[suffix]
            if not isinstance(parser_classes, list):
                parser_classes = [parser_classes]

            # Intentar cada parser hasta que uno funcione
            for parser_class in parser_classes:
                try:
                    return parser_class(str(file_path))
                except Exception:
                    continue

        return None

    def import_file(self, file_path: str) -> bool:
        """Importa un archivo individual"""
        path = Path(file_path)

        if not path.exists():
            err(f"File not found: {file_path}")
            return False

        self.import_stats['total_files'] += 1
        info(f"Importing: {path.name}")

        parser = self.detect_format(path)
        if parser is None:
            err(f"Unsupported format: {path.suffix}")
            self.import_stats['failed_imports'] += 1
            return False

        try:
            findings = parser.parse()
            self.all_findings.extend(findings)
            self.import_stats['successful_imports'] += 1
            self.import_stats['total_findings'] += len(findings)
            return True
        except Exception as e:
            err(f"Error importing {path.name}: {e}")
            self.import_stats['failed_imports'] += 1
            return False

    def import_directory(self, directory: str) -> bool:
        """Importa todos los archivos de un directorio"""
        dir_path = Path(directory)

        if not dir_path.is_dir():
            err(f"Directory not found: {directory}")
            return False

        info(f"Scanning directory: {directory}")

        supported_exts = ['.xml', '.nessus', '.json', '.csv']
        files_found = []

        for ext in supported_exts:
            files_found.extend(dir_path.glob(f'*{ext}'))

        if not files_found:
            warn(f"No supported files found in {directory}")
            return False

        for file_path in sorted(files_found):
            self.import_file(str(file_path))

        return True

    def deduplicate_findings(self):
        """Elimina hallazgos duplicados"""
        seen = set()
        unique = []

        for finding in self.all_findings:
            key = (
                finding['host'],
                finding['port'],
                finding['service'],
                finding['finding_type'],
                finding['tool_source'],
            )

            if key not in seen:
                seen.add(key)
                unique.append(finding)

        removed = len(self.all_findings) - len(unique)
        if removed > 0:
            warn(f"Removed {removed} duplicate findings")

        self.all_findings = unique

    def merge_results(self) -> Dict[str, Any]:
        """Genera reporte combinado"""
        self.deduplicate_findings()

        # Agrupar por host
        by_host = defaultdict(list)
        for finding in self.all_findings:
            by_host[finding['host']].append(finding)

        # Contar severidades
        severity_counts = defaultdict(int)
        for finding in self.all_findings:
            severity_counts[finding['severity']] += 1

        return {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_findings': len(self.all_findings),
                'unique_hosts': len(by_host),
                'import_stats': self.import_stats,
                'severity_distribution': dict(severity_counts),
            },
            'findings': self.all_findings,
            'by_host': dict(by_host),
        }

    def save_json(self, output_file: str):
        """Guarda resultados en JSON"""
        result = self.merge_results()

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)

        ok(f"Results saved to: {output_path}")
        return output_path


# ─── Interfaz interactiva ──────────────────────────────────────────────────
def interactive_mode():
    """Modo interactivo"""
    pr(C.PURPLE, """
    ╔══════════════════════════════════════════════════════════════╗
    ║       KALI LINUX RESULTS IMPORTER - INTERACTIVE MODE          ║
    ║       Purple Team Suite                                      ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    manager = KaliImportManager()

    while True:
        print("\nOptions:")
        print("  1) Import single file")
        print("  2) Import directory")
        print("  3) Generate report")
        print("  4) Exit")

        choice = input("\nSelect option (1-4): ").strip()

        if choice == '1':
            file_path = input("Enter file path: ").strip()
            manager.import_file(file_path)

        elif choice == '2':
            dir_path = input("Enter directory path: ").strip()
            manager.import_directory(dir_path)

        elif choice == '3':
            if manager.all_findings:
                output = input("Enter output file (default: kali_results.json): ").strip()
                output = output or "kali_results.json"
                manager.save_json(output)
                print_summary(manager)
            else:
                warn("No findings imported yet")

        elif choice == '4':
            print("Exiting...")
            break

        else:
            err("Invalid option")


def print_summary(manager: KaliImportManager):
    """Imprime resumen de importación"""
    result = manager.merge_results()
    meta = result['metadata']

    print("\n" + "=" * 60)
    print(f"{'IMPORT SUMMARY':^60}")
    print("=" * 60)
    print(f"Files processed:      {meta['import_stats']['total_files']}")
    print(f"Successful imports:   {meta['import_stats']['successful_imports']}")
    print(f"Failed imports:       {meta['import_stats']['failed_imports']}")
    print(f"Total findings:       {meta['total_findings']}")
    print(f"Unique hosts:         {meta['unique_hosts']}")
    print()
    print("Severity Distribution:")
    for severity in ['CRITICO', 'ALTO', 'MEDIO', 'BAJO', 'INFO']:
        count = meta['severity_distribution'].get(severity, 0)
        if count > 0:
            print(f"  {severity:10s}: {count:3d}")
    print("=" * 60)


# ─── CLI ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='Kali Linux Results Importer for Purple Team Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python kali_importer.py
    → Interactive mode

  python kali_importer.py --file nmap_scan.xml
    → Import single file

  python kali_importer.py --directory /path/to/kali/results/
    → Import all files from directory

  python kali_importer.py --file nmap.xml --file nessus.nessus --output merged.json
    → Merge multiple files
        """
    )

    parser.add_argument('--file', action='append', help='Input file to import (can be used multiple times)')
    parser.add_argument('--directory', help='Directory to scan for result files')
    parser.add_argument('--output', default='kali_results.json', help='Output JSON file')

    args = parser.parse_args()

    # Si no hay argumentos, modo interactivo
    if not args.file and not args.directory:
        interactive_mode()
        return

    # Modo CLI
    manager = KaliImportManager()

    if args.file:
        for file_path in args.file:
            manager.import_file(file_path)

    if args.directory:
        manager.import_directory(args.directory)

    if manager.all_findings:
        manager.save_json(args.output)
        print_summary(manager)
        ok(f"Report generated: {args.output}")
    else:
        err("No findings were imported")
        sys.exit(1)


if __name__ == '__main__':
    main()
