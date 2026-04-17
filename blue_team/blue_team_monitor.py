# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║         PURPLE TEAM SUITE - BLUE TEAM MONITOR                ║
║         Detección · Análisis · Respuesta a Incidentes        ║
║                                                              ║
║  Módulo defensivo: analiza el estado de seguridad del        ║
║  sistema, detecta indicadores de compromiso (IoC) y          ║
║  genera playbooks de respuesta a incidentes.                 ║
║                                                              ║
║  Uso:                                                        ║
║    python blue_team/blue_team_monitor.py                     ║
║    python blue_team/blue_team_monitor.py --target 192.168.1.0/24 ║
║    python blue_team/blue_team_monitor.py --mode ioc          ║
║    python blue_team/blue_team_monitor.py --mode logs         ║
║    python blue_team/blue_team_monitor.py --mode hardening    ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import socket
import subprocess
import re
import time
import platform
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter

# ── Colores ───────────────────────────────────────────────────────────────────
class C:
    PURPLE = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN  = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    BOLD   = '\033[1m';  DIM = '\033[2m'; END = '\033[0m'

def ok(m):    print(f"{C.GREEN}  ✅  {m}{C.END}")
def warn(m):  print(f"{C.YELLOW}  ⚠️   {m}{C.END}")
def crit(m):  print(f"{C.RED}  🚨  {m}{C.END}")
def info(m):  print(f"{C.CYAN}  ℹ️   {m}{C.END}")
def blue(m):  print(f"{C.BLUE}  🔵  {m}{C.END}")
def hdr(m):   print(f"\n{C.BLUE}{C.BOLD}  ╔══ {m} ══╗{C.END}\n")

BANNER = f"""
{C.BLUE}{C.BOLD}
  ╔══════════════════════════════════════════════════╗
  ║   🔵  PURPLE TEAM — BLUE TEAM MONITOR            ║
  ║        Detectar · Analizar · Responder            ║
  ╚══════════════════════════════════════════════════╝
{C.END}"""


# ─── Indicadores de compromiso conocidos ─────────────────────────────────────
KNOWN_MALICIOUS_PORTS = {
    1337, 4444, 4445, 5555, 6666, 6667, 7777, 8888, 9999,
    31337, 12345, 54321, 65535, 1234, 2222, 3333,
}

SUSPICIOUS_PROCESSES = [
    'nc', 'netcat', 'ncat', 'socat', 'msfconsole', 'msfvenom',
    'metasploit', 'cobaltstrike', 'empire', 'powersploit',
    'mimikatz', 'crackmapexec', 'bloodhound', 'impacket',
    'hydra', 'medusa', 'john', 'hashcat', 'aircrack-ng',
    'bettercap', 'ettercap', 'responder', 'beef-xss',
]

SUSPICIOUS_DIRS = [
    '/tmp', '/var/tmp', '/dev/shm', '/run/shm',
    '/proc/*/fd', '/tmp/.ICE-unix',
]

HIGH_RISK_SUID_BINS = [
    'nmap', 'vim', 'python', 'python3', 'perl', 'ruby', 'bash',
    'sh', 'find', 'curl', 'wget', 'awk', 'env', 'tee', 'less',
    'more', 'nano', 'cp', 'mv', 'chmod', 'chown',
]

# ─── CIS Benchmark checks (Linux) ────────────────────────────────────────────
CIS_CHECKS = {
    "Partition /tmp separada": {
        "cmd": "mount | grep -E '\\s/tmp\\s'",
        "expect_output": True,
        "severity": "medium",
        "remediation": "Configurar /tmp en partición separada con opciones noexec,nosuid,nodev"
    },
    "SSH PermitRootLogin desactivado": {
        "cmd": "grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'not_found'",
        "expect": "no",
        "severity": "high",
        "remediation": "Añadir/cambiar 'PermitRootLogin no' en /etc/ssh/sshd_config"
    },
    "SSH Protocol v2": {
        "cmd": "grep -i '^Protocol' /etc/ssh/sshd_config 2>/dev/null || echo '2'",
        "expect": "2",
        "severity": "high",
        "remediation": "Añadir 'Protocol 2' en /etc/ssh/sshd_config"
    },
    "Firewall activo (ufw/iptables)": {
        "cmd": "ufw status 2>/dev/null | head -1 || iptables -L 2>/dev/null | head -3",
        "expect_output": True,
        "severity": "high",
        "remediation": "Activar ufw: 'ufw enable' o configurar iptables"
    },
    "Cuentas sin contraseña": {
        "cmd": "awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null || echo 'ok'",
        "expect": "ok",
        "severity": "critical",
        "remediation": "Establecer contraseña para todas las cuentas: passwd <usuario>"
    },
    "SSH MaxAuthTries <= 4": {
        "cmd": "grep -i '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null || echo 'not_set'",
        "check_func": lambda x: int(re.search(r'\d+', x).group()) <= 4 if re.search(r'\d+', x) else False,
        "severity": "medium",
        "remediation": "Añadir 'MaxAuthTries 4' en /etc/ssh/sshd_config"
    },
    "Syslog activo": {
        "cmd": "systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog 2>/dev/null || echo 'inactive'",
        "expect": "active",
        "severity": "high",
        "remediation": "Activar rsyslog: systemctl enable rsyslog && systemctl start rsyslog"
    },
}

# ─── Clase principal ──────────────────────────────────────────────────────────
class BlueTeamMonitor:
    def __init__(self, target_network=None):
        self.target_network = target_network
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "ioc_findings": [],
            "hardening_findings": [],
            "network_anomalies": [],
            "log_anomalies": [],
            "defense_score": 0,
            "risk_level": "unknown",
        }
        self.score = 100  # Puntuación que va bajando con hallazgos

    # ──────────────────────────────────────────────────────────────────────────
    def run_cmd(self, cmd, timeout=10):
        """Ejecuta comando shell de forma segura."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout
            )
            return result.stdout.strip()
        except Exception:
            return ""

    # ──────────────────────────────────────────────────────────────────────────
    def check_ioc(self):
        """Busca Indicadores de Compromiso en el sistema."""
        hdr("🔍 ANÁLISIS DE INDICADORES DE COMPROMISO (IoC)")
        findings = []

        # 1. Conexiones activas sospechosas
        info("Revisando conexiones de red activas...")
        net_out = self.run_cmd("ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null")
        if net_out:
            for line in net_out.splitlines():
                for port in KNOWN_MALICIOUS_PORTS:
                    if f":{port}" in line or f":{port} " in line:
                        crit(f"Puerto sospechoso detectado: {line.strip()}")
                        findings.append({
                            "type": "suspicious_port",
                            "severity": "high",
                            "detail": line.strip(),
                            "port": port
                        })
                        self.score -= 20

        # 2. Procesos sospechosos
        info("Revisando procesos activos...")
        ps_out = self.run_cmd("ps aux 2>/dev/null || ps -ef 2>/dev/null")
        if ps_out:
            for proc in SUSPICIOUS_PROCESSES:
                pattern = rf'\b{re.escape(proc)}\b'
                matches = re.findall(pattern, ps_out, re.IGNORECASE)
                if matches:
                    warn(f"Proceso sospechoso en ejecución: {proc}")
                    findings.append({
                        "type": "suspicious_process",
                        "severity": "high",
                        "detail": f"Proceso detectado: {proc}"
                    })
                    self.score -= 15

        # 3. Archivos SUID peligrosos
        info("Buscando binarios SUID de alto riesgo...")
        suid_out = self.run_cmd("find / -perm -4000 -type f 2>/dev/null", timeout=30)
        if suid_out:
            for line in suid_out.splitlines():
                binary = Path(line).name
                if binary in HIGH_RISK_SUID_BINS:
                    warn(f"SUID peligroso: {line}")
                    findings.append({
                        "type": "dangerous_suid",
                        "severity": "medium",
                        "detail": f"Binario SUID: {line}"
                    })
                    self.score -= 10

        # 4. Archivos ejecutables en /tmp
        info("Revisando archivos ejecutables en directorios temporales...")
        tmp_exec = self.run_cmd("find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null")
        if tmp_exec:
            for f in tmp_exec.splitlines()[:10]:
                crit(f"Ejecutable en directorio temporal: {f}")
                findings.append({
                    "type": "executable_in_tmp",
                    "severity": "critical",
                    "detail": f"Ejecutable: {f}"
                })
                self.score -= 25

        # 5. Crontabs sospechosas
        info("Revisando tareas programadas...")
        cron_out = self.run_cmd("crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null | head -20")
        suspicious_cron_patterns = [r'curl\s+.*\|.*sh', r'wget\s+.*\|.*sh', r'base64\s+-d', r'/tmp/']
        for pattern in suspicious_cron_patterns:
            if re.search(pattern, cron_out, re.IGNORECASE):
                warn(f"Crontab sospechosa con patrón: {pattern}")
                findings.append({
                    "type": "suspicious_crontab",
                    "severity": "high",
                    "detail": f"Patrón sospechoso en crontab: {pattern}"
                })
                self.score -= 20

        # 6. Usuarios con UID 0 (root) no estándar
        info("Revisando cuentas con privilegios root...")
        uid0_users = self.run_cmd("awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null")
        uid0_list = uid0_users.splitlines() if uid0_users else []
        for user in uid0_list:
            if user.strip() not in ('root',):
                crit(f"Usuario con UID 0 no estándar: {user}")
                findings.append({
                    "type": "unauthorized_root_user",
                    "severity": "critical",
                    "detail": f"Usuario UID=0: {user}"
                })
                self.score -= 30

        # Resumen
        if not findings:
            ok("No se detectaron indicadores de compromiso activos")
        else:
            print(f"\n  {C.RED}{C.BOLD}  ⚠️  {len(findings)} IoC(s) detectados{C.END}")

        self.results["ioc_findings"] = findings
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    def check_hardening(self):
        """Evalúa el nivel de hardening del sistema (basado en CIS Benchmark)."""
        hdr("🛡️ EVALUACIÓN DE HARDENING (CIS Benchmark)")
        findings = []
        passed = 0
        total = len(CIS_CHECKS)

        for check_name, check_data in CIS_CHECKS.items():
            output = self.run_cmd(check_data["cmd"])
            severity = check_data.get("severity", "medium")
            remediation = check_data.get("remediation", "")

            # Evaluar resultado
            passed_check = False
            if "check_func" in check_data:
                try:
                    passed_check = check_data["check_func"](output)
                except Exception:
                    passed_check = False
            elif "expect" in check_data:
                passed_check = check_data["expect"].lower() in output.lower()
            elif "expect_output" in check_data:
                passed_check = bool(output and len(output) > 3)

            if passed_check:
                ok(f"{check_name}")
                passed += 1
            else:
                severity_icon = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢"}.get(severity, "⚠️")
                print(f"  {C.RED}  {severity_icon}  FALLO: {check_name}{C.END}")
                print(f"       {C.DIM}↳ Remediación: {remediation}{C.END}")
                findings.append({
                    "type": "hardening_failure",
                    "check": check_name,
                    "severity": severity,
                    "remediation": remediation,
                    "output": output[:200]
                })
                penalty = {"critical": 25, "high": 15, "medium": 8, "low": 3}.get(severity, 8)
                self.score -= penalty

        score_pct = int((passed / total) * 100) if total > 0 else 0
        color = C.GREEN if score_pct >= 80 else (C.YELLOW if score_pct >= 60 else C.RED)
        print(f"\n  {color}{C.BOLD}  Hardening Score: {passed}/{total} ({score_pct}%){C.END}")
        self.results["hardening_findings"] = findings
        self.results["hardening_score"] = score_pct
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    def analyze_logs(self):
        """Analiza logs del sistema en busca de anomalías."""
        hdr("📋 ANÁLISIS DE LOGS DEL SISTEMA")
        anomalies = []

        # Auth logs - intentos de login fallidos
        auth_files = ['/var/log/auth.log', '/var/log/secure', '/var/log/messages']
        auth_content = ""
        for auth_file in auth_files:
            if Path(auth_file).exists():
                auth_content = self.run_cmd(f"tail -500 {auth_file} 2>/dev/null")
                if auth_content:
                    info(f"Analizando {auth_file}...")
                    break

        if auth_content:
            # Contar fallos de autenticación
            failed_logins = re.findall(r'Failed password for (\S+) from ([\d.]+)', auth_content)
            if failed_logins:
                user_count = Counter([f[0] for f in failed_logins])
                ip_count = Counter([f[1] for f in failed_logins])
                total_fails = len(failed_logins)

                if total_fails > 10:
                    crit(f"Detectados {total_fails} intentos de login fallidos")
                    # IPs más atacantes
                    for ip, count in ip_count.most_common(5):
                        if count > 5:
                            warn(f"  IP sospechosa: {ip} — {count} intentos fallidos")
                            anomalies.append({
                                "type": "brute_force_attempt",
                                "severity": "high",
                                "detail": f"IP {ip}: {count} intentos de login fallidos",
                                "ip": ip,
                                "count": count
                            })
                            self.score -= min(count, 30)
                elif total_fails > 0:
                    warn(f"{total_fails} intentos de login fallidos recientes")
            else:
                ok("Sin intentos de login fallidos recientes")

            # SSH root login directo
            root_logins = re.findall(r'Accepted.*for root from ([\d.]+)', auth_content)
            if root_logins:
                for ip in set(root_logins):
                    warn(f"Login directo como root desde: {ip}")
                    anomalies.append({
                        "type": "root_login",
                        "severity": "critical",
                        "detail": f"Login root directo desde {ip}",
                        "ip": ip
                    })
                    self.score -= 25

            # Sudo abuse
            sudo_events = re.findall(r'sudo.*COMMAND=(.*)', auth_content)
            if sudo_events:
                info(f"{len(sudo_events)} eventos sudo recientes registrados")

        else:
            warn("No se encontraron logs de autenticación accesibles")

        # Kernel/dmesg anomalies
        dmesg_out = self.run_cmd("dmesg 2>/dev/null | tail -100")
        if dmesg_out:
            oom_events = len(re.findall(r'Out of memory|OOM killer', dmesg_out, re.IGNORECASE))
            segfault_events = len(re.findall(r'segfault', dmesg_out, re.IGNORECASE))
            if oom_events > 0:
                warn(f"{oom_events} eventos OOM en kernel (posible DoS o proceso malicioso)")
                anomalies.append({"type": "oom_events", "severity": "medium",
                                  "detail": f"{oom_events} eventos OOM en dmesg"})
            if segfault_events > 5:
                warn(f"{segfault_events} segfaults en dmesg (posible exploit)")
                anomalies.append({"type": "segfault_events", "severity": "medium",
                                  "detail": f"{segfault_events} segfaults en dmesg"})

        if not anomalies:
            ok("Sin anomalías significativas en logs del sistema")

        self.results["log_anomalies"] = anomalies
        return anomalies

    # ──────────────────────────────────────────────────────────────────────────
    def network_baseline(self):
        """Genera baseline de red y detecta anomalías."""
        hdr("🌐 ANÁLISIS DE RED Y DETECCIÓN DE ANOMALÍAS")
        anomalies = []

        # Puertos abiertos en escucha
        info("Mapeando servicios en escucha...")
        listening = self.run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        open_ports = []
        if listening:
            for line in listening.splitlines():
                match = re.search(r':(\d+)\s', line)
                if match:
                    port = int(match.group(1))
                    open_ports.append(port)
                    if port in KNOWN_MALICIOUS_PORTS:
                        crit(f"Puerto de C2/backdoor en escucha: {port}")
                        anomalies.append({
                            "type": "malicious_port_listening",
                            "severity": "critical",
                            "port": port,
                            "detail": line.strip()
                        })
                        self.score -= 30

        # ARP table - detectar posible ARP spoofing
        info("Verificando tabla ARP...")
        arp_out = self.run_cmd("arp -an 2>/dev/null || ip neigh 2>/dev/null")
        if arp_out:
            # Buscar duplicados de MAC (ARP poisoning)
            mac_to_ips = defaultdict(list)
            for line in arp_out.splitlines():
                mac_match = re.search(r'([0-9a-fA-F:]{17})', line)
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if mac_match and ip_match:
                    mac_to_ips[mac_match.group(1)].append(ip_match.group(1))

            for mac, ips in mac_to_ips.items():
                if len(ips) > 1:
                    crit(f"Posible ARP Spoofing: MAC {mac} responde por IPs {ips}")
                    anomalies.append({
                        "type": "arp_spoofing",
                        "severity": "critical",
                        "detail": f"MAC {mac} asociada a {ips}"
                    })
                    self.score -= 35

        # Interfaces en modo promiscuo (sniffing)
        info("Verificando interfaces en modo promiscuo...")
        iface_out = self.run_cmd("ip link 2>/dev/null || ifconfig -a 2>/dev/null")
        if 'PROMISC' in iface_out:
            crit("Interfaz de red en modo PROMISCUO — posible sniffer activo")
            anomalies.append({
                "type": "promiscuous_mode",
                "severity": "critical",
                "detail": "Interfaz de red en modo promiscuo detectada"
            })
            self.score -= 40

        # Resumen de puertos abiertos
        if open_ports:
            benign_common = {22, 80, 443, 8080, 8443, 3000, 5000}
            unknown_ports = [p for p in open_ports if p not in benign_common and p > 1024]
            if unknown_ports:
                info(f"Puertos no estándar en escucha: {sorted(unknown_ports)[:10]}")

        if not anomalies:
            ok("Sin anomalías de red detectadas")

        self.results["network_anomalies"] = anomalies
        return anomalies

    # ──────────────────────────────────────────────────────────────────────────
    def generate_playbook(self):
        """Genera playbook de respuesta a incidentes basado en hallazgos."""
        hdr("📖 PLAYBOOK DE RESPUESTA A INCIDENTES")
        all_findings = (
            self.results.get("ioc_findings", []) +
            self.results.get("log_anomalies", []) +
            self.results.get("network_anomalies", [])
        )

        if not all_findings:
            ok("Sin incidentes activos — sistema en estado normal")
            return {}

        playbook = {
            "generated_at": datetime.now().isoformat(),
            "total_incidents": len(all_findings),
            "steps": []
        }

        critical_findings = [f for f in all_findings if f.get("severity") == "critical"]
        high_findings = [f for f in all_findings if f.get("severity") == "high"]

        step_num = 1

        if critical_findings:
            print(f"\n  {C.RED}{C.BOLD}  🚨 RESPUESTA INMEDIATA REQUERIDA{C.END}")
            for f in critical_findings:
                print(f"\n  {C.RED}  Paso {step_num}: {f.get('type', 'incident').upper().replace('_', ' ')}{C.END}")
                playbook["steps"].append({
                    "step": step_num,
                    "priority": "INMEDIATA",
                    "type": f.get("type"),
                    "detail": f.get("detail"),
                    "actions": self._get_response_actions(f)
                })
                for action in self._get_response_actions(f):
                    print(f"       {C.CYAN}↳ {action}{C.END}")
                step_num += 1

        if high_findings:
            print(f"\n  {C.YELLOW}{C.BOLD}  ⚠️ ACCIONES DE ALTA PRIORIDAD{C.END}")
            for f in high_findings[:5]:
                print(f"\n  {C.YELLOW}  Paso {step_num}: {f.get('type', 'incident').upper().replace('_', ' ')}{C.END}")
                playbook["steps"].append({
                    "step": step_num,
                    "priority": "ALTA",
                    "type": f.get("type"),
                    "detail": f.get("detail"),
                    "actions": self._get_response_actions(f)
                })
                for action in self._get_response_actions(f):
                    print(f"       {C.YELLOW}↳ {action}{C.END}")
                step_num += 1

        self.results["incident_playbook"] = playbook
        return playbook

    def _get_response_actions(self, finding):
        """Mapea tipo de hallazgo a acciones de respuesta."""
        actions_map = {
            "suspicious_port": [
                "Identificar el proceso usando el puerto: `ss -tlnp | grep :<puerto>`",
                "Terminar el proceso si no es legítimo: `kill -9 <pid>`",
                "Bloquear el puerto en firewall: `ufw deny <puerto>`",
                "Investigar el origen del proceso en logs"
            ],
            "suspicious_process": [
                "Documentar el estado actual: `ps aux > /tmp/ps_evidence.txt`",
                "Verificar hash del binario contra VirusTotal",
                "Aislar el proceso: `kill -STOP <pid>`",
                "Analizar conexiones del proceso: `lsof -p <pid>`",
                "Considerar aislamiento de red del sistema afectado"
            ],
            "executable_in_tmp": [
                "INMEDIATO: Copiar para análisis forense antes de eliminar",
                "Calcular hash: `md5sum <archivo>`",
                "Analizar con: `file <archivo>` y `strings <archivo> | head -50`",
                "Eliminar el ejecutable: `rm -f <archivo>`",
                "Revisar crontabs y scripts que puedan recrearlo"
            ],
            "unauthorized_root_user": [
                "CRÍTICO: Cambiar contraseña del usuario inmediatamente",
                "Revocar privilegios: editar /etc/passwd y cambiar UID",
                "Revisar historial del usuario: `cat /home/<user>/.bash_history`",
                "Auditar cuándo se creó: `last <user>`",
                "Considerar deshabilitar la cuenta hasta investigar"
            ],
            "brute_force_attempt": [
                "Bloquear IP atacante: `ufw deny from <ip>`",
                "Configurar fail2ban: `apt install fail2ban`",
                "Revisar si algún intento tuvo éxito en auth.log",
                "Aumentar MaxAuthTries en sshd_config a 3",
                "Considerar cambiar puerto SSH por defecto"
            ],
            "arp_spoofing": [
                "CRÍTICO: Posible Man-in-the-Middle activo en la red",
                "Identificar el gateway legítimo: `ip route`",
                "Añadir ARP estático del gateway: `arp -s <gateway_ip> <mac_real>`",
                "Instalar protección ARP: `apt install arptables`",
                "Investigar todos los sistemas en la red"
            ],
            "promiscuous_mode": [
                "Identificar la interfaz: `ip link | grep PROMISC`",
                "Identificar qué proceso activó modo promiscuo: `tcpdump -D`",
                "Desactivar: `ip link set <iface> promisc off`",
                "Revisar si hay herramientas de sniffing instaladas"
            ],
            "root_login": [
                "Revisar qué comandos ejecutó root en esa sesión",
                "Verificar si el login fue legítimo con el administrador",
                "Deshabilitar login root por SSH: PermitRootLogin no",
                "Revisar ~/.bash_history de root"
            ],
        }
        return actions_map.get(finding.get("type", ""), [
            "Documentar el hallazgo con evidencia",
            "Escalar al equipo de seguridad",
            "Revisar logs relacionados",
            "Aplicar remediación específica según el tipo de incidente"
        ])

    # ──────────────────────────────────────────────────────────────────────────
    def calculate_defense_score(self):
        """Calcula y muestra el Defense Score final."""
        final_score = max(0, min(100, self.score))
        self.results["defense_score"] = final_score

        if final_score >= 85:
            level = "ALTO"; color = C.GREEN; icon = "🟢"
        elif final_score >= 65:
            level = "MEDIO"; color = C.YELLOW; icon = "🟡"
        elif final_score >= 40:
            level = "BAJO"; color = C.RED; icon = "🔴"
        else:
            level = "CRÍTICO"; color = C.RED; icon = "🚨"

        self.results["risk_level"] = level

        print(f"\n{C.BLUE}{'═'*52}{C.END}")
        print(f"{color}{C.BOLD}  {icon}  DEFENSE SCORE: {final_score}/100 — Nivel {level}{C.END}")
        print(f"{C.BLUE}{'═'*52}{C.END}\n")

        return final_score

    # ──────────────────────────────────────────────────────────────────────────
    def save_results(self, output_dir=None):
        """Guarda resultados en JSON."""
        if output_dir is None:
            output_dir = Path.home() / "Documents" / "purple_team_reports" / "blue_team"
        else:
            output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = output_dir / f"blue_team_report_{ts}.json"
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)

        ok(f"Resultados guardados: {out_file}")
        return str(out_file)

    # ──────────────────────────────────────────────────────────────────────────
    def run(self, mode="full"):
        """Ejecuta el análisis completo o un módulo específico."""
        print(BANNER)
        print(f"  Host: {C.BOLD}{self.results['hostname']}{C.END}  |  "
              f"Plataforma: {C.BOLD}{self.results['platform']}{C.END}  |  "
              f"Modo: {C.BOLD}{mode.upper()}{C.END}")
        print()

        if mode in ("full", "ioc"):
            self.check_ioc()
        if mode in ("full", "hardening"):
            self.check_hardening()
        if mode in ("full", "logs"):
            self.analyze_logs()
        if mode in ("full", "network"):
            self.network_baseline()
        if mode == "full":
            self.generate_playbook()

        self.calculate_defense_score()
        return self.save_results()


# ─── Entry point ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Blue Team Monitor — Detección y respuesta defensiva"
    )
    parser.add_argument("--target", help="Red objetivo (ej: 192.168.1.0/24)", default=None)
    parser.add_argument("--mode", choices=["full", "ioc", "hardening", "logs", "network"],
                        default="full", help="Módulo a ejecutar")
    parser.add_argument("--output", help="Directorio de salida para resultados", default=None)
    args = parser.parse_args()

    monitor = BlueTeamMonitor(target_network=args.target)
    monitor.run(mode=args.mode)


if __name__ == "__main__":
    main()
