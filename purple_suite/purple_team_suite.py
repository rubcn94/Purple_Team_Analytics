# -*- coding: utf-8 -*-
"""
Purple Team Suite for Termux
Framework completo Attack → Detect → Respond

Simula ataques red team y practica detección/respuesta blue team

Uso: python purple_team_suite.py
"""

import subprocess
import json
import time
from datetime import datetime
from pathlib import Path
import re

class PurpleTeamSuite:
    def __init__(self):
        self.output_dir = self.get_output_path()
        self.red_log = self.output_dir / f"red_team_{datetime.now().strftime('%Y%m%d')}.log"
        self.blue_log = self.output_dir / f"blue_team_{datetime.now().strftime('%Y%m%d')}.log"
        self.alerts_log = self.output_dir / f"alerts_{datetime.now().strftime('%Y%m%d')}.log"

        self.attack_techniques = {
            '1': {
                'name': 'Reconnaissance',
                'mitre': 'TA0043',
                'description': 'WiFi scanning + Network discovery'
            },
            '2': {
                'name': 'Port Scanning',
                'mitre': 'T1046',
                'description': 'Active port enumeration'
            },
            '3': {
                'name': 'DNS Enumeration',
                'mitre': 'T1590.002',
                'description': 'DNS record collection'
            },
            '4': {
                'name': 'Web Vulnerability Scan',
                'mitre': 'T1190',
                'description': 'HTTP security headers analysis'
            },
            '5': {
                'name': 'Banner Grabbing',
                'mitre': 'T1046',
                'description': 'Service version identification'
            }
        }

    def get_output_path(self):
        """Detecta si estamos en Termux"""
        termux_storage = Path.home() / "storage" / "shared" / "Documents" / "purple_team_reports"

        if termux_storage.parent.exists():
            termux_storage.mkdir(exist_ok=True)
            return termux_storage
        else:
            desktop_path = Path.home() / "Documents" / "purple_team_reports"
            desktop_path.mkdir(exist_ok=True)
            return desktop_path

    def log_event(self, team, technique, details, severity="INFO"):
        """Registra eventos con formato SIEM-friendly"""

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if team == "RED":
            log_file = self.red_log
            prefix = "🔴"
        elif team == "BLUE":
            log_file = self.blue_log
            prefix = "🔵"
        else:
            log_file = self.alerts_log
            prefix = "🚨"

        # Ensure output directory exists
        log_file.parent.mkdir(parents=True, exist_ok=True)

        # Formato CEF-like para práctica
        entry = f"{timestamp}|{team}|{technique}|{severity}|{details}\n"

        with open(log_file, 'a') as f:
            f.write(entry)

        print(f"{prefix} [{team}] {technique}: {details}")

    def red_team_attack(self, attack_id, target=""):
        """Ejecuta ataque red team"""

        if attack_id not in self.attack_techniques:
            print("❌ Ataque inválido")
            return False

        technique = self.attack_techniques[attack_id]

        print("\n" + "=" * 70)
        print(f"🔴 RED TEAM ATTACK")
        print("=" * 70)
        print(f"Technique:   {technique['name']}")
        print(f"MITRE ATT&CK: {technique['mitre']}")
        print(f"Description: {technique['description']}")
        print("=" * 70 + "\n")

        self.log_event("RED", technique['name'], f"Starting attack on {target or 'environment'}")

        # Simular ataque según tipo
        success = False

        if attack_id == '1':  # Reconnaissance
            success = self._attack_reconnaissance()

        elif attack_id == '2':  # Port Scan
            if not target:
                target = input("🎯 Target IP: ").strip()
            if target:
                success = self._attack_port_scan(target)

        elif attack_id == '3':  # DNS Enum
            if not target:
                target = input("🎯 Target domain: ").strip()
            if target:
                success = self._attack_dns_enum(target)

        elif attack_id == '4':  # Web Vuln Scan
            if not target:
                target = input("🎯 Target URL: ").strip()
            if target:
                success = self._attack_web_scan(target)

        elif attack_id == '5':  # Banner Grabbing
            if not target:
                target = input("🎯 Target IP:Port (ej: 192.168.1.1:80): ").strip()
            if target:
                success = self._attack_banner_grab(target)

        if success:
            self.log_event("RED", technique['name'], "Attack completed successfully")
            print("\n✅ Ataque completado - Revisa logs para análisis blue team\n")

            # Generar alerta automática para blue team
            self._generate_alert(technique['name'], target)

        else:
            self.log_event("RED", technique['name'], "Attack failed or blocked")
            print("\n❌ Ataque falló\n")

        return success

    def _attack_reconnaissance(self):
        """WiFi reconnaissance — análisis completo de redes con inteligencia de seguridad"""

        print("📡 Iniciando reconocimiento WiFi completo...\n")

        # ── 1. Obtener info de red actual (conexión activa) ────────────────────
        current_net = {}
        try:
            conn_result = subprocess.run(
                ['termux-wifi-connectioninfo'],
                capture_output=True, text=True, timeout=8
            )
            if conn_result.returncode == 0 and conn_result.stdout.strip():
                try:
                    current_net = json.loads(conn_result.stdout)
                    if isinstance(current_net, dict) and 'ssid' in current_net:
                        print(f"  📶 Red actual: {current_net.get('ssid','?')}  |  IP: {current_net.get('ip','?')}  |  MAC tablet: {current_net.get('mac_address','?')}")
                        print(f"     BSSID AP: {current_net.get('bssid','?')}  |  Señal: {current_net.get('rssi','?')} dBm  |  Velocidad: {current_net.get('link_speed_mbps','?')} Mbps\n")
                except Exception:
                    pass
        except Exception:
            pass

        # ── 2. Escanear todas las redes ───────────────────────────────────────
        try:
            result = subprocess.run(
                ['termux-wifi-scaninfo'],
                capture_output=True, text=True, timeout=15
            )
        except FileNotFoundError:
            print("❌ termux-wifi-scaninfo no encontrado")
            print("  1. pkg install termux-api")
            print("  2. Instala 'Termux:API' desde Play Store/F-Droid")
            print("  3. Ajustes Android → Apps → Termux → Permisos → Ubicación: Permitir")
            return False
        except subprocess.TimeoutExpired:
            print("⏱️  Timeout en el escaneo")
            return False

        if result.returncode != 0:
            print(f"❌ Error: {result.stderr[:200]}")
            return False

        # ── 3. Parsear JSON ───────────────────────────────────────────────────
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"❌ No se pudo parsear respuesta: {result.stdout[:150]}")
            return False

        # Gestión de errores de API
        if isinstance(data, dict) and 'API_ERROR' in data:
            err = data['API_ERROR']
            print(f"❌ API Error: {err}")
            if 'ocation' in err:
                print("  → Activa la Ubicación en Ajustes de Android")
            elif 'ermission' in err.lower():
                print("  → Ajustes → Apps → Termux → Permisos → Ubicación: Permitir")
            return False

        # Normalizar a lista
        networks = []
        if isinstance(data, list):
            networks = data
        elif isinstance(data, dict):
            for key in ['results', 'networks', 'data', 'scans']:
                if key in data and isinstance(data[key], list):
                    networks = data[key]
                    break
            if not networks and 'ssid' in data:
                networks = [data]

        if not networks:
            print("⚠️  No se detectaron redes (¿WiFi activado? ¿Permisos de ubicación?)")
            return False

        # ── 4. Analizar cada red ──────────────────────────────────────────────
        open_nets     = []
        weak_nets     = []   # WEP o sin WPA2/3
        wps_nets      = []   # WPS habilitado
        hidden_nets   = []   # SSID vacío
        strong_nets   = []   # WPA2/WPA3 bien configuradas
        duplicate_bssid = {}
        all_channels   = []

        # OUI lookup básico (primeros 6 chars del BSSID → fabricante)
        KNOWN_OUI = {
            'e8:65:d4': 'Xiaomi', 'f4:f2:6d': 'Apple', '00:50:f2': 'Microsoft',
            'b8:27:eb': 'Raspberry Pi', '00:1a:2b': 'Cisco', 'a4:c3:f0': 'Apple',
            '40:49:0f': 'Zyxel', 'c8:3a:35': 'Tenda', '14:cc:20': 'TP-Link',
            '50:c7:bf': 'TP-Link', 'b0:95:8e': 'TP-Link', 'ec:08:6b': 'TP-Link',
            '2c:3a:28': 'Huawei', 'e4:19:c1': 'Huawei', '00:26:5a': 'Netgear',
            '20:e5:2a': 'Netgear', 'a0:40:a0': 'Netgear', 'c4:04:15': 'ASUS',
            '04:d4:c4': 'ASUS', '74:d0:2b': 'ASUS', '00:11:92': 'D-Link',
            '1c:7e:e5': 'D-Link', '28:10:7b': 'D-Link', 'f8:1a:67': 'Vodafone',
            'dc:a9:04': 'Telefónica', '00:23:f8': 'Telefónica',
        }

        def get_vendor(bssid):
            if not bssid:
                return "Desconocido"
            prefix = bssid[:8].lower()
            for oui, vendor in KNOWN_OUI.items():
                if prefix.startswith(oui.lower()):
                    return vendor
            return "Desconocido"

        def parse_capabilities(caps):
            """Extrae info de seguridad del string de capabilities de Android."""
            caps = caps.upper() if caps else ""
            security = []
            if 'WPA3' in caps or 'SAE' in caps:
                security.append('WPA3')
            if 'WPA2' in caps or 'RSN' in caps:
                security.append('WPA2')
            if 'WPA' in caps and 'WPA2' not in security and 'WPA3' not in security:
                security.append('WPA')
            if 'WEP' in caps:
                security.append('WEP')
            wps = 'WPS' in caps
            hidden = False
            return security, wps, hidden

        def signal_quality(dbm):
            """Convierte dBm a calidad y distancia estimada."""
            try:
                dbm = int(dbm)
            except (ValueError, TypeError):
                return "?", "?"
            if dbm >= -50:
                return "Excelente", "~10m"
            elif dbm >= -60:
                return "Buena", "~20m"
            elif dbm >= -70:
                return "Aceptable", "~30m"
            elif dbm >= -80:
                return "Débil", "~50m"
            else:
                return "Muy débil", ">50m"

        def freq_to_channel(freq_mhz):
            """Convierte frecuencia MHz a canal WiFi."""
            try:
                freq = int(freq_mhz)
                if freq == 2412: return "1 (2.4GHz)"
                if freq == 2417: return "2 (2.4GHz)"
                if freq == 2422: return "3 (2.4GHz)"
                if freq == 2427: return "4 (2.4GHz)"
                if freq == 2432: return "5 (2.4GHz)"
                if freq == 2437: return "6 (2.4GHz)"
                if freq == 2442: return "7 (2.4GHz)"
                if freq == 2447: return "8 (2.4GHz)"
                if freq == 2452: return "9 (2.4GHz)"
                if freq == 2457: return "10 (2.4GHz)"
                if freq == 2462: return "11 (2.4GHz)"
                if freq == 5180: return "36 (5GHz)"
                if freq == 5200: return "40 (5GHz)"
                if freq == 5220: return "44 (5GHz)"
                if freq == 5240: return "48 (5GHz)"
                if freq == 5260: return "52 (5GHz)"
                if freq == 5280: return "56 (5GHz)"
                if freq == 5300: return "60 (5GHz)"
                if freq == 5320: return "64 (5GHz)"
                if 5170 <= freq <= 5330: return f"5GHz ({freq}MHz)"
                if 5490 <= freq <= 5850: return f"5GHz DFS ({freq}MHz)"
                return f"{freq}MHz"
            except Exception:
                return str(freq_mhz)

        print(f"  Redes detectadas: {len(networks)}\n")
        print(f"  {'SSID':<28} {'BSSID':<20} {'Seg.':<14} {'Canal':<14} {'Señal':<12} {'Fabricante':<15} {'Alertas'}")
        print(f"  {'─'*125}")

        for net in networks:
            if not isinstance(net, dict):
                continue

            ssid       = net.get('ssid', '') or ''
            bssid      = net.get('bssid', '') or ''
            level      = net.get('level', -100)
            frequency  = net.get('frequency', 0)
            caps_raw   = net.get('capabilities', '') or ''

            security, wps, _ = parse_capabilities(caps_raw)
            quality, dist    = signal_quality(level)
            channel          = freq_to_channel(frequency)
            vendor           = get_vendor(bssid)
            is_hidden        = (ssid.strip() == '' or ssid == '<hidden>')
            display_ssid     = '[OCULTA]' if is_hidden else ssid

            # Clasificación de seguridad
            alerts = []
            if not security:
                alert_str = "🔴 ABIERTA"
                open_nets.append(net)
                alerts.append("Sin cifrado")
            elif 'WEP' in security and 'WPA2' not in security and 'WPA3' not in security:
                alert_str = "🟡 WEP"
                weak_nets.append(net)
                alerts.append("WEP=roto en min")
            elif 'WPA' in security and 'WPA2' not in security and 'WPA3' not in security:
                alert_str = "🟡 WPA"
                weak_nets.append(net)
                alerts.append("WPA legacy")
            elif 'WPA2' in security or 'WPA3' in security:
                alert_str = "🟢 " + "+".join(security)
                strong_nets.append(net)
            else:
                alert_str = "❓ ?"
                alerts.append("Desconocido")

            if wps:
                alerts.append("WPS!")
                wps_nets.append(net)

            if is_hidden:
                alerts.append("SSID oculto")
                hidden_nets.append(net)

            # Detectar posible Evil Twin (mismo SSID, distinto BSSID)
            bssid_key = ssid.lower().strip()
            if bssid_key not in duplicate_bssid:
                duplicate_bssid[bssid_key] = []
            duplicate_bssid[bssid_key].append(bssid)

            all_channels.append(channel)

            # Señal cercana = más relevante para el análisis
            proximity_tag = f" [{dist}]" if quality in ("Excelente", "Buena") else ""

            alert_display = ", ".join(alerts) if alerts else ""
            sec_display   = alert_str[:13]
            ssid_display  = display_ssid[:27]

            print(f"  {ssid_display:<28} {bssid:<20} {sec_display:<14} {channel:<14} {level} dBm{proximity_tag:<6} {vendor:<15} {alert_display}")

        # ── 5. Detección de Evil Twin ─────────────────────────────────────────
        evil_twins = {ssid: bssids for ssid, bssids in duplicate_bssid.items()
                      if len(bssids) > 1 and ssid not in ('', '[oculta]')}

        # ── 6. Resumen de inteligencia ────────────────────────────────────────
        print(f"\n{'─'*60}")
        print("  📊 RESUMEN DE INTELIGENCIA:")
        print(f"{'─'*60}")
        print(f"  Total redes detectadas : {len(networks)}")
        print(f"  🔴 Redes ABIERTAS       : {len(open_nets)}   ← sin contraseña")
        print(f"  🟡 Cifrado DÉBIL (WEP/WPA) : {len(weak_nets)}")
        print(f"  ⚠️  Con WPS habilitado  : {len(wps_nets)}   ← bruteforceable")
        print(f"  👻 SSID ocultos         : {len(hidden_nets)}")
        print(f"  🟢 WPA2/WPA3            : {len(strong_nets)}")
        if evil_twins:
            print(f"\n  🚨 POSIBLES EVIL TWIN / ROGUE AP detectados:")
            for ssid_name, bssids in evil_twins.items():
                print(f"     '{ssid_name}' aparece con {len(bssids)} MACs distintas:")
                for b in bssids:
                    print(f"       → {b}")

        # ── 7. Hallazgos de seguridad ─────────────────────────────────────────
        if open_nets or weak_nets or wps_nets or evil_twins:
            print(f"\n{'─'*60}")
            print("  🔍 HALLAZGOS DE SEGURIDAD (argumento de venta):")
            print(f"{'─'*60}")

        if open_nets:
            print(f"\n  🔴 REDES ABIERTAS ({len(open_nets)}):")
            for net in open_nets[:3]:
                ssid = net.get('ssid') or '[sin nombre]'
                print(f"     • '{ssid}' — cualquier persona puede conectarse y capturar tráfico")
            print(f"     → RGPD Art.32: falta de medidas técnicas de seguridad")
            print(f"     → PCI DSS Req.1.3: separación de redes de pago")

        if weak_nets:
            print(f"\n  🟡 CIFRADO DÉBIL ({len(weak_nets)}):")
            for net in weak_nets[:3]:
                ssid = net.get('ssid') or '[sin nombre]'
                sec, _, _ = parse_capabilities(net.get('capabilities',''))
                print(f"     • '{ssid}' usa {'+'.join(sec) if sec else '?'} — hackeable con herramientas gratuitas")

        if wps_nets:
            print(f"\n  ⚠️  WPS HABILITADO ({len(wps_nets)}) — PIN de 8 dígitos bruteforceable en horas:")
            for net in wps_nets[:3]:
                ssid = net.get('ssid') or '[sin nombre]'
                print(f"     • '{ssid}'")

        if evil_twins:
            print(f"\n  🚨 EVIL TWIN — alguien podría estar suplantando la red del local:")
            for ssid_name in list(evil_twins.keys())[:2]:
                print(f"     • '{ssid_name}' tiene múltiples puntos de acceso con diferente MAC")

        total_findings = len(open_nets) + len(weak_nets) + len(wps_nets) + len(evil_twins)
        self.log_event("RED", "WiFi Recon",
                       f"Redes:{len(networks)} Abiertas:{len(open_nets)} WPS:{len(wps_nets)} "
                       f"EvilTwin:{len(evil_twins)} Debiles:{len(weak_nets)}")
        print()
        return True

    def _attack_port_scan(self, target):
        """Port scan con identificación de servicios, versiones y riesgos por puerto"""

        print(f"🔍 Port scan a {target}...\n")
        self.log_event("RED", "Port Scan", f"Target: {target}")

        # Servicios con implicaciones de seguridad conocidas
        RISKY_SERVICES = {
            21:   ("FTP",         "🔴 ALTO",   "Credenciales en claro, anonymous login posible"),
            22:   ("SSH",         "🟡 MEDIO",  "Verificar versión y política de contraseñas"),
            23:   ("Telnet",      "🚨 CRIT",   "Protocolo sin cifrado — sustituir por SSH"),
            25:   ("SMTP",        "🟡 MEDIO",  "Verificar open relay y auth"),
            53:   ("DNS",         "🟡 MEDIO",  "Verificar zone transfer (AXFR)"),
            80:   ("HTTP",        "🟡 MEDIO",  "Sin cifrado — redirigir a HTTPS"),
            110:  ("POP3",        "🟡 MEDIO",  "Credenciales en claro si sin TLS"),
            111:  ("RPCbind",     "🔴 ALTO",   "Puede exponer servicios NFS/NIS"),
            135:  ("RPC/DCE",     "🔴 ALTO",   "Explotable remotamente en Windows antiguo"),
            139:  ("NetBIOS",     "🔴 ALTO",   "Enumeración de recursos Windows"),
            143:  ("IMAP",        "🟡 MEDIO",  "Credenciales en claro si sin TLS"),
            161:  ("SNMP",        "🔴 ALTO",   "Community string 'public' permite info dump"),
            389:  ("LDAP",        "🔴 ALTO",   "Enumeración de directorio activo"),
            443:  ("HTTPS",       "🟢 BAJO",   "Verificar versión TLS y certificado"),
            445:  ("SMB",         "🚨 CRIT",   "EternalBlue (MS17-010), ransomware vector"),
            512:  ("rexec",       "🚨 CRIT",   "Servicio Unix legacy sin autenticación"),
            513:  ("rlogin",      "🚨 CRIT",   "Login remoto sin cifrado"),
            514:  ("rsh/syslog",  "🚨 CRIT",   "Shell remoto sin autenticación"),
            993:  ("IMAPS",       "🟢 BAJO",   "IMAP sobre TLS"),
            995:  ("POP3S",       "🟢 BAJO",   "POP3 sobre TLS"),
            1433: ("MSSQL",       "🔴 ALTO",   "Base de datos SQL Server expuesta"),
            1521: ("Oracle DB",   "🔴 ALTO",   "Base de datos Oracle expuesta"),
            2049: ("NFS",         "🔴 ALTO",   "Posible montaje de sistema de ficheros remoto"),
            3306: ("MySQL",       "🔴 ALTO",   "Base de datos MySQL expuesta a Internet"),
            3389: ("RDP",         "🚨 CRIT",   "BlueKeep (CVE-2019-0708), BlasterRDP"),
            4444: ("Metasploit",  "🚨 CRIT",   "Puerto de backdoor/C2 común"),
            5432: ("PostgreSQL",  "🔴 ALTO",   "Base de datos expuesta"),
            5900: ("VNC",         "🔴 ALTO",   "Escritorio remoto sin cifrado frecuente"),
            5985: ("WinRM",       "🔴 ALTO",   "PowerShell remoto Windows"),
            6379: ("Redis",       "🚨 CRIT",   "Redis sin auth — lectura/escritura de datos"),
            8080: ("HTTP-Alt",    "🟡 MEDIO",  "Servidor web alternativo, revisar"),
            8443: ("HTTPS-Alt",   "🟡 MEDIO",  "Admin panel frecuente"),
            27017:("MongoDB",     "🚨 CRIT",   "MongoDB sin auth — base de datos expuesta"),
        }

        open_ports_data = []

        # ── Intento 1: nmap con detección de versiones ────────────────────────
        try:
            print("  Ejecutando nmap con detección de versiones...")
            nmap_result = subprocess.run(
                ['nmap', '-sV', '--version-intensity', '5',
                 '--top-ports', '100', '--open', '-T4',
                 '--script', 'banner,http-title,ssh-hostkey',
                 target],
                capture_output=True, text=True, timeout=120
            )

            if nmap_result.returncode == 0:
                output = nmap_result.stdout
                # Parsear líneas de puertos: 22/tcp  open  ssh  OpenSSH 8.9p1
                port_lines = re.findall(
                    r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)',
                    output
                )
                for port, proto, service, version in port_lines:
                    port_int = int(port)
                    version = version.strip()
                    risk_info = RISKY_SERVICES.get(port_int, (service, "⬜ INFO", ""))
                    open_ports_data.append({
                        'port': port_int, 'proto': proto,
                        'service': risk_info[0] or service,
                        'risk': risk_info[1],
                        'version': version[:60] if version else "—",
                        'note': risk_info[2],
                    })

                # Extraer OS detection si está
                os_match = re.search(r'OS details:\s*(.+)', output)
                if os_match:
                    print(f"  🖥️  SO detectado: {os_match.group(1)[:80]}")

                # Extraer http-title si está
                titles = re.findall(r'http-title:\s*(.+)', output)
                for t in titles[:2]:
                    print(f"  🌐 HTTP Title: {t.strip()}")

                use_fallback = False
            else:
                use_fallback = True

        except FileNotFoundError:
            print("  nmap no disponible — usando socket scan...")
            use_fallback = True
        except subprocess.TimeoutExpired:
            print("  nmap timeout — usando socket scan...")
            use_fallback = True
        except Exception:
            use_fallback = True

        # ── Fallback: socket scan en puertos clave ────────────────────────────
        if use_fallback or not open_ports_data:
            import socket as _socket
            key_ports = [21,22,23,25,53,80,110,135,139,143,443,445,
                         1433,3306,3389,5432,5900,6379,8080,8443,27017]
            print(f"  Escaneando {len(key_ports)} puertos clave via socket...")
            for p in key_ports:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s.settimeout(1.5)
                try:
                    if s.connect_ex((target, p)) == 0:
                        risk_info = RISKY_SERVICES.get(p, (str(p), "⬜ INFO", ""))
                        open_ports_data.append({
                            'port': p, 'proto': 'tcp',
                            'service': risk_info[0],
                            'risk': risk_info[1],
                            'version': "—",
                            'note': risk_info[2],
                        })
                except Exception:
                    pass
                finally:
                    s.close()

        # ── Resultados ────────────────────────────────────────────────────────
        if not open_ports_data:
            print("  ℹ️  Sin puertos abiertos detectados (o host no alcanzable)")
            return False

        print(f"\n  {'Puerto':<10} {'Servicio':<14} {'Riesgo':<12} {'Versión':<35} {'Nota'}")
        print(f"  {'─'*110}")
        critical_found = []
        for p in sorted(open_ports_data, key=lambda x: x['port']):
            risk   = p['risk']
            note   = p['note'][:55] if p['note'] else ""
            ver    = p['version'][:34] if p['version'] else "—"
            port_s = f"{p['port']}/{p['proto']}"
            print(f"  {port_s:<10} {p['service']:<14} {risk:<12} {ver:<35} {note}")
            if '🚨' in risk or '🔴' in risk:
                critical_found.append(p)

        # Resumen de hallazgos críticos
        if critical_found:
            print(f"\n  🚨 HALLAZGOS CRÍTICOS/ALTOS ({len(critical_found)}):")
            for p in critical_found[:5]:
                print(f"     Puerto {p['port']} ({p['service']}): {p['note']}")

        self.log_event("RED", "Port Scan",
                       f"Target:{target} Abiertos:{len(open_ports_data)} "
                       f"Criticos:{len(critical_found)}")
        return True

    def _attack_dns_enum(self, domain):
        """DNS enumeration attack"""

        print(f"🔎 Enumerating DNS for {domain}...\n")

        self.log_event("RED", "DNS Enum", f"Target: {domain}")

        findings = []

        try:
            # A records
            result = subprocess.run(['nslookup', domain],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                ips = re.findall(r'Address: (\d+\.\d+\.\d+\.\d+)', result.stdout)
                for ip in ips:
                    if not ip.startswith('127.'):
                        findings.append(f"A: {ip}")
                        print(f"  → IP: {ip}")

            # MX records
            result = subprocess.run(['nslookup', '-type=mx', domain],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                mx_records = re.findall(r'mail exchanger = (.*)', result.stdout)
                for mx in mx_records:
                    findings.append(f"MX: {mx.strip()}")
                    print(f"  → Mail: {mx.strip()}")

            if findings:
                self.log_event("RED", "DNS Enum", f"Found {len(findings)} records")
                return True
            else:
                print("ℹ️  No significant findings")
                return False

        except Exception as e:
            print(f"❌ Error: {e}")
            return False

    def _attack_web_scan(self, url):
        """Web vulnerability scanning"""

        print(f"🌐 Scanning web security headers for {url}...\n")

        self.log_event("RED", "Web Scan", f"Target: {url}")

        try:
            import requests

            response = requests.get(url, timeout=10)
            headers = response.headers

            vulnerabilities = []

            # Check security headers
            if 'Strict-Transport-Security' not in headers:
                vulnerabilities.append("Missing HSTS")

            if 'Content-Security-Policy' not in headers:
                vulnerabilities.append("Missing CSP")

            if 'X-Frame-Options' not in headers:
                vulnerabilities.append("Clickjacking possible")

            if 'Server' in headers:
                vulnerabilities.append(f"Server disclosure: {headers['Server']}")

            if vulnerabilities:
                print("✅ Vulnerabilidades encontradas:")
                for vuln in vulnerabilities:
                    print(f"  🔴 {vuln}")

                self.log_event("RED", "Web Scan", f"Found {len(vulnerabilities)} issues")
                return True
            else:
                print("ℹ️  No significant vulnerabilities")
                return False

        except ImportError:
            print("❌ requests no instalado: pip install requests")
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False

    def _attack_banner_grab(self, target):
        """Banner grabbing attack"""

        print(f"📋 Grabbing banner from {target}...\n")

        try:
            import socket

            # Parse target:port
            if ':' in target:
                host, port = target.split(':')
                port = int(port)
            else:
                host = target
                port = 80

            self.log_event("RED", "Banner Grab", f"Target: {host}:{port}")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            result = sock.connect_ex((host, port))

            if result == 0:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore')

                if banner:
                    print("✅ Banner obtenido:")
                    print("-" * 50)
                    print(banner[:300])
                    print("-" * 50)

                    self.log_event("RED", "Banner Grab", f"Success on {host}:{port}")
                    sock.close()
                    return True

            sock.close()
            print("❌ No se pudo obtener banner")
            return False

        except Exception as e:
            print(f"❌ Error: {e}")
            return False

    def _generate_alert(self, technique, target):
        """Genera alerta para blue team (simula SIEM)"""

        alert_id = datetime.now().strftime("%Y%m%d%H%M%S")

        self.log_event("ALERT", technique, f"Suspicious activity detected on {target}", severity="HIGH")

        print(f"🚨 Alert #{alert_id} generated for blue team analysis")

    def blue_team_analyze(self):
        """Análisis blue team de logs"""

        print("\n" + "=" * 70)
        print("🔵 BLUE TEAM ANALYSIS")
        print("=" * 70 + "\n")

        if not self.red_log.exists():
            print("ℹ️  No red team logs to analyze yet")
            return

        with open(self.red_log, 'r') as f:
            red_events = f.readlines()

        print(f"📊 Total red team events: {len(red_events)}\n")

        # Análisis por técnica
        techniques = {}
        for event in red_events:
            match = re.search(r'\|(RED)\|([^|]+)\|', event)
            if match:
                technique = match.group(2)
                techniques[technique] = techniques.get(technique, 0) + 1

        print("🔍 Attack techniques detected:\n")
        for technique, count in sorted(techniques.items(), key=lambda x: x[1], reverse=True):
            print(f"  {technique:30s} {count:3d} events")

        # Generar detecciones
        print("\n" + "=" * 70)
        print("🛡️  DETECTION & RESPONSE RECOMMENDATIONS")
        print("=" * 70 + "\n")

        detections = {
            'Port Scan': [
                "Deploy IDS/IPS rules para detectar port scans (Snort/Suricata)",
                "Rate limiting en firewall",
                "Alertas en SIEM para múltiples conexiones fallidas"
            ],
            'DNS Enum': [
                "Implementar DNSSEC",
                "Monitorear queries anómalas en DNS logs",
                "Rate limiting en DNS server"
            ],
            'Web Scan': [
                "WAF con reglas anti-scanning",
                "Monitorear requests con User-Agents de scanners",
                "Implementar security headers faltantes"
            ],
            'WiFi Scan': [
                "Detectar probe requests anómalos",
                "Wireless IDS (WIDS)",
                "Segmentar redes WiFi (VLANs)"
            ],
            'Banner Grab': [
                "Ocultar/remover server banners",
                "Deploy firewall rules para conexiones sospechosas",
                "Honeypots en puertos comunes"
            ]
        }

        for technique in techniques.keys():
            if technique in detections:
                print(f"🔵 {technique}:")
                for recommendation in detections[technique]:
                    print(f"   → {recommendation}")
                print()

        # Log blue team analysis
        self.log_event("BLUE", "Analysis Complete", f"Analyzed {len(red_events)} red team events")

        # Guardar reporte
        report_file = self.output_dir / f"blue_team_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("BLUE TEAM ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Total events analyzed: {len(red_events)}\n\n")

            f.write("ATTACK TECHNIQUES DETECTED:\n")
            f.write("-" * 80 + "\n")
            for technique, count in sorted(techniques.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{technique:30s} {count:3d} events\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("DETECTION & MITIGATION RECOMMENDATIONS\n")
            f.write("=" * 80 + "\n\n")

            for technique in techniques.keys():
                if technique in detections:
                    f.write(f"\n{technique}:\n")
                    for rec in detections[technique]:
                        f.write(f"  - {rec}\n")

        print(f"\n💾 Blue team report saved: {report_file}")

    def view_logs(self):
        """Visualizar logs"""

        print("\n" + "=" * 70)
        print("📝 LOGS VIEWER")
        print("=" * 70 + "\n")

        print("1) Red Team logs")
        print("2) Blue Team logs")
        print("3) Alerts")
        print("4) All logs")

        choice = input("\nOpción: ").strip()

        logs_to_show = []

        if choice == '1' and self.red_log.exists():
            logs_to_show.append(("RED TEAM", self.red_log))
        elif choice == '2' and self.blue_log.exists():
            logs_to_show.append(("BLUE TEAM", self.blue_log))
        elif choice == '3' and self.alerts_log.exists():
            logs_to_show.append(("ALERTS", self.alerts_log))
        elif choice == '4':
            if self.red_log.exists():
                logs_to_show.append(("RED TEAM", self.red_log))
            if self.blue_log.exists():
                logs_to_show.append(("BLUE TEAM", self.blue_log))
            if self.alerts_log.exists():
                logs_to_show.append(("ALERTS", self.alerts_log))

        if not logs_to_show:
            print("\nℹ️  No logs disponibles todavía")
            return

        for log_name, log_file in logs_to_show:
            print("\n" + "=" * 70)
            print(f"{log_name} LOGS")
            print("=" * 70 + "\n")

            with open(log_file, 'r') as f:
                print(f.read())

    def run(self):
        """Interactive CLI"""

        print("=" * 70)
        print("  🟣 PURPLE TEAM SUITE - Attack & Defend")
        print("=" * 70)
        print("\n⚠️  SOLO USAR EN ENTORNOS AUTORIZADOS\n")
        print("Este framework simula ataques red team y practica detección blue team\n")

        while True:
            print("=" * 70)
            print("MODO DE OPERACIÓN:")
            print("=" * 70)
            print("\n🔴 RED TEAM (Ataque):")
            for key, tech in self.attack_techniques.items():
                print(f"  {key}) {tech['name']} - {tech['description']}")

            print("\n🔵 BLUE TEAM (Defensa):")
            print("  6) Analizar logs y generar detecciones")

            print("\n📊 UTILS:")
            print("  7) Ver logs")
            print("  8) Limpiar logs")
            print("  q) Salir")

            print("\n" + "=" * 70)

            choice = input("\nOpción: ").strip()

            if choice in self.attack_techniques:
                self.red_team_attack(choice)

            elif choice == '6':
                self.blue_team_analyze()

            elif choice == '7':
                self.view_logs()

            elif choice == '8':
                confirm = input("⚠️  Eliminar todos los logs? (y/N): ")
                if confirm.lower() == 'y':
                    for log_file in [self.red_log, self.blue_log, self.alerts_log]:
                        if log_file.exists():
                            log_file.unlink()
                    print("✅ Logs eliminados")

            elif choice.lower() in ['q', 'quit', 'exit', 'salir']:
                print("\n👋 Purple Team Suite cerrado")
                break

            else:
                print("\n❌ Opción inválida")

            print()

if __name__ == "__main__":
    suite = PurpleTeamSuite()

    try:
        suite.run()
    except KeyboardInterrupt:
        print("\n\n👋 Interrumpido por usuario")
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
