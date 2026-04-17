# -*- coding: utf-8 -*-
"""
Network Reconnaissance Tool for Termux
Escaneo y enumeración de red para purple team

Requiere: pkg install nmap dnsutils iproute2 termux-api

Uso: python network_recon.py
"""

import subprocess
import re
import json
from datetime import datetime
from pathlib import Path
import socket

class NetworkRecon:
    def __init__(self):
        self.output_dir = self.get_output_path()
        self.log_file = self.output_dir / f"recon_log_{datetime.now().strftime('%Y%m%d')}.txt"

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

    def log_action(self, action, details=""):
        """Registra acciones para blue team analysis"""
        # Ensure output directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [RED_TEAM] {action}: {details}\n"

        with open(self.log_file, 'a') as f:
            f.write(entry)

        print(f"📝 Logged: {action}")

    def get_network_info(self):
        """Obtiene información de la red actual"""

        print("=" * 70)
        print("📱 NETWORK INFORMATION")
        print("=" * 70 + "\n")

        try:
            # Intentar con termux-api primero
            result = subprocess.run(['termux-wifi-connectioninfo'],
                                  capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                info = json.loads(result.stdout)
                ssid = info.get('ssid', 'Unknown')
                bssid = info.get('bssid', 'Unknown')
                ip = info.get('ip', 'Unknown')

                print(f"SSID:  {ssid}")
                print(f"BSSID: {bssid}")
                print(f"IP:    {ip}")

                self.log_action("NETWORK_INFO", f"Connected to {ssid}")

                return {'ssid': ssid, 'bssid': bssid, 'ip': ip}

        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass

        # Fallback: usar ip command
        try:
            result = subprocess.run(['ip', 'addr', 'show'],
                                  capture_output=True, text=True)

            if result.returncode == 0:
                # Buscar IP local
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/\d+ ', result.stdout)
                if ip_match:
                    local_ip = ip_match.group(1)
                    if not local_ip.startswith('127.'):
                        print(f"Local IP: {local_ip}")
                        return {'ip': local_ip}

        except Exception:
            pass

        print("⚠️  No se pudo obtener info de red")
        return {}

    def dns_enumeration(self, domain):
        """Enumeración DNS de dominio objetivo"""

        print("\n" + "=" * 70)
        print("🔎 DNS ENUMERATION")
        print("=" * 70 + "\n")
        print(f"Target domain: {domain}\n")

        self.log_action("DNS_ENUM", domain)

        findings = []

        # A records
        print("📍 A Records (IPv4):")
        try:
            result = subprocess.run(['nslookup', domain],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                # Extraer IPs
                ips = re.findall(r'Address: (\d+\.\d+\.\d+\.\d+)', result.stdout)
                for ip in ips:
                    if not ip.startswith('127.'):
                        print(f"  → {ip}")
                        findings.append(('A', ip))
            else:
                print("  ❌ No A records encontrados")

        except Exception as e:
            print(f"  ❌ Error: {e}")

        # MX records (mail servers)
        print("\n📧 MX Records (Mail Servers):")
        try:
            result = subprocess.run(['nslookup', '-type=mx', domain],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                mx_records = re.findall(r'mail exchanger = (.*)', result.stdout)
                if mx_records:
                    for mx in mx_records:
                        print(f"  → {mx.strip()}")
                        findings.append(('MX', mx.strip()))
                else:
                    print("  ℹ️  No MX records")

        except Exception as e:
            print(f"  ❌ Error: {e}")

        # TXT records (SPF, DKIM, DMARC)
        print("\n📝 TXT Records (SPF/DKIM/DMARC):")
        try:
            result = subprocess.run(['nslookup', '-type=txt', domain],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                txt_records = re.findall(r'"([^"]+)"', result.stdout)
                if txt_records:
                    for txt in txt_records:
                        if 'spf' in txt.lower() or 'dmarc' in txt.lower() or 'dkim' in txt.lower():
                            print(f"  → {txt[:60]}...")
                            findings.append(('TXT', txt))
                else:
                    print("  ℹ️  No TXT records relevantes")

        except Exception as e:
            print(f"  ❌ Error: {e}")

        # Guardar findings
        if findings:
            report_file = self.output_dir / f"dns_enum_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

            with open(report_file, 'w') as f:
                f.write(f"DNS Enumeration Report - {domain}\n")
                f.write(f"Generated: {datetime.now()}\n")
                f.write("=" * 70 + "\n\n")

                for record_type, value in findings:
                    f.write(f"[{record_type}] {value}\n")

            print(f"\n💾 DNS report saved: {report_file}")

        print()

    def port_scan(self, target):
        """Port scanning con nmap"""

        print("\n" + "=" * 70)
        print("🔍 PORT SCANNING")
        print("=" * 70 + "\n")
        print(f"Target: {target}\n")

        self.log_action("PORT_SCAN", target)

        # Verificar si nmap está instalado
        try:
            subprocess.run(['nmap', '--version'],
                         capture_output=True, timeout=5)
        except FileNotFoundError:
            print("❌ nmap no instalado")
            print("📦 Instala con: pkg install nmap\n")
            return

        print("🔎 Scanning common ports (top 100)...\n")
        print("⏱️  Esto puede tardar 1-2 minutos...\n")

        try:
            # Nmap scan: top 100 puertos, solo abiertos
            result = subprocess.run(
                ['nmap', '-F', '--open', '-T4', target],
                capture_output=True, text=True, timeout=120
            )

            if result.returncode == 0:
                output = result.stdout

                # Extraer puertos abiertos
                open_ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', output)

                if open_ports:
                    print("🔓 Puertos abiertos detectados:\n")
                    print(f"{'PORT':<10} {'SERVICE':<20} {'RISK'}")
                    print("-" * 50)

                    for port, service in open_ports:
                        # Risk assessment básico
                        high_risk_ports = ['21', '23', '445', '3389', '1433', '3306']
                        medium_risk_ports = ['22', '80', '443', '8080']

                        if port in high_risk_ports:
                            risk = "🔴 HIGH"
                        elif port in medium_risk_ports:
                            risk = "🟡 MEDIUM"
                        else:
                            risk = "🟢 LOW"

                        print(f"{port:<10} {service:<20} {risk}")

                    # Guardar reporte
                    report_file = self.output_dir / f"port_scan_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

                    with open(report_file, 'w') as f:
                        f.write(output)

                    print(f"\n💾 Scan guardado: {report_file}")

                else:
                    print("ℹ️  No se detectaron puertos abiertos (o host filtrado)")

            else:
                print(f"❌ Error en nmap: {result.stderr}")

        except subprocess.TimeoutExpired:
            print("⏱️  TIMEOUT: Scan tardó demasiado")
        except Exception as e:
            print(f"❌ Error: {e}")

        print()

    def service_enumeration(self, target, port):
        """Enumeración de servicio en puerto específico"""

        print(f"\n🔍 Service Enumeration: {target}:{port}\n")

        self.log_action("SERVICE_ENUM", f"{target}:{port}")

        try:
            # Intentar conexión básica
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            result = sock.connect_ex((target, port))

            if result == 0:
                print(f"✅ Puerto {port} accesible")

                # Intentar banner grab
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')

                    if banner:
                        print(f"\n📋 Banner:")
                        print("-" * 50)
                        print(banner[:500])
                        print("-" * 50)

                except Exception:
                    print("⚠️  No se pudo obtener banner")

            else:
                print(f"❌ Puerto {port} cerrado/filtrado")

            sock.close()

        except socket.timeout:
            print("⏱️  Timeout al conectar")
        except Exception as e:
            print(f"❌ Error: {e}")

        print()

    def run(self):
        """Interactive CLI"""

        print("=" * 70)
        print("  🔍 Network Reconnaissance - Purple Team Edition")
        print("=" * 70)
        print("\n⚠️  SOLO USAR EN REDES AUTORIZADAS\n")

        while True:
            print("=" * 70)
            print("OPCIONES:")
            print("  1) Network info (WiFi actual)")
            print("  2) DNS enumeration")
            print("  3) Port scan (nmap)")
            print("  4) Service enumeration")
            print("  5) Ver logs")
            print("  q) Salir")
            print("=" * 70)

            choice = input("\nOpción: ").strip()

            if choice == '1':
                self.get_network_info()

            elif choice == '2':
                domain = input("\n🎯 Dominio objetivo (ej: example.com): ").strip()
                if domain:
                    self.dns_enumeration(domain)

            elif choice == '3':
                target = input("\n🎯 IP objetivo (ej: 192.168.1.1): ").strip()
                if target:
                    confirm = input(f"\n⚠️  Escanear {target}? Esto puede ser detectado. (y/N): ")
                    if confirm.lower() == 'y':
                        self.port_scan(target)

            elif choice == '4':
                target = input("\n🎯 IP objetivo: ").strip()
                port_input = input("🎯 Puerto (ej: 80): ").strip()

                if target and port_input:
                    try:
                        port = int(port_input)
                        self.service_enumeration(target, port)
                    except ValueError:
                        print("❌ Puerto inválido")

            elif choice == '5':
                if self.log_file.exists():
                    with open(self.log_file, 'r') as f:
                        print("\n" + "=" * 70)
                        print("📝 LOGS RECIENTES")
                        print("=" * 70 + "\n")
                        print(f.read())
                else:
                    print("\n📝 No hay logs todavía")

            elif choice.lower() in ['q', 'quit', 'exit', 'salir']:
                print("\n👋 Hasta luego!")
                break

            else:
                print("\n❌ Opción inválida")

            print()

if __name__ == "__main__":
    recon = NetworkRecon()

    try:
        recon.run()
    except KeyboardInterrupt:
        print("\n\n👋 Interrumpido por usuario")
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
