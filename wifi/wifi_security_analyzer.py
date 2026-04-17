# -*- coding: utf-8 -*-
"""
WiFi Security Analyzer for Termux
Analiza redes WiFi cercanas y detecta configuraciones inseguras

Requiere: pkg install termux-api
También: Termux:API app desde Google Play

Uso: python wifi_security_analyzer.py
"""

import subprocess
import json
from datetime import datetime
from pathlib import Path

class WiFiSecurityAnalyzer:
    def __init__(self):
        self.output_dir = self.get_output_path()

    def get_output_path(self):
        """Detecta si estamos en Termux y usa almacenamiento compartido"""
        termux_storage = Path.home() / "storage" / "shared" / "Documents" / "purple_team_reports"

        if termux_storage.parent.exists():
            termux_storage.mkdir(exist_ok=True)
            return termux_storage
        else:
            # Fallback para testing en PC
            desktop_path = Path.home() / "Documents" / "purple_team_reports"
            desktop_path.mkdir(exist_ok=True)
            return desktop_path

    def analyze_wifi(self):
        """Analiza redes WiFi cercanas y detecta vulnerabilidades"""

        print("📡 WiFi Security Analyzer")
        print("=" * 60)

        try:
            # Obtener lista de redes (requiere termux-api)
            print("🔍 Escaneando redes WiFi...\n")
            result = subprocess.run(['termux-wifi-scaninfo'],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                raise Exception("termux-wifi-scaninfo falló. ¿Instalaste termux-api?")

            # Parse JSON output
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise Exception(f"Error parsing JSON: {e}")

            # Check for API errors first
            if isinstance(data, dict) and 'API_ERROR' in data:
                error_msg = data['API_ERROR']
                print(f"\n❌ API Error: {error_msg}\n")

                # Provide specific instructions based on error
                if 'Location' in error_msg or 'location' in error_msg:
                    print("📍 SOLUCIÓN:")
                    print("  1. Abre Ajustes de Android")
                    print("  2. Ubicación → Activar ubicación")
                    print("  3. Vuelve a Termux e intenta de nuevo\n")
                elif 'permission' in error_msg.lower():
                    print("🔐 SOLUCIÓN:")
                    print("  1. Abre Ajustes de Android")
                    print("  2. Apps → Termux → Permisos")
                    print("  3. Ubicación → Permitir\n")

                raise Exception(f"API Error: {error_msg}")

            # Handle both dict and list formats
            networks_data = []

            if isinstance(data, list):
                # Format 1: Direct list of networks
                networks_data = data
            elif isinstance(data, dict):
                # Format 2: Dict with 'results' or similar key
                # Try common keys
                for key in ['results', 'networks', 'data', 'scans']:
                    if key in data and isinstance(data[key], list):
                        networks_data = data[key]
                        break

                # If no list found in dict, treat single dict as single network
                if not networks_data and 'ssid' in data:
                    networks_data = [data]
            else:
                raise Exception(f"Unexpected data type: {type(data)}")

            if len(networks_data) == 0:
                print("⚠️  No se detectaron redes WiFi")
                return

            vulnerable = []
            secure = []

            for net in networks_data:
                # Ensure each network is a dictionary
                if not isinstance(net, dict):
                    print(f"⚠️  Skipping invalid network entry: {net}")
                    continue

                ssid = net.get('ssid', 'Hidden')
                bssid = net.get('bssid', 'Unknown')
                capabilities = net.get('capabilities', '')
                frequency = net.get('frequency', 0)
                level = net.get('level', -100)

                # Detección de vulnerabilidades
                issues = []
                severity = "SECURE"

                # CRÍTICO: WEP
                if 'WEP' in capabilities:
                    issues.append("🔴 WEP encryption (CRÍTICO - crackeado en minutos)")
                    severity = "CRITICAL"

                # ALTO: WPA1
                if 'WPA-PSK' in capabilities and 'WPA2' not in capabilities:
                    issues.append("🟠 WPA1 only (VULNERABLE - deprecated)")
                    severity = "HIGH" if severity != "CRITICAL" else severity

                # MEDIO: WPS enabled
                if 'WPS' in capabilities:
                    issues.append("🟡 WPS enabled (brute-force attack possible)")
                    severity = "MEDIUM" if severity not in ["CRITICAL", "HIGH"] else severity

                # INFO: Señal muy fuerte (posible rogue AP)
                if level > -40:
                    issues.append("📶 Señal muy fuerte (posible rogue AP cercano)")

                # Default SSIDs comunes (info disclosure)
                default_ssids = [
                    'MOVISTAR', 'Vodafone', 'Orange', 'Jazztel', 'MasMovil',
                    'TP-LINK', 'NETGEAR', 'Linksys', 'ASUS', 'D-Link',
                    'Xiaomi', 'Huawei', 'ZTE'
                ]
                if any(d in ssid.upper() for d in default_ssids):
                    issues.append("⚠️  SSID por defecto detectado (info disclosure)")

                # WPA3 check (bueno)
                if 'WPA3' in capabilities:
                    issues.append("✅ WPA3 detected (modern security)")

                network_info = {
                    'ssid': ssid,
                    'bssid': bssid,
                    'security': capabilities,
                    'signal': level,
                    'frequency': frequency,
                    'channel': self.freq_to_channel(frequency),
                    'severity': severity,
                    'issues': issues
                }

                if issues and severity != "SECURE":
                    vulnerable.append(network_info)
                else:
                    secure.append(network_info)

            # Mostrar resultados
            self.display_results(networks_data, vulnerable, secure)

            # Guardar reporte
            self.save_report(networks_data, vulnerable, secure)

        except subprocess.TimeoutExpired:
            print("❌ Timeout: El escaneo tardó demasiado")
            print("Intenta de nuevo o verifica permisos de ubicación")
        except FileNotFoundError:
            print("❌ Error: termux-wifi-scaninfo no encontrado")
            print("\n📦 Instalación requerida:")
            print("  1. pkg install termux-api")
            print("  2. Instala 'Termux:API' desde Google Play/F-Droid")
            print("  3. Concede permisos de ubicación a Termux")
        except json.JSONDecodeError:
            print("❌ Error: Respuesta inválida de termux-wifi-scaninfo")
            print("Verifica que Termux:API esté instalado correctamente")
        except Exception as e:
            print(f"❌ Error inesperado: {e}")

    def freq_to_channel(self, freq):
        """Convierte frecuencia a canal WiFi"""
        if 2412 <= freq <= 2484:
            # 2.4 GHz
            return (freq - 2407) // 5
        elif 5170 <= freq <= 5825:
            # 5 GHz
            return (freq - 5000) // 5
        else:
            return "Unknown"

    def display_results(self, all_networks, vulnerable, secure):
        """Muestra resultados en consola"""

        print(f"\n✅ Total redes escaneadas: {len(all_networks)}")
        print(f"🔴 Redes vulnerables: {len(vulnerable)}")
        print(f"🔒 Redes seguras: {len(secure)}\n")

        if vulnerable:
            print("=" * 60)
            print("🔴 REDES VULNERABLES DETECTADAS")
            print("=" * 60)

            for v in sorted(vulnerable, key=lambda x: x['severity'], reverse=True):
                print(f"\nSSID: {v['ssid']}")
                print(f"BSSID: {v['bssid']}")
                print(f"Señal: {v['signal']} dBm")
                print(f"Canal: {v['channel']} ({v['frequency']} MHz)")
                print(f"Seguridad: {v['security']}")
                print(f"Severidad: {v['severity']}")
                print("Issues:")
                for issue in v['issues']:
                    print(f"  - {issue}")
                print("-" * 60)

        # Top 5 redes más fuertes
        print("\n📶 Top 5 señales más fuertes:")
        top_signals = sorted(all_networks, key=lambda x: x.get('level', -100), reverse=True)[:5]
        for net in top_signals:
            print(f"  {net.get('ssid', 'Hidden'):30s} {net.get('level', -100):4d} dBm")

    def save_report(self, all_networks, vulnerable, secure):
        """Guarda reporte detallado"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"wifi_security_report_{timestamp}.txt"

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("WiFi Security Analysis Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")

            # Summary
            f.write("SUMMARY\n")
            f.write("-" * 70 + "\n")
            f.write(f"Total networks scanned: {len(all_networks)}\n")
            f.write(f"Vulnerable networks:    {len(vulnerable)}\n")
            f.write(f"Secure networks:        {len(secure)}\n\n")

            # Vulnerable networks
            if vulnerable:
                f.write("\n" + "=" * 70 + "\n")
                f.write("VULNERABLE NETWORKS\n")
                f.write("=" * 70 + "\n\n")

                for v in sorted(vulnerable, key=lambda x: x['severity'], reverse=True):
                    f.write(f"SSID:      {v['ssid']}\n")
                    f.write(f"BSSID:     {v['bssid']}\n")
                    f.write(f"Signal:    {v['signal']} dBm\n")
                    f.write(f"Channel:   {v['channel']} ({v['frequency']} MHz)\n")
                    f.write(f"Security:  {v['security']}\n")
                    f.write(f"Severity:  {v['severity']}\n")
                    f.write("Issues:\n")
                    for issue in v['issues']:
                        f.write(f"  - {issue}\n")
                    f.write("\n" + "-" * 70 + "\n\n")

            # Recommendations
            f.write("\n" + "=" * 70 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("=" * 70 + "\n\n")

            if any('WEP' in v['security'] for v in vulnerable):
                f.write("🔴 CRÍTICO - WEP detected:\n")
                f.write("  → Migrar inmediatamente a WPA2/WPA3\n")
                f.write("  → WEP se crackea en <5 minutos con aircrack-ng\n\n")

            if any('WPS' in v['security'] for v in vulnerable):
                f.write("🟡 WPS enabled:\n")
                f.write("  → Deshabilitar WPS en router\n")
                f.write("  → Vulnerable a Reaver/Bully attacks\n\n")

            f.write("✅ Best practices:\n")
            f.write("  → Usar WPA3 si disponible, sino WPA2-AES\n")
            f.write("  → Contraseña >15 caracteres aleatorios\n")
            f.write("  → Deshabilitar WPS\n")
            f.write("  → Cambiar SSID por defecto\n")
            f.write("  → Actualizar firmware del router regularmente\n")

        print(f"\n💾 Reporte guardado: {report_file}")

if __name__ == "__main__":
    analyzer = WiFiSecurityAnalyzer()

    try:
        analyzer.analyze_wifi()
    except KeyboardInterrupt:
        print("\n\n👋 Interrumpido por usuario")
    except Exception as e:
        print(f"\n❌ Error: {e}")
