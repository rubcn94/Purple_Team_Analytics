# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║       PURPLE TEAM SUITE - BLUETOOTH SECURITY AUDITOR         ║
║       Descubrimiento · Vulnerabilidades · Demo Clientes      ║
║                                                              ║
║  Módulo de auditoría de seguridad Bluetooth:                 ║
║  Detecta dispositivos visibles, evalúa riesgos de            ║
║  exposición y genera informe para presentar al cliente.      ║
║                                                              ║
║  AVISO LEGAL: Solo usar en entornos con autorización         ║
║  expresa del propietario. Auditoría autorizada únicamente.   ║
║                                                              ║
║  Uso:                                                        ║
║    python bluetooth/bluetooth_security.py                    ║
║    python bluetooth/bluetooth_security.py --mode demo        ║
║    python bluetooth/bluetooth_security.py --mode full --duration 60 ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import os
import json
import time
import argparse
import subprocess
import re
from datetime import datetime
from pathlib import Path

# ── Colores ───────────────────────────────────────────────────────────────────
class C:
    PURPLE = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN  = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    BOLD   = '\033[1m';  DIM = '\033[2m'; END = '\033[0m'

def ok(m):    print(f"{C.GREEN}  ✅  {m}{C.END}")
def warn(m):  print(f"{C.YELLOW}  ⚠️   {m}{C.END}")
def crit(m):  print(f"{C.RED}  🚨  {m}{C.END}")
def info(m):  print(f"{C.CYAN}  ℹ️   {m}{C.END}")
def found(m): print(f"{C.BLUE}  📡  {m}{C.END}")
def hdr(m):   print(f"\n{C.BLUE}{C.BOLD}  ╔══ {m} ══╗{C.END}\n")

BANNER = f"""
{C.BLUE}{C.BOLD}
  ╔══════════════════════════════════════════════════╗
  ║   📡  PURPLE TEAM — BLUETOOTH SECURITY           ║
  ║        Auditoría de Seguridad Bluetooth           ║
  ╚══════════════════════════════════════════════════╝
{C.END}"""

LEGAL_WARNING = f"""
  {C.YELLOW}{C.BOLD}⚠️  AVISO LEGAL IMPORTANTE:{C.END}
  {C.YELLOW}Esta herramienta realiza análisis pasivo de señales Bluetooth públicas.
  Solo detecta dispositivos que VOLUNTARIAMENTE se anuncian en modo visible.
  Usar únicamente en entornos con autorización escrita del propietario.
  El uso no autorizado puede ser ilegal según la Ley 9/2014 General de Telecomunicaciones.{C.END}
"""

# ─── Clasificación de tipos de dispositivo ───────────────────────────────────
DEVICE_CLASSES = {
    # Major class codes (simplificado)
    "computer":    {"icon": "💻", "risk": "medium", "desc": "Ordenador/portátil"},
    "phone":       {"icon": "📱", "risk": "medium", "desc": "Teléfono móvil"},
    "headset":     {"icon": "🎧", "risk": "low",    "desc": "Auriculares/headset"},
    "audio":       {"icon": "🔊", "risk": "low",    "desc": "Dispositivo de audio"},
    "printer":     {"icon": "🖨️", "risk": "high",   "desc": "Impresora — puede exponer documentos"},
    "camera":      {"icon": "📷", "risk": "high",   "desc": "Cámara Bluetooth — revisar privacidad"},
    "watch":       {"icon": "⌚", "risk": "medium", "desc": "Smartwatch — puede exponer datos de salud"},
    "fitness":     {"icon": "💪", "risk": "medium", "desc": "Tracker fitness — datos de salud/ubicación"},
    "keyboard":    {"icon": "⌨️", "risk": "high",   "desc": "Teclado — riesgo de keystroke injection"},
    "mouse":       {"icon": "🖱️", "risk": "medium", "desc": "Ratón Bluetooth"},
    "medical":     {"icon": "🏥", "risk": "critical","desc": "Dispositivo médico — CRÍTICO"},
    "lock":        {"icon": "🔒", "risk": "critical","desc": "Cerradura inteligente — CRÍTICO"},
    "car":         {"icon": "🚗", "risk": "high",   "desc": "Sistema de vehículo"},
    "unknown":     {"icon": "❓", "risk": "medium", "desc": "Tipo desconocido"},
}

# ─── Vulnerabilidades conocidas de Bluetooth ─────────────────────────────────
BT_VULNERABILITIES = {
    "BLUEBORNE": {
        "cve": "CVE-2017-1000250",
        "name": "BlueBorne",
        "severity": "critical",
        "description": "Familia de vulnerabilidades que permite ejecución remota de código sin emparejamiento",
        "affected": "Android < 8.0, Linux kernel < 4.14, Windows Vista-10 sin parche",
        "mitigation": "Actualizar sistema operativo. Deshabilitar Bluetooth cuando no se use."
    },
    "BLUESMITH": {
        "cve": "CVE-2021-28139",
        "name": "BlueSMith",
        "severity": "high",
        "description": "Ejecución de código arbitrario en ESP32 vía Bluetooth",
        "affected": "Dispositivos IoT con ESP32",
        "mitigation": "Actualizar firmware ESP32"
    },
    "BLUROOTKIT": {
        "cve": "CVE-2020-0022",
        "name": "BlueFrag",
        "severity": "critical",
        "description": "Ejecución de código remota en Android 8.0/8.1 vía Bluetooth",
        "affected": "Android 8.0 y 8.1",
        "mitigation": "Actualizar a Android 9+ o aplicar parche de seguridad Feb 2020"
    },
    "BRAKTOOTH": {
        "cve": "CVE-2021-28135",
        "name": "BrakTooth",
        "severity": "high",
        "description": "Familia de vulnerabilidades DoS y ejecución de código en Bluetooth Classic",
        "affected": "Chipsets: Intel, Qualcomm, Texas Instruments, Infineon",
        "mitigation": "Actualizar firmware del chipset Bluetooth"
    },
    "BISC": {
        "cve": "Multiple",
        "name": "Bluetooth Impersonation Attacks (BIAS)",
        "severity": "high",
        "description": "Permite suplantar dispositivos Bluetooth previamente emparejados",
        "affected": "Bluetooth BR/EDR (Classic) — ampliamente afectado",
        "mitigation": "Actualizar dispositivos con soporte a Secure Authentication"
    },
    "DEFAULT_PIN": {
        "cve": "N/A",
        "name": "PIN de emparejamiento por defecto",
        "severity": "medium",
        "description": "Dispositivos con PIN 0000 o 1234 pueden ser emparejados sin consentimiento",
        "affected": "Dispositivos Bluetooth legacy sin SSP (Secure Simple Pairing)",
        "mitigation": "Cambiar PIN de fábrica. Actualizar a dispositivos con SSP."
    },
}

# ─── Argumentos de venta para clientes ───────────────────────────────────────
SALES_ARGUMENTS = {
    "critical": "🚨 RIESGO INMEDIATO: Este dispositivo expone datos críticos del negocio o puede ser controlado remotamente.",
    "high": "🔴 RIESGO ALTO: Un atacante en la zona podría acceder a información sensible o interrumpir operaciones.",
    "medium": "🟡 RIESGO MEDIO: Información personal de empleados o clientes accesible para dispositivos cercanos.",
    "low": "🟢 RIESGO BAJO: Exposición mínima, pero sigue siendo buena práctica reducir la superficie de ataque.",
}


class BluetoothSecurityAuditor:
    def __init__(self, duration=30, mode="full"):
        self.duration = duration
        self.mode = mode
        self.devices = []
        self.vulnerabilities = []
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "mode": mode,
            "scan_duration": duration,
            "devices_found": [],
            "vulnerabilities": [],
            "risk_level": "unknown",
            "defense_score": 0,
            "demo_report": [],
        }
        self.bt_available = self._check_bluetooth()

    def _check_bluetooth(self):
        """Verifica si Bluetooth está disponible."""
        # Método 1: bluetoothctl
        try:
            result = subprocess.run(
                ["bluetoothctl", "show"],
                capture_output=True, text=True, timeout=5
            )
            if "Controller" in result.stdout:
                return "bluetoothctl"
        except Exception:
            pass

        # Método 2: hciconfig (Linux clásico)
        try:
            result = subprocess.run(
                ["hciconfig"],
                capture_output=True, text=True, timeout=5
            )
            if "hci" in result.stdout:
                return "hciconfig"
        except Exception:
            pass

        # Método 3: Python bluetooth
        try:
            import bluetooth
            return "pybluetooth"
        except ImportError:
            pass

        # Método 4: Termux-specific
        try:
            result = subprocess.run(
                ["termux-bluetooth-scanresult"],
                capture_output=True, text=True, timeout=5
            )
            return "termux"
        except Exception:
            pass

        return None

    def _run_cmd(self, cmd, timeout=30):
        """Ejecuta comando de forma segura."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout
            )
            return result.stdout.strip()
        except Exception:
            return ""

    # ──────────────────────────────────────────────────────────────────────────
    def scan_devices(self):
        """Escanea dispositivos Bluetooth visibles en el entorno."""
        hdr("📡 ESCANEO DE DISPOSITIVOS BLUETOOTH")
        print(LEGAL_WARNING)

        if not self.bt_available:
            warn("Bluetooth no disponible en este sistema")
            info("Para usar este módulo necesitas:")
            print(f"  {C.DIM}  • En Linux/Kali: sudo apt install bluetooth bluez{C.END}")
            print(f"  {C.DIM}  • En Termux: pkg install termux-api && termux-bluetooth-enable{C.END}")
            print(f"  {C.DIM}  • Permisos: sudo rfkill unblock bluetooth{C.END}")
            return self._demo_scan()

        info(f"Escaneando dispositivos Bluetooth durante {self.duration}s...")
        info(f"Método de escaneo: {self.bt_available}")
        print()

        devices = []

        if self.bt_available == "bluetoothctl":
            devices = self._scan_bluetoothctl()
        elif self.bt_available == "hciconfig":
            devices = self._scan_hcitool()
        elif self.bt_available == "pybluetooth":
            devices = self._scan_pybluetooth()
        elif self.bt_available == "termux":
            devices = self._scan_termux()

        if not devices:
            info("No se encontraron dispositivos en modo visible")
            info("Esto puede significar que los dispositivos tienen el Bluetooth oculto (buena práctica)")

        self.devices = devices
        self.results["devices_found"] = devices
        return devices

    def _scan_bluetoothctl(self):
        """Escanea con bluetoothctl."""
        devices = []
        # Iniciar scan
        scan_proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        commands = f"scan on\n"
        try:
            scan_proc.stdin.write(commands)
            scan_proc.stdin.flush()
            time.sleep(min(self.duration, 15))
            scan_proc.stdin.write("scan off\ndevices\nquit\n")
            scan_proc.stdin.flush()
            output, _ = scan_proc.communicate(timeout=5)
        except Exception:
            output = ""
            try:
                scan_proc.terminate()
            except Exception:
                pass

        # Parsear dispositivos
        for line in output.splitlines():
            match = re.search(r'Device\s+([0-9A-F:]{17})\s+(.+)', line, re.IGNORECASE)
            if match:
                mac = match.group(1).strip()
                name = match.group(2).strip()
                device = self._classify_device(mac, name)
                devices.append(device)
                self._print_device(device)

        return devices

    def _scan_hcitool(self):
        """Escanea con hcitool (legacy)."""
        devices = []
        output = self._run_cmd("timeout 15 hcitool scan 2>/dev/null", timeout=20)
        for line in output.splitlines():
            match = re.search(r'([0-9A-F:]{17})\s+(.+)', line, re.IGNORECASE)
            if match:
                mac = match.group(1).strip()
                name = match.group(2).strip()
                device = self._classify_device(mac, name)
                devices.append(device)
                self._print_device(device)

        # También BLE
        ble_out = self._run_cmd("timeout 10 hcitool lescan 2>/dev/null", timeout=15)
        for line in ble_out.splitlines():
            match = re.search(r'([0-9A-F:]{17})\s+(.+)', line, re.IGNORECASE)
            if match and match.group(1) not in [d['mac'] for d in devices]:
                mac = match.group(1).strip()
                name = match.group(2).strip()
                device = self._classify_device(mac, name, ble=True)
                devices.append(device)
                self._print_device(device)

        return devices

    def _scan_pybluetooth(self):
        """Escanea con python-bluetooth."""
        devices = []
        try:
            import bluetooth
            nearby = bluetooth.discover_devices(
                duration=min(self.duration, 15),
                lookup_names=True,
                flush_cache=True,
                lookup_class=True
            )
            for addr, name, device_class in nearby:
                device = self._classify_device(addr, name or "Unknown", device_class=device_class)
                devices.append(device)
                self._print_device(device)
        except Exception as e:
            warn(f"Error en escaneo python-bluetooth: {e}")
        return devices

    def _scan_termux(self):
        """Escanea con Termux API."""
        devices = []
        output = self._run_cmd("termux-bluetooth-scanresult 2>/dev/null", timeout=20)
        if output:
            try:
                bt_results = json.loads(output)
                for item in bt_results:
                    addr = item.get("address", "")
                    name = item.get("name", "Unknown")
                    device = self._classify_device(addr, name)
                    devices.append(device)
                    self._print_device(device)
            except json.JSONDecodeError:
                for line in output.splitlines():
                    if ":" in line and len(line) >= 17:
                        parts = line.split()
                        if parts:
                            mac = parts[0] if len(parts[0]) == 17 else ""
                            name = " ".join(parts[1:]) if len(parts) > 1 else "Unknown"
                            if mac:
                                device = self._classify_device(mac, name)
                                devices.append(device)
                                self._print_device(device)
        return devices

    def _demo_scan(self):
        """Modo demo — simula dispositivos encontrados para presentaciones a clientes."""
        info("Modo DEMO activado — simulando dispositivos típicos de un gimnasio/local")
        print()
        demo_devices = [
            {"mac": "AA:BB:CC:11:22:33", "name": "iPhone de Juan", "type": "phone",
             "risk": "medium", "protocol": "BLE", "rssi": -55, "visible": True},
            {"mac": "AA:BB:CC:44:55:66", "name": "Galaxy Watch Active", "type": "watch",
             "risk": "medium", "protocol": "BLE", "rssi": -62, "visible": True},
            {"mac": "AA:BB:CC:77:88:99", "name": "JBL Flip 5", "type": "audio",
             "risk": "low", "protocol": "BT Classic", "rssi": -70, "visible": True},
            {"mac": "AA:BB:CC:AA:BB:CC", "name": "HP LaserJet M404", "type": "printer",
             "risk": "high", "protocol": "BT Classic", "rssi": -45, "visible": True,
             "notes": "Impresora corporativa visible — puede exponer documentos en cola"},
            {"mac": "AA:BB:CC:DD:EE:FF", "name": "Polar H10", "type": "fitness",
             "risk": "medium", "protocol": "BLE", "rssi": -68, "visible": True,
             "notes": "Monitor de frecuencia cardíaca — datos de salud de clientes"},
            {"mac": "11:22:33:44:55:66", "name": "Xiaomi Mi Band 7", "type": "fitness",
             "risk": "medium", "protocol": "BLE", "rssi": -72, "visible": True},
            {"mac": "11:22:33:77:88:99", "name": "Keyboard BT-500", "type": "keyboard",
             "risk": "high", "protocol": "BT Classic", "rssi": -50, "visible": True,
             "notes": "Teclado Bluetooth — vulnerable a MouseJack/KeySweeper injection"},
            {"mac": "DE:AD:BE:EF:00:01", "name": "Smart Lock Pro", "type": "lock",
             "risk": "critical", "protocol": "BLE", "rssi": -40, "visible": True,
             "notes": "¡CERRADURA INTELIGENTE VISIBLE! Posible acceso físico no autorizado"},
        ]

        for device in demo_devices:
            self._print_device(device)

        self.devices = demo_devices
        self.results["devices_found"] = demo_devices
        self.results["demo_mode"] = True
        return demo_devices

    def _classify_device(self, mac, name, device_class=None, ble=False):
        """Clasifica un dispositivo por nombre y características."""
        name_lower = name.lower()
        device_type = "unknown"

        # Clasificación por nombre
        type_keywords = {
            "phone":    ["iphone", "galaxy", "pixel", "oneplus", "xiaomi", "huawei", "phone", "móvil"],
            "watch":    ["watch", "band", "gear", "fenix", "vivoactive", "forerunner"],
            "fitness":  ["polar", "garmin", "fitbit", "heartrate", "h10", "h7", "chest"],
            "headset":  ["airpods", "buds", "headset", "earphone", "jabra", "plantronics", "bose"],
            "audio":    ["jbl", "speaker", "soundbar", "bose", "sony", "audio", "sonos"],
            "printer":  ["printer", "hp", "canon", "epson", "brother", "impresora", "laserjet"],
            "keyboard": ["keyboard", "teclado", "kb", "keys"],
            "mouse":    ["mouse", "ratón", "trackpad", "mx"],
            "car":      ["car", "vehicle", "auto", "obd"],
            "lock":     ["lock", "cerradura", "smart lock", "nuki", "yale"],
            "computer": ["mac", "laptop", "pc", "desktop", "thinkpad", "dell", "hp"],
            "camera":   ["camera", "cam", "gopro", "ricoh"],
        }

        for dev_type, keywords in type_keywords.items():
            if any(kw in name_lower for kw in keywords):
                device_type = dev_type
                break

        # Si tenemos device_class (bluetooth class of device)
        if device_class:
            major = (device_class >> 8) & 0x1F
            major_map = {
                1: "computer", 2: "phone", 3: "network", 4: "audio",
                5: "peripheral", 6: "imaging", 7: "wearable", 8: "toy",
                9: "medical"
            }
            if major in major_map and device_type == "unknown":
                device_type = major_map[major]

        type_info = DEVICE_CLASSES.get(device_type, DEVICE_CLASSES["unknown"])
        return {
            "mac": mac,
            "name": name,
            "type": device_type,
            "icon": type_info["icon"],
            "risk": type_info["risk"],
            "desc": type_info["desc"],
            "protocol": "BLE" if ble else "BT Classic",
            "visible": True,
            "timestamp": datetime.now().isoformat(),
        }

    def _print_device(self, device):
        """Imprime info del dispositivo en terminal."""
        risk = device.get("risk", "unknown")
        colors = {"critical": C.RED, "high": C.RED, "medium": C.YELLOW, "low": C.GREEN}
        color = colors.get(risk, C.CYAN)
        icon = device.get("icon", "📡")
        name = device.get("name", "Unknown")
        mac = device.get("mac", "??:??:??:??:??:??")
        protocol = device.get("protocol", "BT")
        notes = device.get("notes", "")

        print(f"  {icon}  {color}{C.BOLD}{name}{C.END}  {C.DIM}{mac}{C.END}  [{protocol}]  {color}[{risk.upper()}]{C.END}")
        if notes:
            print(f"       {C.DIM}↳ {notes}{C.END}")

    # ──────────────────────────────────────────────────────────────────────────
    def analyze_vulnerabilities(self):
        """Analiza vulnerabilidades basándose en dispositivos encontrados."""
        hdr("🔍 ANÁLISIS DE VULNERABILIDADES BLUETOOTH")
        vulns = []

        if not self.devices:
            info("Sin dispositivos para analizar")
            return []

        # Estadísticas
        risk_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for d in self.devices:
            r = d.get("risk", "low")
            risk_count[r] = risk_count.get(r, 0) + 1

        info(f"Dispositivos detectados: {len(self.devices)}")
        info(f"Distribución de riesgo: 🚨{risk_count['critical']} críticos | 🔴{risk_count['high']} altos | 🟡{risk_count['medium']} medios | 🟢{risk_count['low']} bajos")
        print()

        # Vulnerabilidades estructurales del entorno
        phone_count = sum(1 for d in self.devices if d.get("type") == "phone")
        printer_found = any(d.get("type") == "printer" for d in self.devices)
        lock_found = any(d.get("type") == "lock" for d in self.devices)
        keyboard_found = any(d.get("type") == "keyboard" for d in self.devices)
        fitness_count = sum(1 for d in self.devices if d.get("type") == "fitness")

        if phone_count > 3:
            warn(f"{phone_count} móviles de clientes/empleados visibles en Bluetooth")
            info("Los datos de estos dispositivos (historial de conexiones, MAC address) pueden")
            info("usarse para tracking de personas sin su consentimiento — implicaciones RGPD")
            vulns.append({
                "type": "device_tracking",
                "severity": "medium",
                "detail": f"{phone_count} móviles con Bluetooth visible en el entorno",
                "rgpd_risk": "Tracking de personas por MAC Bluetooth — dato personal según RGPD",
                "remediation": "Informar a clientes. Deshabilitar Bluetooth en zonas de atención al cliente."
            })

        if printer_found:
            crit("Impresora Bluetooth corporativa visible desde exterior")
            info("Un atacante en zona WiFi podría enviar trabajos de impresión sin autenticación")
            vulns.append({
                "type": "exposed_printer",
                "severity": "high",
                "detail": "Impresora corporativa en modo discoverable",
                "attack": "Bluejacking de documentos, interceptación de cola de impresión",
                "remediation": "Deshabilitar Bluetooth en impresoras o configurar modo 'no discoverable'"
            })

        if lock_found:
            crit("¡CERRADURA INTELIGENTE Bluetooth EXPUESTA!")
            crit("Un atacante podría analizar el protocolo de comunicación para intentar acceso físico")
            vulns.append({
                "type": "smart_lock_exposed",
                "severity": "critical",
                "detail": "Smart lock BLE en modo discoverable",
                "attack": "Replay attack, fuzzing del protocolo BLE, clonación de señal",
                "remediation": "Actualizar firmware. Configurar modo 'not connectable'. Revisar logs de acceso."
            })

        if keyboard_found:
            warn("Teclado Bluetooth en modo visible — riesgo de KeySweeper/MouseJack")
            vulns.append({
                "type": "keyboard_injection",
                "severity": "high",
                "detail": "Teclado BT visible — potencial inyección de keystrokes",
                "attack": "KeySweeper (Microsoft BT keyboards), MouseJack, Keystroke injection",
                "remediation": "Usar teclados con cifrado AES. Cambiar a conexión con cable para equipos críticos."
            })

        if fitness_count > 0:
            info(f"{fitness_count} dispositivos fitness (datos de salud) visibles")
            vulns.append({
                "type": "health_data_exposure",
                "severity": "medium",
                "detail": f"{fitness_count} wearables/fitness trackers en modo discoverable",
                "rgpd_risk": "Datos biométricos son categoría especial RGPD (Art. 9) — protección reforzada",
                "remediation": "Informar a clientes/empleados sobre privacidad de wearables"
            })

        # Añadir CVEs relevantes
        info("\nVulnerabilidades conocidas relevantes para este entorno:")
        for cve_name, cve_data in list(BT_VULNERABILITIES.items())[:4]:
            sev = cve_data["severity"]
            icon = "🚨" if sev == "critical" else ("🔴" if sev == "high" else "🟡")
            print(f"  {icon}  {C.BOLD}{cve_data['name']}{C.END} ({cve_data['cve']})")
            print(f"       {C.DIM}↳ {cve_data['description'][:80]}...{C.END}")
            print(f"       {C.DIM}↳ Mitigación: {cve_data['mitigation']}{C.END}")
            vulns.append({
                "type": "known_cve",
                "name": cve_data["name"],
                "cve": cve_data["cve"],
                "severity": sev,
                "detail": cve_data["description"],
                "remediation": cve_data["mitigation"]
            })

        self.vulnerabilities = vulns
        self.results["vulnerabilities"] = vulns
        return vulns

    # ──────────────────────────────────────────────────────────────────────────
    def generate_demo_report(self):
        """Genera el informe de demostración para mostrar al cliente."""
        hdr("📊 INFORME DE DEMOSTRACIÓN PARA CLIENTE")
        print(f"  {C.BOLD}Lo que un atacante en tu {'{local}' if not self.devices else 'local'} puede ver AHORA MISMO:{C.END}\n")

        demo_items = []
        for device in self.devices[:8]:
            risk = device.get("risk", "medium")
            sales_arg = SALES_ARGUMENTS.get(risk, "")
            item = {
                "device": device.get("name", "Desconocido"),
                "type": DEVICE_CLASSES.get(device.get("type", "unknown"), {}).get("desc", "Tipo desconocido"),
                "risk": risk,
                "sales_argument": sales_arg,
                "visible": device.get("visible", True),
            }
            demo_items.append(item)
            print(f"  {device.get('icon', '📡')}  {C.BOLD}{device.get('name')}{C.END}")
            print(f"       Tipo: {item['type']}")
            print(f"       {sales_arg}")
            print()

        # Resumen de impacto para el cliente
        print(f"{C.YELLOW}{'─'*52}{C.END}")
        critical_n = sum(1 for d in self.devices if d.get("risk") == "critical")
        high_n = sum(1 for d in self.devices if d.get("risk") == "high")
        total = len(self.devices)

        print(f"\n  {C.BOLD}Resumen para el cliente:{C.END}")
        print(f"  • {total} dispositivos visibles desde exterior del local")
        if critical_n > 0:
            print(f"  {C.RED}• {critical_n} dispositivos con riesgo CRÍTICO{C.END}")
        if high_n > 0:
            print(f"  {C.RED}• {high_n} dispositivos con riesgo ALTO{C.END}")

        print(f"\n  {C.BOLD}Argumento de venta:{C.END}")
        print(f"  {C.CYAN}\"En menos de 30 segundos y sin tocar nada, hemos detectado {total} dispositivos")
        print(f"  Bluetooth en tu local que cualquier persona en la calle puede ver.{C.END}")
        if critical_n > 0 or high_n > 0:
            print(f"  {C.RED}  {critical_n + high_n} de ellos representan un riesgo alto o crítico para tu negocio.\"")
        print()

        self.results["demo_report"] = demo_items
        return demo_items

    # ──────────────────────────────────────────────────────────────────────────
    def calculate_risk_score(self):
        """Calcula el nivel de riesgo Bluetooth del entorno."""
        score = 100
        critical_devices = sum(1 for d in self.devices if d.get("risk") == "critical")
        high_devices = sum(1 for d in self.devices if d.get("risk") == "high")
        medium_devices = sum(1 for d in self.devices if d.get("risk") == "medium")
        critical_vulns = sum(1 for v in self.vulnerabilities if v.get("severity") == "critical")

        score -= critical_devices * 30
        score -= high_devices * 15
        score -= medium_devices * 5
        score -= critical_vulns * 20
        score = max(0, score)

        if score >= 80:
            level = "BAJO"; color = C.GREEN; icon = "🟢"
        elif score >= 60:
            level = "MEDIO"; color = C.YELLOW; icon = "🟡"
        elif score >= 30:
            level = "ALTO"; color = C.RED; icon = "🔴"
        else:
            level = "CRÍTICO"; color = C.RED; icon = "🚨"

        self.results["risk_level"] = level
        self.results["defense_score"] = score

        print(f"\n{C.BLUE}{'═'*52}{C.END}")
        print(f"{color}{C.BOLD}  {icon}  BLUETOOTH RISK SCORE: {score}/100 — Nivel {level}{C.END}")
        print(f"{C.BLUE}{'═'*52}{C.END}\n")
        return score

    # ──────────────────────────────────────────────────────────────────────────
    def save_results(self, output_dir=None):
        """Guarda resultados en JSON."""
        if output_dir is None:
            base = Path.home() / "Documents" / "purple_team_reports" / "bluetooth"
        else:
            base = Path(output_dir) / "bluetooth"
        base.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = base / f"bluetooth_audit_{ts}.json"
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        ok(f"Resultados guardados: {out_file}")
        return str(out_file)

    # ──────────────────────────────────────────────────────────────────────────
    def run(self):
        """Ejecuta la auditoría completa."""
        print(BANNER)
        print(f"  Modo: {C.BOLD}{self.mode.upper()}{C.END}  |  "
              f"Duración: {C.BOLD}{self.duration}s{C.END}  |  "
              f"BT disponible: {C.BOLD}{self.bt_available or 'No'}{C.END}")
        print()

        self.scan_devices()

        if self.mode in ("full", "demo"):
            self.analyze_vulnerabilities()
            self.generate_demo_report()

        self.calculate_risk_score()
        return self.save_results()


# ─── Entry point ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Bluetooth Security Auditor — Auditoría de seguridad Bluetooth"
    )
    parser.add_argument("--mode", choices=["scan", "demo", "full"],
                        default="full", help="Modo de ejecución")
    parser.add_argument("--duration", type=int, default=30,
                        help="Duración del escaneo en segundos (default: 30)")
    parser.add_argument("--output", help="Directorio de salida")
    args = parser.parse_args()

    print(f"\n  {C.YELLOW}⚠️  Este módulo solo realiza análisis PASIVO de señales Bluetooth públicas.")
    print(f"  Solo detecta dispositivos que voluntariamente emiten señal en modo visible.{C.END}\n")

    auditor = BluetoothSecurityAuditor(duration=args.duration, mode=args.mode)
    auditor.run()


if __name__ == "__main__":
    main()
