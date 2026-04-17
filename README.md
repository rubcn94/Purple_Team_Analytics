# 🟣 Purple Team Security Suite v2.0

**Plataforma profesional de auditoría de seguridad** diseñada para funcionar desde **tablet Android con Termux** y opcionalmente desde **Kali Linux**. Sin dependencias externas en los escáneres principales — todo funciona con la librería estándar de Python.

---

## 🎯 ¿Qué es este proyecto?

Una suite completa de herramientas de pentesting y auditoría de seguridad que:

- ✅ **Funciona en Android** (Termux) para auditorías desde tablet en campo
- ✅ **Sin dependencias complejas** — usa solo Python estándar para escáneres
- ✅ **Genera informes PDF profesionales** (en ordenador)
- ✅ **Integra con Kali Linux** para auditorías avanzadas
- ✅ **Dashboard web** para gestión de auditorías y clientes
- ✅ **Plantillas comerciales** listas para usar (contratos, facturas, propuestas)

---

## 📁 Estructura del proyecto

```
Termux_Purple_Team_Project/
│
├── 🎛️ ORQUESTADORES
│   ├── orchestrator.py              ← Orquestador principal (lanza todos los módulos)
│   ├── prospect_scan.py             ← Escaneo rápido para prospección de PYMEs (2-3 min)
│
├── 📄 GENERACIÓN DE INFORMES
│   ├── report_generator.py          ← Generador de informes PDF básico
│   ├── report_generator_pro.py      ← PDF profesional con branding y gráficas
│
├── 🌐 DASHBOARD WEB
│   └── dashboard/
│       └── dashboard.html           ← Panel de gestión de auditorías y hallazgos
│
├── 🔧 MÓDULOS DE AUDITORÍA
│   ├── wifi/                        ← Suite WiFi (door-openers para demos)
│   │   ├── wifi_audit_suite.py
│   │   ├── rogue_ap_detector.py
│   │   ├── client_isolation_tester.py
│   │   ├── router_default_checker.py
│   │   ├── network_exposure_scanner.py
│   │   └── wifi_security_analyzer.py
│   │
│   ├── bluetooth/                   ← Auditoría Bluetooth
│   │   └── bluetooth_security.py
│   │
│   ├── osint/                       ← Inteligencia en fuentes abiertas
│   │   └── osint_recon.py           ← WHOIS, DNS, brechas, Google Dorks
│   │
│   ├── blue_team/                   ← Módulo defensivo Blue Team
│   │   └── blue_team_monitor.py     ← IoC detection, hardening CIS, logs
│   │
│   ├── compliance/                  ← Evaluación de cumplimiento normativo
│   │   └── compliance_checker.py    ← RGPD, ENS, PCI DSS
│   │
│   ├── http/
│   │   └── http_security_scanner.py
│   │
│   ├── network/
│   │   └── network_recon.py
│   │
│   ├── ssl_tls/
│   │   └── ssl_analyzer.py
│   │
│   ├── subdomain/
│   │   └── subdomain_enumerator.py
│   │
│   ├── web_discovery/
│   │   └── directory_scanner.py
│   │
│   ├── cve/
│   │   └── cve_correlator.py
│   │
│   └── purple_suite/
│       └── purple_team_suite.py
│
├── 🐧 INTEGRACIÓN KALI LINUX
│   └── kali_integration/
│       ├── kali_automation.sh
│       ├── kali_web_audit.sh
│       ├── kali_internal_audit.sh
│       ├── kali_wireless_audit.sh
│       ├── install_kali_tools.sh
│       ├── kali_importer.py
│       └── examples_*.{xml,json,nessus}
│
├── 📋 PLANTILLAS COMERCIALES
│   └── plantillas/
│       ├── autorizacion_auditoria.docx
│       ├── catalogo_servicios.docx
│       ├── contrato_servicios.docx
│       ├── factura_plantilla.docx
│       ├── guion_prospeccion_ventas.docx
│       ├── onepager_comercial.docx
│       └── email_prospeccion.md
│
└── ⚙️ INSTALACIÓN Y CONFIGURACIÓN
    ├── install.sh                   ← Instalador de dependencias para Termux
    ├── setup_termux.sh              ← Configuración opcional del entorno Termux
    ├── INSTALL.md                   ← Guía de instalación detallada
    └── TROUBLESHOOTING.md           ← Resolución de problemas comunes
```

---

## 🚀 Instalación rápida

### En Termux (Android)

```bash
# 1. Descargar el proyecto
git clone https://github.com/tu-usuario/Termux_Purple_Team_Project.git
cd Termux_Purple_Team_Project

# 2. Instalar dependencias
chmod +x install.sh && ./install.sh

# 3. Configurar permisos de almacenamiento (opcional)
termux-setup-storage

# 4. Para Bluetooth (opcional)
pkg install termux-api
termux-bluetooth-enable
```

### En PC (para informes PDF)

```bash
pip install reportlab
```

Ver **[INSTALL.md](INSTALL.md)** para instrucciones detalladas.

---

## 💼 Casos de uso

### 1️⃣ Prospección de clientes (door-opener)

**Objetivo:** Escaneo rápido de 2-3 minutos para demostrar vulnerabilidades básicas a clientes potenciales.

```bash
python prospect_scan.py --url https://restaurante.com --client "Restaurante La Taberna"
```

**Resultado:** Informe conciso con hallazgos básicos para primera reunión comercial.

---

### 2️⃣ Auditoría completa externa

**Objetivo:** Análisis completo de superficie de ataque externa de un cliente.

```bash
python orchestrator.py \
  --mode external \
  --target empresa.com \
  --domain empresa.com \
  --url https://empresa.com \
  --client "Nombre Cliente SA"
```

**Módulos ejecutados:**
- OSINT (dominios, emails expuestos, brechas)
- SSL/TLS (certificados, cifrados débiles)
- HTTP Security (headers, cookies, CORS)
- Subdominios (enumeración)
- Directorios web
- CVE correlation
- Compliance (RGPD, ENS, PCI DSS)

---

### 3️⃣ Auditoría interna WiFi (in-situ)

**Objetivo:** Evaluación de seguridad de red WiFi del cliente desde sus instalaciones.

```bash
python orchestrator.py --mode wifi
```

**Door-openers incluidos:**
- **Rogue AP Detection** — detecta puntos de acceso maliciosos
- **Client Isolation Test** — verifica si los clientes pueden verse entre sí
- **Router Default Checker** — identifica credenciales por defecto
- **Network Exposure** — mapea dispositivos visibles (cámaras, POS, impresoras)

**Argumento de venta:** "Cualquiera puede suplantar tu WiFi o acceder a tus terminales de pago"

---

### 4️⃣ OSINT + Bluetooth (demo en local del cliente)

```bash
# OSINT completo
python osint/osint_recon.py --domain empresa.com --email info@empresa.com

# Bluetooth Security (demo en local)
python bluetooth/bluetooth_security.py --mode demo
```

**Argumento de venta:** "Cualquier persona en la calle puede ver estos dispositivos Bluetooth expuestos"

---

### 5️⃣ Blue Team — Evaluación defensiva

```bash
# Análisis completo
python blue_team/blue_team_monitor.py

# Solo verificación de IoC (Indicators of Compromise)
python blue_team/blue_team_monitor.py --mode ioc

# Solo hardening CIS
python blue_team/blue_team_monitor.py --mode hardening

# Solo análisis de logs
python blue_team/blue_team_monitor.py --mode logs
```

---

### 6️⃣ Compliance RGPD/ENS

```bash
python compliance/compliance_checker.py \
  --url https://empresa.com \
  --sector restaurante
```

**Resultado:** Informe de cumplimiento con **multas aplicables** según el sector.

---

### 7️⃣ Generar informe PDF profesional

**En el ordenador:**

```bash
pip install reportlab

# Informe completo con branding
python report_generator_pro.py \
  --session ./sessions/20260322_103000_cliente/ \
  --client "Empresa SA"

# Informe ejecutivo (resumen)
python report_generator_pro.py \
  --session ./sessions/XYZ/ \
  --client "Cliente" \
  --type executive
```

---

### 8️⃣ Dashboard web — Gestión de auditorías

```bash
# Opción 1: Abrir directamente
# Navegar a dashboard/dashboard.html en el navegador

# Opción 2: Servidor local
python -m http.server 8080
# Luego abrir: http://localhost:8080/dashboard/dashboard.html
```

**Funcionalidades:**
- Gestión de clientes
- Seguimiento de hallazgos
- Visualización de métricas
- Exportación de datos

---

## 🎛️ Modos del orquestador

El archivo `orchestrator.py` soporta múltiples modos de ejecución:

| Modo | Módulos ejecutados | Uso típico |
|------|-------------------|-----------|
| `full` | **Todos** (wifi + osint + blue_team + http + ssl + network + subdomain + cve + compliance) | Auditoría integral (interna + externa) |
| `external` | OSINT + SSL + subdomain + HTTP + directorios + CVE + compliance | Auditoría externa completa |
| `web` | HTTP + SSL + directorios + compliance | Solo auditoría web |
| `internal` | WiFi + Bluetooth + network + blue_team + CVE | Auditoría interna in-situ |
| `wifi` | Solo WiFi Suite | Door-opener WiFi |
| `bluetooth` | Solo Bluetooth Security | Door-opener Bluetooth |
| `osint` | Solo OSINT Recon | Reconocimiento pasivo |
| `blue` | Solo Blue Team Monitor | Evaluación defensiva |
| `compliance` | Solo Compliance Checker | Evaluación normativa |
| `http` | Solo HTTP Scanner | Auditoría HTTP headers |
| `ssl` | Solo SSL Analyzer | Auditoría SSL/TLS |
| `network` | Solo Network Recon | Escaneo de red |
| `quick` | WiFi + HTTP | Prospección rápida |

**Ejemplo de uso:**

```bash
python orchestrator.py --mode web --url https://ejemplo.com --client "Ejemplo SA"
```

---

## 🛠️ WiFi Door-Openers (para demostraciones)

Herramientas diseñadas para **mostrar vulnerabilidades evidentes** a clientes durante reuniones comerciales:

| Herramienta | Lo que demuestra | Argumento de venta |
|-------------|-----------------|-------------------|
| `rogue_ap_detector.py` | Evil Twin / AP malicioso | *"Cualquiera puede suplantar tu WiFi"* |
| `client_isolation_tester.py` | Clientes y POS en misma red | *"Tus terminales de pago están expuestas"* |
| `router_default_checker.py` | Router con credenciales por defecto | *"Tu router tiene la contraseña de fábrica"* |
| `network_exposure_scanner.py` | Cámaras, impresoras, NAS expuestos | *"Cualquier cliente puede ver tus dispositivos"* |
| `bluetooth_security.py --mode demo` | Dispositivos BT expuestos | *"Personas en la calle pueden ver estos dispositivos"* |

**Uso típico:**

```bash
# Ejecutar todas las pruebas WiFi
cd wifi
python wifi_audit_suite.py

# O individualmente
python rogue_ap_detector.py
python client_isolation_tester.py
```

---

## 🎯 Sectores prioritarios para prospección

1. **Restaurantes / Bares** — reservas online, formularios, QR, WiFi, Bluetooth
2. **Clínicas dentales / Fisioterapia** — datos de salud (multas RGPD más altas)
3. **Centros de estética / Peluquerías** — citas online, historial de servicios
4. **Academias / Escuelas de idiomas** — menores de edad (RGPD reforzado)
5. **Tiendas online pequeñas** — PCI DSS + RGPD + cookies
6. **Coworking / Gimnasios** — membresías, datos biométricos, WiFi, Bluetooth

---

## 🐧 Integración con Kali Linux

Para auditorías avanzadas, los resultados de herramientas de Kali pueden importarse:

```bash
# En Kali: Ejecutar auditoría web automatizada
cd kali_integration
./kali_web_audit.sh https://ejemplo.com

# Importar resultados a la suite
python kali_importer.py --nmap results_nmap.xml --nikto results_nikto.json
```

**Scripts disponibles:**
- `kali_automation.sh` — Orquestador general
- `kali_web_audit.sh` — Auditoría web (nikto, dirb, whatweb)
- `kali_internal_audit.sh` — Auditoría interna (nmap, netdiscover)
- `kali_wireless_audit.sh` — Auditoría WiFi (aircrack-ng suite)
- `install_kali_tools.sh` — Instalador de herramientas necesarias

---

## 📋 Plantillas comerciales

El directorio `plantillas/` incluye documentos listos para usar:

- **autorizacion_auditoria.docx** — Carta de autorización legal
- **catalogo_servicios.docx** — Catálogo de servicios de seguridad
- **contrato_servicios.docx** — Contrato tipo con cláusulas
- **factura_plantilla.docx** — Plantilla de factura
- **guion_prospeccion_ventas.docx** — Guion para llamadas comerciales
- **onepager_comercial.docx** — Propuesta comercial de una página
- **email_prospeccion.md** — Plantillas de emails para prospección

**Generación automatizada:**

```bash
cd plantillas
npm install
node generar_contrato.js --cliente "Empresa SA" --output contrato_firmado.docx
```

---

## 📚 Metodología

El proyecto sigue una metodología de 7 fases documentada en:

📄 **Purple_Team_Metodologia_Auditorias.pdf**

**Fases:**
1. **Reconocimiento** (OSINT)
2. **Escaneo y enumeración** (Network, subdominios)
3. **Análisis de vulnerabilidades** (CVE, SSL, HTTP)
4. **Explotación simulada** (WiFi door-openers, Bluetooth)
5. **Post-explotación** (Blue team defense evaluation)
6. **Informe** (PDF profesional)
7. **Remediación** (Recomendaciones documentadas)

**Mapeo MITRE ATT&CK:** Cada hallazgo se mapea a tácticas y técnicas MITRE.

---

## 🔒 Uso responsable

⚠️ **IMPORTANTE:** Esta herramienta está diseñada **exclusivamente** para auditorías de seguridad con **autorización escrita** del cliente.

**Uso NO autorizado es ilegal.**

**Antes de cualquier auditoría:**
1. Obtener carta de autorización firmada (`plantillas/autorizacion_auditoria.docx`)
2. Definir alcance claro (IPs, dominios, redes permitidas)
3. Establecer fecha/hora de auditoría
4. Coordinar con el cliente para evitar impacto en producción

---

## 🐛 Resolución de problemas

Si encuentras errores, consulta **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**.

**Problemas comunes:**

- **Error de permisos en Termux:** Ejecutar `termux-setup-storage`
- **Bluetooth no funciona:** Verificar `pkg install termux-api`
- **Informes PDF no generan:** Verificar `pip install reportlab`
- **WiFi scan falla:** Verificar permisos de ubicación en Android

---

## 📞 Soporte

Para reportar issues o contribuir:
- **Issues:** [GitHub Issues](https://github.com/tu-usuario/Termux_Purple_Team_Project/issues)
- **Contribuciones:** Pull requests bienvenidos

---

## 📄 Licencia

Proyecto de código abierto bajo licencia MIT (pendiente de confirmar).

---

## 🙏 Créditos

Desarrollado por **Ruben** como proyecto de prácticas ASIR y especialización en AI Security.

**Tecnologías:**
- Python 3.x (librería estándar)
- Termux (Android)
- Kali Linux (integración opcional)
- ReportLab (generación de PDFs)

---

*Purple Team Security Suite · v2.0 · Solo para auditorías con autorización escrita*
# Purple_Team_Analytics
