# Termux Purple Team Suite - Instalación

## 📦 Requisitos

### 1. Instalar Termux
- **Google Play** (versión desactualizada, NO recomendada)
- **F-Droid** (RECOMENDADO): https://f-droid.org/packages/com.termux/

### 2. Instalar Termux:API
- **F-Droid**: https://f-droid.org/packages/com.termux.api/
- Necesario para WiFi scanning y network info

---

## 🚀 Instalación Rápida

### Paso 1: Actualizar Termux
```bash
pkg update && pkg upgrade -y
```

### Paso 2: Instalar dependencias del sistema
```bash
pkg install -y \
    python \
    nmap \
    dnsutils \
    iproute2 \
    termux-api \
    wget \
    git
```

### Paso 3: Instalar dependencias Python
```bash
# ⚠️ IMPORTANTE: NO ejecutes "pip install --upgrade pip" en Termux
# Rompe el gestor de paquetes. Usa "pkg upgrade python-pip" en su lugar.

pip install requests youtube-transcript-api
```

### Paso 4: Configurar almacenamiento compartido
```bash
termux-setup-storage
```
*Acepta el permiso cuando aparezca el prompt*

### Paso 5: Copiar scripts
```bash
# Opción A: Desde PC vía USB
# 1. Conecta el móvil por USB
# 2. Copia la carpeta Termux_Purple_Team a:
#    Almacenamiento interno/Documents/

# Opción B: Desde PC vía SSH (si tienes openssh-server)
# En Termux:
pkg install openssh
sshd

# En PC:
scp -r Termux_Purple_Team/* usuario@IP_MOVIL:~/storage/shared/Documents/

# Opción C: Manualmente desde GitHub (cuando lo subas)
git clone https://github.com/tu_usuario/termux-purple-team.git
```

### Paso 6: Dar permisos de ejecución
```bash
cd ~/storage/shared/Documents/Termux_Purple_Team
chmod +x wifi/*.py
chmod +x http/*.py
chmod +x network/*.py
chmod +x purple_suite/*.py
```

---

## ✅ Verificar Instalación

### Test 1: Python y dependencias
```bash
python --version
python -c "import requests; print('requests OK')"
python -c "from youtube_transcript_api import YouTubeTranscriptApi; print('youtube-transcript-api OK')"
```

### Test 2: Termux API
```bash
termux-wifi-connectioninfo
# Debería mostrar info de tu WiFi actual
```

### Test 3: Nmap
```bash
nmap --version
```

### Test 4: DNS tools
```bash
nslookup google.com
```

---

## 🔧 Troubleshooting

### Error: "termux-wifi-scaninfo: command not found"
```bash
pkg install termux-api
# También instala Termux:API app desde F-Droid
```

### Error: "Permission denied" al acceder a /storage/emulated/0/
```bash
termux-setup-storage
# Acepta el permiso de almacenamiento
```

### Error: "ModuleNotFoundError: No module named 'requests'"
```bash
pip install requests
```

### Error: "ERROR: pip is configured with locations that require TLS/SSL..."
```bash
# Esto ocurre si actualizaste pip con "pip install --upgrade pip"
# En Termux esto está PROHIBIDO porque rompe el package manager

# SOLUCIÓN: Reinstalar python y python-pip
pkg uninstall python python-pip
pkg install python python-pip

# Luego reinstalar paquetes Python:
pip install requests youtube-transcript-api
```

### ⚠️ NUNCA uses "pip install --upgrade pip" en Termux
```bash
# ❌ INCORRECTO (rompe Termux):
pip install --upgrade pip

# ✅ CORRECTO (actualizar pip en Termux):
pkg upgrade python-pip
```

### Nmap muy lento o no funciona
```bash
# Verifica permisos de red
# En algunos dispositivos, nmap requiere root para full functionality
# Alternativamente, usa opciones menos agresivas:
nmap -F -T4 target  # Fast scan
```

### WiFi scan no detecta redes
```bash
# Verifica permisos de ubicación
# Android requiere permisos de ubicación para escanear WiFi

# Intenta desde configuración del sistema:
# Ajustes > Aplicaciones > Termux > Permisos > Ubicación
```

---

## 📱 Permisos Necesarios

En **Ajustes > Aplicaciones > Termux > Permisos**, habilita:

- ✅ **Almacenamiento** (para guardar reportes)
- ✅ **Ubicación** (para WiFi scanning)
- ⚠️  **Red** (generalmente ya habilitado)

---

## 🎯 Primer Uso

### Test WiFi Scanner
```bash
cd ~/storage/shared/Documents/Termux_Purple_Team/wifi
python wifi_security_analyzer.py
```

### Test HTTP Scanner
```bash
cd ~/storage/shared/Documents/Termux_Purple_Team/http
python http_security_scanner.py
# Prueba con: https://example.com
```

### Test Network Recon
```bash
cd ~/storage/shared/Documents/Termux_Purple_Team/network
python network_recon.py
```

### Test Purple Team Suite (RECOMENDADO)
```bash
cd ~/storage/shared/Documents/Termux_Purple_Team/purple_suite
python purple_team_suite.py
```

---

## 📂 Estructura de Archivos

```
Termux_Purple_Team/
├── wifi/
│   └── wifi_security_analyzer.py
├── http/
│   └── http_security_scanner.py
├── network/
│   └── network_recon.py
├── purple_suite/
│   └── purple_team_suite.py      ← SUITE COMPLETA
├── logs/                          (se crea automáticamente)
└── INSTALL.md                     (este archivo)
```

Los reportes se guardan en:
`~/storage/shared/Documents/purple_team_reports/`

Visibles desde PC cuando conectas por USB en:
`Almacenamiento interno/Documents/purple_team_reports/`

---

## 🔐 Seguridad

⚠️  **MUY IMPORTANTE:**

- Estos scripts son para **aprendizaje y entornos autorizados ÚNICAMENTE**
- Escanear redes sin autorización es **ILEGAL** en la mayoría de países
- Usa solo en tu propia red WiFi doméstica o en entornos de lab controlados
- Para pentesting profesional, requieres **autorización escrita** del dueño de la red

### Uso Recomendado

✅ **PERMITIDO:**
- Tu propia red WiFi doméstica
- Laboratorios de ciberseguridad (TryHackMe, HackTheBox, etc.)
- Entornos corporativos con autorización escrita
- CTF competitions
- Educación en ciberseguridad

❌ **PROHIBIDO:**
- Redes WiFi públicas sin autorización
- Redes de vecinos
- Redes corporativas sin permiso
- Cualquier red que no sea tuya

---

## 📚 Recursos Adicionales

### Aprender más sobre Purple Teaming
- **MITRE ATT&CK**: https://attack.mitre.org/
- **Purple Team Exercise Framework**: https://www.scythe.io/library/purple-team-exercise-framework

### Labs para practicar
- **TryHackMe**: https://tryhackme.com/ (recomendado para empezar)
- **HackTheBox**: https://www.hackthebox.com/
- **OverTheWire**: https://overthewire.org/wargames/

### Certificaciones relevantes
- Security+ (fundamentos)
- BTL1 (Blue Team)
- CySA+ (SOC Analyst)
- OSCP (Red Team avanzado)

---

## 🆘 Soporte

Si encuentras problemas:

1. Revisa la sección **Troubleshooting** arriba
2. Verifica que todas las dependencias estén instaladas
3. Comprueba permisos de Android en Ajustes
4. Revisa logs de error en los scripts

---

**Versión:** 1.0
**Fecha:** Marzo 2026
**Autor:** Purple Team Security Research
