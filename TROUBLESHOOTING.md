# 🔧 Troubleshooting Guide - Termux Purple Team

## ❌ Problema: "Expected list, got class dict"

### Causa
`termux-wifi-scaninfo` puede devolver diferentes formatos JSON según la versión de Termux:API.

### ✅ Solución Aplicada
El código ahora maneja **6 formatos diferentes** automáticamente:

1. **Lista directa**: `[{red1}, {red2}]`
2. **Dict con 'results'**: `{"results": [{red1}]}`
3. **Dict con 'networks'**: `{"networks": [{red1}]}`
4. **Dict con 'data'**: `{"data": [{red1}]}`
5. **Red única como dict**: `{"ssid": "...", "bssid": "..."}`
6. **Lista/dict vacío**: `[]` o `{}`

### 🐛 Debug en Termux

Ejecuta el script de debug para ver exactamente qué formato está devolviendo:

```bash
cd ~/Termux_Purple_Team
bash debug_wifi_api.sh
```

**Output esperado:**
```
==========================================
  WiFi API Debug Tool
==========================================

✅ termux-wifi-scaninfo encontrado

Ejecutando termux-wifi-scaninfo...

==========================================
  Resultado
==========================================
Exit code: 0

✅ Comando ejecutado exitosamente

Output completo:
----------------------------------------
[{"ssid":"MyNetwork",...}]
----------------------------------------

Analizando estructura JSON...

Tipo de datos: list
✅ Es una lista con 5 elemento(s)
```

---

## ❌ Problema: "Ataque falló o bloqueado"

### Posibles causas

#### 1. Termux:API no instalado correctamente

**Verificar:**
```bash
pkg list-installed | grep termux-api
```

**Si no aparece:**
```bash
pkg install termux-api
```

**Además necesitas la app Termux:API:**
- Descarga desde [F-Droid](https://f-droid.org/packages/com.termux.api/) o Google Play Store
- Busca: "Termux:API"

#### 2. Permisos de ubicación no concedidos

Android requiere permisos de ubicación para escanear WiFi.

**Conceder permisos:**
1. Abre Ajustes de Android
2. Apps → Termux
3. Permisos → Ubicación → Permitir

**O ejecuta:**
```bash
termux-location
# Acepta el permiso cuando aparezca el prompt
```

#### 3. WiFi deshabilitado

**Verificar:**
```bash
termux-wifi-connectioninfo
```

Si devuelve error, habilita WiFi en Android.

#### 4. Versión antigua de Termux:API

**Actualizar:**
```bash
pkg upgrade termux-api
```

**Luego actualiza la app Termux:API desde la tienda.**

---

## ❌ Problema: Error "\r: command not found"

### Causa
Archivos con line endings Windows (CRLF) en lugar de Unix (LF).

### ✅ Solución
```bash
cd ~/Termux_Purple_Team
bash fix_line_endings.sh
```

---

## ❌ Problema: "No se detectaron redes WiFi"

### Diagnóstico

**1. Verifica que el WiFi esté funcionando:**
```bash
termux-wifi-connectioninfo
```

Debería mostrar tu red actual.

**2. Escanea manualmente:**
```bash
termux-wifi-scaninfo
```

**3. Si devuelve JSON vacío:**
- Activa/desactiva WiFi en Android
- Espera 10 segundos
- Intenta de nuevo

**4. Si sigue sin funcionar:**
```bash
# Reinstalar termux-api
pkg uninstall termux-api
pkg install termux-api

# Reiniciar termux
exit
# (abre Termux de nuevo)
```

---

## ❌ Problema: Emojis se ven como "?" o cuadrados

### Causa
Tu terminal no tiene Nerd Font instalado.

### ✅ Solución

**Instalar Nerd Font en Termux:**
```bash
cd ~/.termux
curl -fLo "font.ttf" https://github.com/ryanoasis/nerd-fonts/raw/master/patched-fonts/JetBrainsMono/Ligatures/Regular/JetBrainsMonoNerdFont-Regular.ttf

# Recargar configuración
termux-reload-settings
```

**Alternativamente:** Los emojis son estéticos, el código funciona igual sin ellos.

---

## ✅ Verificación de instalación completa

Ejecuta este checklist:

```bash
# 1. Termux:API package
pkg list-installed | grep termux-api
# Debe mostrar: termux-api/...

# 2. Python
python --version
# Debe mostrar: Python 3.x

# 3. Nmap
nmap --version
# Debe mostrar: Nmap version 7.x

# 4. termux-wifi-scaninfo disponible
command -v termux-wifi-scaninfo
# Debe mostrar: /data/data/com.termux/files/usr/bin/termux-wifi-scaninfo

# 5. Test WiFi API
bash ~/Termux_Purple_Team/debug_wifi_api.sh

# 6. Test suite Python
cd ~/Termux_Purple_Team
python test_suite.py
# Debe mostrar: ALL TESTS PASSED (7/7) - 100%
```

---

## 📊 Test de formatos JSON

Para verificar que el parsing de JSON funciona con todos los formatos:

```bash
cd ~/Termux_Purple_Team
python test_json_formats.py
```

**Output esperado:**
```
[PASS] Format 1 - List of networks (expected)
[PASS] Format 2 - Dict with 'results' key
[PASS] Format 3 - Dict with 'networks' key
[PASS] Format 4 - Single network as dict
[PASS] Format 5 - Empty list
[PASS] Format 6 - Dict without networks

Result: 6/6 tests passed (100.0%)
```

---

## 🆘 Si nada funciona

### Reset completo

```bash
# 1. Limpiar todo
cd ~
rm -rf Termux_Purple_Team
rm -rf .zsh*
rm -f .zshrc

# 2. Reinstalar paquetes
pkg update && pkg upgrade
pkg install -y python nmap termux-api git curl wget

# 3. Reinstalar proyecto
# (Transferir archivos de nuevo)

# 4. Ejecutar instalación
cd ~/Termux_Purple_Team
bash setup_termux.sh
bash install.sh

# 5. Probar
bash ~/purple_team.sh
```

---

## 📝 Logs de debugging

Todos los logs se guardan en:
```
~/storage/shared/Documents/purple_team_reports/
```

O fallback:
```
~/purple_team_reports/
```

**Ver logs recientes:**
```bash
cd ~/storage/shared/Documents/purple_team_reports/
ls -lht | head -10
```

---

## 🐛 Reportar bugs

Si encuentras un bug no documentado aquí:

1. Ejecuta el debug script:
   ```bash
   bash ~/Termux_Purple_Team/debug_wifi_api.sh > debug_output.txt
   ```

2. Captura el error exacto

3. Incluye:
   - Output del debug script
   - Versión de Android
   - Versión de Termux (`termux-info`)
   - Output de `pkg list-installed | grep termux-api`

---

**Última actualización:** 2026-03-21
**Versión:** 2.0 - Multi-format JSON support
