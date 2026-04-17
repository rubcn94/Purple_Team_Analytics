#!/bin/bash
# -*- coding: utf-8 -*-
# debug_wifi_api.sh - Debug tool para Termux:API WiFi
# Diagnostica problemas con termux-wifi-scaninfo

echo ""
echo "=========================================="
echo "  WiFi API Debug Tool"
echo "=========================================="
echo ""

# ── 1. Verificar que termux-wifi-scaninfo existe ──────────────────────────────
if command -v termux-wifi-scaninfo &>/dev/null; then
    echo "✅ termux-wifi-scaninfo encontrado"
    echo "   Ruta: $(which termux-wifi-scaninfo)"
else
    echo "❌ termux-wifi-scaninfo NO encontrado"
    echo ""
    echo "   Instala con:"
    echo "     pkg install termux-api"
    echo "   Y también instala la app 'Termux:API' desde F-Droid"
    exit 1
fi

echo ""

# ── 2. Verificar que la app Termux:API está activa ────────────────────────────
echo "Comprobando Termux:API app..."
API_TEST=$(timeout 3 termux-battery-status 2>&1)
API_EXIT=$?

if echo "$API_TEST" | grep -q "CONFIG URL FETCH FAILED"; then
    echo ""
    echo "❌ PROBLEMA DETECTADO: CONFIG URL FETCH FAILED"
    echo ""
    echo "   Causa: Android (especialmente MIUI/Android 13+) bloquea"
    echo "          la comunicación entre Termux y la app Termux:API."
    echo ""
    echo "   Soluciones:"
    echo "   1. Ajustes → Apps → Termux:API → Batería → Sin restricciones"
    echo "   2. Ajustes → Apps → Termux → Permisos → Ubicación → Permitir siempre"
    echo "   3. Ajustes → Apps → Termux:API → Permisos → Ubicación → Permitir siempre"
    echo "   4. Activa Ubicación del sistema (GPS)"
    echo "   5. Si usas Xiaomi/MIUI: Ajustes → Batería → Ahorro de batería → Sin restricciones"
    echo ""
    echo "   Si nada funciona: Android 15 + MIUI bloquea esto de forma agresiva."
    echo "   Considera usar modo simulación en purple_team_suite.py"
    exit 2
elif [ $API_EXIT -eq 124 ]; then
    echo "⚠️  termux-battery-status → TIMEOUT (app Termux:API no responde)"
    echo ""
    echo "   Probable causa: permisos de fondo bloqueados por Android"
    echo "   → Activa 'Autoinicio' y 'Sin restricciones de batería' para Termux:API"
else
    echo "✅ Termux:API app responde correctamente"
fi

echo ""

# ── 3. Verificar WiFi activo ──────────────────────────────────────────────────
echo "Comprobando conexión WiFi..."
WIFI_INFO=$(timeout 5 termux-wifi-connectioninfo 2>&1)
WIFI_EXIT=$?

if echo "$WIFI_INFO" | grep -q "CONFIG URL FETCH FAILED"; then
    echo "❌ WiFi info: CONFIG URL FETCH FAILED (mismo problema que arriba)"
elif [ $WIFI_EXIT -eq 124 ]; then
    echo "⚠️  WiFi info: timeout"
elif echo "$WIFI_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); print('✅ WiFi activo: ' + d.get('ssid','?'))" 2>/dev/null; then
    :
else
    echo "⚠️  WiFi info no disponible o WiFi desactivado"
    echo "   Respuesta: $WIFI_INFO"
fi

echo ""

# ── 4. Ejecutar termux-wifi-scaninfo ─────────────────────────────────────────
echo "Ejecutando termux-wifi-scaninfo..."
echo ""
OUTPUT=$(timeout 10 termux-wifi-scaninfo 2>&1)
EXIT_CODE=$?

echo "=========================================="
echo "  Resultado"
echo "=========================================="
echo "Exit code: $EXIT_CODE"
echo ""

if [ $EXIT_CODE -eq 124 ]; then
    echo "⏱️  TIMEOUT: El comando se colgó (>10s)"
    echo ""
    echo "   Causa casi segura: permisos de ubicación no concedidos"
    echo "   o Android bloqueando el acceso en segundo plano."
    exit 3
elif [ $EXIT_CODE -ne 0 ]; then
    echo "❌ Comando falló (exit code $EXIT_CODE)"
    echo "Output: $OUTPUT"
    exit 4
else
    echo "✅ Comando ejecutado exitosamente"
    echo ""
    echo "Output completo:"
    echo "----------------------------------------"
    echo "$OUTPUT"
    echo "----------------------------------------"
fi

echo ""

# ── 5. Analizar estructura JSON ───────────────────────────────────────────────
echo "Analizando estructura JSON..."
echo ""

python3 - <<EOF
import json, sys

raw = """$OUTPUT"""

try:
    data = json.loads(raw)
except json.JSONDecodeError as e:
    print(f"❌ JSON inválido: {e}")
    sys.exit(5)

dtype = type(data).__name__
print(f"Tipo de datos: {dtype}")

if isinstance(data, list):
    print(f"✅ Es una lista con {len(data)} elemento(s)")
    if len(data) > 0:
        print("   Primer elemento (muestra):")
        first = data[0]
        if isinstance(first, dict):
            for k, v in list(first.items())[:5]:
                print(f"     {k}: {v}")
elif isinstance(data, dict):
    if "API_ERROR" in data:
        print(f"❌ API_ERROR: {data['API_ERROR']}")
    else:
        keys = list(data.keys())
        print(f"   Claves: {keys}")
        for key in ["results", "networks", "data", "scans"]:
            if key in data and isinstance(data[key], list):
                print(f"✅ Encontrada lista en clave '{key}' con {len(data[key])} elemento(s)")
                break
        else:
            if "ssid" in data:
                print(f"✅ Red única detectada: {data.get('ssid', '?')}")
            else:
                print("⚠️  Dict sin redes reconocibles")
else:
    print(f"⚠️  Tipo inesperado: {dtype}")
EOF

echo ""
echo "=========================================="
echo "  Debug completado"
echo "=========================================="
echo ""
