#!/data/data/com.termux/files/usr/bin/bash
# Termux Purple Team Suite - Auto Installer
# Instala todas las dependencias necesarias

set -e  # Exit on error

echo "=========================================="
echo "  🟣 Termux Purple Team Suite Installer"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "ℹ️  $1"
}

# Check if running in Termux
if [ ! -d "/data/data/com.termux" ]; then
    print_error "Este script debe ejecutarse en Termux"
    exit 1
fi

print_success "Ejecutando en Termux"

# Step 1: Update packages
echo ""
echo "📦 Paso 1/5: Actualizando repositorios..."
if pkg update -y && pkg upgrade -y; then
    print_success "Repositorios actualizados"
else
    print_warning "Error al actualizar repositorios (puede ser ignorado)"
fi

# Step 2: Install system packages
echo ""
echo "📦 Paso 2/5: Instalando dependencias del sistema..."
echo ""
print_info "Esto puede tardar 2-3 minutos..."
echo ""

PACKAGES="python nmap dnsutils iproute2 termux-api wget git"

for pkg_name in $PACKAGES; do
    print_info "Instalando $pkg_name..."
    if pkg install -y $pkg_name 2>&1 | tail -5; then
        print_success "$pkg_name instalado correctamente"
        echo ""
    else
        print_error "Error instalando $pkg_name"
        echo ""
    fi
done

# Step 3: Install Python packages
echo ""
echo "🐍 Paso 3/5: Instalando paquetes Python..."

# Note: NEVER use "pip install --upgrade pip" in Termux - it breaks the package manager
# Use "pkg upgrade python-pip" instead (already done in Step 1)

PYTHON_PACKAGES="requests youtube-transcript-api"

for py_pkg in $PYTHON_PACKAGES; do
    echo ""
    print_info "Instalando $py_pkg (esto puede tardar 1-2 min)..."
    if pip install $py_pkg; then
        echo ""
        print_success "$py_pkg instalado correctamente"
    else
        echo ""
        print_error "Error instalando $py_pkg"
    fi
done

# Step 4: Setup storage
echo ""
echo "📂 Paso 4/5: Configurando acceso a almacenamiento..."

if [ ! -d "$HOME/storage" ]; then
    print_info "Ejecutando termux-setup-storage..."
    print_warning "ACEPTA EL PERMISO cuando aparezca el prompt"
    termux-setup-storage

    # Wait for user to accept permission
    sleep 2

    if [ -d "$HOME/storage" ]; then
        print_success "Almacenamiento configurado"
    else
        print_error "Almacenamiento NO configurado - ejecuta 'termux-setup-storage' manualmente"
    fi
else
    print_success "Almacenamiento ya configurado"
fi

# Step 5: Create output directory
echo ""
echo "📁 Paso 5/5: Creando directorios de reportes..."

REPORT_DIR="$HOME/storage/shared/Documents/purple_team_reports"

if mkdir -p "$REPORT_DIR" 2>/dev/null; then
    print_success "Directorio de reportes creado: $REPORT_DIR"
else
    print_warning "No se pudo crear directorio de reportes (verifica permisos)"
    REPORT_DIR="$HOME/purple_team_reports"
    mkdir -p "$REPORT_DIR"
    print_info "Usando directorio alternativo: $REPORT_DIR"
fi

# Step 6: Make scripts executable
echo ""
echo "🔧 Configurando permisos de scripts..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find "$SCRIPT_DIR" -name "*.py" -type f -exec chmod +x {} \;
print_success "Permisos configurados"

# Verification
echo ""
echo "=========================================="
echo "  ✅ VERIFICACIÓN DE INSTALACIÓN"
echo "=========================================="
echo ""

# Check Python
if python --version &> /dev/null; then
    PYTHON_VER=$(python --version 2>&1)
    print_success "Python: $PYTHON_VER"
else
    print_error "Python NO instalado"
fi

# Check nmap
if nmap --version &> /dev/null; then
    print_success "nmap: Instalado"
else
    print_error "nmap NO instalado"
fi

# Check termux-api
if termux-wifi-connectioninfo &> /dev/null; then
    print_success "termux-api: Funcionando"
else
    print_warning "termux-api: No disponible o sin permisos"
    print_info "Instala Termux:API app desde F-Droid"
fi

# Check Python packages
if python -c "import requests" &> /dev/null; then
    print_success "requests: Instalado"
else
    print_error "requests NO instalado"
fi

if python -c "from youtube_transcript_api import YouTubeTranscriptApi" &> /dev/null; then
    print_success "youtube-transcript-api: Instalado"
else
    print_error "youtube-transcript-api NO instalado"
fi

# Check storage
if [ -d "$HOME/storage/shared" ]; then
    print_success "Almacenamiento compartido: Accesible"
else
    print_warning "Almacenamiento compartido: NO accesible"
    print_info "Ejecuta: termux-setup-storage"
fi

# Final instructions
echo ""
echo "=========================================="
echo "  🎉 INSTALACIÓN COMPLETADA"
echo "=========================================="
echo ""
print_info "Para ejecutar la Purple Team Suite:"
echo ""
echo "  cd $SCRIPT_DIR/purple_suite"
echo "  python purple_team_suite.py"
echo ""
print_info "Otras herramientas:"
echo ""
echo "  WiFi Scanner:    python $SCRIPT_DIR/wifi/wifi_security_analyzer.py"
echo "  HTTP Scanner:    python $SCRIPT_DIR/http/http_security_scanner.py"
echo "  Network Recon:   python $SCRIPT_DIR/network/network_recon.py"
echo ""
print_warning "IMPORTANTE: Solo usa en redes/sistemas autorizados"
echo ""

# Create quick launcher script
LAUNCHER="$HOME/purple_team.sh"

cat > "$LAUNCHER" << EOF
#!/data/data/com.termux/files/usr/bin/bash
# Quick launcher for Purple Team Suite

SCRIPT_DIR="$SCRIPT_DIR"

if [ ! -d "\$SCRIPT_DIR" ]; then
    echo "❌ Purple Team Suite no encontrado en \$SCRIPT_DIR"
    exit 1
fi

echo "🟣 Purple Team Suite Launcher"
echo ""
echo "1) Purple Team Suite (Full)"
echo "2) WiFi Security Analyzer"
echo "3) HTTP Security Scanner"
echo "4) Network Reconnaissance"
echo "q) Salir"
echo ""

read -p "Opción: " choice

case \$choice in
    1)
        python "\$SCRIPT_DIR/purple_suite/purple_team_suite.py"
        ;;
    2)
        python "\$SCRIPT_DIR/wifi/wifi_security_analyzer.py"
        ;;
    3)
        python "\$SCRIPT_DIR/http/http_security_scanner.py"
        ;;
    4)
        python "\$SCRIPT_DIR/network/network_recon.py"
        ;;
    q|Q)
        echo "Hasta luego!"
        exit 0
        ;;
    *)
        echo "Opción inválida"
        exit 1
        ;;
esac
EOF

chmod +x "$LAUNCHER"

print_success "Launcher creado en: $LAUNCHER"
echo ""
print_info "Ejecuta 'bash ~/purple_team.sh' para lanzar rápidamente"
echo ""
