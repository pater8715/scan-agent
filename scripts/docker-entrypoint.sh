#!/bin/bash
# docker-entrypoint.sh - Enhanced Entry Point for Scan Agent v3.0
# ================================================================
# Soporte para CLI, Web UI, análisis, y desarrollo
# Funciones: verificación de herramientas, logging, healthcheck

set -e

# ============================================================================
# CONFIGURACIÓN Y VARIABLES
# ============================================================================

# Colores para output mejorados
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Variables de entorno por defecto
SCAN_MODE=${SCAN_MODE:-"cli"}
LOG_LEVEL=${LOG_LEVEL:-"INFO"}
WEB_HOST=${WEB_HOST:-"0.0.0.0"}
WEB_PORT=${WEB_PORT:-"8080"}
API_PORT=${API_PORT:-"8000"}

# Archivos de log
LOG_DIR="/scan-agent/logs"
LOG_FILE="$LOG_DIR/scan-agent.log"
ERROR_LOG="$LOG_DIR/error.log"

# ============================================================================
# FUNCIONES AUXILIARES
# ============================================================================

# Función de logging
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Banner mejorado
show_banner() {
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                           ║${NC}"
    echo -e "${CYAN}║  ${WHITE}🛡️  SCAN AGENT v3.0 - Professional Security Scanner${WHITE}  🛡️${CYAN}  ║${NC}"
    echo -e "${CYAN}║                                                           ║${NC}"
    echo -e "${CYAN}║  ${GREEN}✨ Intelligent Vulnerability Analysis & Reporting${GREEN} ✨${CYAN}   ║${NC}"
    echo -e "${CYAN}║                                                           ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo -e "${BLUE}Mode: ${WHITE}$SCAN_MODE${NC} | ${BLUE}Log Level: ${WHITE}$LOG_LEVEL${NC} | ${BLUE}Time: ${WHITE}$(date)${NC}"
    echo ""
}

# Verificación de herramientas mejorada
check_tools() {
    log "INFO" "Verificando herramientas de seguridad..."
    
    local tools=("python3" "nmap" "nikto" "gobuster" "curl" "wget" "sqlite3")
    local web_tools=("dirb" "whatweb")
    local missing_tools=()
    
    # Verificar herramientas básicas
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            local version=$(get_tool_version "$tool")
            echo -e "${GREEN}[✓]${NC} $tool ${YELLOW}$version${NC} - $(command -v "$tool")"
            log "INFO" "Tool found: $tool $version"
        else
            echo -e "${RED}[✗]${NC} $tool - ${RED}No encontrado${NC}"
            missing_tools+=("$tool")
            log "ERROR" "Missing tool: $tool"
        fi
    done
    
    # Verificar herramientas web (opcionales)
    if [[ "$SCAN_MODE" == "web" ]] || [[ "$*" == *"--web"* ]]; then
        echo -e "${BLUE}[i]${NC} Verificando herramientas web adicionales..."
        for tool in "${web_tools[@]}"; do
            if command -v "$tool" &> /dev/null; then
                echo -e "${GREEN}[✓]${NC} $tool - $(command -v "$tool")"
            else
                echo -e "${YELLOW}[!]${NC} $tool - Opcional, no encontrado"
            fi
        done
    fi
    
    # Verificar herramientas críticas faltantes
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}[ERROR]${NC} Herramientas críticas faltantes: ${missing_tools[*]}"
        log "ERROR" "Critical tools missing: ${missing_tools[*]}"
        if [[ "$*" == *"--scan"* ]]; then
            echo -e "${RED}[ERROR]${NC} No se puede ejecutar escaneo sin las herramientas necesarias"
            exit 1
        fi
    fi
    
    echo ""
}

# Obtener versión de herramienta
get_tool_version() {
    local tool=$1
    case "$tool" in
        "python3")
            python3 --version 2>&1 | cut -d' ' -f2
            ;;
        "nmap")
            nmap --version 2>&1 | head -n1 | grep -oE '[0-9]+\.[0-9]+'
            ;;
        "nikto")
            nikto -Version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
            ;;
        "gobuster")
            gobuster version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+'
            ;;
        "curl")
            curl --version 2>&1 | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Configurar directorios
setup_directories() {
    log "INFO" "Configurando directorios de trabajo..."
    
    local dirs=("outputs" "reports" "data" "logs")
    
    for dir in "${dirs[@]}"; do
        local full_path="/scan-agent/$dir"
        if [ ! -d "$full_path" ]; then
            mkdir -p "$full_path"
            log "INFO" "Directorio creado: $full_path"
        fi
        
        # Verificar permisos
        if [ -w "$full_path" ]; then
            echo -e "${GREEN}[✓]${NC} $dir/ - Permisos OK"
        else
            echo -e "${YELLOW}[!]${NC} $dir/ - Permisos limitados"
            log "WARN" "Limited permissions for: $full_path"
        fi
    done
    
    echo ""
}

# Verificar permisos de red
check_network_permissions() {
    if [[ "$*" == *"--scan"* ]]; then
        log "INFO" "Verificando permisos de red para escaneo..."
        
        # Verificar capacidades de red
        if [[ "$*" == *"--profile stealth"* ]] || [[ "$*" == *"--profile network"* ]] || [[ "$*" == *"--profile full"* ]]; then
            echo -e "${YELLOW}[!]${NC} Escaneo avanzado detectado"
            echo -e "${BLUE}[i]${NC} Verificando capacidades de red..."
            
            # Intentar verificar si tenemos NET_RAW
            if [ -w "/proc/sys/net/ipv4/ping_group_range" ] 2>/dev/null; then
                echo -e "${GREEN}[✓]${NC} Capacidades de red disponibles"
            else
                echo -e "${YELLOW}[!]${NC} Capacidades de red limitadas"
                echo -e "${YELLOW}[!]${NC} Para escaneos avanzados usar: ${WHITE}--cap-add=NET_RAW --cap-add=NET_ADMIN${NC}"
            fi
        fi
        
        echo ""
    fi
}

# Configurar modo web
setup_web_mode() {
    if [[ "$SCAN_MODE" == "web" ]] || [[ "$*" == *"--web"* ]]; then
        log "INFO" "Configurando modo web..."
        echo -e "${CYAN}[WEB]${NC} Iniciando Scan Agent Web UI"
        echo -e "${CYAN}[WEB]${NC} Host: ${WHITE}$WEB_HOST${NC}"
        echo -e "${CYAN}[WEB]${NC} Puerto: ${WHITE}$WEB_PORT${NC}"
        echo -e "${CYAN}[WEB]${NC} API Docs: ${WHITE}http://$WEB_HOST:$WEB_PORT/api/docs${NC}"
        echo ""
        
        # Verificar puerto disponible
        if netstat -tuln 2>/dev/null | grep -q ":$WEB_PORT "; then
            echo -e "${YELLOW}[!]${NC} Puerto $WEB_PORT ya en uso"
            log "WARN" "Port $WEB_PORT already in use"
        fi
    fi
}

# Healthcheck
health_check() {
    if [[ "$1" == "--health" ]]; then
        echo -e "${GREEN}[HEALTH]${NC} Verificando estado del sistema..."
        
        # Verificar Python
        if python3 -c "import sys; exit(0)" 2>/dev/null; then
            echo -e "${GREEN}[✓]${NC} Python OK"
        else
            echo -e "${RED}[✗]${NC} Python ERROR"
            exit 1
        fi
        
        # Verificar web UI si está activo
        if [[ "$SCAN_MODE" == "web" ]]; then
            if curl -f "http://localhost:$WEB_PORT/health" &>/dev/null; then
                echo -e "${GREEN}[✓]${NC} Web UI OK"
            else
                echo -e "${RED}[✗]${NC} Web UI ERROR"
                exit 1
            fi
        fi
        
        echo -e "${GREEN}[HEALTH]${NC} Sistema funcionando correctamente"
        exit 0
    fi
}

# ============================================================================
# SCRIPT PRINCIPAL
# ============================================================================

# Crear directorio de logs
mkdir -p "$LOG_DIR"

# Inicializar log
log "INFO" "=== Scan Agent v3.0 Docker Container Starting ==="
log "INFO" "Arguments: $*"
log "INFO" "Environment: SCAN_MODE=$SCAN_MODE, LOG_LEVEL=$LOG_LEVEL"

# Verificar healthcheck
health_check "$@"

# Mostrar banner
show_banner

# Verificar herramientas
check_tools "$@"

# Configurar directorios
setup_directories

# Verificar permisos de red
check_network_permissions "$@"

# Configurar modo web si es necesario
setup_web_mode "$@"

# Determinar comando a ejecutar
if [[ "$*" == *"--web"* ]] || [[ "$SCAN_MODE" == "web" ]]; then
    # Modo web
    log "INFO" "Starting web mode"
    echo -e "${GREEN}[*]${NC} Iniciando Web UI: ${WHITE}uvicorn webapp.main:app --host $WEB_HOST --port $WEB_PORT${NC}"
    cd /scan-agent
    exec uvicorn webapp.main:app --host "$WEB_HOST" --port "$WEB_PORT" --reload
elif [[ "$*" == *"--help"* ]] || [[ $# -eq 0 ]] || [[ "$1" == "--help" ]]; then
    # Mostrar ayuda
    log "INFO" "Showing help"
    echo -e "${GREEN}[*]${NC} Mostrando ayuda: ${WHITE}python3 scan-agent.py --help${NC}"
    python3 scan-agent.py --help
elif [[ "$1" == "/bin/bash" ]] || [[ "$1" == "bash" ]]; then
    # Modo interactivo
    log "INFO" "Starting interactive mode"
    echo -e "${GREEN}[*]${NC} Modo interactivo: ${WHITE}/bin/bash${NC}"
    exec /bin/bash
else
    # Modo CLI normal
    log "INFO" "Starting CLI mode with args: $*"
    echo -e "${GREEN}[*]${NC} Ejecutando CLI: ${WHITE}python3 scan-agent.py $*${NC}"
    echo ""
    exec python3 scan-agent.py "$@"
fi
