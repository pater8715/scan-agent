#!/bin/bash
# docker-test.sh - Script de pruebas para configuración Docker
# ===========================================================
# Valida que los archivos Docker funcionen correctamente

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variables
IMAGE_NAME="scan-agent"
VERSION="3.0.0"
TEST_TARGET="scanme.nmap.org"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              Scan Agent v3.3 - Docker Tests             ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Función para logging
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[✓]${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[!]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[✗]${NC} $message"
            ;;
    esac
}

# Función para ejecutar test
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "\n${YELLOW}Testing:${NC} $test_name"
    echo -e "${BLUE}Command:${NC} $test_command"
    echo "----------------------------------------"
    
    if eval "$test_command"; then
        log "SUCCESS" "$test_name"
        return 0
    else
        log "ERROR" "$test_name FAILED"
        return 1
    fi
}

# Variables de control
FAILED_TESTS=0
TOTAL_TESTS=0

#!/bin/bash
# docker-test.sh - Script de pruebas para Docker
# ==============================================
# Valida que la configuración Docker funcione correctamente

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Variables
IMAGE_NAME="scan-agent:3.0.0"
TEST_TARGET="scanme.nmap.org"
TIMEOUT=300  # 5 minutos

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🧪 SCAN AGENT v3.0 - DOCKER TESTING SUITE 🧪              ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Función de logging
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] [${level}] ${message}"
}

# Función para ejecutar test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_exit_code="${3:-0}"
    
    echo -e "${BLUE}[TEST]${NC} Ejecutando: ${YELLOW}${test_name}${NC}"
    echo -e "${BLUE}[CMD]${NC} ${test_command}"
    
    if timeout $TIMEOUT bash -c "$test_command"; then
        if [ $? -eq $expected_exit_code ]; then
            echo -e "${GREEN}[PASS]${NC} ✅ ${test_name}"
            return 0
        else
            echo -e "${RED}[FAIL]${NC} ❌ ${test_name} - Exit code incorrecto"
            return 1
        fi
    else
        echo -e "${RED}[FAIL]${NC} ❌ ${test_name} - Timeout o error"
        return 1
    fi
}

# Contadores
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

# ============================================================================
# TESTS BÁSICOS
# ============================================================================

echo -e "${CYAN}[PHASE 1]${NC} Tests básicos de imagen"
echo "=============================================="

# Test 1: Verificar que la imagen existe
TESTS_TOTAL=$((TESTS_TOTAL + 1))
if run_test "Imagen Docker existe" "docker images | grep -q 'scan-agent.*3.0.0'"; then
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${YELLOW}[INFO]${NC} Construyendo imagen..."
    if docker build -t $IMAGE_NAME -f docker/Dockerfile .; then
        echo -e "${GREEN}[OK]${NC} Imagen construida exitosamente"
    else
        echo -e "${RED}[ERROR]${NC} Error construyendo imagen"
        exit 1
    fi
fi

# Test 2: Contenedor inicia correctamente
TESTS_TOTAL=$((TESTS_TOTAL + 1))
if run_test "Contenedor inicia" "docker run --rm $IMAGE_NAME --version"; then
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 2: Verificar Docker Compose
echo -e "\n${BLUE}[2/10]${NC} Verificando Docker Compose..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if ! command -v docker-compose &> /dev/null; then
    log "ERROR" "Docker Compose no está instalado"
    exit 1
fi
log "SUCCESS" "Docker Compose encontrado: $(docker-compose --version)"

# Test 3: Construir imagen
echo -e "\n${BLUE}[3/10]${NC} Construyendo imagen Docker..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if run_test "Build Image" "docker build -t $IMAGE_NAME:$VERSION -f docker/Dockerfile . > /dev/null 2>&1"; then
    log "SUCCESS" "Imagen construida correctamente"
else
    log "ERROR" "Fallo en construcción de imagen"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 4: Verificar imagen creada
echo -e "\n${BLUE}[4/10]${NC} Verificando imagen creada..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if docker images | grep -q "$IMAGE_NAME.*$VERSION"; then
    log "SUCCESS" "Imagen $IMAGE_NAME:$VERSION encontrada"
    # Mostrar información de la imagen
    echo -e "${BLUE}Detalles de la imagen:${NC}"
    docker images | grep "$IMAGE_NAME.*$VERSION"
else
    log "ERROR" "Imagen no encontrada"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 5: Test básico de ayuda
echo -e "\n${BLUE}[5/10]${NC} Probando comando --help..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if run_test "Help Command" "docker run --rm $IMAGE_NAME:$VERSION --help > /dev/null 2>&1"; then
    log "SUCCESS" "Comando --help funciona"
else
    log "ERROR" "Comando --help falló"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 6: Test de versión
echo -e "\n${BLUE}[6/10]${NC} Probando comando --version..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if run_test "Version Command" "docker run --rm $IMAGE_NAME:$VERSION --version > /dev/null 2>&1"; then
    log "SUCCESS" "Comando --version funciona"
    echo -e "${BLUE}Versión:${NC} $(docker run --rm $IMAGE_NAME:$VERSION --version 2>/dev/null)"
else
    log "ERROR" "Comando --version falló"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 7: Test de perfiles
echo -e "\n${BLUE}[7/10]${NC} Probando listado de perfiles..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if run_test "List Profiles" "docker run --rm $IMAGE_NAME:$VERSION --list-profiles > /dev/null 2>&1"; then
    log "SUCCESS" "Listado de perfiles funciona"
    echo -e "${BLUE}Perfiles disponibles:${NC}"
    docker run --rm $IMAGE_NAME:$VERSION --list-profiles 2>/dev/null | grep -E "^\s*-" | head -5
else
    log "ERROR" "Listado de perfiles falló"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 8: Test de directorios
echo -e "\n${BLUE}[8/10]${NC} Verificando estructura de directorios..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))
mkdir -p test_outputs test_reports test_data test_logs
if run_test "Directory Structure" "docker run --rm -v $(pwd)/test_outputs:/scan-agent/outputs -v $(pwd)/test_reports:/scan-agent/reports $IMAGE_NAME:$VERSION --version > /dev/null 2>&1"; then
    log "SUCCESS" "Estructura de directorios OK"
    # Limpiar directorios de prueba
    rm -rf test_outputs test_reports test_data test_logs
else
    log "ERROR" "Problema con estructura de directorios"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 9: Test docker-compose syntax
echo -e "\n${BLUE}[9/10]${NC} Verificando sintaxis de docker-compose..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))
cd docker
if run_test "Docker Compose Syntax" "docker-compose config > /dev/null 2>&1"; then
    log "SUCCESS" "Sintaxis de docker-compose.yml es válida"
else
    log "ERROR" "Error en sintaxis de docker-compose.yml"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
cd ..

# Test 10: Test de análisis (usando archivos de ejemplo si existen)
echo -e "\n${BLUE}[10/10]${NC} Probando análisis de archivos de ejemplo..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if [ -d "examples" ] && [ "$(ls -A examples/)" ]; then
    if run_test "Analysis Test" "docker run --rm -v $(pwd)/examples:/scan-agent/outputs -v $(pwd)/reports:/scan-agent/reports $IMAGE_NAME:$VERSION --outputs-dir /scan-agent/outputs --format txt > /dev/null 2>&1"; then
        log "SUCCESS" "Análisis de archivos de ejemplo funciona"
    else
        log "WARNING" "Análisis de archivos de ejemplo falló (puede ser normal si no hay archivos compatibles)"
    fi
else
    log "WARNING" "No se encontraron archivos de ejemplo para probar análisis"
fi

# Resumen final
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                      RESUMEN DE TESTS                   ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

PASSED_TESTS=$((TOTAL_TESTS - FAILED_TESTS))

if [ $FAILED_TESTS -eq 0 ]; then
    log "SUCCESS" "Todos los tests pasaron ($PASSED_TESTS/$TOTAL_TESTS)"
    echo ""
    echo -e "${GREEN}✅ Configuración Docker de Scan Agent v3.0 está lista para usar${NC}"
    echo ""
    echo -e "${BLUE}Comandos útiles:${NC}"
    echo "• make build              # Construir imagen"
    echo "• make run-web           # Iniciar interfaz web"
    echo "• make run-cli TARGET=scanme.nmap.org  # Escaneo CLI"
    echo "• make shell             # Acceso interactivo"
    echo "• docker-compose --profile web up  # Web UI con compose"
    exit 0
else
    log "ERROR" "Algunos tests fallaron ($FAILED_TESTS/$TOTAL_TESTS)"
    echo ""
    echo -e "${RED}❌ Hay problemas con la configuración Docker${NC}"
    echo ""
    echo -e "${YELLOW}Sugerencias para depurar:${NC}"
    echo "• Verificar logs: docker logs <container_name>"
    echo "• Probar construcción manual: docker build -f docker/Dockerfile ."
    echo "• Verificar sintaxis: docker-compose config"
    exit 1
fi