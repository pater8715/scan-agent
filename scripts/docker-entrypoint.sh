#!/bin/bash
# docker-entrypoint.sh - Script de entrada para contenedor Scan Agent
# =====================================================================

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Scan Agent v2.1 - Docker Edition    ║${NC}"
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo ""

# Verificar herramientas instaladas
echo -e "${YELLOW}[*]${NC} Verificando herramientas..."
for tool in nmap nikto gobuster curl python3; do
    if command -v $tool &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} $tool - $(command -v $tool)"
    else
        echo -e "${RED}[✗]${NC} $tool - No encontrado"
    fi
done
echo ""

# Crear directorios si no existen
mkdir -p /scan-agent/outputs
mkdir -p /scan-agent/reports
mkdir -p /scan-agent/data

# Si se pasa --scan, verificar permisos para escaneos que requieren sudo
if [[ "$*" == *"--scan"* ]]; then
    if [[ "$*" == *"--profile stealth"* ]] || [[ "$*" == *"--profile network"* ]]; then
        echo -e "${YELLOW}[!]${NC} Escaneo requiere permisos elevados (SYN scan)"
        echo -e "${YELLOW}[!]${NC} Ejecutar contenedor con: docker run --cap-add=NET_RAW --cap-add=NET_ADMIN"
        echo ""
    fi
fi

# Ejecutar comando
echo -e "${GREEN}[*]${NC} Ejecutando: python3 scan-agent.py $@"
echo ""

exec python3 scan-agent.py "$@"
