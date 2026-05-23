#!/bin/bash
# build.sh - Script para construir la imagen Docker de Scan Agent
# ================================================================

set -e

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Scan Agent v2.1 - Docker Build       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""

# Verificar que Docker está instalado
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[✗]${NC} Docker no está instalado"
    echo -e "${YELLOW}[!]${NC} Instalar Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

echo -e "${GREEN}[✓]${NC} Docker detectado: $(docker --version)"
echo ""

# Opciones
IMAGE_NAME="scan-agent"
IMAGE_TAG="2.1.0"
NO_CACHE=${1:-false}

# Construir
echo -e "${YELLOW}[*]${NC} Construyendo imagen ${IMAGE_NAME}:${IMAGE_TAG}..."
echo ""

# Cambiar al directorio raíz del proyecto
cd "$(dirname "$0")/.."

if [ "$NO_CACHE" == "--no-cache" ]; then
    echo -e "${YELLOW}[!]${NC} Modo: Sin caché"
    docker build --no-cache -f docker/Dockerfile -t ${IMAGE_NAME}:${IMAGE_TAG} .
else
    docker build -f docker/Dockerfile -t ${IMAGE_NAME}:${IMAGE_TAG} .
fi

# Verificar construcción
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}[✓]${NC} Imagen construida exitosamente"
    echo ""
    echo -e "${GREEN}Imagen:${NC} ${IMAGE_NAME}:${IMAGE_TAG}"
    docker images | grep ${IMAGE_NAME}
    echo ""
    echo -e "${YELLOW}Comandos útiles:${NC}"
    echo "  docker run --rm ${IMAGE_NAME}:${IMAGE_TAG} --help"
    echo "  docker run --rm ${IMAGE_NAME}:${IMAGE_TAG} --version"
    echo "  docker run --rm ${IMAGE_NAME}:${IMAGE_TAG} --list-profiles"
    echo ""
    echo -e "${YELLOW}Escaneo rápido:${NC}"
    echo "  docker run --rm -v \$(pwd)/outputs:/scan-agent/outputs ${IMAGE_NAME}:${IMAGE_TAG} --scan --target 127.0.0.1 --profile quick"
    echo ""
else
    echo -e "${RED}[✗]${NC} Error al construir la imagen"
    exit 1
fi
