#!/bin/bash

# Colores para output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}  Scan Agent - Web Interface${NC}"
echo -e "${BLUE}================================${NC}\n"

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Error: Python3 no está instalado${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}✓${NC} Python detectado: $PYTHON_VERSION"

# Crear entorno virtual si no existe
if [ ! -d "venv" ]; then
    echo -e "\n${YELLOW}📦 Creando entorno virtual...${NC}"
    python3 -m venv venv
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} Entorno virtual creado exitosamente"
    else
        echo -e "${RED}❌ Error al crear entorno virtual${NC}"
        echo -e "${YELLOW}Intenta instalar: sudo apt install python3-venv${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓${NC} Entorno virtual ya existe"
fi

# Activar entorno virtual
echo -e "\n${YELLOW}🔄 Activando entorno virtual...${NC}"
source venv/bin/activate

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Entorno virtual activado"
else
    echo -e "${RED}❌ Error al activar entorno virtual${NC}"
    exit 1
fi

# Actualizar pip
echo -e "\n${YELLOW}⬆️  Actualizando pip...${NC}"
pip install --upgrade pip > /dev/null 2>&1
echo -e "${GREEN}✓${NC} pip actualizado"

# Instalar/Actualizar dependencias
echo -e "\n${YELLOW}📥 Instalando dependencias...${NC}"
pip install -r webapp/requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Dependencias instaladas correctamente"
else
    echo -e "${RED}❌ Error al instalar dependencias${NC}"
    deactivate
    exit 1
fi

# Verificar instalación de FastAPI
echo -e "\n${YELLOW}🔍 Verificando instalación...${NC}"
python -c "import fastapi, uvicorn, pydantic" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Todas las dependencias están correctas"
else
    echo -e "${RED}❌ Faltan algunas dependencias${NC}"
    deactivate
    exit 1
fi

# Mostrar información
echo -e "\n${BLUE}================================${NC}"
echo -e "${GREEN}✓ Sistema listo para iniciar${NC}"
echo -e "${BLUE}================================${NC}\n"

echo -e "${YELLOW}📍 URLs disponibles:${NC}"
echo -e "   Aplicación Web: ${GREEN}http://localhost:8000${NC}"
echo -e "   Swagger UI:     ${GREEN}http://localhost:8000/docs${NC}"
echo -e "   ReDoc:          ${GREEN}http://localhost:8000/redoc${NC}"
echo -e "\n${YELLOW}ℹ️  Presiona Ctrl+C para detener el servidor${NC}\n"

# Iniciar servidor
echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}  Iniciando servidor...${NC}"
echo -e "${BLUE}================================${NC}\n"

# Ejecutar desde raíz del proyecto usando Python del venv
python -m uvicorn webapp.main:app --reload --host 0.0.0.0 --port 8000

# Al salir, desactivar entorno virtual
deactivate#!/bin/bash
#
# Script de inicio rápido para Scan Agent Web
# ============================================

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              SCAN AGENT WEB - INICIO RÁPIDO                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Verificar Python
echo "🔍 Verificando Python..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 no está instalado"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✅ Python $PYTHON_VERSION encontrado"
echo ""

# Verificar dependencias web
echo "🔍 Verificando dependencias web..."
if ! python3 -c "import fastapi" 2>/dev/null; then
    echo "📦 Instalando dependencias web..."
    pip3 install -r webapp/requirements.txt
    echo "✅ Dependencias instaladas"
else
    echo "✅ Dependencias ya instaladas"
fi
echo ""

# Verificar herramientas de escaneo (opcional)
echo "🔍 Verificando herramientas de escaneo..."
TOOLS_MISSING=()

if ! command -v nmap &> /dev/null; then
    TOOLS_MISSING+=("nmap")
fi

if ! command -v nikto &> /dev/null; then
    TOOLS_MISSING+=("nikto")
fi

if ! command -v gobuster &> /dev/null; then
    TOOLS_MISSING+=("gobuster")
fi

if [ ${#TOOLS_MISSING[@]} -gt 0 ]; then
    echo "⚠️  Herramientas faltantes: ${TOOLS_MISSING[*]}"
    echo "   Para instalarlas: sudo apt install -y ${TOOLS_MISSING[*]}"
    echo "   (Opcional, solo necesarias para ejecutar escaneos)"
else
    echo "✅ Todas las herramientas de escaneo están instaladas"
fi
echo ""

# Crear directorios necesarios
echo "📁 Creando directorios..."
mkdir -p outputs reports
echo "✅ Directorios creados"
echo ""

# Iniciar servidor
echo "🚀 Iniciando servidor web..."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   🌐 Interfaz Web:    http://localhost:8000"
echo "   📚 Documentación:   http://localhost:8000/api/docs"
echo "   ❤️  Health Check:   http://localhost:8000/health"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Presiona Ctrl+C para detener el servidor"
echo ""

uvicorn webapp.main:app --host 0.0.0.0 --port 8000 --reload
