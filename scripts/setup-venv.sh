#!/bin/bash

# Script de configuración inicial del entorno virtual
# Este script solo necesita ejecutarse una vez

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}  Setup - Scan Agent Web        ${NC}"
echo -e "${BLUE}================================${NC}\n"

# Verificar si python3-venv está instalado
echo -e "${YELLOW}🔍 Verificando python3-venv...${NC}"
dpkg -l | grep python3-venv > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠️  python3-venv no está instalado${NC}"
    echo -e "${YELLOW}📦 Instalando python3-venv...${NC}\n"
    
    sudo apt update
    sudo apt install -y python3-venv python3-full
    
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✓${NC} python3-venv instalado correctamente"
    else
        echo -e "\n${RED}❌ Error al instalar python3-venv${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓${NC} python3-venv ya está instalado"
fi

# Crear entorno virtual
echo -e "\n${YELLOW}📦 Creando entorno virtual...${NC}"
python3 -m venv venv

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Entorno virtual creado"
else
    echo -e "${RED}❌ Error al crear entorno virtual${NC}"
    exit 1
fi

# Activar y actualizar pip
echo -e "\n${YELLOW}🔄 Activando entorno virtual...${NC}"
source venv/bin/activate

echo -e "${YELLOW}⬆️  Actualizando pip...${NC}"
pip install --upgrade pip

# Instalar dependencias
echo -e "\n${YELLOW}📥 Instalando dependencias...${NC}"
pip install -r webapp/requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Dependencias instaladas"
else
    echo -e "${RED}❌ Error al instalar dependencias${NC}"
    deactivate
    exit 1
fi

# Verificar instalación
echo -e "\n${YELLOW}🔍 Verificando instalación...${NC}"
python3 -c "import fastapi, uvicorn, pydantic, jinja2" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Todas las dependencias verificadas"
else
    echo -e "${RED}❌ Error en las dependencias${NC}"
    deactivate
    exit 1
fi

deactivate

# Resumen
echo -e "\n${BLUE}================================${NC}"
echo -e "${GREEN}✓ Setup completado exitosamente${NC}"
echo -e "${BLUE}================================${NC}\n"

echo -e "${YELLOW}📝 Próximos pasos:${NC}"
echo -e "   1. Ejecuta: ${GREEN}./start-web.sh${NC}"
echo -e "   2. Abre: ${GREEN}http://localhost:8000${NC}"
echo -e "   3. Para detener: ${GREEN}Ctrl+C${NC} o ${GREEN}./stop-web.sh${NC}\n"

echo -e "${YELLOW}ℹ️  El entorno virtual está en:${NC} ${GREEN}./venv/${NC}\n"
