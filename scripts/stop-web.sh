#!/bin/bash

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}🛑 Deteniendo Scan Agent Web...${NC}\n"

# Buscar proceso de uvicorn
PID=$(ps aux | grep "uvicorn main:app" | grep -v grep | awk '{print $2}')

if [ -z "$PID" ]; then
    echo -e "${YELLOW}ℹ️  No hay servidor ejecutándose${NC}"
else
    echo -e "${YELLOW}📍 Encontrado proceso: PID $PID${NC}"
    kill $PID
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} Servidor detenido correctamente"
    else
        echo -e "${RED}❌ Error al detener servidor${NC}"
        echo -e "${YELLOW}Intenta: sudo kill -9 $PID${NC}"
    fi
fi

# Desactivar entorno virtual si está activo
if [ -n "$VIRTUAL_ENV" ]; then
    deactivate 2>/dev/null
    echo -e "${GREEN}✓${NC} Entorno virtual desactivado"
fi

echo -e "\n${GREEN}✓ Scan Agent Web detenido${NC}"
