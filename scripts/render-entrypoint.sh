#!/bin/sh
# render-entrypoint.sh — Script de inicio para Render.com
# =========================================================
# Siembra datos iniciales si el directorio /app/data está vacío
# (ocurre la primera vez que se monta un disco persistente nuevo).

set -e

# Asegurar que los directorios de trabajo existen
mkdir -p /app/data /app/outputs /app/reports /app/logs

# Sembrar catálogo si no existe (primer arranque con disco vacío)
if [ ! -f /app/data/recommendations_catalog.json ]; then
    if [ -f /app/data_seed/recommendations_catalog.json ]; then
        echo "[render] Inicializando catálogo desde semilla..."
        cp /app/data_seed/recommendations_catalog.json /app/data/recommendations_catalog.json
    else
        echo "[render] AVISO: catálogo de recomendaciones no encontrado"
    fi
fi

# Iniciar servidor web
cd /app
exec python3 -m uvicorn webapp.main:app \
    --host 0.0.0.0 \
    --port "${PORT:-8080}" \
    --workers 1 \
    --log-level "${LOG_LEVEL:-info}"
