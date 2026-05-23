#!/bin/bash

# Script para probar el escaneo con los nuevos reportes

echo "🧪 Iniciando escaneo de prueba..."

RESPONSE=$(curl -s -X POST http://localhost:8000/api/scans/start \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org", "profile": "quick", "output_formats": ["json", "html", "txt", "md"]}')

echo "$RESPONSE" | python3 -m json.tool

SCAN_ID=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['scan_id'])" 2>/dev/null)

if [ ! -z "$SCAN_ID" ]; then
    echo ""
    echo "✅ Escaneo iniciado: $SCAN_ID"
    echo ""
    echo "Esperando 30 segundos para que complete..."
    
    for i in {1..30}; do
        sleep 1
        echo -n "."
    done
    
    echo ""
    echo ""
    echo "📊 Estado del escaneo:"
    curl -s http://localhost:8000/api/scans/status/$SCAN_ID | python3 -m json.tool
    
    echo ""
    echo "📁 Reportes generados:"
    ls -lh reports/scan_$SCAN_ID.* 2>/dev/null || echo "No se encontraron reportes aún"
    
    echo ""
    echo "🔍 Para ver el reporte HTML, abre:"
    echo "   file:///home/clase/scan-agent/reports/scan_$SCAN_ID.html"
else
    echo "❌ Error al iniciar el escaneo"
fi
