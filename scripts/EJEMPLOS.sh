#!/bin/bash
#
# EJEMPLOS DE USO - Scan Agent
# =============================
# Este script muestra diferentes formas de usar el agente
#

echo "============================================"
echo "EJEMPLOS DE USO DEL SCAN AGENT"
echo "============================================"
echo ""

# Ejemplo 1: Uso básico (todos los formatos)
echo "1. Uso Básico - Generar todos los formatos de informe"
echo "   Comando:"
echo "   $ python3 agent.py"
echo ""

# Ejemplo 2: Solo HTML
echo "2. Generar solo informe HTML"
echo "   Comando:"
echo "   $ python3 agent.py --format html"
echo ""

# Ejemplo 3: Especificar directorio
echo "3. Especificar directorio personalizado de archivos"
echo "   Comando:"
echo "   $ python3 agent.py --outputs-dir /ruta/a/escaneos"
echo ""

# Ejemplo 4: Especificar IP manualmente
echo "4. Especificar IP objetivo manualmente"
echo "   Comando:"
echo "   $ python3 agent.py --target-ip 192.168.1.100"
echo ""

# Ejemplo 5: Modo verbose
echo "5. Modo verbose para depuración"
echo "   Comando:"
echo "   $ python3 agent.py --verbose"
echo ""

# Ejemplo 6: Combinado
echo "6. Combinando múltiples opciones"
echo "   Comando:"
echo "   $ python3 agent.py --outputs-dir ./scans --format all --verbose"
echo ""

# Ejemplo 7: Ver ayuda
echo "7. Ver todas las opciones disponibles"
echo "   Comando:"
echo "   $ python3 agent.py --help"
echo ""

echo "============================================"
echo "FLUJO COMPLETO DE TRABAJO"
echo "============================================"
echo ""
echo "PASO 1: Realizar escaneos con herramientas de pentesting"
echo "--------"
echo "TARGET=\"10.1.11.177\""
echo ""
echo "# Nmap - Escaneo de servicios"
echo "nmap -sV -p- \$TARGET -oN outputs/nmap_service_\$TARGET.txt"
echo ""
echo "# Nmap - Scripts de vulnerabilidades"
echo "nmap --script=vuln,exploit \$TARGET -oN outputs/nmap_nse_\$TARGET.txt"
echo ""
echo "# Nikto - Escaneo web"
echo "nikto -h http://\$TARGET -o outputs/nikto_\$TARGET.txt"
echo ""
echo "# Gobuster - Descubrimiento de directorios"
echo "gobuster dir -u http://\$TARGET -w /usr/share/wordlists/dirb/common.txt -o outputs/gobuster_\$TARGET.txt"
echo ""
echo "# Headers HTTP"
echo "curl -I http://\$TARGET > outputs/headers_\$TARGET.txt"
echo ""
echo "# Curl verbose"
echo "curl -v http://\$TARGET > outputs/curl_verbose_\$TARGET.txt 2>&1"
echo ""
echo "PASO 2: Ejecutar el agente"
echo "--------"
echo "python3 agent.py"
echo ""
echo "PASO 3: Revisar informes"
echo "--------"
echo "# Ver informe HTML en navegador"
echo "firefox informe_tecnico.html"
echo ""
echo "# O leer el informe en texto"
echo "cat informe_tecnico.txt | less"
echo ""

echo "============================================"
echo "ARCHIVOS GENERADOS"
echo "============================================"
echo ""
echo "El agente genera los siguientes archivos:"
echo ""
echo "  📄 parsed_data.json      - Datos parseados (intermedio)"
echo "  📄 analysis.json         - Análisis completo (intermedio)"
echo "  📄 informe_tecnico.txt   - Informe en texto plano"
echo "  📄 informe_tecnico.json  - Informe estructurado en JSON"
echo "  📄 informe_tecnico.html  - Informe web interactivo ⭐"
echo "  📄 informe_tecnico.md    - Informe en Markdown"
echo ""

echo "============================================"
echo "TIPS Y RECOMENDACIONES"
echo "============================================"
echo ""
echo "✅ Usa el formato HTML para presentaciones profesionales"
echo "✅ El formato JSON es ideal para integración con otras herramientas"
echo "✅ Usa --verbose para ver detalles del proceso de análisis"
echo "✅ Los archivos deben seguir el patrón: herramienta_IP.txt"
echo "✅ No es necesario tener todos los archivos - el agente funciona con los disponibles"
echo "✅ Revisa primero el Resumen Ejecutivo para priorizar acciones"
echo ""

echo "============================================"
echo "EJECUCIÓN DE EJEMPLO"
echo "============================================"
echo ""
echo "¿Ejecutar el agente ahora con los archivos de ejemplo? (s/n)"
read -r response

if [[ "$response" =~ ^[Ss]$ ]]; then
    echo ""
    echo "Ejecutando: python3 agent.py --verbose"
    echo ""
    python3 agent.py --verbose
    
    echo ""
    echo "============================================"
    echo "✅ ¡Proceso completado!"
    echo "============================================"
    echo ""
    echo "Los informes han sido generados."
    echo "Para ver el informe HTML, ejecuta:"
    echo "  firefox informe_tecnico.html"
    echo ""
else
    echo ""
    echo "OK. Puedes ejecutar el agente manualmente cuando estés listo."
    echo ""
fi
