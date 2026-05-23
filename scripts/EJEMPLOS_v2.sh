#!/bin/bash
#
# EJEMPLOS DE USO - Scan Agent v2.0
# ==================================
# 
# Este script contiene ejemplos prácticos de cómo usar Scan Agent v2.0
# con las nuevas capacidades de escaneo.
#

# Colores para output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          SCAN AGENT v2.0 - EJEMPLOS DE USO                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# =============================================================================
# SECCIÓN 1: INFORMACIÓN DE PERFILES
# =============================================================================

echo -e "\n${YELLOW}═══ 1. LISTAR PERFILES DISPONIBLES ═══${NC}\n"
echo "Comando:"
echo "  python3 agent.py --list-profiles"
echo ""
echo "Descripción:"
echo "  Muestra todos los perfiles de escaneo disponibles con sus características"
echo ""
read -p "Presiona ENTER para ejecutar..." dummy
python3 agent.py --list-profiles
echo ""

echo -e "\n${YELLOW}═══ 2. VER DETALLES DE UN PERFIL ═══${NC}\n"
echo "Comando:"
echo "  python3 agent.py --show-profile web"
echo ""
echo "Descripción:"
echo "  Muestra información detallada del perfil 'web'"
echo ""
read -p "Presiona ENTER para ejecutar..." dummy
python3 agent.py --show-profile web
echo ""

# =============================================================================
# SECCIÓN 2: EJEMPLOS DE ESCANEO
# =============================================================================

echo -e "\n${YELLOW}═══ 3. ESCANEO RÁPIDO (QUICK) ═══${NC}\n"
echo "Comando:"
echo "  python3 agent.py --scan --target OBJETIVO --profile quick"
echo ""
echo "Descripción:"
echo "  Escaneo rápido de ~5 minutos para reconocimiento inicial"
echo "  - Top 100 puertos con nmap"
echo "  - Scan básico con nikto"
echo "  - Análisis de headers HTTP"
echo ""
echo "Ejemplo:"
cat << 'EOF'
# Para escanear un servidor web local
python3 agent.py --scan --target 192.168.1.100 --profile quick

# Para escanear un dominio externo
python3 agent.py --scan --target example.com --profile quick --verbose
EOF
echo ""

echo -e "\n${YELLOW}═══ 4. ESCANEO ESTÁNDAR (STANDARD) ═══${NC}\n"
echo "Comando:"
echo "  python3 agent.py --scan --target OBJETIVO --profile standard"
echo ""
echo "Descripción:"
echo "  Escaneo equilibrado de ~15 minutos"
echo "  - Top 1000 puertos + scripts NSE"
echo "  - Scan completo nikto"
echo "  - Enumeración de directorios (diccionario común)"
echo "  - Análisis completo de headers y respuestas HTTP"
echo ""
echo "Ejemplo:"
cat << 'EOF'
# Escaneo estándar con verbose
python3 agent.py --scan --target 10.0.0.50 --profile standard --verbose

# Escaneo a directorio personalizado
python3 agent.py --scan --target webapp.com --profile standard \
  --outputs-dir ./scan_webapp
EOF
echo ""

echo -e "\n${YELLOW}═══ 5. ESCANEO COMPLETO (FULL) ═══${NC}\n"
echo "Comando:"
echo "  python3 agent.py --scan --target OBJETIVO --profile full"
echo ""
echo "Descripción:"
echo "  Escaneo exhaustivo de 30-60 minutos"
echo "  - Todos los puertos (65535)"
echo "  - Scripts NSE agresivos"
echo "  - Múltiples diccionarios en gobuster"
echo "  - Análisis detallado de todas las respuestas"
echo ""
echo "⚠️  ADVERTENCIA: Este escaneo puede tardar más de 1 hora"
echo ""
echo "Ejemplo:"
cat << 'EOF'
# Escaneo completo con verbose y directorio personalizado
python3 agent.py --scan --target 10.10.10.100 --profile full \
  --outputs-dir ./pentest_full --verbose
EOF
echo ""

echo -e "\n${YELLOW}═══ 6. ESCANEO WEB (WEB) ═══${NC}\n"
echo "Comando:"
echo "  python3 agent.py --scan --target OBJETIVO --profile web"
echo ""
echo "Descripción:"
echo "  Escaneo enfocado en aplicaciones web (~20-30 min)"
echo "  - Puertos web: 80, 443, 8080, 8443"
echo "  - Nikto exhaustivo para vulnerabilidades web"
echo "  - Enumeración extensiva de directorios y archivos"
echo "  - Análisis detallado de cookies y headers de seguridad"
echo ""
echo "Ejemplo:"
cat << 'EOF'
# Escaneo de aplicación web
python3 agent.py --scan --target webapp.company.com --profile web

# Escaneo web con análisis inmediato
python3 agent.py --scan --target api.example.com --profile web && \
python3 agent.py --outputs-dir ./outputs --format html
EOF
echo ""

echo -e "\n${YELLOW}═══ 7. ESCANEO SIGILOSO (STEALTH) ═══${NC}\n"
echo "Comando:"
echo "  sudo python3 agent.py --scan --target OBJETIVO --profile stealth"
echo ""
echo "Descripción:"
echo "  Escaneo diseñado para evadir IDS/IPS (~30-45 min)"
echo "  - Timing paranoid (muy lento)"
echo "  - Fragmentación de paquetes"
echo "  - Uso de decoys (señuelos)"
echo "  - SYN stealth scan"
echo ""
echo "⚠️  REQUIERE SUDO para técnicas avanzadas"
echo ""
echo "Ejemplo:"
cat << 'EOF'
# Escaneo sigiloso (requiere root)
sudo python3 agent.py --scan --target sensitive-server.com --profile stealth

# Con verbose para monitorear progreso
sudo python3 agent.py --scan --target 192.168.1.1 --profile stealth --verbose
EOF
echo ""

echo -e "\n${YELLOW}═══ 8. ESCANEO DE RED (NETWORK) ═══${NC}\n"
echo "Comando:"
echo "  sudo python3 agent.py --scan --target OBJETIVO --profile network"
echo ""
echo "Descripción:"
echo "  Escaneo de infraestructura de red (~40 min)"
echo "  - Detección de sistema operativo"
echo "  - Detección de versiones de servicios"
echo "  - Scripts de descubrimiento de red"
echo "  - Mapeo de topología de red"
echo ""
echo "⚠️  REQUIERE SUDO para detección de OS"
echo ""
echo "Ejemplo:"
cat << 'EOF'
# Escaneo de infraestructura de red
sudo python3 agent.py --scan --target 10.10.10.0/24 --profile network

# Escaneo de servidor individual
sudo python3 agent.py --scan --target router.local --profile network --verbose
EOF
echo ""

echo -e "\n${YELLOW}═══ 9. ESCANEO DE CUMPLIMIENTO (COMPLIANCE) ═══${NC}\n"
echo "Comando:"
echo "  python3 agent.py --scan --target OBJETIVO --profile compliance"
echo ""
echo "Descripción:"
echo "  Verificación de configuraciones seguras (~10 min)"
echo "  - Detección de protocolos inseguros (SSLv2, SSLv3)"
echo "  - Verificación de headers de seguridad"
echo "  - Configuraciones débiles de cifrado"
echo "  - Cookies inseguras"
echo ""
echo "Ejemplo:"
cat << 'EOF'
# Verificación de cumplimiento PCI-DSS / OWASP
python3 agent.py --scan --target secure.bank.com --profile compliance

# Con informe JSON para procesamiento posterior
python3 agent.py --scan --target payment.gateway.com --profile compliance && \
python3 agent.py --outputs-dir ./outputs --format json
EOF
echo ""

echo -e "\n${YELLOW}═══ 10. ESCANEO DE API (API) ═══${NC}\n"
echo "Comando:"
echo "  python3 agent.py --scan --target OBJETIVO --profile api"
echo ""
echo "Descripción:"
echo "  Testing especializado de APIs REST/SOAP (~15 min)"
echo "  - Enumeración de endpoints API"
echo "  - Testing de métodos HTTP (GET, POST, PUT, DELETE, etc.)"
echo "  - Análisis de CORS y autenticación"
echo "  - Detección de vulnerabilidades comunes en APIs"
echo ""
echo "Ejemplo:"
cat << 'EOF'
# Escaneo de API REST
python3 agent.py --scan --target api.example.com --profile api

# Escaneo de microservicios
python3 agent.py --scan --target microservice.k8s.local --profile api --verbose
EOF
echo ""

# =============================================================================
# SECCIÓN 3: WORKFLOW COMPLETO
# =============================================================================

echo -e "\n${YELLOW}═══ 11. WORKFLOW COMPLETO: ESCANEO + ANÁLISIS ═══${NC}\n"
echo "Descripción:"
echo "  Ejemplo de workflow completo desde escaneo hasta informe final"
echo ""
cat << 'EOF'
# PASO 1: Ejecutar escaneo
echo "Ejecutando escaneo..."
python3 agent.py --scan --target 192.168.1.100 --profile standard

# PASO 2: Verificar archivos generados
echo "Archivos generados:"
ls -lh outputs/

# PASO 3: Analizar resultados
echo "Analizando resultados..."
python3 agent.py --outputs-dir ./outputs --format all

# PASO 4: Revisar informes
echo "Informes generados:"
ls -lh informe_tecnico.*

# PASO 5: Abrir informe HTML
firefox informe_tecnico.html &

# PASO 6: Verificar vulnerabilidades críticas
grep -i "CRITICA\|ALTA" informe_tecnico.txt

# PASO 7: Exportar para reportes
cp informe_tecnico.html /ruta/a/entrega/informe_cliente.html
EOF
echo ""

echo -e "\n${YELLOW}═══ 12. PROYECTO COMPLETO DE PENTESTING ═══${NC}\n"
echo "Descripción:"
echo "  Estructura de proyecto profesional para pentesting"
echo ""
cat << 'EOF'
#!/bin/bash
# Script de pentesting completo

# Variables
TARGET="10.0.0.100"
CLIENT="Cliente_Corp"
DATE=$(date +%Y%m%d)
PROJECT_DIR="pentest_${CLIENT}_${DATE}"

# 1. Crear estructura de proyecto
mkdir -p ${PROJECT_DIR}/{recon,scan,analysis,reports}
cd ${PROJECT_DIR}

# 2. Reconocimiento rápido
echo "[*] Fase 1: Reconocimiento..."
python3 ../agent.py --scan --target ${TARGET} --profile quick \
  --outputs-dir ./recon

# 3. Escaneo completo
echo "[*] Fase 2: Escaneo completo..."
python3 ../agent.py --scan --target ${TARGET} --profile full \
  --outputs-dir ./scan --verbose

# 4. Análisis de resultados
echo "[*] Fase 3: Análisis..."
python3 ../agent.py --outputs-dir ./scan --format all

# 5. Mover informes
mv informe_tecnico.* ./reports/

# 6. Generar resumen ejecutivo
echo "[*] Fase 4: Resumen..."
head -n 100 ./reports/informe_tecnico.txt > ./reports/resumen_ejecutivo.txt

# 7. Backup del proyecto
echo "[*] Creando backup..."
cd ..
tar -czf ${PROJECT_DIR}_backup.tar.gz ${PROJECT_DIR}/

echo "[✓] Pentesting completado!"
echo "    Informes en: ${PROJECT_DIR}/reports/"
echo "    Backup: ${PROJECT_DIR}_backup.tar.gz"
EOF
echo ""

# =============================================================================
# SECCIÓN 4: TIPS Y TRUCOS
# =============================================================================

echo -e "\n${YELLOW}═══ 13. TIPS Y TRUCOS ═══${NC}\n"

cat << 'EOF'
# Monitorear progreso del escaneo en tiempo real
watch -n 1 'ls -lh outputs/'

# Verificar qué herramientas están ejecutándose
watch -n 2 'ps aux | grep -E "nmap|nikto|gobuster" | grep -v grep'

# Guardar logs del escaneo
python3 agent.py --scan --target IP --profile standard 2>&1 | tee scan.log

# Escanear múltiples objetivos (script)
for target in 192.168.1.{1..10}; do
  python3 agent.py --scan --target $target --profile quick \
    --outputs-dir ./scans/${target}
done

# Comparar dos escaneos
diff -u scan1/informe_tecnico.txt scan2/informe_tecnico.txt

# Extraer solo vulnerabilidades críticas del JSON
jq '.vulnerabilidades[] | select(.severidad=="CRITICA")' informe_tecnico.json

# Buscar CVEs específicos
grep -r "CVE-" outputs/

# Contar puertos abiertos
grep -c "open" outputs/nmap_service_*.txt

# Generar informe rápido en consola
python3 agent.py --outputs-dir ./outputs --format txt && \
cat informe_tecnico.txt | head -n 50
EOF
echo ""

# =============================================================================
# SECCIÓN 5: TROUBLESHOOTING
# =============================================================================

echo -e "\n${YELLOW}═══ 14. TROUBLESHOOTING ═══${NC}\n"

cat << 'EOF'
# Verificar instalación de herramientas
which nmap nikto gobuster curl

# Verificar versiones
nmap --version
nikto -Version

# Probar escaneo manual con nmap
nmap -p 80,443 -sV google.com

# Verificar permisos
ls -la agent.py scanner.py

# Modo debug extremo
python3 -u agent.py --scan --target IP --profile quick --verbose 2>&1 | tee debug.log

# Limpiar outputs anteriores
rm -rf outputs/*

# Verificar espacio en disco
df -h .

# Ver procesos bloqueados
lsof | grep -E "nmap|nikto|gobuster"
EOF
echo ""

# =============================================================================
# FIN
# =============================================================================

echo -e "\n${GREEN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                   EJEMPLOS COMPLETADOS                         ║"
echo "║                                                                ║"
echo "║  Para más información:                                         ║"
echo "║    - README.md       : Documentación general                   ║"
echo "║    - GUIA_ESCANEO.md : Guía detallada de escaneo              ║"
echo "║    - RESUMEN.md      : Resumen técnico del proyecto           ║"
echo "║                                                                ║"
echo "║  Comandos útiles:                                              ║"
echo "║    python3 agent.py --help                                     ║"
echo "║    python3 agent.py --list-profiles                            ║"
echo "║    python3 agent.py --show-profile <nombre>                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
