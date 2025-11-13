# 📡 Guía de Escaneo - Scan Agent v2.0

## Índice
1. [Introducción](#introducción)
2. [Instalación de Herramientas](#instalación-de-herramientas)
3. [Perfiles de Escaneo](#perfiles-de-escaneo)
4. [Uso Básico](#uso-básico)
5. [Ejemplos Prácticos](#ejemplos-prácticos)
6. [Troubleshooting](#troubleshooting)
7. [Mejores Prácticas](#mejores-prácticas)

---

## Introducción

La versión 2.0 de Scan Agent incluye capacidades de **escaneo automático** que permiten ejecutar análisis de vulnerabilidades sin necesidad de archivos pre-existentes.

### Workflow Completo

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐      ┌──────────────┐
│  ESCANEO    │ ───> │   PARSING    │ ───> │  ANÁLISIS   │ ───> │   INFORMES   │
│  (v2.0)     │      │              │      │             │      │              │
└─────────────┘      └──────────────┘      └─────────────┘      └──────────────┘
  nmap, nikto     Extracción datos    Clasificación CVSS    HTML, PDF, JSON
  gobuster, curl   en JSON            OWASP Top 10          Markdown, TXT
```

---

## Instalación de Herramientas

### Debian/Ubuntu/Kali Linux

```bash
# Actualizar repositorios
sudo apt update

# Instalar herramientas de pentesting
sudo apt install -y nmap nikto gobuster curl

# Verificar instalación
nmap --version
nikto -Version
gobuster version
curl --version
```

### Fedora/RHEL/CentOS

```bash
# Instalar herramientas
sudo dnf install -y nmap nikto gobuster curl

# Verificar instalación
which nmap nikto gobuster curl
```

### Arch Linux

```bash
# Instalar herramientas
sudo pacman -S nmap nikto gobuster curl

# Verificar instalación
nmap --version
```

### Verificación desde Scan Agent

```bash
# El agente puede verificar automáticamente
cd scan-agent
python3 scanner.py --check-tools
```

---

## Perfiles de Escaneo

### 1️⃣ Quick (Rápido)

**Duración:** ~5 minutos  
**Uso:** Reconocimiento inicial, pruebas rápidas  
**Requiere sudo:** No

**Herramientas:**
- Nmap: Top 100 puertos
- Nikto: Scan básico
- Headers: Análisis de cabeceras

**Comando:**
```bash
python3 agent.py --scan --target 192.168.1.100 --profile quick
```

---

### 2️⃣ Standard (Estándar)

**Duración:** ~15 minutos  
**Uso:** Análisis regular, equilibrio velocidad/profundidad  
**Requiere sudo:** No

**Herramientas:**
- Nmap: Top 1000 puertos + scripts NSE
- Nikto: Scan completo
- Gobuster: Enumeración de directorios (diccionario común)
- Headers + Curl: Análisis de respuestas

**Comando:**
```bash
python3 agent.py --scan --target example.com --profile standard
```

---

### 3️⃣ Full (Completo)

**Duración:** 30-60 minutos  
**Uso:** Pentesting completo, auditorías exhaustivas  
**Requiere sudo:** No

**Herramientas:**
- Nmap: Todos los puertos (65535) + scripts NSE agresivos
- Nikto: Scan exhaustivo con todas las opciones
- Gobuster: Múltiples diccionarios (common + medium)
- Headers + Curl: Análisis detallado

**Comando:**
```bash
python3 agent.py --scan --target 10.0.0.50 --profile full --verbose
```

---

### 4️⃣ Web (Aplicaciones Web)

**Duración:** 20-30 minutos  
**Uso:** Enfoque exclusivo en vulnerabilidades web  
**Requiere sudo:** No

**Herramientas:**
- Nmap: Puertos web (80, 443, 8080, 8443)
- Nikto: Scan web exhaustivo
- Gobuster: Enumeración extensiva de directorios/archivos
- Headers + Curl: Análisis de respuestas y cookies

**Comando:**
```bash
python3 agent.py --scan --target webapp.example.com --profile web
```

---

### 5️⃣ Stealth (Sigiloso)

**Duración:** 30-45 minutos  
**Uso:** Evasión de IDS/IPS, pentesting no detectado  
**Requiere sudo:** ✅ Sí (para técnicas de fragmentación)

**Características:**
- Timing: T1 (paranoid) - muy lento
- Fragmentación de paquetes
- Decoys (señuelos)
- Escaneo SYN stealth

**Comando:**
```bash
sudo python3 agent.py --scan --target 192.168.1.100 --profile stealth
```

⚠️ **Importante:** Este perfil es muy lento pero difícil de detectar.

---

### 6️⃣ Network (Red/Infraestructura)

**Duración:** ~40 minutos  
**Uso:** Análisis de infraestructura de red completa  
**Requiere sudo:** ✅ Sí (para detección de OS)

**Herramientas:**
- Nmap: Detección de OS y versiones
- Nmap: Scripts de descubrimiento de red
- Análisis de servicios de infraestructura

**Comando:**
```bash
sudo python3 agent.py --scan --target 10.10.10.0/24 --profile network
```

---

### 7️⃣ Compliance (Cumplimiento)

**Duración:** ~10 minutos  
**Uso:** Verificación de configuraciones seguras (PCI-DSS, OWASP)  
**Requiere sudo:** No

**Verifica:**
- Protocolos inseguros (SSLv2, SSLv3, TLSv1.0)
- Headers de seguridad faltantes
- Configuraciones débiles de cifrado
- Cookies inseguras

**Comando:**
```bash
python3 agent.py --scan --target secure.example.com --profile compliance
```

---

### 8️⃣ API (APIs REST/SOAP)

**Duración:** ~15 minutos  
**Uso:** Testing específico de APIs  
**Requiere sudo:** No

**Herramientas:**
- Gobuster: Enumeración de endpoints API
- Curl: Testing de métodos HTTP
- Headers: Análisis de CORS, autenticación

**Comando:**
```bash
python3 agent.py --scan --target api.example.com --profile api
```

---

## Uso Básico

### Listar Perfiles Disponibles

```bash
python3 agent.py --list-profiles
```

**Salida:**
```
Perfiles de Escaneo Disponibles:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 1. quick       ⏱️  ~5 min      Escaneo rápido
 2. standard    ⏱️  ~15 min     Escaneo estándar equilibrado
 3. full        ⏱️  30-60 min   Escaneo exhaustivo completo
 ...
```

### Ver Detalles de un Perfil

```bash
python3 agent.py --show-profile web
```

**Salida:**
```
Perfil: web
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Descripción: Escaneo enfocado en aplicaciones web
Duración estimada: 20-30 minutos
Requiere sudo: No

Herramientas utilizadas:
  • nmap
  • nikto
  • gobuster
  • curl

Comandos que se ejecutarán:
  nmap -p 80,443,8080,8443 -sV -sC {target} -oN {output_dir}/nmap_service_{target}.txt
  ...
```

### Ejecutar un Escaneo

```bash
# Sintaxis básica
python3 agent.py --scan --target <IP_O_DOMINIO> --profile <PERFIL>

# Con directorio personalizado
python3 agent.py --scan --target 192.168.1.100 --profile quick --outputs-dir ./mi_scan

# Con modo verbose
python3 agent.py --scan --target example.com --profile standard --verbose
```

### Analizar Resultados del Escaneo

```bash
# Después del escaneo, ejecutar análisis
python3 agent.py --outputs-dir ./outputs

# O especificar formato
python3 agent.py --outputs-dir ./outputs --format html
```

---

## Ejemplos Prácticos

### Ejemplo 1: Escaneo Quick (Rápido)

**Escenario:** Reconocimiento inicial de un servidor desconocido

```bash
# 1. Ejecutar escaneo rápido
python3 agent.py --scan --target 192.168.1.100 --profile quick

# Salida esperada:
# ================================================================================
# 🎯 INICIANDO ESCANEO: Quick Scan
# ================================================================================
# Target: 192.168.1.100
# Comandos a ejecutar: 2
# Duración estimada: ~5 minutos
# ...
# ✅ ESCANEO COMPLETADO
# Archivos generados: 2
#   📄 outputs/nmap_service_192.168.1.100.txt
#   📄 outputs/headers_192.168.1.100.txt

# 2. Analizar resultados
python3 agent.py --outputs-dir ./outputs --format txt

# 3. Ver resumen rápido
head -50 informe_tecnico.txt

# 4. Si se detectaron servicios interesantes, ejecutar escaneo más profundo
python3 agent.py --scan --target 192.168.1.100 --profile standard
```

**Tiempo total:** ~6 minutos  
**Archivos generados:** 2-3 archivos

---

### Ejemplo 2: Escaneo Standard (Estándar)

**Escenario:** Auditoría regular de un servidor conocido

```bash
# 1. Escaneo estándar con verbose para monitorear progreso
python3 agent.py --scan --target webapp.company.local --profile standard --verbose

# Salida durante el escaneo:
# [1/4] Ejecutando nmap...
#    ✅ Completado en 180.23s (código: 0)
# [2/4] Ejecutando nikto...
#    ✅ Completado en 420.15s (código: 0)
# [3/4] Ejecutando gobuster...
#    ✅ Completado en 300.45s (código: 0)
# [4/4] Ejecutando curl...
#    ✅ Completado en 2.10s (código: 0)

# 2. Generar todos los formatos de informe
python3 agent.py --outputs-dir ./outputs --format all

# 3. Revisar informe HTML interactivo
firefox informe_tecnico.html

# 4. Buscar vulnerabilidades altas y críticas
grep -E "SEVERIDAD: (ALTA|CRITICA)" informe_tecnico.txt

# 5. Exportar JSON para procesamiento
cp informe_tecnico.json /informes/auditoria_webapp_$(date +%Y%m%d).json
```

**Tiempo total:** ~16 minutos  
**Archivos generados:** 6-8 archivos

---

### Ejemplo 3: Escaneo Full (Completo)

**Escenario:** Pentesting exhaustivo para auditoría de seguridad

```bash
# 1. Crear proyecto estructurado
mkdir pentest_cliente_$(date +%Y%m%d)
cd pentest_cliente_$(date +%Y%m%d)

# 2. Ejecutar escaneo completo (esto puede tardar 30-60 minutos)
python3 ../scan-agent/agent.py --scan --target 10.0.0.100 --profile full \
  --outputs-dir ./scan_results --verbose 2>&1 | tee scan.log

# Durante el escaneo, monitorear en otra terminal:
watch -n 10 'ls -lh scan_results/ && tail -5 scan.log'

# 3. Verificar archivos generados
ls -lh scan_results/
# Esperados:
# - nmap_service_10.0.0.100.txt (escaneo de 65535 puertos)
# - nmap_nse_10.0.0.100.txt (scripts NSE agresivos)
# - nikto_10.0.0.100.txt (escaneo exhaustivo)
# - gobuster_10.0.0.100.txt (múltiples diccionarios)
# - headers_10.0.0.100.txt
# - curl_verbose_10.0.0.100.txt

# 4. Analizar resultados
python3 ../scan-agent/agent.py --outputs-dir ./scan_results \
  --target-ip 10.0.0.100 --format all

# 5. Generar resumen ejecutivo
echo "=== RESUMEN DE AUDITORÍA ===" > resumen.txt
echo "Fecha: $(date)" >> resumen.txt
echo "Objetivo: 10.0.0.100" >> resumen.txt
echo "" >> resumen.txt
grep "Vulnerabilidades totales:" informe_tecnico.txt >> resumen.txt
grep -A 4 "Distribución por severidad:" informe_tecnico.txt >> resumen.txt

# 6. Backup del proyecto completo
cd ..
tar -czf pentest_cliente_$(date +%Y%m%d)_backup.tar.gz pentest_cliente_$(date +%Y%m%d)/
```

**Tiempo total:** 1-2 horas  
**Archivos generados:** 10-15 archivos

---

### Ejemplo 4: Escaneo Web (Aplicaciones Web)

**Escenario:** Testing de seguridad en aplicación web corporativa

```bash
# 1. Escaneo enfocado en web
python3 agent.py --scan --target store.ecommerce.com --profile web --verbose

# 2. Mientras se ejecuta, verificar progreso
# En otra terminal:
tail -f outputs/nikto_store.ecommerce.com.txt
tail -f outputs/gobuster_store.ecommerce.com.txt

# 3. Una vez completado, analizar
python3 agent.py --outputs-dir ./outputs --format html

# 4. Buscar vulnerabilidades OWASP Top 10
grep -i "owasp" informe_tecnico.txt

# 5. Verificar headers de seguridad faltantes
echo "=== HEADERS DE SEGURIDAD ==="
grep -i "X-Frame-Options\|Content-Security-Policy\|Strict-Transport-Security" \
  informe_tecnico.txt

# 6. Verificar directorios sensibles descubiertos
echo "=== DIRECTORIOS DESCUBIERTOS ==="
cat outputs/gobuster_store.ecommerce.com.txt | grep "Status: 200"

# 7. Generar informe para el equipo de desarrollo
cp informe_tecnico.html /compartido/seguridad/web_scan_$(date +%Y%m%d_%H%M).html
```

**Tiempo total:** 25-30 minutos  
**Archivos generados:** 6-8 archivos

---

### Ejemplo 5: Escaneo Stealth (Sigiloso)

**Escenario:** Pentesting en entorno con IDS/IPS activo

```bash
# ⚠️ REQUIERE SUDO

# 1. Verificar que tienes permisos de root
sudo -v

# 2. Ejecutar escaneo sigiloso (muy lento pero difícil de detectar)
sudo python3 agent.py --scan --target firewall.protected.net --profile stealth --verbose

# Salida esperada:
# ================================================================================
# 🎯 INICIANDO ESCANEO: Stealth Scan
# ================================================================================
# Target: firewall.protected.net
# ⚠️  ADVERTENCIA: Este perfil requiere privilegios de root
# ⚠️  El escaneo será MUY LENTO debido al timing paranoid
# 
# Configuración stealth:
#   • Timing: T1 (Paranoid)
#   • Fragmentación de paquetes: Activada
#   • Decoys: Activados
#   • SYN stealth scan: Activado
# ...

# 3. Monitorear progreso (el escaneo es LENTO)
# En otra terminal sin sudo:
watch -n 30 'ls -lh outputs/ && tail -10 outputs/nmap_service_*.txt'

# 4. Cuando complete (30-45 min), analizar SIN sudo
python3 agent.py --outputs-dir ./outputs --format all

# 5. Verificar si el escaneo fue detectado
# (Revisar logs del IDS/IPS del objetivo si tienes acceso)
```

**Tiempo total:** 35-50 minutos  
**Archivos generados:** 3-5 archivos  
**⚠️ Nota:** Extremadamente lento pero difícil de detectar

---

### Ejemplo 6: Escaneo Network (Infraestructura)

**Escenario:** Mapeo de red corporativa y detección de sistemas operativos

```bash
# ⚠️ REQUIERE SUDO para detección de OS

# 1. Escaneo de un segmento de red completo
sudo python3 agent.py --scan --target 10.10.10.0/24 --profile network --verbose

# 2. O escaneo de servidor individual
sudo python3 agent.py --scan --target router.internal.corp --profile network --verbose

# Salida esperada:
# ================================================================================
# 🎯 INICIANDO ESCANEO: Network Infrastructure Scan
# ================================================================================
# Target: router.internal.corp
# Perfil: Network Infrastructure Scan
# 
# Funcionalidades especiales:
#   • Detección de sistema operativo
#   • Detección de versiones de servicios
#   • Scripts de descubrimiento de red
#   • Traceroute
# ...

# 3. Analizar resultados (sin sudo)
python3 agent.py --outputs-dir ./outputs --format txt

# 4. Extraer información de sistema operativo detectado
echo "=== SISTEMAS OPERATIVOS DETECTADOS ==="
grep -A 5 "OS details:" outputs/nmap_service_*.txt

# 5. Listar servicios de infraestructura encontrados
echo "=== SERVICIOS DE RED ==="
grep -E "(ssh|telnet|ftp|snmp|rdp)" outputs/nmap_service_*.txt

# 6. Generar diagrama de puertos abiertos
grep "open" outputs/nmap_service_*.txt | cut -d'/' -f1 | sort -n | uniq
```

**Tiempo total:** 40-45 minutos  
**Archivos generados:** 2-4 archivos

---

### Ejemplo 7: Escaneo Compliance (Cumplimiento)

**Escenario:** Verificación de cumplimiento PCI-DSS / OWASP

```bash
# 1. Verificar configuraciones de seguridad
python3 agent.py --scan --target payment.gateway.com --profile compliance

# 2. Generar informe JSON para procesamiento automático
python3 agent.py --outputs-dir ./outputs --format json

# 3. Verificar protocolos inseguros
echo "=== VERIFICACIÓN DE PROTOCOLOS ==="
jq '.vulnerabilidades[] | select(.descripcion | contains("SSL") or contains("TLS"))' \
  informe_tecnico.json

# 4. Verificar headers de seguridad
echo "=== HEADERS DE SEGURIDAD FALTANTES ==="
jq '.vulnerabilidades[] | select(.categoria | contains("Headers"))' \
  informe_tecnico.json

# 5. Verificar cookies inseguras
echo "=== COOKIES SIN FLAGS SEGUROS ==="
grep -i "cookie" informe_tecnico.txt | grep -i "secure\|httponly"

# 6. Generar checklist de cumplimiento
cat > compliance_checklist.txt << 'EOF'
CHECKLIST DE CUMPLIMIENTO - PCI-DSS / OWASP
============================================

✓ = Cumple | ✗ = No cumple | ? = Verificar manualmente

[ ] No usa SSLv2/SSLv3
[ ] No usa TLS 1.0
[ ] Usa cifrado fuerte (TLS 1.2+)
[ ] Headers HSTS configurados
[ ] Headers CSP configurados
[ ] Headers X-Frame-Options configurados
[ ] Cookies con flag Secure
[ ] Cookies con flag HttpOnly
[ ] No expone información sensible en headers
[ ] No expone versiones de software
EOF

# Completar checklist automáticamente
python3 << 'PYTHON'
import json

with open('informe_tecnico.json') as f:
    data = json.load(f)

checks = {
    'ssl_old': any('SSLv2' in v.get('descripcion', '') or 'SSLv3' in v.get('descripcion', '') 
                   for v in data.get('vulnerabilidades', [])),
    'tls_old': any('TLS 1.0' in v.get('descripcion', '') for v in data.get('vulnerabilidades', [])),
}

print("Resultados automáticos:")
print(f"✗ SSLv2/v3 detectado" if checks['ssl_old'] else "✓ No usa SSLv2/v3")
print(f"✗ TLS 1.0 detectado" if checks['tls_old'] else "✓ No usa TLS 1.0")
PYTHON
```

**Tiempo total:** 10-12 minutos  
**Archivos generados:** 2-4 archivos

---

### Ejemplo 8: Escaneo API (APIs REST/SOAP)

**Escenario:** Testing de seguridad en microservicios

```bash
# 1. Escaneo de API
python3 agent.py --scan --target api.microservices.k8s.local --profile api --verbose

# 2. Analizar y generar informe JSON
python3 agent.py --outputs-dir ./outputs --format json

# 3. Extraer endpoints descubiertos
echo "=== ENDPOINTS API DESCUBIERTOS ==="
jq -r '.superficie_ataque.rutas_descubiertas[]' informe_tecnico.json

# 4. Verificar métodos HTTP permitidos
echo "=== MÉTODOS HTTP ==="
grep -i "methods:" outputs/nmap_nse_*.txt

# 5. Verificar CORS mal configurado
echo "=== CONFIGURACIÓN CORS ==="
grep -i "access-control-allow-origin" outputs/headers_*.txt

# 6. Buscar autenticación débil o ausente
echo "=== AUTENTICACIÓN ==="
jq '.vulnerabilidades[] | select(.categoria | contains("Autenticación"))' \
  informe_tecnico.json

# 7. Probar endpoints manualmente
echo "=== TESTING MANUAL DE ENDPOINTS ==="
# Obtener primer endpoint descubierto
ENDPOINT=$(jq -r '.superficie_ataque.rutas_descubiertas[0]' informe_tecnico.json)

# Probar diferentes métodos
curl -X GET http://api.microservices.k8s.local$ENDPOINT
curl -X POST http://api.microservices.k8s.local$ENDPOINT
curl -X PUT http://api.microservices.k8s.local$ENDPOINT
curl -X DELETE http://api.microservices.k8s.local$ENDPOINT
```

**Tiempo total:** 15-18 minutos  
**Archivos generados:** 3-5 archivos

---

## Ejemplos Prácticos

### Ejemplo 1: Reconocimiento Rápido

```bash
# 1. Escaneo rápido
python3 agent.py --scan --target 192.168.1.50 --profile quick

# 2. Analizar resultados
python3 agent.py --outputs-dir ./outputs --format html

# 3. Revisar informe
firefox informe_tecnico.html
```

### Ejemplo 2: Auditoría Web Completa

```bash
# 1. Escaneo web exhaustivo
python3 agent.py --scan --target webapp.company.com --profile web --verbose

# 2. Generar todos los formatos de informe
python3 agent.py --outputs-dir ./outputs --format all

# 3. Revisar informes
ls -lh informe_tecnico.*
```

### Ejemplo 3: Pentesting Completo

```bash
# 1. Crear directorio para el proyecto
mkdir pentest_client_2024
cd pentest_client_2024

# 2. Escaneo completo
python3 ../scan-agent/agent.py --scan --target 10.0.0.100 --profile full \
  --outputs-dir ./scan_results --verbose

# 3. Análisis detallado
python3 ../scan-agent/agent.py --outputs-dir ./scan_results \
  --target-ip 10.0.0.100 --format all

# 4. Revisar vulnerabilidades críticas
grep -i "critical\|high" informe_tecnico.txt
```

### Ejemplo 4: Escaneo Sigiloso

```bash
# Requiere sudo para técnicas avanzadas
sudo python3 agent.py --scan --target sensitive-server.com --profile stealth

# Analizar sin sudo
python3 agent.py --outputs-dir ./outputs
```

### Ejemplo 5: Verificación de Compliance

```bash
# 1. Escaneo de cumplimiento
python3 agent.py --scan --target secure.bank.com --profile compliance

# 2. Generar informe JSON para procesamiento
python3 agent.py --outputs-dir ./outputs --format json

# 3. Verificar protocolos inseguros
jq '.vulnerabilidades[] | select(.severidad=="ALTA")' informe_tecnico.json
```

---

## Troubleshooting

### Error: "Herramienta no encontrada"

**Problema:**
```
[ERROR] nmap no está instalado
```

**Solución:**
```bash
sudo apt install nmap
# o la herramienta específica que falta
```

---

### Error: "Permission denied" en perfil stealth/network

**Problema:**
```
[ERROR] Este perfil requiere privilegios de root
```

**Solución:**
```bash
# Usar sudo
sudo python3 agent.py --scan --target IP --profile stealth
```

---

### Error: "Timeout durante el escaneo"

**Problema:** El escaneo tarda demasiado o se congela

**Solución:**
```bash
# 1. Usar un perfil más rápido
python3 agent.py --scan --target IP --profile quick

# 2. O aumentar timeout manualmente editando scanner.py
# Buscar: timeout=300
# Cambiar a: timeout=600
```

---

### Warning: "No se generaron todos los archivos"

**Problema:** Algunos archivos de salida no se crearon

**Causas comunes:**
1. Puerto cerrado/filtrado (normal)
2. Herramienta no instalada
3. Timeout insuficiente

**Solución:**
```bash
# Verificar qué archivos se generaron
ls -la outputs/

# Ejecutar análisis con los archivos disponibles
python3 agent.py --outputs-dir ./outputs
```

---

### Error: "Target no alcanzable"

**Problema:**
```
[ERROR] No se puede alcanzar el objetivo
```

**Verificación:**
```bash
# Ping básico
ping -c 3 192.168.1.100

# Verificar conectividad
curl -I http://192.168.1.100

# Verificar firewall local
sudo iptables -L
```

---

## Mejores Prácticas

### ✅ Antes del Escaneo

1. **Obtener autorización por escrito**
   - ⚠️ Escanear sin permiso es ilegal
   - Documentar alcance del pentesting

2. **Verificar conectividad**
   ```bash
   ping -c 3 <target>
   nslookup <target>
   ```

3. **Preparar entorno**
   ```bash
   mkdir proyecto_pentest_$(date +%Y%m%d)
   cd proyecto_pentest_$(date +%Y%m%d)
   ```

4. **Revisar perfil adecuado**
   ```bash
   python3 agent.py --list-profiles
   python3 agent.py --show-profile <profile>
   ```

### ✅ Durante el Escaneo

1. **Usar modo verbose para monitorear**
   ```bash
   python3 agent.py --scan --target IP --profile standard --verbose
   ```

2. **Monitorear recursos**
   ```bash
   # En otra terminal
   watch -n 1 'ps aux | grep -E "nmap|nikto|gobuster"'
   ```

3. **Guardar logs**
   ```bash
   python3 agent.py --scan --target IP --profile full 2>&1 | tee scan.log
   ```

### ✅ Después del Escaneo

1. **Verificar archivos generados**
   ```bash
   ls -lh outputs/
   wc -l outputs/*.txt
   ```

2. **Backup de resultados**
   ```bash
   tar -czf scan_backup_$(date +%Y%m%d_%H%M).tar.gz outputs/
   ```

3. **Generar informes múltiples formatos**
   ```bash
   python3 agent.py --outputs-dir outputs --format all
   ```

4. **Proteger datos sensibles**
   ```bash
   chmod 600 outputs/*
   chmod 600 informe_tecnico.*
   ```

### ⚠️ Seguridad y Ética

1. **NUNCA escanear sin autorización**
2. **Respetar alcance acordado**
3. **No explotar vulnerabilidades encontradas sin permiso**
4. **Proteger resultados (datos confidenciales)**
5. **Informar vulnerabilidades críticas inmediatamente**

### 🎯 Recomendaciones por Escenario

| Escenario | Perfil Recomendado | Tiempo | Notas |
|-----------|-------------------|--------|-------|
| Primera vez viendo el objetivo | `quick` | 5 min | Reconocimiento inicial |
| Auditoría programada | `standard` | 15 min | Equilibrado |
| Pentesting contratado | `full` | 60 min | Exhaustivo |
| Aplicación web | `web` | 30 min | Específico web |
| Red corporativa | `network` | 40 min | Requiere sudo |
| Evadir detección | `stealth` | 45 min | Muy lento |
| Certificación PCI/OWASP | `compliance` | 10 min | Configs seguras |
| Microservicios/API | `api` | 15 min | Endpoints REST |

### 📊 Interpretación de Resultados

```bash
# Ver resumen rápido
head -n 50 informe_tecnico.txt

# Buscar vulnerabilidades críticas
grep -A 5 "CRITICA\|CRITICAL" informe_tecnico.txt

# Contar vulnerabilidades por severidad
grep -c "ALTA" informe_tecnico.txt
grep -c "MEDIA" informe_tecnico.txt
grep -c "BAJA" informe_tecnico.txt

# Exportar a Excel (desde JSON)
python3 -c "import json; data=json.load(open('informe_tecnico.json')); 
print('Severidad,Descripción'); 
[print(f'{v[\"severidad\"]},{v[\"descripcion\"]}') for v in data['vulnerabilidades']]" > vulnerabilidades.csv
```

---

## Soporte

Para más información:
- README.md - Documentación general
- EJEMPLOS.sh - Scripts de ejemplo
- RESUMEN.md - Resumen técnico del proyecto

**¿Encontraste un bug?**  
Reporta en: Issues del proyecto

---

**Scan Agent v2.0**  
Desarrollado con ❤️ para la comunidad de ciberseguridad
