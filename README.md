# 🛡️ Scan Agent - Agente de Análisis de Vulnerabilidades Web

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.0-orange.svg)]()
[![Status](https://img.shields.io/badge/status-production-brightgreen.svg)]()

**Scan Agent v3.0** es un agente de software inteligente que automatiza el análisis de vulnerabilidades web, con **reportes profesionales**, **análisis inteligente de vulnerabilidades**, dashboard interactivo y sistema de clasificación de riesgo.

## 🆕 NUEVO: Versión 3.0 - Reportes Profesionales

- 🎯 **Análisis Inteligente**: Sistema de clasificación automática por severidad (CRITICAL/HIGH/MEDIUM/LOW)
- 📊 **Reportes Profesionales**: Templates HTML con diseño moderno, gradientes CSS y cards por severidad
- 🔍 **Parser Avanzado**: Extracción estructurada de datos desde Nmap, Nikto, Gobuster, Headers HTTP
- ⚡ **Resumen Ejecutivo**: Vista clara del nivel de riesgo con puntuación de 0-100+
- 💡 **Recomendaciones Accionables**: Sugerencias específicas para cada hallazgo
- 📈 **Risk Scoring**: Sistema de puntuación basado en puertos, versiones y vulnerabilidades conocidas
- 🎨 **Múltiples Formatos**: HTML profesional, JSON estructurado, TXT y Markdown

**[📖 Ver Changelog Completo v3.0](docs/changelog/CHANGELOG_v3.0.md)**

### Mejoras de UX en v3.0

**Antes (v2.x):**
```
Reporte = Dump de texto raw sin estructura
Tiempo de análisis manual: 15 minutos
```

**Después (v3.0):**
```
Reporte = Análisis profesional con clasificación automática
Tiempo de análisis manual: 2 minutos (-87%)
```

## 🆕 Interfaz Web v2.0

- 🌐 **Interfaz Web Completa**: Ejecuta escaneos sin usar la línea de comandos
- 🎨 **UI Moderna e Intuitiva**: Diseño responsive con validación en tiempo real
- 📊 **Monitoreo en Vivo**: Barra de progreso que se actualiza automáticamente
- 📋 **Historial Visual**: Navega y busca todos tus escaneos anteriores
- 📄 **Reportes Integrados**: Descarga en múltiples formatos con análisis completo
- ⚡ **API REST Completa**: Documentación interactiva con Swagger/OpenAPI

**[📖 Ver Documentación Completa de la Interfaz Web](docs/WEB_IMPLEMENTATION.md)**

### Inicio Rápido - Interfaz Web

```bash
# 1. Instalar dependencias web
pip3 install -r webapp/requirements.txt

# 2. Iniciar servidor
./start-web.sh

# 3. Abrir navegador
# http://localhost:8000
```

## 🆕 Novedades v2.1

- 📁 **Estructura Reorganizada**: Siguiendo mejores prácticas Python (src/, config/, docs/, etc.)
- 💾 **Base de Datos SQLite**: Almacenamiento persistente de escaneos con histórico completo
- 📊 **Dashboard Interactivo**: Navegación cronológica por IP y escaneos desde HTML
- 🔗 **Organización por IP**: Timeline de escaneos ordenados del más reciente al más antiguo
- 🐳 **Docker Actualizado**: Imagen v2.1 con soporte completo para BD y dashboard

## 🆕 Novedades v2.0

- 🚀 **Ejecución de Escaneos**: 8 perfiles de escaneo integrados (quick, standard, full, web, stealth, network, compliance, api)
- 🔧 **Workflow Completo**: Escaneo → Parsing → Análisis → Informes → BD → Dashboard
- ⚡ **Perfiles Inteligentes**: Desde reconocimiento rápido (5 min) hasta pentesting exhaustivo (60 min)
- 🛠️ **Integración de Herramientas**: nmap, nikto, gobuster, curl ejecutados automáticamente

## 📋 Índice

1. [Características](#-características)
2. [Interfaz Web](#-interfaz-web)
3. [Requisitos](#-requisitos)
4. [Instalación](#-instalación)
5. [Docker](#-docker)
6. [Uso](#-uso)
7. [Perfiles de Escaneo](#-perfiles-de-escaneo)
8. [Ejemplos de Uso](#-ejemplos-de-uso)
9. [Arquitectura](#-arquitectura)
10. [Roadmap](#-roadmap)

## ✨ Características

### Web UI v1.0 - Interfaz Web Moderna

- 🌐 **Aplicación Web Full-Stack**: Backend FastAPI + Frontend JavaScript vanilla
- 🎯 **Selección Visual de Perfiles**: Cards interactivas con descripción detallada
- 📝 **Formularios Inteligentes**: Validación en tiempo real de parámetros
- 📊 **Progreso en Vivo**: Barra de progreso que se actualiza cada 2 segundos
- 📋 **Gestión de Historial**: Búsqueda, filtrado y acceso a escaneos anteriores
- 📥 **Exportación Multi-formato**: Descarga reportes en JSON, HTML, TXT o Markdown
- 🚀 **API REST Documentada**: Swagger UI automático en `/api/docs`
- 📱 **100% Responsive**: Funciona en desktop, tablet y móvil

### v2.0 - Nuevas Funcionalidades

- 🎯 **Escaneo Automático**: Ejecuta nmap, nikto, gobuster y curl automáticamente
- 📊 **8 Perfiles de Escaneo**: Configuraciones optimizadas para diferentes escenarios
- ⚙️ **Gestión de Herramientas**: Verificación automática de dependencias
- ⏱️ **Control de Timeouts**: Gestión inteligente de tiempos de ejecución
- 🔐 **Soporte para Sudo**: Perfiles avanzados (stealth, network) con privilegios elevados

### v1.0 - Funcionalidades Core

- ✅ **Parsing Automático**: Interpreta archivos de múltiples herramientas
- ✅ **Análisis Inteligente**: Clasifica vulnerabilidades según CVSS 3.1 y OWASP Top 10 2021
- ✅ **Múltiples Formatos**: Genera informes en TXT, JSON, HTML y Markdown
- ✅ **Superficie de Ataque**: Mapea puertos, servicios y endpoints expuestos
- ✅ **Detección de Tecnologías**: Identifica servidores web, frameworks y bases de datos
- ✅ **Recomendaciones Priorizadas**: Sugerencias a corto, mediano y largo plazo
- ✅ **Sin Dependencias Python**: Utiliza solo bibliotecas estándar de Python

### Herramientas Soportadas

| Herramienta | Tipo de Archivo | Información Extraída |
|-------------|----------------|---------------------|
| **Nmap** | `nmap_service_*.txt` | Puertos abiertos, servicios, versiones |
| **Nmap NSE** | `nmap_nse_*.txt` | Scripts de vulnerabilidades, CVEs |
| **Nikto** | `nikto_*.txt` | Vulnerabilidades web, OSVDB IDs |
| **Gobuster** | `gobuster_*.txt` | Directorios y archivos descubiertos |
| **Curl** | `curl_verbose_*.txt` | Headers HTTP, códigos de respuesta |
| **Headers** | `headers_*.txt` | Headers de seguridad HTTP |

## 🔧 Requisitos

### Python
- **Python 3.12 o superior**
- Bibliotecas estándar de Python (incluidas por defecto)

### Herramientas de Pentesting (v2.0 - para escaneo)

```bash
# Debian/Ubuntu/Kali
sudo apt install -y nmap nikto gobuster curl

# Fedora/RHEL/CentOS
sudo dnf install -y nmap nikto gobuster curl

# Arch Linux
sudo pacman -S nmap nikto gobuster curl
```

**Nota:** Las herramientas solo son necesarias si usas la funcionalidad de escaneo (--scan). Para análisis de archivos existentes no se requieren.
- Sistema operativo: Linux, macOS o Windows

## 📦 Instalación

### Opción 1: Docker (Recomendado) 🐳

```bash
# Clonar el repositorio
git clone <repo-url> scan-agent
cd scan-agent

# Construir imagen
bash scripts/build.sh

# Verificar instalación
docker run --rm scan-agent:2.1.0 --version
```

**Ver la [Guía Docker](docs/DOCKER.md) completa para más detalles.**

### Opción 2: Instalación Local

```bash
# Clonar repositorio
git clone <repo-url> scan-agent
cd scan-agent

# Verificar Python
python3 --version  # Requiere 3.12+

# Instalar herramientas de pentesting
sudo apt install -y nmap nikto gobuster curl

# Verificar instalación
python3 scan-agent.py --version
```

**Nota:** Las herramientas solo son necesarias si usas la funcionalidad de escaneo (--scan). Para análisis de archivos existentes no se requieren.

## 🚀 Inicio Rápido v2.1

### Modo Escaneo: Todo en Uno

```bash
# 1. Ejecutar escaneo rápido
python3 scan-agent.py --scan --target 192.168.1.100 --profile quick

# 2. Ver dashboard interactivo
firefox reports/dashboard.html

# 3. Ver informe individual
firefox reports/informe_tecnico_1.html
```

### Ver Perfiles Disponibles

```bash
# Listar todos los perfiles
python3 scan-agent.py --list-profiles

# Ver detalles de un perfil específico
python3 scan-agent.py --show-profile web
```

## 🚀 Uso Básico

### Modo 1: Escaneo + Análisis (Recomendado)

```bash
# Escaneo rápido (5 min)
python3 scan-agent.py --scan --target 192.168.1.100 --profile quick

# Escaneo estándar (15 min)
python3 scan-agent.py --scan --target example.com --profile standard

# Escaneo web completo (30 min)
python3 scan-agent.py --scan --target webapp.com --profile web --verbose

# Los informes se generan automáticamente en reports/
```

### Modo 2: Solo Análisis (archivos existentes)

```bash
# Coloca tus archivos de escaneo en ./outputs/
cp nmap_*.txt nikto_*.txt gobuster_*.txt ./outputs/

# Ejecuta el agente
python3 scan-agent.py --outputs-dir ./outputs --format all
```

# O con opciones específicas
python3 agent.py --outputs-dir ./outputs --format html --verbose
```

### Opciones Disponibles

```bash
# Ver ayuda completa
python3 agent.py --help

# Listar perfiles de escaneo
python3 agent.py --list-profiles

# Ver detalles de un perfil
python3 agent.py --show-profile full

# Especificar directorio personalizado
python3 agent.py --outputs-dir /ruta/a/escaneos

# Especificar IP objetivo manualmente
python3 agent.py --target-ip 192.168.1.100

# Generar solo un formato específico
python3 scan-agent.py --format html

# Modo verbose para depuración
python3 scan-agent.py --verbose

# Deshabilitar base de datos
python3 scan-agent.py --outputs-dir ./outputs --no-db
```

## 📁 Estructura del Proyecto

```
scan-agent/
├── src/scanagent/                 # 📦 Código fuente
│   ├── agent.py                   # CLI principal
│   ├── scanner.py                 # Módulo de escaneo
│   ├── parser.py                  # Módulo de parsing
│   ├── interpreter.py             # Módulo de análisis
│   ├── report_generator.py        # Generador de informes
│   ├── dashboard_generator.py     # Generador de dashboard
│   └── database.py                # Gestión de BD
├── config/                        # ⚙️ Configuración
│   └── schema.sql                 # Schema BD SQLite
├── scripts/                       # 🔧 Scripts
│   ├── docker-entrypoint.sh
│   └── build.sh
├── docker/                        # 🐳 Docker
│   ├── Dockerfile
│   └── docker-compose.yml
├── docs/                          # 📚 Documentación
│   ├── README_DATABASE.md
│   ├── DOCKER.md
│   ├── GUIA_ESCANEO.md
│   └── changelog/
├── examples/                      # 📋 Ejemplos
├── data/                          # 💾 Datos (BD)
├── outputs/                       # 📤 Archivos de escaneo
├── reports/                       # 📊 Informes generados
└── tests/                         # 🧪 Tests
```

Ver [docs/INDEX.md](docs/INDEX.md) para más detalles de la estructura.

## 📊 Perfiles de Escaneo

Scan Agent incluye 8 perfiles de escaneo predefinidos para diferentes escenarios:

### 1️⃣ Quick - Reconocimiento Rápido

**Duración:** ~5 minutos | **Sudo:** No necesario

Escaneo inicial para obtener información básica del objetivo.

**Herramientas:**
- Nmap: Top 100 puertos más comunes
- Curl: Headers HTTP básicos

**Ejemplo de uso:**
```bash
# Reconocimiento rápido de un servidor
python3 scan-agent.py --scan --target 192.168.1.100 --profile quick

# Con verbose para ver progreso
python3 scan-agent.py --scan --target example.com --profile quick --verbose
```

**Caso de uso:** Primera exploración de un objetivo desconocido.

---

### 2️⃣ Standard - Análisis Equilibrado

**Duración:** ~15 minutos | **Sudo:** No necesario

Escaneo completo con buen equilibrio entre velocidad y profundidad.

**Herramientas:**
- Nmap: Top 1000 puertos + scripts NSE
- Nikto: Escaneo completo de vulnerabilidades web
- Gobuster: Enumeración de directorios (diccionario común)
- Curl: Headers y respuestas HTTP detalladas

**Ejemplo de uso:**
```bash
# Escaneo estándar (recomendado para la mayoría de casos)
python3 scan-agent.py --scan --target 10.0.0.50 --profile standard

# Con directorio personalizado
python3 scan-agent.py --scan --target webapp.local --profile standard \
  --outputs-dir ./scan_results
```

**Caso de uso:** Auditorías regulares, pentesting estándar.

---

### 3️⃣ Full - Pentesting Completo

**Duración:** 30-60 minutos | **Sudo:** No necesario

Escaneo exhaustivo que analiza todos los puertos y usa todas las herramientas disponibles.

**Herramientas:**
- Nmap: Todos los 65535 puertos + scripts NSE agresivos
- Nikto: Escaneo exhaustivo con todas las opciones
- Gobuster: Múltiples diccionarios (common + medium)
- Curl: Análisis detallado de respuestas

**Ejemplo de uso:**
```bash
# Escaneo completo exhaustivo
python3 scan-agent.py --scan --target 10.10.10.100 --profile full --verbose

# Escaneo completo con análisis automático
python3 scan-agent.py --scan --target target.com --profile full
```

**Caso de uso:** Pentesting profesional, auditorías de seguridad completas.

⚠️ **Advertencia:** Este escaneo puede tardar más de 1 hora.

---

### 4️⃣ Web - Aplicaciones Web

**Duración:** 20-30 minutos | **Sudo:** No necesario

Escaneo especializado en vulnerabilidades de aplicaciones web.

**Herramientas:**
- Nmap: Puertos web (80, 443, 8080, 8443) + scripts HTTP
- Nikto: Escaneo web exhaustivo
- Gobuster: Enumeración extensiva de directorios y archivos
- Curl: Análisis de cookies, headers de seguridad y CORS

**Ejemplo de uso:**
```bash
# Escaneo de aplicación web
python3 agent.py --scan --target webapp.company.com --profile web

# Escaneo web con análisis HTML
python3 agent.py --scan --target store.example.com --profile web && \
python3 agent.py --format html
```

**Caso de uso:** Testing de aplicaciones web, búsqueda de OWASP Top 10.

---

### 5️⃣ Stealth - Evasión de IDS/IPS

**Duración:** 30-45 minutos | **Sudo:** ✅ Requerido

Escaneo sigiloso diseñado para evitar detección por sistemas de seguridad.

**Características:**
- Timing paranoid (muy lento pero difícil de detectar)
- Fragmentación de paquetes
- Uso de decoys (señuelos)
- SYN stealth scan

**Ejemplo de uso:**
```bash
# Escaneo sigiloso (requiere privilegios de root)
sudo python3 agent.py --scan --target sensitive-server.com --profile stealth

# Con verbose para monitorear progreso
sudo python3 agent.py --scan --target 192.168.1.1 --profile stealth --verbose
```

**Caso de uso:** Pentesting en entornos con IDS/IPS activos.

⚠️ **Nota:** Requiere permisos de root para técnicas avanzadas de evasión.

---

### 6️⃣ Network - Infraestructura de Red

**Duración:** ~40 minutos | **Sudo:** ✅ Requerido

Análisis de infraestructura de red y detección de sistemas operativos.

**Características:**
- Detección de sistema operativo
- Detección precisa de versiones de servicios
- Scripts de descubrimiento de red
- Análisis de topología

**Ejemplo de uso:**
```bash
# Escaneo de infraestructura de red
sudo python3 agent.py --scan --target 10.10.10.0/24 --profile network

# Escaneo de servidor individual
sudo python3 agent.py --scan --target router.local --profile network --verbose
```

**Caso de uso:** Mapeo de redes, auditorías de infraestructura.

⚠️ **Nota:** Requiere sudo para detección de OS y técnicas avanzadas.

---

### 7️⃣ Compliance - Verificación de Cumplimiento

**Duración:** ~10 minutos | **Sudo:** No necesario

Verificación de configuraciones de seguridad según estándares (PCI-DSS, OWASP).

**Verifica:**
- Protocolos inseguros (SSLv2, SSLv3, TLSv1.0)
- Headers de seguridad faltantes (HSTS, CSP, X-Frame-Options)
- Configuraciones débiles de cifrado
- Cookies sin flags Secure/HttpOnly

**Ejemplo de uso:**
```bash
# Verificación de cumplimiento
python3 agent.py --scan --target secure.bank.com --profile compliance

# Con informe JSON para procesamiento
python3 agent.py --scan --target payment.gateway.com --profile compliance && \
python3 agent.py --format json
```

**Caso de uso:** Auditorías de cumplimiento, verificación de hardening.

---

### 8️⃣ API - Testing de APIs

**Duración:** ~15 minutos | **Sudo:** No necesario

Escaneo especializado en APIs REST/SOAP y microservicios.

**Herramientas:**
- Gobuster: Enumeración de endpoints API
- Curl: Testing de métodos HTTP (GET, POST, PUT, DELETE)
- Nmap: Detección de puertos API comunes
- Análisis de CORS y autenticación

**Ejemplo de uso:**
```bash
# Escaneo de API REST
python3 agent.py --scan --target api.example.com --profile api

# Escaneo de microservicios
python3 agent.py --scan --target microservice.k8s.local --profile api --verbose
```

**Caso de uso:** Testing de APIs, análisis de microservicios.

---

### 📋 Tabla Comparativa

| Perfil | Duración | Puertos | Herramientas | Sudo | Mejor Para |
|--------|----------|---------|--------------|------|------------|
| **quick** | ~5 min | Top 100 | nmap, curl | No | Reconocimiento inicial |
| **standard** | ~15 min | Top 1000 | nmap, nikto, gobuster, curl | No | Uso general (recomendado) |
| **full** | 30-60 min | Todos (65535) | nmap, nikto, gobuster, curl | No | Pentesting completo |
| **web** | 20-30 min | Web (80,443,8080,8443) | nmap, nikto, gobuster, curl | No | Aplicaciones web |
| **stealth** | 30-45 min | Variable | nmap, nikto | ✅ Sí | Evasión de detección |
| **network** | ~40 min | Top 1000 | nmap | ✅ Sí | Infraestructura |
| **compliance** | ~10 min | Web | nmap, curl | No | Auditorías de cumplimiento |
| **api** | ~15 min | API (3000,5000,8000+) | nmap, gobuster, curl | No | APIs y microservicios |

### 🎯 Comandos Útiles

```bash
# Listar todos los perfiles disponibles
python3 agent.py --list-profiles

# Ver detalles específicos de un perfil
python3 agent.py --show-profile web
python3 agent.py --show-profile stealth

# Workflow completo: escaneo + análisis + informe
python3 agent.py --scan --target 192.168.1.100 --profile standard
python3 agent.py --outputs-dir ./outputs --format html
firefox informe_tecnico.html
```

**Para más información detallada, consulta:** [`GUIA_ESCANEO.md`](GUIA_ESCANEO.md)

## 📁 Estructura del Proyecto

```
scan-agent/
│
├── agent.py                    # 🎯 Archivo principal (ejecutar este)
├── parser.py                   # 📝 Módulo de parsing
├── interpreter.py              # 🔍 Módulo de análisis
├── report_generator.py         # 📊 Módulo de informes
├── scanner.py                  # 🚀 Módulo de escaneo (NUEVO v2.0)
├── requirements.txt            # 📦 Dependencias
├── README.md                   # 📖 Documentación principal
├── GUIA_ESCANEO.md            # 📡 Guía de escaneo v2.0 (NUEVO)
├── RESUMEN.md                  # 📋 Resumen técnico
├── EJEMPLOS.sh                 # 💡 Scripts de ejemplo
│
├── outputs/                    # 📂 Archivos de escaneo (INPUT)
│   ├── nmap_service_*.txt
│   ├── nmap_nse_*.txt
│   ├── nikto_*.txt
│   ├── headers_*.txt
│   ├── curl_verbose_*.txt
│   └── gobuster_*.txt
│
│
└── [Generados automáticamente]
    ├── parsed_data.json        # Datos parseados intermedios
    ├── analysis.json           # Análisis intermedio
    ├── informe_tecnico.txt     # 📄 Informe en texto
    ├── informe_tecnico.json    # 🔧 Informe estructurado
    ├── informe_tecnico.html    # 🌐 Informe web (RECOMENDADO)
    └── informe_tecnico.md      # 📝 Informe en Markdown
```

## 📥 Archivos de Entrada

### Formato Esperado

Los archivos deben seguir esta convención de nombres:

```
[herramienta]_[target_ip].txt
```

### Ejemplos de Nombres Válidos

```
nmap_service_192.168.1.100.txt
nmap_nse_192.168.1.100.txt
nikto_192.168.1.100.txt
headers_192.168.1.100.txt
curl_verbose_192.168.1.100.txt
gobuster_192.168.1.100.txt
```

### Cómo Generar los Archivos de Entrada

#### Nmap Service Scan
```bash
nmap -sV -p- 192.168.1.100 -oN nmap_service_192.168.1.100.txt
```

#### Nmap NSE Scripts
```bash
nmap --script=vuln,exploit 192.168.1.100 -oN nmap_nse_192.168.1.100.txt
```

#### Nikto
```bash
nikto -h http://192.168.1.100 -o nikto_192.168.1.100.txt
```

#### Gobuster
```bash
gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt -o gobuster_192.168.1.100.txt
```

#### Headers HTTP
```bash
curl -I http://192.168.1.100 > headers_192.168.1.100.txt
```

#### Curl Verbose
```bash
curl -v http://192.168.1.100 > curl_verbose_192.168.1.100.txt 2>&1
```

## 📊 Formatos de Salida

### 1. TXT - Informe en Texto Plano
```bash
python3 agent.py --format txt
```
- ✅ Fácil de leer en terminal
- ✅ Compatible con cualquier editor
- ✅ Ideal para documentación simple

### 2. JSON - Datos Estructurados
```bash
python3 agent.py --format json
```
- ✅ Integración con otras herramientas
- ✅ Parsing automático
- ✅ APIs y automatización

### 3. HTML - Informe Web Interactivo ⭐ **RECOMENDADO**
```bash
python3 agent.py --format html
```
- ✅ **Visualización profesional**
- ✅ Estilos y colores por severidad
- ✅ Navegación interactiva
- ✅ Listo para compartir con el equipo

### 4. Markdown - Documentación Técnica
```bash
python3 agent.py --format md
```
- ✅ Compatible con GitHub/GitLab
- ✅ Convertible a PDF
- ✅ Fácil edición

### 5. ALL - Todos los Formatos (Default)
```bash
python3 agent.py --format all
```

## 📚 Ejemplos de Uso

### Ejemplo 1: Reconocimiento Rápido (v2.0)

```bash
# Escaneo inicial de un nuevo objetivo
python3 agent.py --scan --target 192.168.1.50 --profile quick

# Analizar los resultados
python3 agent.py --outputs-dir ./outputs --format html

# Abrir informe en el navegador
firefox informe_tecnico.html
```

**Tiempo total:** ~6 minutos

---

### Ejemplo 2: Pentesting de Aplicación Web (v2.0)

```bash
# 1. Escaneo enfocado en web
python3 agent.py --scan --target webapp.company.com --profile web --verbose

# 2. Generar todos los formatos de informe
python3 agent.py --outputs-dir ./outputs --format all

# 3. Revisar vulnerabilidades críticas
grep -i "ALTA\|CRITICA" informe_tecnico.txt

# 4. Compartir informe HTML con el equipo
cp informe_tecnico.html /compartido/auditoria_webapp_$(date +%Y%m%d).html
```

**Tiempo total:** ~30 minutos

---

### Ejemplo 3: Auditoría Completa (v2.0)

```bash
# Crear proyecto estructurado
mkdir pentest_cliente_2024 && cd pentest_cliente_2024

# Escaneo exhaustivo
python3 ../scan-agent/agent.py --scan --target 10.0.0.100 --profile full \
  --outputs-dir ./resultados --verbose

# Análisis y generación de informes
python3 ../scan-agent/agent.py --outputs-dir ./resultados \
  --target-ip 10.0.0.100 --format all

# Verificar vulnerabilidades por severidad
echo "=== RESUMEN DE VULNERABILIDADES ==="
grep -c "CRITICA" informe_tecnico.txt && echo "Críticas"
grep -c "ALTA" informe_tecnico.txt && echo "Altas"
grep -c "MEDIA" informe_tecnico.txt && echo "Medias"
grep -c "BAJA" informe_tecnico.txt && echo "Bajas"

# Backup del proyecto
cd .. && tar -czf pentest_cliente_backup_$(date +%Y%m%d).tar.gz pentest_cliente_2024/
```

**Tiempo total:** ~1-2 horas

---

### Ejemplo 4: Escaneo Sigiloso (v2.0)

```bash
# Escaneo en entorno con IDS/IPS activo (requiere sudo)
sudo python3 agent.py --scan --target sensitive-server.local --profile stealth

# El escaneo es muy lento pero difícil de detectar
# Monitorear en otra terminal:
watch -n 5 'ls -lh outputs/'

# Analizar sin privilegios
python3 agent.py --outputs-dir ./outputs --format all
```

**Tiempo total:** ~45 minutos

---

### Ejemplo 5: Testing de API (v2.0)

```bash
# Escaneo especializado en API
python3 agent.py --scan --target api.microservices.local --profile api

# Generar informe JSON para procesamiento automático
python3 agent.py --outputs-dir ./outputs --format json

# Extraer endpoints descubiertos
jq '.superficie_ataque.rutas_descubiertas[]' informe_tecnico.json

# Buscar vulnerabilidades en autenticación
jq '.vulnerabilidades[] | select(.categoria | contains("Autenticación"))' \
  informe_tecnico.json
```

**Tiempo total:** ~15 minutos

---

### Ejemplo 6: Verificación de Cumplimiento (v2.0)

```bash
# Verificar configuraciones de seguridad
python3 agent.py --scan --target secure.payment.com --profile compliance

# Generar informe de cumplimiento
python3 agent.py --outputs-dir ./outputs --format txt

# Verificar protocolos inseguros
echo "=== VERIFICACIÓN DE CUMPLIMIENTO ==="
grep -i "sslv2\|sslv3\|tls.*1.0" informe_tecnico.txt

# Verificar headers de seguridad faltantes
grep -i "x-frame-options\|content-security-policy\|hsts" informe_tecnico.txt
```

**Tiempo total:** ~10 minutos

---

### Ejemplo 7: Análisis de Archivos Existentes (v1.0)

```bash
# Si ya tienes archivos de escaneos previos
cp /archivos_antiguos/escaneos/*.txt ./outputs/

# Analizar sin ejecutar escaneos nuevos
python3 agent.py --outputs-dir ./outputs --format all

# Revisar el informe
firefox informe_tecnico.html
```

**Tiempo total:** ~1 minuto

---

### Ejemplo 8: Escaneo Automatizado Múltiple (Script)

```bash
#!/bin/bash
# scan_multiple.sh - Escanear múltiples objetivos

TARGETS="192.168.1.100 192.168.1.101 192.168.1.102"
PROFILE="standard"

for target in $TARGETS; do
    echo "[*] Escaneando $target..."
    
    # Crear directorio para cada objetivo
    mkdir -p "scan_${target}"
    
    # Ejecutar escaneo
    python3 agent.py --scan --target $target --profile $PROFILE \
      --outputs-dir "./scan_${target}/outputs"
    
    # Generar informe
    python3 agent.py --outputs-dir "./scan_${target}/outputs" \
      --format html
    
    # Mover informe
    mv informe_tecnico.html "./scan_${target}/informe_${target}.html"
    
    echo "[✓] Completado: $target"
done

echo "[✓] Todos los escaneos completados"
```

---

### Ejemplo 9: Integración con CI/CD

```bash
#!/bin/bash
# ci_security_scan.sh - Para pipelines de CI/CD

TARGET="${1:-staging.app.com}"
THRESHOLD_CRITICAL=0
THRESHOLD_HIGH=5

# Ejecutar escaneo
python3 agent.py --scan --target $TARGET --profile compliance --outputs-dir ./scan_results

# Generar informe JSON
python3 agent.py --outputs-dir ./scan_results --format json

# Extraer contadores
CRITICAL=$(jq '[.vulnerabilidades[] | select(.severidad=="CRITICA")] | length' informe_tecnico.json)
HIGH=$(jq '[.vulnerabilidades[] | select(.severidad=="ALTA")] | length' informe_tecnico.json)

echo "Vulnerabilidades críticas: $CRITICAL (máximo permitido: $THRESHOLD_CRITICAL)"
echo "Vulnerabilidades altas: $HIGH (máximo permitido: $THRESHOLD_HIGH)"

# Fallar el build si se exceden los límites
if [ $CRITICAL -gt $THRESHOLD_CRITICAL ] || [ $HIGH -gt $THRESHOLD_HIGH ]; then
    echo "❌ Build fallido: demasiadas vulnerabilidades"
    exit 1
fi

echo "✅ Build exitoso: niveles de seguridad aceptables"
exit 0
```

---

### Ejemplo 10: Comparación de Escaneos

```bash
# Escaneo inicial (baseline)
python3 agent.py --scan --target production.app.com --profile web \
  --outputs-dir ./baseline_outputs
python3 agent.py --outputs-dir ./baseline_outputs --format json
cp informe_tecnico.json baseline_report.json

# Esperar 1 semana...

# Escaneo de seguimiento
python3 agent.py --scan --target production.app.com --profile web \
  --outputs-dir ./followup_outputs
python3 agent.py --outputs-dir ./followup_outputs --format json
cp informe_tecnico.json followup_report.json

# Comparar cambios
echo "=== NUEVAS VULNERABILIDADES ==="
diff <(jq -r '.vulnerabilidades[].descripcion' baseline_report.json | sort) \
     <(jq -r '.vulnerabilidades[].descripcion' followup_report.json | sort)
```

# Ejecuta el agente
python3 agent.py --target-ip $TARGET --verbose

# Ver el informe
cat informe_tecnico.txt
```

### Ejemplo 3: Modo Verbose para Debugging

```bash
python3 agent.py --verbose --format html
```

Salida esperada:
```
================================================================================
  ____   ____    _    _   _      _    ____ _____ _   _ _____ 
 / ___| / ___|  / \  | \ | |    / \  / ___| ____| \ | |_   _|
 \___ \| |     / _ \ |  \| |   / _ \| |  _|  _| |  \| | | |  
  ___) | |___ / ___ \| |\  |  / ___ \ |_| | |___| |\  | | |  
 |____/ \____/_/   \_\_| \_| /_/   \_\____|_____|_| \_| |_|  

 Agente de Análisis de Vulnerabilidades Web v1.0.0
 ==============================================================================
 Inicio: 2024-11-12 15:30:45
 ==============================================================================

[VERBOSE] Se encontraron 6 archivos para procesar
[VERBOSE]   - nmap_service_10.1.11.177.txt
[VERBOSE]   - nmap_nse_10.1.11.177.txt
...
```

## 🐳 Docker

Scan Agent está completamente dockerizado para facilitar la distribución y ejecución en cualquier entorno.

### Construcción Rápida

```bash
# Usando el script de build
./build.sh

# O manualmente
docker build -t scan-agent:2.0.0 .
```

### Uso Básico con Docker

```bash
# Ver versión
docker run --rm scan-agent:2.0.0 --version

# Listar perfiles
docker run --rm scan-agent:2.0.0 --list-profiles

# Escaneo rápido
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:2.0.0 \
  --scan --target 192.168.1.100 --profile quick

# Análisis de resultados
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  scan-agent:2.0.0 \
  --outputs-dir /scan-agent/outputs --format html
```

### Docker Compose

```bash
# Escaneo con compose
docker-compose run --rm scan-agent --scan --target 192.168.1.100 --profile standard

# Análisis
docker-compose run --rm scan-agent --outputs-dir /scan-agent/outputs --format txt
```

**📖 Ver la [Guía Docker Completa](DOCKER.md)** para ejemplos avanzados, troubleshooting y configuración de red.

---

## 🏗️ Arquitectura

### Flujo de Procesamiento

```
┌─────────────────┐
│  Archivos .txt  │
│   (outputs/)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   PARSER.PY     │  ◄── Fase 1: Parsing
│  ┌───────────┐  │
│  │ ScanParser│  │      • Lee archivos de herramientas
│  └───────────┘  │      • Extrae datos estructurados
└────────┬────────┘      • Genera parsed_data.json
         │
         ▼
┌─────────────────┐
│ INTERPRETER.PY  │  ◄── Fase 2: Análisis
│  ┌───────────┐  │
│  │Vulnerability│ │      • Clasifica vulnerabilidades
│  │Interpreter │ │      • Mapea OWASP Top 10
│  └───────────┘  │      • Calcula CVSS scores
└────────┬────────┘      • Genera analysis.json
         │
         ▼
┌─────────────────┐
│REPORT_GEN.PY    │  ◄── Fase 3: Informes
│  ┌───────────┐  │
│  │  Report   │  │      • Genera TXT, JSON
│  │ Generator │  │      • Genera HTML, MD
│  └───────────┘  │      • Aplica estilos
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Informes Finales│
│  • .txt         │
│  • .json        │
│  • .html ⭐     │
│  • .md          │
└─────────────────┘
```

### Módulos Principales

#### 1. `parser.py` - ScanParser

**Responsabilidad**: Convertir archivos de texto a JSON estructurado

**Métodos Principales**:
- `parse_all()` - Orquesta el parsing completo
- `_parse_nmap_service()` - Parsea puertos y servicios
- `_parse_nmap_nse()` - Extrae vulnerabilidades NSE
- `_parse_nikto()` - Procesa hallazgos de Nikto
- `_parse_gobuster()` - Extrae rutas descubiertas
- `_parse_headers()` - Analiza headers HTTP
- `_parse_curl_verbose()` - Procesa información de curl

**Salida**:
```json
{
  "target_ip": "10.1.11.177",
  "servicios_detectados": [...],
  "versiones": {...},
  "puertos": [...],
  "rutas_descubiertas": [...],
  "errores_http": [...],
  "vulnerabilidades_nikto": [...],
  "indicadores_owasp_top10": [...],
  "metadata_http": {...}
}
```

#### 2. `interpreter.py` - VulnerabilityInterpreter

**Responsabilidad**: Analizar y clasificar vulnerabilidades

**Métodos Principales**:
- `analyze()` - Ejecuta análisis completo
- `_analyze_attack_surface()` - Mapea superficie de ataque
- `_detect_technologies()` - Identifica tecnologías
- `_process_vulnerabilities()` - Clasifica vulnerabilidades
- `_classify_risks()` - Calcula distribución de riesgos
- `_generate_recommendations()` - Genera recomendaciones

**Clasificación CVSS 3.1**:
- **Crítica**: 9.0 - 10.0
- **Alta**: 7.0 - 8.9
- **Media**: 4.0 - 6.9
- **Baja**: 0.1 - 3.9

#### 3. `report_generator.py` - ReportGenerator

**Responsabilidad**: Generar informes en múltiples formatos

**Métodos Principales**:
- `generate_all_reports()` - Genera todos los formatos
- `generate_txt_report()` - Informe en texto plano
- `generate_json_report()` - Datos estructurados
- `generate_html_report()` - Informe web interactivo
- `generate_markdown_report()` - Documentación técnica

#### 4. `agent.py` - ScanAgent

**Responsabilidad**: Orquestar todo el flujo de trabajo

**Métodos Principales**:
- `run()` - Ejecuta el proceso completo
- `_execute_parsing()` - Fase 1
- `_execute_interpretation()` - Fase 2
- `_execute_report_generation()` - Fase 3

## 📖 Estructura del Informe

### Secciones del Informe

1. **Resumen Ejecutivo**
   - Nivel de riesgo general
   - Distribución de vulnerabilidades
   - Principales riesgos identificados
   - Recomendación general

2. **Mapa de Superficie de Ataque**
   - Puertos expuestos
   - Servicios activos
   - Endpoints descubiertos
   - Rutas críticas

3. **Tecnologías Detectadas**
   - Servidor web y versión
   - Lenguajes y frameworks
   - Bases de datos
   - Configuración SSL/TLS

4. **Vulnerabilidades Detalladas**
   - Por severidad (Crítica, Alta, Media, Baja)
   - ID de vulnerabilidad
   - CVSS Score
   - Categoría OWASP
   - Descripción
   - Evidencia
   - Recomendación específica

5. **Resumen de Riesgos (CVSS 3.1)**
   - Distribución por severidad
   - Gráficos estadísticos (HTML)

6. **Recomendaciones de Mitigación**
   - **Corto Plazo** (Inmediato - 1 semana)
   - **Mediano Plazo** (1-4 semanas)
   - **Largo Plazo** (1-6 meses)

## 🔍 Mapeo OWASP Top 10 2021

El agente mapea automáticamente vulnerabilidades a categorías OWASP:

| Código | Categoría | Ejemplos Detectados |
|--------|-----------|-------------------|
| **A01** | Broken Access Control | Rutas administrativas expuestas |
| **A02** | Cryptographic Failures | SSL/TLS débil, cifrados inseguros |
| **A03** | Injection | SQL injection, XSS potencial |
| **A04** | Insecure Design | Configuraciones inseguras |
| **A05** | Security Misconfiguration | Headers faltantes, errores expuestos |
| **A06** | Vulnerable Components | Versiones desactualizadas |
| **A07** | Auth Failures | Autenticación débil |
| **A08** | Data Integrity Failures | Validación insuficiente |
| **A09** | Logging Failures | Monitoreo insuficiente |
| **A10** | SSRF | Server-Side Request Forgery |

## 🎨 Ejemplo de Salida

### Informe de Consola

```
================================================================================
✅ PROCESO COMPLETADO EXITOSAMENTE
================================================================================

📊 ESTADÍSTICAS DE EJECUCIÓN:
  • Archivos encontrados:       6
  • Elementos parseados:        42
  • Vulnerabilidades detectadas: 15
  • Informes generados:         4
  • Tiempo de ejecución:        2.34 segundos

💡 PRÓXIMOS PASOS:
  1. Revisa el archivo informe_tecnico.html en tu navegador
  2. Lee el resumen ejecutivo para priorizar acciones
  3. Implementa las recomendaciones de corto plazo inmediatamente

================================================================================
```

### Ejemplo de JSON Generado

```json
{
  "metadata": {
    "generated_at": "2024-11-12T15:32:18",
    "generator": "Scan Agent v1.0.0",
    "target_ip": "10.1.11.177",
    "total_vulnerabilities": 15
  },
  "executive_summary": {
    "nivel_riesgo_general": "ALTO",
    "indicador_color": "naranja",
    "total_vulnerabilidades": 15,
    "vulnerabilidades_criticas": 2,
    "vulnerabilidades_altas": 5,
    "principales_riesgos": [
      "Headers de Seguridad HTTP Faltantes",
      "Ruta Administrativa/Sensible Expuesta",
      "Divulgación de Información Sensible"
    ]
  },
  "vulnerabilities": [
    {
      "id": "IND-1",
      "titulo": "Headers de Seguridad HTTP Faltantes",
      "descripcion": "Faltan headers de seguridad críticos",
      "severidad": "alta",
      "cvss_score": 7.5,
      "owasp_category": "A05:2021 - Security Misconfiguration",
      "fuente": "headers_http",
      "recomendacion": "Agregar headers: Strict-Transport-Security, X-Frame-Options..."
    }
  ]
}
```

## 🛠️ Solución de Problemas

### Error: "No se encontraron archivos .txt"

**Solución**:
```bash
# Verifica que los archivos estén en ./outputs/
ls -la outputs/

# Verifica los nombres de archivo
# Deben seguir el formato: herramienta_IP.txt
```

### Error: "No se pudieron importar los módulos"

**Solución**:
```bash
# Asegúrate de estar en el directorio correcto
cd /ruta/a/scan-agent

# Verifica que todos los archivos estén presentes
ls -la *.py

# Ejecuta con Python 3.12+
python3 --version
python3 agent.py
```

### El agente no detecta la IP

**Solución**:
```bash
# Especifica la IP manualmente
python3 agent.py --target-ip 192.168.1.100
```

### Permiso denegado

**Solución**:
```bash
# Haz los archivos ejecutables
chmod +x agent.py parser.py interpreter.py report_generator.py

# O ejecuta con python3 directamente
python3 agent.py
```

## 🤝 Contribuir

¿Quieres mejorar Scan Agent? ¡Las contribuciones son bienvenidas!

### Áreas de Mejora

- [ ] Integración con bases de datos CVE
- [ ] Soporte para más herramientas (Burp Suite, ZAP)
- [ ] Generación de informes PDF
- [ ] API REST para integración
- [ ] Dashboard web en tiempo real
- [ ] Machine Learning para detección de falsos positivos
- [ ] Integración con SIEM

### Cómo Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add: AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📝 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## 👥 Autores

- **Scan Agent Team** - *Desarrollo inicial* - v1.0.0

## 🙏 Agradecimientos

- Comunidad de seguridad open source
- Proyectos OWASP
- Desarrolladores de herramientas de pentesting

## 📞 Soporte

¿Necesitas ayuda? 

- 📧 Email: support@scanagent.local
- 📖 Documentación: [GitHub Wiki](https://github.com/scanagent/docs)
- 🐛 Issues: [GitHub Issues](https://github.com/scanagent/issues)

---

**⚠️ Disclaimer**: Esta herramienta está diseñada para uso legal y ético en entornos autorizados. El uso indebido de esta herramienta puede ser ilegal. Los autores no se responsabilizan por el mal uso de este software.

---

Desarrollado con ❤️ por Scan Agent Team | v1.0.0 | 2024
