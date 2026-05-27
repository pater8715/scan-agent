# 🛡️ Scan Agent v3.3

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.1.0-orange.svg)](docs/VERSION.md)

**Agente educativo de análisis de vulnerabilidades** diseñado para clases de seguridad en aplicaciones web y APIs REST. Detecta vulnerabilidades según OWASP Web Top 10 (2021) y **OWASP API Security Top 10 (2023)**, con entorno de práctica integrado (Juice Shop + DVWA) y base de conocimiento CVE actualizada.

---

## 🆕 Novedades v3.1

### Reportes específicos por perfil de escaneo
Cada perfil genera ahora una sección dedicada en el reporte con análisis adaptado:

- **Perfil `web`** — Tabla de cabeceras de seguridad HTTP (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection) con estado PRESENTE/AUSENTE, hallazgos Nikto, y detección de directorios sensibles
- **Perfil `network`** — Análisis de infraestructura: puertos abiertos, sistema operativo detectado, versiones de servicio con alertas de vulnerabilidad
- **Perfil `api-owasp`** — Tabla OWASP API Security Top 10 2023 con estado por categoría (✅ Revisado / ⚠️ Hallazgo), análisis de CORS, autenticación y rate limiting
- **Perfil `compliance`** — Revisión combinada de cabeceras de seguridad + estado SSL/TLS

### VulnerabilityAnalyzer orientado a perfiles
El analizador de vulnerabilidades acepta ahora un parámetro `profile` que adapta el análisis:
- Detección de 7 cabeceras de seguridad HTTP ausentes
- Detección de rutas sensibles: `.git`, `.env`, `/admin`, `/backup`, `/swagger`, `/phpinfo.php`, etc.
- Mapeo automático de hallazgos al OWASP API Top 10 2023
- Recomendaciones y severidad adaptadas al perfil de escaneo

### Panel de Objetivos de Laboratorio en la UI
- Aparece debajo del campo "Objetivo" en el formulario de escaneo
- Muestra todos los servicios Docker del lab con estado en tiempo real (🟢 activo / 🔴 inactivo)
- Un clic sobre un servicio rellena automáticamente el campo objetivo y selecciona el perfil recomendado
- Servicios monitorizados: Juice Shop, DVWA, DVWA-DB, ZAP, Scan Agent (self), host.docker.internal

### Red Docker con IPs fijas
Todos los servicios del lab tienen IPs estáticas en la subred `172.20.0.0/24`:

| Servicio              | IP fija       |
|-----------------------|---------------|
| scan-agent-web        | 172.20.0.2    |
| juice-shop            | 172.20.0.3    |
| dvwa                  | 172.20.0.4    |
| zap                   | 172.20.0.5    |
| dvwa-db               | 172.20.0.6    |
| scan-agent-analyzer   | 172.20.0.7    |

- `extra_hosts: host.docker.internal:host-gateway` permite escanear el host real desde dentro de los contenedores

### Nuevos endpoints de API REST
| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/lab/targets` | Lista objetivos del lab con conectividad en tiempo real |
| GET | `/api/lab/network-info` | Información de red del contenedor activo |
| GET | `/api/reports/` | Lista todos los escaneos con reportes disponibles |
| GET | `/api/reports/{id}/view/html` | Visualización inline del reporte en HTML |
| GET | `/api/reports/{id}/view/txt` | Visualización inline del reporte en TXT |

### Barra de escaneos activos
- Visible en todas las pestañas de la UI en tiempo real
- Muestra progreso, objetivo y perfil de cada escaneo en curso
- Se actualiza automáticamente al completarse un escaneo

### Pestaña Reportes rediseñada
- Sidebar con lista cronológica de escaneos completados
- Visor inline integrado: HTML, TXT y JSON sin salir de la UI
- Filtro por perfil y estado

### Otras mejoras técnicas
- **Parser de cabeceras HTTP corregido** — extrae únicamente headers de respuesta HTTP del output de `curl --verbose`, ignorando cabeceras de petición
- **Soporte CIDR** para escaneos de red (ej. `192.168.1.0/24`)
- **Variable de entorno `ALLOW_PUBLIC_TARGETS=true`** para habilitar escaneos externos (desactivado por defecto)
- **Ejecución asíncrona** — los escaneos se ejecutan en `ThreadPoolExecutor`, sin bloquear el servidor FastAPI

---

## ✨ Características Principales

### 🎯 Análisis Inteligente
- **10 Perfiles de Escaneo**: Quick, Standard, Full, Web, Stealth, Network, Compliance, API, API-OWASP, Lab
- **Clasificación Automática**: CRITICAL → HIGH → MEDIUM → LOW
- **Risk Scoring**: Puntuación 0-100+ basada en puertos, versiones y CVEs
- **Detección de Servicios**: Identificación automática con nmap 7.99
- **Reportes por perfil**: Secciones de análisis adaptadas al tipo de escaneo seleccionado

### 🔐 OWASP API Security Top 10 (2023)
- **Cobertura completa** de las 10 categorías API Top 10 2023 (`api_security_checker.py`)
- Detección de BOLA/IDOR, Broken Authentication (JWT none alg), Mass Assignment
- Pruebas de Rate Limiting, SSRF, Security Misconfiguration, Unsafe Consumption
- Mapeo automático a **CWE** por cada hallazgo API
- Tabla de estado por categoría en reportes del perfil `api-owasp`

### 🗄️ Base de Conocimiento CVE Actualizada
- Integración con **NVD API 2.0** — enriquecimiento automático de CVEs detectados
- **CISA KEV** (Known Exploited Vulnerabilities) — escala a CRÍTICA si el CVE está activamente explotado
- **OSV** (osv.dev) — vulnerabilidades en librerías y dependencias
- Caché SQLite local con TTL configurable (`vuln_db.py`)

### 🧪 Entorno de Práctica Controlado (Lab)
- **OWASP Juice Shop** accesible en `http://localhost:3000` desde el host
- **DVWA** accesible en `http://localhost:8081` (admin / password)
- Red Docker interna con IPs fijas (`172.20.0.0/24`) para escaneos fiables entre contenedores
- **Panel de Objetivos de Laboratorio** en la UI: selección con un clic y estado en tiempo real
- Perfil `lab` de escaneo que apunta automáticamente a los objetivos locales
- Guía de ejercicios por vulnerabilidad OWASP: [`docs/guides/LAB_GUIDE.md`](docs/guides/LAB_GUIDE.md)

### 📊 Reportes Profesionales
- **Formatos Múltiples**: HTML, JSON, TXT, Markdown
- **Diseño Moderno**: Templates responsive con gradientes CSS
- **Dashboard Interactivo**: Vista cronológica por IP y escaneos
- **Análisis Ejecutivo**: Resumen de riesgos con recomendaciones accionables
- **Visor inline**: Visualización HTML/TXT/JSON directamente en la pestaña Reportes

### 🌐 Interfaz Web (FastAPI + Uvicorn)
- **UI Moderna**: Diseño responsive con validación en tiempo real
- **API REST Completa**: Documentación Swagger/OpenAPI integrada
- **Monitoreo en Vivo**: Barra de escaneos activos visible en todas las pestañas
- **Historial Visual**: Búsqueda y navegación de escaneos anteriores
- **Panel de Lab**: Estado en tiempo real de los servicios Docker del laboratorio

### 🐳 Docker
- **Multi-Stage Build**: Imagen optimizada con Kali Linux base
- **Multi-Service**: CLI, Web UI, Lab, Analyzer, Dev profiles
- **Red estática**: Subred `172.20.0.0/24` con IPs fijas por servicio
- **Health Checks**: Monitoreo automático de servicios

---

## 🚀 Inicio Rápido

### Opción 1: Entorno de Práctica (Lab)

**Windows** — usa el lanzador interactivo incluido:
```powershell
.\start.ps1 -Perfil lab -Accion iniciar
```

**Linux / macOS:**
```bash
# Inicia Scan Agent Web + Juice Shop + DVWA + ZAP
docker compose -f docker/docker-compose.yml --profile lab up -d

# Acceder a:
# - Scan Agent:  http://localhost:8080
# - Juice Shop:  http://localhost:3000
# - DVWA:        http://localhost:8081  (admin / password)
# - ZAP API:     http://localhost:8090

# Escanear Juice Shop desde dentro de la red Docker (usar hostname de servicio)
docker compose -f docker/docker-compose.yml run --rm scan-agent-cli \
  --target juice-shop:3000 --profile web

# Escanear DVWA desde dentro de la red Docker
docker compose -f docker/docker-compose.yml run --rm scan-agent-cli \
  --target dvwa:80 --profile web

# Detener lab
docker compose -f docker/docker-compose.yml --profile lab down
```

> **Nota importante:** Desde dentro de los contenedores Docker, los servicios del lab deben referenciarse por su hostname de servicio (`juice-shop`, `dvwa`), no por `localhost`. El Panel de Objetivos de Laboratorio en la UI hace esto automáticamente.

### Opción 2: Docker Web UI

```bash
# Iniciar solo la interfaz web
docker compose -f docker/docker-compose.yml --profile web up -d

# Web UI: http://localhost:8080
# API Docs: http://localhost:8080/api/docs
# Health: http://localhost:8080/health

docker compose -f docker/docker-compose.yml --profile web down
```

### Opción 3: Docker CLI

```bash
# Escaneo rápido
docker compose -f docker/docker-compose.yml --profile cli run --rm scan-agent-cli \
  --target scanme.nmap.org --profile quick

# Escaneo API completo (OWASP API Top 10 2023)
docker compose -f docker/docker-compose.yml --profile cli run --rm scan-agent-cli \
  --target api.example.com --profile api-owasp

# Escaneo de red con CIDR
docker compose -f docker/docker-compose.yml --profile cli run --rm scan-agent-cli \
  --target 192.168.1.0/24 --profile network

# Ver reportes generados
ls -la reports/
```

### Opción 4: Instalación Local

```bash
git clone https://github.com/pater8715/scan-agent.git
cd scan-agent
pip3 install -r requirements.txt
pip3 install -r webapp/requirements.txt

# Escaneo rápido
python3 scripts/scan-agent.py --target scanme.nmap.org --profile quick

# Actualizar base CVE/KEV
python3 scripts/scan-agent.py --update-db
```

### 🚀 Despliegue en Render.com (Cloud)

```bash
# 1. Sube tu fork a GitHub
# 2. En Render, crea un Web Service → "Deploy from repo"
# 3. Dockerfile path: Dockerfile.render  |  Port: 8080
# 4. Render usa render.yaml automáticamente si está presente
# 5. Accede a: https://<tu-app>.onrender.com
```

**Nota:** Render no permite modo privilegiado — los escaneos activos de red no están disponibles en cloud. Para el lab completo usar Docker local.

---

## 📁 Estructura del Proyecto

```
scan-agent/
├── src/scanagent/              # Módulos principales
│   ├── scanner.py              # Motor de escaneo (10 perfiles)
│   ├── parser.py               # Parser e integración de resultados
│   ├── report_parser.py        # Secciones de reporte por perfil (web/network/api-owasp/compliance)
│   ├── interpreter.py          # Clasificación OWASP Web + API Top 10
│   ├── api_security_checker.py # Pruebas activas OWASP API Top 10 2023
│   ├── vuln_db.py              # Base CVE: NVD, CISA KEV, OSV
│   ├── agent.py                # CLI principal
│   ├── report_generator.py     # Generación de reportes
│   └── database.py             # Gestión SQLite
├── webapp/                     # Interfaz web FastAPI
│   ├── main.py                 # Servidor ASGI
│   ├── api/                    # Endpoints REST
│   │   ├── scans.py            # Escaneos + reportes por perfil
│   │   ├── reports.py          # Listado y visor inline de reportes
│   │   ├── lab.py              # Objetivos del lab y red Docker
│   │   └── profiles.py         # Perfiles de escaneo disponibles
│   ├── templates/              # Plantillas Jinja2
│   └── static/                 # CSS/JS/Assets
│       ├── css/
│       │   ├── styles.css      # Estilos generales
│       │   └── active-scans.css# Barra de escaneos activos
│       └── js/
├── docker/                     # Docker
│   ├── Dockerfile              # Multi-stage build (Kali Linux)
│   └── docker-compose.yml      # Perfiles: cli, web, lab, dev — red 172.20.0.0/24
├── scripts/                    # Scripts
│   ├── scan-agent.py           # Punto de entrada CLI
│   └── docker-entrypoint.sh
├── docs/                       # Documentación
│   └── guides/
│       └── LAB_GUIDE.md        # Guía de ejercicios prácticos
├── config/
│   └── schema.sql              # Esquema SQLite (cve_cache, kev_catalog, osv_cache)
├── outputs/                    # Salidas de escaneo
├── reports/                    # Reportes generados
├── data/                       # Base de datos
└── logs/                       # Archivos de log
```

---

## 📖 Documentación

- **[Manual de Usuario](docs/MANUAL_USUARIO.md)** — Instalación, uso del UI/CLI, reportes, troubleshooting
- **[Guía del Lab](docs/guides/LAB_GUIDE.md)** — Ejercicios prácticos OWASP con Juice Shop y DVWA
- **[Guía de Inicio Rápido Web](docs/guides/QUICKSTART_WEB.md)** — Usar la interfaz web
- **[Guía de Escaneo](docs/GUIA_ESCANEO.md)** — Perfiles y parámetros
- **[Documentación Docker](docs/DOCKER.md)** — Configuración avanzada
- **[Changelog v3.0](docs/changelog/CHANGELOG_v3.0.md)** — Novedades de la versión anterior

---

## 🖥️ Lanzador Windows (`start.ps1`)

```powershell
# Menú interactivo completo
.\start.ps1

# Uso directo con parámetros
.\start.ps1 -Perfil lab   -Accion iniciar     # Iniciar lab
.\start.ps1 -Perfil lab   -Accion estado      # Ver estado
.\start.ps1 -Perfil web   -Accion logs        # Ver logs
.\start.ps1 -Perfil lab   -Accion reconstruir # Rebuild (con cache)
.\start.ps1 -Perfil lab   -Accion limpiar     # Borrar todo (pide confirmación)

# Perfiles: cli, web, lab, analyzer, zap, dev, all
```

---

## 🔧 Comandos Make

```bash
# Lab de práctica
make lab-start        # Iniciar Juice Shop + DVWA + Scan Agent + ZAP
make lab-stop         # Detener lab
make lab-status       # Estado de contenedores del lab
make lab-scan-juice   # Escanear Juice Shop (usa hostname juice-shop:3000)
make lab-scan-dvwa    # Escanear DVWA (usa hostname dvwa:80)

# Docker
make build            # Construir imagen
make up-web           # Iniciar Web UI
make up-cli           # Iniciar CLI
make down             # Detener servicios
make logs-web         # Ver logs web
make shell            # Shell interactivo

# Desarrollo
make run-cli          # Ejecutar CLI local
make test             # Ejecutar tests
make clean            # Limpiar archivos temporales
make rebuild          # Reconstruir imagen

make help             # Ver todos los comandos
```

---

## 🎯 Ejemplos de Uso

### Escaneo API con OWASP API Top 10 2023

```bash
# Escaneo completo de API REST
python3 scripts/scan-agent.py --target api.example.com --profile api-owasp

# Incluye pruebas de:
# - BOLA/IDOR (API1), Broken Auth/JWT (API2), Mass Assignment (API3)
# - Rate Limiting (API4), Function Level AuthZ (API5), SSRF (API7)
# - Security Misconfiguration (API8), Improper Inventory (API9)
# El reporte incluye tabla OWASP API Top 10 con estado por categoría
```

### Lab de práctica (Juice Shop + DVWA)

```bash
# Iniciar entorno completo
make lab-start

# Escanear objetivos del lab (hostnames de servicio Docker)
make lab-scan-juice   # → juice-shop:3000 (perfil web)
make lab-scan-dvwa    # → dvwa:80 (perfil web)

# También desde la UI → Panel de Objetivos de Laboratorio → clic en el servicio

# Ver guía de ejercicios
cat docs/guides/LAB_GUIDE.md
```

### Escaneo de red con CIDR

```bash
# Escanear un rango de red completo
python3 scripts/scan-agent.py --target 192.168.1.0/24 --profile network

# Dentro de Docker (permite escanear el host)
docker compose -f docker/docker-compose.yml run --rm scan-agent-cli \
  --target host.docker.internal --profile network
```

### Actualizar base de CVEs

```bash
# Actualiza CISA KEV + limpia caché expirada
python3 scripts/scan-agent.py --update-db
```

---

## 🔌 API REST

### Endpoints de escaneo

```bash
# Iniciar escaneo
curl -X POST http://localhost:8080/api/scans/start \
  -H "Content-Type: application/json" \
  -d '{"target": "juice-shop:3000", "profile": "web"}'

# Listar escaneos
curl http://localhost:8080/api/scans

# Obtener reporte
curl http://localhost:8080/api/scans/{scan_id}/report?format=json
```

### Endpoints de reportes

```bash
# Listar todos los reportes disponibles
curl http://localhost:8080/api/reports/

# Ver reporte en HTML (inline, para visor en UI)
curl http://localhost:8080/api/reports/{scan_id}/view/html

# Ver reporte en TXT (inline)
curl http://localhost:8080/api/reports/{scan_id}/view/txt
```

### Endpoints del laboratorio

```bash
# Lista objetivos del lab con estado de conectividad en tiempo real
curl http://localhost:8080/api/lab/targets

# Información de red del contenedor
curl http://localhost:8080/api/lab/network-info
```

---

## ⚙️ Variables de Entorno

| Variable | Valor por defecto | Descripción |
|----------|-------------------|-------------|
| `ALLOW_PUBLIC_TARGETS` | `false` | Habilitar escaneos a IPs/dominios externos |
| `PORT` | `8080` | Puerto del servidor FastAPI |
| `LOG_LEVEL` | `INFO` | Nivel de logging |
| `REPORTS_DIR` | `reports/` | Directorio de reportes generados |
| `NVD_API_KEY` | _(vacío)_ | API key para NVD (aumenta rate limit) |

---

## 🛠️ Requisitos

### Docker (recomendado)
- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB RAM (lab completo con Juice Shop + DVWA)
- 8GB espacio en disco

### Instalación Local
- Python 3.12+
- nmap 7.95+
- nikto 2.5.0+
- gobuster, curl
- SQLite3

---

## 📦 Instalación de Dependencias

### Ubuntu/Debian / Kali Linux
```bash
sudo apt update && sudo apt install nmap nikto gobuster curl
pip3 install -r requirements.txt
```

### macOS
```bash
brew install nmap nikto gobuster
pip3 install -r requirements.txt
```

---

## 🔒 Aviso de Uso Ético

- ⚠️ **Uso Autorizado**: Escanear únicamente sistemas propios o con permiso explícito
- 🧪 **Lab controlado**: Usar Juice Shop y DVWA para práctica — son aplicaciones diseñadas para ser vulneradas
- 📝 **Logging**: Todos los escaneos se registran en `logs/`
- 🛡️ **Entornos de producción**: Considerar el impacto antes de ejecutar escaneos activos
- 🌐 **Escaneos externos**: Requieren `ALLOW_PUBLIC_TARGETS=true` para evitar escaneos accidentales

---

## 🤝 Contribuir

1. Fork el repositorio
2. Crea una rama feature (`git checkout -b feature/nueva-caracteristica`)
3. Commit tus cambios (`git commit -am 'Añadir nueva característica'`)
4. Push a la rama (`git push origin feature/nueva-caracteristica`)
5. Abre un Pull Request

---

## 📄 Licencia

MIT License — Ver [LICENSE](LICENSE) para más detalles

---

## 👤 Autor

**Alberto Paternina León**
- GitHub: [@pater8715](https://github.com/pater8715)

---

## 🎉 Agradecimientos

- [OWASP](https://owasp.org/) — OWASP Top 10 Web 2021 y API Security Top 10 2023
- [Nmap Project](https://nmap.org/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [DVWA](https://github.com/digininja/DVWA)
- [FastAPI](https://fastapi.tiangolo.com/)
- [NVD / CISA KEV / OSV](https://nvd.nist.gov/)

---

**⭐ Si encuentras útil este proyecto, considera darle una estrella en GitHub!**
