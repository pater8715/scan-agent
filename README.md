# 🛡️ Scan Agent v3.0

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.0-orange.svg)](docs/VERSION.md)

**Agente educativo de análisis de vulnerabilidades** diseñado para clases de seguridad en aplicaciones web y APIs REST. Detecta vulnerabilidades según OWASP Web Top 10 (2021) y **OWASP API Security Top 10 (2023)**, con entorno de práctica integrado (Juice Shop + DVWA) y base de conocimiento CVE actualizada.

---

## ✨ Características Principales

### 🎯 Análisis Inteligente
- **10 Perfiles de Escaneo**: Quick, Standard, Full, Web, Stealth, Network, Compliance, API, API-OWASP, Lab
- **Clasificación Automática**: CRITICAL → HIGH → MEDIUM → LOW
- **Risk Scoring**: Puntuación 0-100+ basada en puertos, versiones y CVEs
- **Detección de Servicios**: Identificación automática con nmap 7.99

### 🔐 OWASP API Security Top 10 (2023)
- **Cobertura completa** de las 10 categorías API Top 10 2023 (`api_security_checker.py`)
- Detección de BOLA/IDOR, Broken Authentication (JWT none alg), Mass Assignment
- Pruebas de Rate Limiting, SSRF, Security Misconfiguration, Unsafe Consumption
- Mapeo automático a **CWE** por cada hallazgo API

### 🗄️ Base de Conocimiento CVE Actualizada
- Integración con **NVD API 2.0** — enriquecimiento automático de CVEs detectados
- **CISA KEV** (Known Exploited Vulnerabilities) — escala a CRÍTICA si el CVE está activamente explotado
- **OSV** (osv.dev) — vulnerabilidades en librerías y dependencias
- Caché SQLite local con TTL configurable (`vuln_db.py`)

### 🧪 Entorno de Práctica Controlado (Lab)
- **OWASP Juice Shop** en `http://localhost:3000` — aplicación web vulnerable moderna
- **DVWA** en `http://localhost:8081` — ejercicios clásicos por nivel de dificultad
- Perfil `lab` de escaneo que apunta automáticamente a los objetivos locales
- Guía de ejercicios por vulnerabilidad OWASP: [`docs/guides/LAB_GUIDE.md`](docs/guides/LAB_GUIDE.md)

### 📊 Reportes Profesionales
- **Formatos Múltiples**: HTML, JSON, TXT, Markdown
- **Diseño Moderno**: Templates responsive con gradientes CSS
- **Dashboard Interactivo**: Vista cronológica por IP y escaneos
- **Análisis Ejecutivo**: Resumen de riesgos con recomendaciones accionables

### 🌐 Interfaz Web (FastAPI + Uvicorn)
- **UI Moderna**: Diseño responsive con validación en tiempo real
- **API REST Completa**: Documentación Swagger/OpenAPI integrada
- **Monitoreo en Vivo**: Seguimiento de progreso en tiempo real
- **Historial Visual**: Búsqueda y navegación de escaneos anteriores

### 🐳 Docker
- **Multi-Stage Build**: Imagen optimizada con Kali Linux base
- **Multi-Service**: CLI, Web UI, Lab, Analyzer, Dev profiles
- **Health Checks**: Monitoreo automático de servicios

---

## 🚀 Inicio Rápido

### Opción 1: Entorno de Práctica (Lab)

```bash
# Inicia Scan Agent Web + Juice Shop + DVWA
docker compose -f docker/docker-compose.yml --profile lab up -d

# Acceder a:
# - Scan Agent:  http://localhost:8080
# - Juice Shop:  http://localhost:3000
# - DVWA:        http://localhost:8081  (admin / password)

# Escanear Juice Shop desde el lab
docker compose -f docker/docker-compose.yml run --rm scan-agent-cli \
  --target localhost --port 3000 --profile lab

# Detener lab
docker compose -f docker/docker-compose.yml --profile lab down
```

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
│   ├── interpreter.py          # Clasificación OWASP Web + API Top 10
│   ├── api_security_checker.py # Pruebas activas OWASP API Top 10 2023
│   ├── vuln_db.py              # Base CVE: NVD, CISA KEV, OSV
│   ├── agent.py                # CLI principal
│   ├── report_generator.py     # Generación de reportes
│   └── database.py             # Gestión SQLite
├── webapp/                     # Interfaz web FastAPI
│   ├── main.py                 # Servidor ASGI
│   ├── api/                    # Endpoints REST
│   ├── templates/              # Plantillas Jinja2
│   └── static/                 # CSS/JS/Assets
├── docker/                     # Docker
│   ├── Dockerfile              # Multi-stage build (Kali Linux)
│   └── docker-compose.yml      # Perfiles: cli, web, lab, dev
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
- **[Changelog v3.0](docs/changelog/CHANGELOG_v3.0.md)** — Novedades de la versión

---

## 🔧 Comandos Make

```bash
# Lab de práctica
make lab-start        # Iniciar Juice Shop + DVWA + Scan Agent
make lab-stop         # Detener lab
make lab-status       # Estado de contenedores del lab
make lab-scan-juice   # Escanear Juice Shop
make lab-scan-dvwa    # Escanear DVWA

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
```

### Lab de práctica (Juice Shop + DVWA)

```bash
# Iniciar entorno completo
make lab-start

# Escanear objetivos del lab
make lab-scan-juice   # → http://localhost:3000
make lab-scan-dvwa    # → http://localhost:8081

# Ver guía de ejercicios
cat docs/guides/LAB_GUIDE.md
```

### Actualizar base de CVEs

```bash
# Actualiza CISA KEV + limpia caché expirada
python3 scripts/scan-agent.py --update-db
```

### API REST

```bash
# Iniciar escaneo
curl -X POST http://localhost:8080/api/scans/start \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org", "profile": "quick"}'

# Listar escaneos
curl http://localhost:8080/api/scans

# Obtener reporte
curl http://localhost:8080/api/scans/{scan_id}/report?format=json
```

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