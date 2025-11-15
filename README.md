# 🛡️ Scan Agent v3.0

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.0-orange.svg)](docs/VERSION.md)

**Agente de análisis de vulnerabilidades automatizado** con reportes profesionales, clasificación inteligente de riesgos, interfaz web moderna y arquitectura Docker optimizada.

---

## ✨ Características Principales

### 🎯 Análisis Inteligente
- **8 Perfiles de Escaneo**: Quick, Standard, Full, Web, Stealth, Network, Compliance, API
- **Clasificación Automática**: CRITICAL → HIGH → MEDIUM → LOW
- **Risk Scoring**: Puntuación 0-100+ basada en puertos, versiones y CVEs
- **Detección de Servicios**: Identificación automática con nmap 7.95

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

### 🐳 Docker v3.0
- **Multi-Stage Build**: Imagen optimizada de 1.2GB
- **Multi-Service**: CLI, Web UI, Analyzer, Dev profiles
- **Privileged Mode**: Soporte completo para escaneos de red
- **Health Checks**: Monitoreo automático de servicios

---

## 🚀 Inicio Rápido

### Opción 1: Docker (Recomendado)

```bash
# Iniciar Web UI
make up-web

# Abrir navegador
open http://localhost:8080

# Ver logs
make logs-web

# Detener servicios
make down
```

### Opción 2: Instalación Local

```bash
# 1. Clonar repositorio
git clone https://github.com/pater8715/scan-agent.git
cd scan-agent

# 2. Instalar dependencias
pip3 install -r requirements.txt

# 3. Ejecutar escaneo
python3 scripts/scan-agent.py --target scanme.nmap.org --profile quick

# 4. Ver reporte
open reports/dashboard.html
```

---

## 📁 Estructura del Proyecto

```
scan-agent/
├── src/scanagent/          # Código fuente principal
│   ├── scanner.py          # Motor de escaneo
│   ├── parser.py           # Parser de resultados
│   ├── analyzer.py         # Análisis de vulnerabilidades
│   ├── report_generator.py # Generación de reportes
│   └── database.py         # Gestión SQLite
├── webapp/                 # Interfaz web FastAPI
│   ├── main.py            # Servidor ASGI
│   ├── api/               # Endpoints REST
│   ├── templates/         # Plantillas Jinja2
│   └── static/            # CSS/JS/Assets
├── docker/                # Configuración Docker
│   ├── Dockerfile         # Multi-stage build
│   ├── docker-compose.yml # Orquestación
│   └── docker-compose.override.yml
├── scripts/               # Scripts de utilidad
│   ├── scan-agent.py      # CLI principal
│   ├── docker-entrypoint.sh
│   └── build.sh
├── docs/                  # Documentación
│   ├── guides/            # Guías de usuario
│   ├── changelog/         # Historial de cambios
│   └── archived/          # Documentación antigua
├── config/                # Configuración
│   └── schema.sql         # Esquema SQLite
├── outputs/               # Salidas de escaneo
├── reports/               # Reportes generados
├── data/                  # Base de datos
└── logs/                  # Archivos de log
```

---

## 📖 Documentación

- **[Guía de Inicio Rápido Web](docs/guides/QUICKSTART_WEB.md)** - Usar la interfaz web
- **[Guía de Escaneo](docs/GUIA_ESCANEO.md)** - Perfiles y parámetros
- **[Documentación Docker](docs/DOCKER.md)** - Configuración avanzada
- **[Testing Guide](docs/guides/TESTING_GUIDE.md)** - Pruebas y validación
- **[Changelog v3.0](docs/changelog/CHANGELOG_v3.0.md)** - Novedades de la versión
- **[API Reference](docs/api/)** - Documentación de endpoints
- **[Roadmap](docs/ROADMAP.md)** - Próximas características

---

## 🔧 Comandos Make

```bash
# Docker
make build          # Construir imagen
make up-web         # Iniciar Web UI
make up-cli         # Iniciar CLI
make down           # Detener servicios
make logs-web       # Ver logs web
make shell          # Shell interactivo

# Desarrollo
make run-cli        # Ejecutar CLI local
make test           # Ejecutar tests
make clean          # Limpiar archivos temporales
make rebuild        # Reconstruir imagen

# Ver todos los comandos
make help
```

---

## 🎯 Ejemplos de Uso

### CLI - Escaneo Rápido
```bash
python3 scripts/scan-agent.py --target 192.168.1.1 --profile quick
```

### CLI - Escaneo Completo
```bash
python3 scripts/scan-agent.py --target example.com --profile full --description "Pentesting inicial"
```

### Docker - Web UI
```bash
docker-compose --profile web up -d
```

### API REST
```bash
curl -X POST http://localhost:8080/api/scans/start \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org", "profile": "quick"}'
```

---

## 🛠️ Requisitos

### Docker
- Docker Engine 20.10+
- Docker Compose 2.0+
- 2GB RAM mínimo
- 5GB espacio en disco

### Instalación Local
- Python 3.12+
- nmap 7.95
- nikto 2.5.0
- gobuster, dirb, whatweb
- SQLite3

---

## 📦 Instalación de Dependencias

### macOS
```bash
brew install nmap nikto gobuster
pip3 install -r requirements.txt
```

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install nmap nikto gobuster dirb whatweb
pip3 install -r requirements.txt
```

### Kali Linux
```bash
sudo apt update
sudo apt install nmap nikto gobuster
pip3 install -r requirements.txt
```

---

## 🔒 Seguridad

- ⚠️ **Uso Ético**: Solo escanear sistemas autorizados
- 🔐 **Privilegios**: Requiere permisos de red para escaneos completos
- 📝 **Logging**: Todos los escaneos se registran en `logs/`
- 🛡️ **Firewall**: Considera el impacto en sistemas de producción

---

## 🤝 Contribuir

1. Fork el repositorio
2. Crea una rama feature (`git checkout -b feature/nueva-caracteristica`)
3. Commit tus cambios (`git commit -am 'Añadir nueva característica'`)
4. Push a la rama (`git push origin feature/nueva-caracteristica`)
5. Abre un Pull Request

---

## 📄 Licencia

MIT License - Ver [LICENSE](LICENSE) para más detalles

---

## 👤 Autor

**Alberto Paternina León**
- GitHub: [@pater8715](https://github.com/pater8715)

---

## 📞 Soporte

- 📧 Issues: [GitHub Issues](https://github.com/pater8715/scan-agent/issues)
- 📖 Docs: [Documentación Completa](docs/)
- 💬 Discussions: [GitHub Discussions](https://github.com/pater8715/scan-agent/discussions)

---

## 🎉 Agradecimientos

- [Nmap Project](https://nmap.org/)
- [OWASP](https://owasp.org/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [Kali Linux](https://www.kali.org/)

---

**⭐ Si encuentras útil este proyecto, considera darle una estrella en GitHub!**
