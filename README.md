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

---

## 🚀 Inicio Rápido

### Opción 1: Despliegue en Render.com (Recomendado)

```bash
# 1. Sube tu fork o repo a GitHub
# 2. En Render, crea un nuevo servicio Web → "Deploy from repo"
# 3. Selecciona el repo y configura:
#    - Web Service Port: 8080
#    - Root Directory: (raíz del repo)
#    - Variables de entorno: (opcional)
# 4. Render instalará automáticamente las dependencias de requirements.txt y webapp/requirements.txt
# 5. Accede a la web: https://<tu-app>.onrender.com
```

**Comando de inicio Render:**
```
python3 -m uvicorn webapp.main:app --host 0.0.0.0 --port 8080
```

### Opción 2: Instalación Local

```bash
# 1. Clonar repositorio
git clone https://github.com/pater8715/scan-agent.git
cd scan-agent

# 2. Instalar dependencias
pip3 install -r requirements.txt
pip3 install -r webapp/requirements.txt

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

- **[Guía de Escaneo](docs/GUIA_ESCANEO.md)** - Perfiles y parámetros
- **[Testing Guide](docs/guides/TESTING_GUIDE.md)** - Pruebas y validación
- **[Changelog v3.0](docs/changelog/CHANGELOG_v3.0.md)** - Novedades de la versión
- **[API Reference](docs/api/)** - Documentación de endpoints
- **[Roadmap](docs/ROADMAP.md)** - Próximas características

---

## 🔧 Comandos Make

```bash
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

### CLI Local

```bash
# Escaneo rápido
python3 scripts/scan-agent.py --target 192.168.1.100 --profile quick

# Escaneo completo
python3 scripts/scan-agent.py --target example.com --profile full --description "Pentesting inicial"

# Análisis de archivos existentes
python3 scripts/scan-agent.py --outputs-dir ./outputs --format html
```

---

## 🛠️ Requisitos

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
