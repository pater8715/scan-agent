# 🐳 Scan Agent - Guía Docker

## 📦 Instalación y Construcción

### Prerrequisitos

- Docker Desktop 20.10+
- Docker Compose v2.0+
- 4GB RAM mínimo
- 10GB espacio en disco

### Construcción de la imagen

```bash
# Usando Docker Compose (recomendado)
cd scan-agent
docker compose -f docker/docker-compose.yml --profile web build

# O construcción directa
docker build -f docker/Dockerfile -t scan-agent:3.0.0 .
```

### Verificar imagen creada

```bash
docker images | grep scan-agent
# scan-agent                3.0.0    <IMAGE_ID>    <SIZE>
# scan-agent-analyzer       3.0.0    <IMAGE_ID>    <SIZE>
```

---

## 🆕 Novedades v3.0 - Docker Edition

La imagen Docker ahora incluye:

✅ **Interfaz Web FastAPI**: Servidor web en puerto 8080 con UI moderna  
✅ **Entrypoint Optimizado**: Uvicorn ASGI server para alto rendimiento  
✅ **Multi-Service**: Perfiles para web, CLI, analyzer y desarrollo  
✅ **Reportes Profesionales**: HTML/JSON/TXT/MD con diseño moderno  
✅ **Análisis Inteligente**: Clasificación automática CRITICAL/HIGH/MEDIUM/LOW  
✅ **Risk Scoring**: Puntuación 0-100+ basada en hallazgos  
✅ **Parser Mejorado**: Extracción estructurada desde Nmap, Nikto, Gobuster  
✅ **Executive Summary**: Resumen ejecutivo con badges y métricas  
✅ **Health Checks**: Monitoreo automático del estado de contenedores  

---

## 🚀 Inicio Rápido

### 1. Iniciar Web UI (Recomendado)

```bash
# PowerShell (Windows)
cd scan-agent
docker compose -f docker/docker-compose.yml --profile web up -d

# Bash (Linux/Mac)
cd scan-agent
docker compose -f docker/docker-compose.yml --profile web up -d
```

### 2. Acceder a la aplicación

- **Web UI**: http://localhost:8080
- **API Docs**: http://localhost:8080/api/docs
- **Health Check**: http://localhost:8080/health

### 3. Ver logs en tiempo real

```bash
# Logs del servicio web
docker logs scan-agent-web -f

# Logs de todos los servicios
docker compose -f docker/docker-compose.yml --profile web logs -f
```

### 4. Detener servicios

```bash
docker compose -f docker/docker-compose.yml --profile web down
```

---

## 🔍 Escaneos

### Escaneo rápido (sin sudo)

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:3.0.0 \
  --scan --target 192.168.1.100 --profile quick
```

### Escaneo estándar

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:3.0.0 \
  --scan --target example.com --profile standard
```

### Escaneo web

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:3.0.0 \
  --scan --target https://example.com --profile web
```

### Escaneo stealth (requiere permisos especiales)

```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:3.0.0 \
  --scan --target 192.168.1.100 --profile stealth
```

### Escaneo completo de red (requiere permisos especiales)

```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network host \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:3.0.0 \
  --scan --target 192.168.1.0/24 --profile network
```

---

## 📊 Análisis de Resultados

### Analizar archivos existentes en outputs/

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  scan-agent:3.0.0 \
  --outputs-dir /scan-agent/outputs --format txt
```

### Generar reporte HTML

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  scan-agent:3.0.0 \
  --outputs-dir /scan-agent/outputs --format html --report-file security_report.html
```

### Generar reporte JSON

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  scan-agent:3.0.0 \
  --outputs-dir /scan-agent/outputs --format json --report-file vulnerabilities.json
```

---

## 🔍 Perfiles de Servicio

### Perfil Web (Recomendado)

Inicia la interfaz web completa con API REST:

```bash
# Iniciar
docker compose -f docker/docker-compose.yml --profile web up -d

# Servicios incluidos:
# - scan-agent-web: Interfaz web en http://localhost:8080
# - scan-agent-analyzer: Procesador de análisis en segundo plano
```

**Características:**
- ✅ Interfaz web moderna y responsive
- ✅ API REST documentada (Swagger/OpenAPI)
- ✅ Ejecución de escaneos desde navegador
- ✅ Visualización de reportes en tiempo real
- ✅ Historial de escaneos
- ✅ Health checks automáticos

### Perfil CLI

Para escaneos desde línea de comandos:

```bash
# Iniciar contenedor CLI
docker compose -f docker/docker-compose.yml --profile cli run --rm scan-agent-cli \
  --target scanme.nmap.org --profile quick

# Ver ayuda
docker compose -f docker/docker-compose.yml --profile cli run --rm scan-agent-cli --help
```

### Perfil All

Inicia todos los servicios:

```bash
docker compose -f docker/docker-compose.yml --profile all up -d
```

---

## 📊 Uso de la Web UI

### 1. Ejecutar escaneo desde el navegador

1. Acceder a http://localhost:8080
2. Ingresar IP o dominio objetivo
3. Seleccionar perfil de escaneo
4. Hacer clic en "Iniciar Escaneo"
5. Ver progreso en tiempo real

### 2. Consultar API REST

```bash
# Listar escaneos
curl http://localhost:8080/api/scans

# Ver detalles de un escaneo
curl http://localhost:8080/api/scans/{scan_id}

# Descargar reporte
curl http://localhost:8080/api/scans/{scan_id}/report?format=json
```

### 3. Documentación interactiva

Visitar http://localhost:8080/api/docs para explorar todos los endpoints disponibles.

---

## 🛠️ Administración de Contenedores

### Ver estado de servicios

```bash
docker ps
# o
docker compose -f docker/docker-compose.yml --profile web ps
```

### Reiniciar servicios

```bash
# Reiniciar todos los servicios
docker compose -f docker/docker-compose.yml --profile web restart

# Reiniciar solo web
docker restart scan-agent-web
```

### Ver logs

```bash
# Logs del servicio web
docker logs scan-agent-web --tail 50 -f

# Logs del analyzer
docker logs scan-agent-analyzer --tail 50 -f
```

### Ejecutar comandos dentro del contenedor

```bash
# Shell interactivo
docker exec -it scan-agent-web /bin/bash

# Ejecutar comando específico
docker exec scan-agent-web python3 --version
```

```bash
# Acceder al contenedor
docker-compose run --rm scan-agent /bin/bash

# Dentro del contenedor
python3 agent.py --scan --target 192.168.1.100 --profile quick
python3 agent.py --outputs-dir outputs --format txt
exit
```

---

## 📁 Estructura de Volúmenes

```
scan-agent/
├── outputs/          # Archivos de escaneo (montado como volumen)
│   ├── nmap_*.txt
│   ├── nikto_*.txt
│   └── ...
├── reports/          # Reportes generados (montado como volumen)
│   ├── security_report.html
│   ├── vulnerabilities.json
│   └── ...
```

---

## ⚙️ Configuración Avanzada

### Variables de entorno

```bash
docker run --rm \
  -e TZ=America/New_York \
  -e PYTHONUNBUFFERED=1 \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:3.0.0 \
  --scan --target example.com --profile standard
```

### Límites de recursos

```bash
docker run --rm \
  --cpus="2.0" \
  --memory="2g" \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:3.0.0 \
  --scan --target 192.168.1.100 --profile full
```

### Red personalizada

```bash
# Crear red
docker network create scan-network

# Ejecutar en red personalizada
docker run --rm \
  --network scan-network \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:3.0.0 \
  --scan --target 192.168.1.100 --profile standard
```

---

## 🔒 Consideraciones de Seguridad

### Permisos de red

- **Escaneos básicos (quick, standard, web, compliance, api)**: No requieren permisos especiales
- **Escaneos avanzados (stealth, network, full con SYN)**: Requieren `--cap-add=NET_RAW` y `--cap-add=NET_ADMIN`

### Modo de red

- **bridge** (default): Para escaneos externos, aislado del host
- **host**: Para escaneos en la red local del host (requiere más permisos)

### Ejemplo seguro para pentesting externo

```bash
docker run --rm \
  --network bridge \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v $(pwd)/outputs:/scan-agent/outputs:rw \
  -v $(pwd)/reports:/scan-agent/reports:rw \
  scan-agent:3.0.0 \
  --scan --target external-target.com --profile full
```

---

## 🛠️ Troubleshooting

### Error: "Permission denied" en escaneos stealth/network

**Solución**: Agregar capacidades de red
```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  scan-agent:3.0.0 \
  --scan --target TARGET --profile stealth
```

### Error: "Cannot connect to target"

**Solución**: Verificar modo de red
```bash
# Para objetivos en red local
docker run --rm --network host ...

# Para objetivos externos
docker run --rm --network bridge ...
```

### Los archivos generados no persisten

**Solución**: Verificar volúmenes montados
```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  ...
```

### Verificar herramientas instaladas

```bash
docker run --rm scan-agent:3.0.0 /bin/bash -c "nmap --version && nikto -Version && gobuster version"
```

---

## 📝 Ejemplos Completos

### Workflow completo: Escaneo + Análisis + Reporte

```bash
# 1. Escaneo
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:3.0.0 \
  --scan --target 192.168.1.100 --profile standard

# 2. Análisis y generación de reporte HTML
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  scan-agent:3.0.0 \
  --outputs-dir /scan-agent/outputs --format html --report-file audit_192.168.1.100.html

# 3. Ver reporte
firefox reports/audit_192.168.1.100.html
```

### Escaneo de múltiples objetivos con script

```bash
#!/bin/bash
TARGETS=("192.168.1.100" "192.168.1.101" "192.168.1.102")

for target in "${TARGETS[@]}"; do
  echo "[*] Escaneando $target..."
  docker run --rm \
    -v $(pwd)/outputs:/scan-agent/outputs \
    scan-agent:3.0.0 \
    --scan --target "$target" --profile quick
done

echo "[*] Generando reporte consolidado..."
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  scan-agent:3.0.0 \
  --outputs-dir /scan-agent/outputs --format html --report-file consolidated_report.html
```

### Integración CI/CD (Jenkins, GitLab CI, etc.)

```yaml
# .gitlab-ci.yml
scan-security:
  stage: test
  image: scan-agent:3.0.0
  script:
    - python3 agent.py --scan --target $TARGET_URL --profile web
    - python3 agent.py --outputs-dir outputs --format json --report-file vulnerabilities.json
  artifacts:
    paths:
      - outputs/
      - reports/vulnerabilities.json
    expire_in: 30 days
  only:
    - main
```

---

## 🔄 Actualización y Mantenimiento

### Reconstruir imagen con cambios

```bash
docker build --no-cache -t scan-agent:3.0.0 .
```

### Limpiar imágenes antiguas

```bash
docker image prune -a
```

### Ver logs del contenedor

```bash
docker logs <container_id>
```

---

## 📚 Referencias

- [Documentación principal](../README.md)
- [Guía de escaneo](GUIA_ESCANEO.md)
- [Dockerfile](Dockerfile)
- [Docker Compose](docker-compose.yml)

---

# [ARCHIVO OBSOLETO]

Esta guía ya no es relevante para despliegue directo en Render.com. El proyecto ahora se despliega sin Docker. Usa únicamente las instrucciones del README.md para Render.

---

## 🆕 Render.com y Dockerfile Separados

A partir de la versión 3.0, Scan Agent soporta despliegue cloud en [Render.com](https://render.com/) usando archivos dedicados:

- `Dockerfile.render`: Imagen minimal para Render (sin modo privilegiado, solo web)
- `render.yaml`: Configuración declarativa Render
- `docker/Dockerfile.backup-local`: Dockerfile completo para desarrollo/local (multi-stage, modo privilegiado, herramientas avanzadas)

**Diferencias clave:**
- Render no permite `--privileged` ni capacidades avanzadas de red
- Solo expone el puerto 8080
- El Dockerfile local soporta todos los perfiles y escaneos avanzados

### Despliegue en Render.com

1. Sube tu repo a GitHub
2. En Render, crea un nuevo servicio Web y selecciona:
   - Dockerfile path: `Dockerfile.render`
   - Web Service Port: 8080
   - Variables de entorno: (opcional, ver `render.yaml`)
3. Render usará automáticamente el archivo `render.yaml` si está presente
4. Accede a la web: https://<tu-app>.onrender.com
