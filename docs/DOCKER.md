# 🐳 Scan Agent - Guía Docker

## 📦 Instalación

### Construcción de la imagen

```bash
# Desde el directorio scan-agent
docker build -t scan-agent:2.0.0 .

# O usando docker-compose
docker-compose build
```

### Verificar imagen creada

```bash
docker images | grep scan-agent
# scan-agent   2.0.0   <IMAGE_ID>   <SIZE>
```

---

## 🚀 Uso Básico

### 1. Ayuda y comandos disponibles

```bash
docker run --rm scan-agent:2.0.0 --help
```

### 2. Ver versión

```bash
docker run --rm scan-agent:2.0.0 --version
# Scan Agent v2.0.0
```

### 3. Listar perfiles de escaneo

```bash
docker run --rm scan-agent:2.0.0 --list-profiles
```

---

## 🔍 Escaneos

### Escaneo rápido (sin sudo)

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:2.0.0 \
  --scan --target 192.168.1.100 --profile quick
```

### Escaneo estándar

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:2.0.0 \
  --scan --target example.com --profile standard
```

### Escaneo web

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:2.0.0 \
  --scan --target https://example.com --profile web
```

### Escaneo stealth (requiere permisos especiales)

```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:2.0.0 \
  --scan --target 192.168.1.100 --profile stealth
```

### Escaneo completo de red (requiere permisos especiales)

```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network host \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:2.0.0 \
  --scan --target 192.168.1.0/24 --profile network
```

---

## 📊 Análisis de Resultados

### Analizar archivos existentes en outputs/

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  scan-agent:2.0.0 \
  --outputs-dir /scan-agent/outputs --format txt
```

### Generar reporte HTML

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  scan-agent:2.0.0 \
  --outputs-dir /scan-agent/outputs --format html --report-file security_report.html
```

### Generar reporte JSON

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  scan-agent:2.0.0 \
  --outputs-dir /scan-agent/outputs --format json --report-file vulnerabilities.json
```

---

## 🐙 Uso con Docker Compose

### Escaneo con compose

```bash
# Escaneo rápido
docker-compose run --rm scan-agent --scan --target 192.168.1.100 --profile quick

# Escaneo web
docker-compose run --rm scan-agent --scan --target https://example.com --profile web

# Escaneo completo
docker-compose run --rm scan-agent --scan --target 192.168.1.100 --profile full
```

### Análisis solamente (perfil analyzer)

```bash
# Activar servicio de análisis
docker-compose --profile analyzer up scan-agent-analyzer

# O ejecutar una vez
docker-compose --profile analyzer run --rm scan-agent-analyzer
```

### Modo interactivo

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
  scan-agent:2.0.0 \
  --scan --target example.com --profile standard
```

### Límites de recursos

```bash
docker run --rm \
  --cpus="2.0" \
  --memory="2g" \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:2.0.0 \
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
  scan-agent:2.0.0 \
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
  scan-agent:2.0.0 \
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
  scan-agent:2.0.0 \
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
docker run --rm scan-agent:2.0.0 /bin/bash -c "nmap --version && nikto -Version && gobuster version"
```

---

## 📝 Ejemplos Completos

### Workflow completo: Escaneo + Análisis + Reporte

```bash
# 1. Escaneo
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:2.0.0 \
  --scan --target 192.168.1.100 --profile standard

# 2. Análisis y generación de reporte HTML
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  scan-agent:2.0.0 \
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
    scan-agent:2.0.0 \
    --scan --target "$target" --profile quick
done

echo "[*] Generando reporte consolidado..."
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  scan-agent:2.0.0 \
  --outputs-dir /scan-agent/outputs --format html --report-file consolidated_report.html
```

### Integración CI/CD (Jenkins, GitLab CI, etc.)

```yaml
# .gitlab-ci.yml
scan-security:
  stage: test
  image: scan-agent:2.0.0
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
docker build --no-cache -t scan-agent:2.0.0 .
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

- [Documentación principal](README.md)
- [Guía de escaneo](GUIA_ESCANEO.md)
- [Dockerfile](Dockerfile)
- [Docker Compose](docker-compose.yml)
