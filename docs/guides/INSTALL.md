# Guía de Instalación Local — Scan Agent v3.0

## Requisitos previos

| Requisito | Versión mínima | Verificar |
|-----------|----------------|-----------|
| Python | 3.12+ | `python3 --version` |
| pip | cualquiera | `pip3 --version` |
| Git | cualquiera | `git --version` |
| Docker (opcional) | 24+ | `docker --version` |

Las herramientas de escaneo son opcionales si solo usas la interfaz web para analizar archivos existentes:

```bash
# Debian / Ubuntu / Kali
sudo apt install -y nmap nikto gobuster curl dirb

# Fedora / RHEL
sudo dnf install -y nmap nikto gobuster curl

# Arch Linux
sudo pacman -S nmap nikto gobuster curl
```

---

## Método 1 — Instalación directa (sin Docker)

### 1. Clonar el repositorio

```bash
git clone https://github.com/pater8715/scan-agent.git
cd scan-agent
```

### 2. Crear y activar entorno virtual

```bash
python3 -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 4. Iniciar el servidor

```bash
# Con script (recomendado)
./scripts/start-web.sh

# O manualmente
python3 -m uvicorn webapp.main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Verificar

Abre en el navegador:

| Recurso | URL |
|---------|-----|
| Interfaz web | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| Health check | http://localhost:8000/health |

---

## Método 2 — Docker (imagen standalone)

Solo requiere Docker instalado; no necesitas Python local.

### 1. Construir la imagen

```bash
docker build -f Dockerfile.render -t scan-agent:latest .
```

### 2. Ejecutar

```bash
docker run -p 8080:8080 \
  -e SCAN_MODE=web \
  -e LOG_LEVEL=INFO \
  -v "$(pwd)/reports:/app/reports" \
  scan-agent:latest
```

Accede en: **http://localhost:8080**

### Variables de entorno disponibles

| Variable | Valor por defecto | Descripción |
|----------|-------------------|-------------|
| `SCAN_MODE` | `web` | Modo de ejecución |
| `LOG_LEVEL` | `INFO` | Nivel de log (`DEBUG`, `INFO`, `WARNING`) |
| `JSON_LOGGING` | `true` | Logs en formato JSON |
| `ALLOW_PUBLIC_TARGETS` | `false` | Permite escanear IPs públicas |
| `SCAN_AGENT_API_KEY` | _(vacío)_ | Activa autenticación por API key |

---

## Método 3 — Lab completo con Docker Compose

Levanta Scan Agent junto a los entornos de práctica (Juice Shop y DVWA).

```bash
cd docker
docker compose --profile web --profile lab up -d
```

Servicios disponibles:

| Servicio | URL | Descripción |
|----------|-----|-------------|
| Scan Agent Web | http://localhost:8080 | Interfaz principal |
| OWASP Juice Shop | http://localhost:3000 | App web vulnerable moderna |
| DVWA | http://localhost:8081 | Ejercicios clásicos por nivel |
| OWASP ZAP API | http://localhost:8090 | Escaneo activo/pasivo |

Para detener todos los servicios:

```bash
docker compose --profile web --profile lab down
```

Consulta la guía de ejercicios en [`docs/guides/LAB_GUIDE.md`](LAB_GUIDE.md).

---

## Solución de problemas comunes

**`No module named uvicorn`**
El entorno virtual no está activado o las dependencias no se instalaron correctamente.
```bash
source venv/bin/activate
pip install -r requirements.txt
```

**`Address already in use` (puerto ocupado)**
```bash
# Ver qué proceso usa el puerto 8000
lsof -i :8000        # Linux/macOS
netstat -ano | findstr :8000  # Windows

# Usar otro puerto
uvicorn webapp.main:app --port 8001
```

**`Permission denied` al ejecutar el script**
```bash
chmod +x scripts/start-web.sh
./scripts/start-web.sh
```

**Las herramientas de escaneo no se encuentran**
El agente muestra un aviso pero sigue funcionando para análisis de archivos. Para instalarlas ver la sección de [Requisitos previos](#requisitos-previos).