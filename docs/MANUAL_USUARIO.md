# Manual de Usuario — Scan Agent Lab

**Versión:** 3.0  
**Audiencia:** Estudiantes de desarrollo de aplicaciones web y APIs REST  
**Requisito previo:** Docker Desktop instalado y funcionando

---

## Tabla de Contenidos

1. [Requisitos](#1-requisitos)
2. [Instalación y primer arranque](#2-instalación-y-primer-arranque)
3. [Descripción del entorno de laboratorio](#3-descripción-del-entorno-de-laboratorio)
4. [Usar la interfaz web](#4-usar-la-interfaz-web)
5. [Usar el CLI](#5-usar-el-cli)
6. [Perfiles de escaneo](#6-perfiles-de-escaneo)
7. [Interpretar los reportes](#7-interpretar-los-reportes)
8. [OWASP API Security Top 10](#8-owasp-api-security-top-10)
9. [Base de conocimiento CVE](#9-base-de-conocimiento-cve)
10. [Solución de problemas](#10-solución-de-problemas)
11. [Referencia rápida](#11-referencia-rápida)

---

## 1. Requisitos

### Software obligatorio

| Requisito | Versión mínima | Verificación |
|-----------|---------------|--------------|
| Docker Desktop | 20.10 | `docker --version` |
| Docker Compose | 2.0 | `docker compose version` |

### Puertos que deben estar libres

| Puerto | Servicio |
|--------|---------|
| 8080 | Scan Agent Web UI |
| 3000 | OWASP Juice Shop |
| 8081 | DVWA |

### Recursos del sistema

- RAM: mínimo 4 GB disponibles para Docker
- Disco: 8 GB libres (imágenes Docker)
- Red: conexión a internet para el primer arranque (descarga de imágenes)

---

## 2. Instalación y primer arranque

### Paso 1 — Clonar el repositorio

```bash
git clone https://github.com/pater8715/scan-agent.git
cd scan-agent
```

### Paso 2 — Arrancar el laboratorio

```bash
# Con Make (recomendado)
make lab-start

# O directamente con Docker Compose
docker compose -f docker/docker-compose.yml --profile lab up -d
```

La primera vez este comando descarga las imágenes Docker (~2 GB). Puede tardar varios minutos dependiendo de la conexión.

### Paso 3 — Verificar que todo está corriendo

```bash
make lab-status
```

Resultado esperado:

```
NAMES            STATUS          PORTS
scan-agent-web   Up (healthy)    0.0.0.0:8080->8080/tcp
juice-shop       Up              0.0.0.0:3000->3000/tcp
dvwa             Up              0.0.0.0:8081->80/tcp
dvwa-db          Up              3306/tcp
```

Todos los contenedores deben mostrar `Up`. Si alguno aparece como `Restarting`, consulta la sección [Solución de problemas](#10-solución-de-problemas).

### Paso 4 — Configurar DVWA (solo la primera vez)

1. Abre http://localhost:8081 en el navegador
2. Inicia sesión con `admin` / `password`
3. Ve a http://localhost:8081/setup.php
4. Haz clic en **"Create / Reset Database"**
5. Vuelve al login e ingresa de nuevo con `admin` / `password`

### Paso 5 — Acceder a los servicios

| Servicio | URL | Credenciales |
|---------|-----|-------------|
| Scan Agent | http://localhost:8080 | — |
| Juice Shop | http://localhost:3000 | Registrar cuenta nueva |
| DVWA | http://localhost:8081 | admin / password |
| API Docs | http://localhost:8080/api/docs | — |

---

## 3. Descripción del entorno de laboratorio

```
┌─────────────────────────────────────────────────────┐
│                  Red Docker interna                  │
│                                                      │
│  ┌──────────────┐   escanea   ┌──────────────────┐  │
│  │ scan-agent   │ ──────────► │  juice-shop      │  │
│  │ :8080        │             │  :3000           │  │
│  │              │ ──────────► │  dvwa            │  │
│  └──────────────┘             │  :8081           │  │
│                               └──────────────────┘  │
│                               ┌──────────────────┐  │
│                               │  dvwa-db (MySQL) │  │
│                               │  :3306 (interno) │  │
│                               └──────────────────┘  │
└─────────────────────────────────────────────────────┘
         ▲ acceso desde navegador
```

### Scan Agent

Herramienta de análisis que orquesta múltiples escáneres:

- **nmap** — descubrimiento de puertos y versiones de servicios
- **nikto** — detección de vulnerabilidades web conocidas
- **gobuster** — enumeración de rutas y directorios
- **módulo propio** — pruebas OWASP API Security Top 10 2023

### OWASP Juice Shop

Aplicación NodeJS moderna diseñada para ser vulnerable. Contiene más de 100 retos de seguridad que cubren el OWASP Web Top 10 2021. Es el objetivo principal del laboratorio para vulnerabilidades web.

### DVWA (Damn Vulnerable Web Application)

Aplicación PHP clásica con vulnerabilidades organizadas por módulo y nivel de dificultad (Low / Medium / High / Impossible). Ideal para entender SQLi, XSS, Command Injection y otros ataques en forma progresiva.

---

## 4. Usar la interfaz web

### Pantalla principal

Al abrir http://localhost:8080 verás tres secciones:

1. **Formulario de escaneo** — donde se configura y lanza un nuevo escaneo
2. **Historial** — lista de escaneos anteriores con sus resultados
3. **Dashboard** — resumen visual de vulnerabilidades encontradas

### Lanzar un escaneo

**Campos del formulario:**

| Campo | Descripción | Ejemplo para el lab |
|-------|-------------|---------------------|
| Target | IP, hostname o URL del objetivo | `juice-shop` |
| Profile | Tipo de escaneo (ver sección 6) | `lab` |
| Description | Nota opcional para identificar el escaneo | `Práctica clase 3` |

> **Nota sobre el target en el lab:** Dentro de Docker, los contenedores se comunican por nombre. Usa `juice-shop` o `dvwa` como target en lugar de `localhost`.

**Pasos:**

1. Escribe `juice-shop` en el campo Target
2. Selecciona el perfil **Lab**
3. Opcionalmente añade una descripción
4. Haz clic en **Start Scan**
5. El progreso se muestra en tiempo real

### Ver resultados

Una vez terminado el escaneo:

1. El resultado aparece automáticamente en pantalla
2. Puedes descargarlo en los formatos disponibles: **HTML**, **JSON**, **TXT**, **Markdown**
3. El reporte HTML es el más completo — se abre en el navegador con diseño visual

### Historial de escaneos

- En la sección "Historial" puedes ver todos los escaneos anteriores
- Haz clic en cualquier escaneo para ver su reporte completo
- Puedes filtrar por target, fecha o perfil

### API Docs (Swagger)

Accede a http://localhost:8080/api/docs para ver y probar todos los endpoints REST disponibles directamente desde el navegador.

---

## 5. Usar el CLI

El CLI permite ejecutar escaneos directamente desde la terminal, útil para automatización y para ver la salida en tiempo real.

### Dentro de Docker (recomendado en el lab)

```bash
# Escaneo rápido de Juice Shop
docker compose -f docker/docker-compose.yml --profile cli run --rm scan-agent-cli \
  --target juice-shop --profile lab

# Escaneo de API con OWASP API Top 10 2023
docker compose -f docker/docker-compose.yml --profile cli run --rm scan-agent-cli \
  --target juice-shop --profile api-owasp

# Ver todos los perfiles disponibles
docker compose -f docker/docker-compose.yml --profile cli run --rm scan-agent-cli \
  --help
```

### Targets Make disponibles

```bash
make lab-scan-juice    # Escanea Juice Shop con perfil lab
make lab-scan-dvwa     # Escanea DVWA con perfil lab
```

### Opciones principales del CLI

| Opción | Descripción | Ejemplo |
|--------|-------------|---------|
| `--target` | IP o hostname objetivo | `--target juice-shop` |
| `--profile` | Perfil de escaneo | `--profile lab` |
| `--format` | Formato del reporte | `--format html` |
| `--description` | Descripción del escaneo | `--description "Clase 4"` |
| `--output-dir` | Carpeta de salida | `--output-dir ./reports` |
| `--update-db` | Actualizar base CVE/KEV | `--update-db` |
| `--web` | Iniciar en modo web UI | `--web --port 8080` |

---

## 6. Perfiles de escaneo

| Perfil | Descripción | Tiempo estimado | Uso recomendado |
|--------|-------------|-----------------|-----------------|
| `quick` | Puertos más comunes + versiones | 2-5 min | Primera exploración |
| `standard` | Escaneo completo de puertos y servicios | 10-15 min | Escaneo de referencia |
| `full` | Todo: puertos, versiones, scripts NSE, directorios | 30-60 min | Análisis exhaustivo |
| `web` | Foco en HTTP/HTTPS + nikto + gobuster | 10-20 min | Aplicaciones web |
| `api` | Endpoints REST + headers de seguridad API | 5-10 min | APIs REST generales |
| `api-owasp` | OWASP API Security Top 10 2023 completo | 10-20 min | Auditoría de APIs |
| `lab` | Optimizado para Juice Shop y DVWA | 10-15 min | **Uso en el lab** |
| `stealth` | Escaneo lento para evitar detección | 20-40 min | Entornos con IDS |
| `network` | Descubrimiento de hosts y topología de red | 5-10 min | Redes locales |
| `compliance` | Verifica controles de seguridad específicos | 15-25 min | Auditorías formales |

> Para el laboratorio, el perfil **`lab`** es el punto de partida ideal. Cubre web y API con una intensidad balanceada.

---

## 7. Interpretar los reportes

### Estructura del reporte HTML

El reporte HTML tiene estas secciones:

1. **Resumen ejecutivo** — puntuación de riesgo general, conteo por severidad
2. **Información del objetivo** — puertos abiertos, servicios detectados, versiones
3. **Hallazgos de vulnerabilidades** — lista ordenada por severidad
4. **Recomendaciones** — acciones de remediación por hallazgo

### Niveles de severidad

| Nivel | Color | CVSS | Qué significa |
|-------|-------|------|---------------|
| CRITICAL | Rojo oscuro | 9.0 – 10.0 | Explotable de forma directa, impacto total |
| HIGH | Rojo | 7.0 – 8.9 | Vulnerabilidad seria con impacto significativo |
| MEDIUM | Naranja | 4.0 – 6.9 | Riesgo real, requiere condiciones adicionales |
| LOW | Amarillo | 0.1 – 3.9 | Riesgo menor, difícil de explotar |
| INFO | Azul | 0.0 | No es vulnerabilidad, pero es información útil |

### Cómo leer un hallazgo

Cada hallazgo muestra:

```
┌─────────────────────────────────────────────────┐
│ [HIGH] Missing X-Frame-Options Header           │
│ ─────────────────────────────────────────────── │
│ OWASP: A05 Security Misconfiguration            │
│ CWE: CWE-1021                                   │
│                                                 │
│ Descripción:                                    │
│ El encabezado X-Frame-Options no está           │
│ configurado, permitiendo ataques de             │
│ clickjacking.                                   │
│                                                 │
│ Remediación:                                    │
│ Añadir el header: X-Frame-Options: DENY         │
└─────────────────────────────────────────────────┘
```

### Falsos positivos

No todos los hallazgos son vulnerabilidades reales. Siempre **verifica manualmente** los hallazgos críticos antes de dar por confirmada una vulnerabilidad:

1. Lee la descripción completa del hallazgo
2. Intenta reproducirlo manualmente en el navegador o con curl
3. Si no puedes reproducirlo, probablemente es un falso positivo

### Comparar escaneos

Para ver el progreso después de aplicar correcciones:

1. Ejecuta un escaneo inicial → descarga el reporte como referencia
2. Aplica los cambios de seguridad en la aplicación
3. Ejecuta un segundo escaneo con la misma configuración
4. Compara los reportes — los hallazgos resueltos no deberían aparecer

---

## 8. OWASP API Security Top 10

El perfil `api-owasp` ejecuta pruebas específicas para las 10 vulnerabilidades más críticas en APIs REST según OWASP 2023.

### Las 10 categorías

| ID | Nombre | Qué detecta Scan Agent |
|----|--------|------------------------|
| API1 | Broken Object Level Authorization (BOLA/IDOR) | Acceso cruzado de IDs numéricos |
| API2 | Broken Authentication | JWT con algoritmo `none`, fuerza bruta sin bloqueo |
| API3 | Broken Object Property Level Authorization | Campos sensibles en respuestas, mass assignment |
| API4 | Unrestricted Resource Consumption | Ausencia de rate limiting en endpoints |
| API5 | Broken Function Level Authorization | Endpoints admin/privilegiados sin autenticación |
| API6 | Unrestricted Access to Sensitive Business Flows | Funciones críticas (pagos, votos) sin protección |
| API7 | Server-Side Request Forgery | Parámetros de URL sin validar (`url`, `redirect`, `webhook`) |
| API8 | Security Misconfiguration | CORS abierto, headers faltantes, errores verbose |
| API9 | Improper Inventory Management | Múltiples versiones de API activas, endpoints debug |
| API10 | Unsafe Consumption of APIs | Open redirects, consumo de APIs externas sin validación |

### Cómo ejecutar un escaneo de API

```bash
# Desde la Web UI: seleccionar perfil "api-owasp"
# Desde el CLI:
docker compose -f docker/docker-compose.yml --profile cli run --rm scan-agent-cli \
  --target juice-shop --profile api-owasp
```

Juice Shop tiene varias de estas vulnerabilidades en su API REST — es un objetivo excelente para practicar con este perfil.

---

## 9. Base de conocimiento CVE

Scan Agent enriquece automáticamente sus hallazgos consultando bases de datos de vulnerabilidades externas.

### Fuentes integradas

| Fuente | Descripción | TTL caché |
|--------|-------------|-----------|
| NVD (NIST) | Base oficial de CVEs con CVSS scores | 24 horas |
| CISA KEV | CVEs activamente explotados en producción | 12 horas |
| OSV (osv.dev) | Vulnerabilidades en librerías y paquetes | 24 horas |

### Cuándo se activa

- Cuando el escaneo detecta un CVE en el banner de un servicio (ej: `Apache 2.4.49`)
- Cuando nikto reporta una vulnerabilidad con ID conocido
- El enriquecimiento es automático — no requiere configuración

### Actualizar la base de datos manualmente

```bash
# Actualiza CISA KEV y purga caché expirada
python3 scripts/scan-agent.py --update-db

# O desde Docker
docker compose -f docker/docker-compose.yml --profile cli run --rm scan-agent-cli \
  --update-db
```

### Indicador KEV en el reporte

Si un CVE detectado está en el catálogo CISA KEV (Known Exploited Vulnerabilities), el hallazgo se escala automáticamente a **CRITICAL** y aparece marcado con una advertencia especial en el reporte. Esto indica que la vulnerabilidad tiene explotación activa documentada en el mundo real.

---

## 10. Solución de problemas

### Un contenedor aparece como `Restarting`

```bash
# Ver los logs del contenedor problemático
docker logs <nombre-contenedor>

# Ejemplos
docker logs dvwa
docker logs juice-shop
docker logs dvwa-db
```

**dvwa-db en loop de restart:**  
Limpiar el volumen de datos e intentar de nuevo:
```bash
docker compose -f docker/docker-compose.yml --profile lab down --volumes
docker compose -f docker/docker-compose.yml --profile lab up -d
```

**juice-shop falla con error de Node.js:**  
Verificar que se usa la versión `v17.1.1` de la imagen (no `latest`):
```bash
docker compose -f docker/docker-compose.yml --profile lab pull juice-shop
```

### No puedo acceder a http://localhost:3000

1. Verifica que el contenedor esté corriendo: `make lab-status`
2. Verifica que el puerto 3000 no esté ocupado por otro proceso:
   ```bash
   # Windows
   netstat -ano | findstr :3000
   # Linux/Mac
   lsof -i :3000
   ```
3. Si hay conflicto de puerto, cambia el mapeo en `docker/docker-compose.yml`

### El escaneo falla o no produce resultados

1. Confirma que el target existe y está corriendo:
   ```bash
   docker exec scan-agent-web curl -s -o /dev/null -w "%{http_code}" http://juice-shop:3000
   ```
   Debe responder `200`.

2. Verifica que usas el nombre correcto del contenedor como target (no `localhost`):
   - Correcto: `juice-shop`, `dvwa`
   - Incorrecto: `localhost:3000`, `127.0.0.1`

3. Revisa los logs del contenedor scan-agent-web:
   ```bash
   docker logs scan-agent-web --tail 50
   ```

### DVWA no permite acceder después de setup

1. Asegúrate de haber completado el setup: http://localhost:8081/setup.php
2. Haz clic en **"Create / Reset Database"**
3. Vuelve a http://localhost:8081 e inicia sesión con `admin` / `password`

### Scan Agent aparece como `unhealthy` en Docker

El servicio funciona aunque Docker lo marque como unhealthy. Puedes verificarlo:
```bash
curl http://localhost:8080/health
# Debe responder: {"status":"healthy","version":"1.0.0"}
```

### Liberar recursos después del laboratorio

```bash
# Solo detener contenedores (conserva datos)
make lab-stop

# Detener y eliminar volúmenes (libera espacio)
docker compose -f docker/docker-compose.yml --profile lab down --volumes

# Eliminar todas las imágenes del proyecto
docker rmi scan-agent:3.0.0 bkimminich/juice-shop:v17.1.1
```

---

## 11. Referencia rápida

### Comandos Make

```bash
make lab-start          # Iniciar el laboratorio completo
make lab-stop           # Detener el laboratorio
make lab-status         # Ver estado de los contenedores
make lab-scan-juice     # Escanear Juice Shop (perfil lab)
make lab-scan-dvwa      # Escanear DVWA (perfil lab)
make build              # Reconstruir la imagen de Scan Agent
make logs-web           # Ver logs de la interfaz web en tiempo real
make help               # Listar todos los comandos disponibles
```

### URLs del laboratorio

| URL | Servicio |
|-----|---------|
| http://localhost:8080 | Scan Agent — Web UI |
| http://localhost:8080/api/docs | Scan Agent — API Swagger |
| http://localhost:8080/health | Scan Agent — Health check |
| http://localhost:3000 | OWASP Juice Shop |
| http://localhost:8081 | DVWA |
| http://localhost:8081/setup.php | DVWA — Configuración inicial |
| http://localhost:8081/security.php | DVWA — Cambiar nivel de dificultad |

### Targets de escaneo válidos (dentro de Docker)

| Valor | Apunta a |
|-------|---------|
| `juice-shop` | OWASP Juice Shop en puerto 3000 |
| `dvwa` | DVWA en puerto 80 (mapeado a 8081) |

### Credenciales del lab

| Servicio | Usuario | Contraseña |
|---------|---------|-----------|
| DVWA | `admin` | `password` |
| Juice Shop | Registrar cuenta nueva en /#/register | — |

---

*Este manual cubre el uso básico y avanzado del entorno. Para los ejercicios prácticos de vulnerabilidades específicas, consulta [`docs/guides/LAB_GUIDE.md`](guides/LAB_GUIDE.md).*

*Uso exclusivo en entornos de práctica controlados. No usar las técnicas aquí descritas en sistemas sin autorización expresa.*