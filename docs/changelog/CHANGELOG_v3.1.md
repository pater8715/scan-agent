# CHANGELOG — Versión 3.1

**Fecha:** 2026-05-23
**Tipo de release:** Minor — Mejoras de usabilidad y control de escaneos

---

## Resumen

La versión 3.1 añade dos funcionalidades principales: descubrimiento de hosts activos tras escaneos de red en formato CIDR, y cancelación real de escaneos que termina el proceso subyacente en lugar de solo cambiar el estado.

Incluye además cuatro correcciones de bugs detectados en QA el mismo día del release.

---

## Nuevas funcionalidades

### 1. Hosts activos tras escaneo de red (CIDR)

Cuando se ejecuta un escaneo con un target en notación CIDR (ej: `172.20.0.0/24`), al completarse aparece automáticamente un panel **"Hosts Descubiertos"** en la interfaz web.

**Qué muestra cada tarjeta de host:**
- Dirección IP y hostname (si está disponible)
- Latencia de red
- Puertos abiertos detectados
- Selector de perfil de escaneo
- Botón "Escanear" para lanzar un escaneo profundo sobre ese host

**Flujo típico de uso:**
1. Escanear `172.20.0.0/24` con cualquier perfil (~6 segundos)
2. El panel de hosts muestra todos los equipos activos en la red
3. Seleccionar perfil `lab` en la tarjeta del host deseado → clic en "Escanear"
4. Se lanza automáticamente un nuevo escaneo profundo sobre esa IP

**Nuevo endpoint de API:**

```
GET /api/scans/{scan_id}/hosts
```

Respuesta:
```json
{
  "scan_id": "abc123",
  "hosts": [
    {
      "ip": "172.20.0.3",
      "hostname": "juice-shop.scan-agent-network",
      "latency_ms": 0.2,
      "open_ports": [{"port": 3000, "protocol": "tcp", "service": "ppp"}]
    }
  ],
  "count": 6
}
```

**Archivos modificados:**
- `webapp/utils/report_parser.py` — nuevo método `_parse_nmap_hosts()` y campo `active_hosts` en el parser
- `webapp/api/scans.py` — `active_hosts` en `scan_data`, nuevo endpoint `GET /api/scans/{scan_id}/hosts`
- `webapp/templates/index.html` — sección `#discovered-hosts-section` con tarjetas de hosts
- `webapp/static/css/active-scans.css` — estilos para las tarjetas de hosts descubiertos
- `webapp/static/js/app.js` — funciones `loadDiscoveredHosts()`, `renderDiscoveredHosts()`, `launchHostScan()`

---

### 2. Cancelación real de escaneos

**Problema previo:** al cancelar un escaneo, el estado en el dict cambiaba a `cancelled` pero el proceso nmap seguía corriendo en segundo plano, consumiendo recursos.

**Solución implementada:** al cancelar, se envía `kill()` al proceso nmap activo, terminándolo de inmediato.

**Cambios en el comportamiento:**
- La cancelación es instantánea — el proceso nmap termina en el acto
- El estado pasa a `cancelled` de forma definitiva; los callbacks posteriores del escáner no lo sobreescriben
- No hay diálogo de confirmación — la acción es directa

**Desde dónde se puede cancelar:**
- Botón **Cancelar** en el formulario principal (durante el escaneo activo)
- Botón `⛔` en los chips de la barra de escaneos activos
- Botón `⛔ Cancelar` en la fila del historial para escaneos `running` o `pending`

**Archivos modificados:**
- `src/scanagent/scanner.py` — `self._current_process` para rastrear el proceso activo; limpieza en `finally`
- `webapp/api/scans.py` — dict global `_active_scanners`; `cancel_scan` llama a `scanner._current_process.kill()`; guards para no sobreescribir estado `cancelled`
- `webapp/static/js/app.js` — `cancelScan()` sin `confirm()`, feedback visual inmediato; lectura de ID desde el DOM como fallback
- `webapp/templates/index.html` — botón `⛔` por chip en la barra de escaneos activos; sin `confirm()` en ningún botón de cancelar

---

## Correcciones de bugs (QA 2026-05-23)

### Fix 1 — Panel de hosts mostrado en scans de host único

**Síntoma:** al completar un escaneo sobre un host individual (ej: `juice-shop`), el endpoint `/hosts` devolvía ese mismo host como "descubierto", activando el panel innecesariamente y mostrando la IP incorrecta del contenedor scanner.

**Causa:** `_parse_nmap_hosts()` se ejecutaba en todos los scans; para un host único la salida nmap incluye una sola línea `Nmap scan report for`, que el parser añadía a `active_hosts`.

**Corrección:** `active_hosts` solo se lee del reporte JSON cuando el target contiene `/` (es CIDR). Para scans de host individual el campo queda vacío.

**Archivo:** `webapp/api/scans.py`

---

### Fix 2 — `created_at` como Unix timestamp en `/api/reports/{id}`

**Síntoma:** el endpoint `GET /api/reports/{scan_id}` devolvía `created_at` como número de punto flotante (`"1779536786.271664"`) en lugar de fecha ISO 8601, inconsistente con el resto de la API.

**Causa:** `str(stat.st_mtime)` en lugar de `datetime.fromtimestamp(stat.st_mtime).isoformat()`.

**Corrección:** uso de `datetime.fromtimestamp().isoformat()` para el campo `created_at`.

**Archivo:** `webapp/api/reports.py`

---

### Fix 3 — Campo `description` ignorado en `ScanRequest`

**Síntoma:** al enviar `description` en el body del `POST /api/scans/start`, el campo era descartado silenciosamente por FastAPI (no estaba en el modelo).

**Corrección:** añadido `description: Optional[str]` a `ScanRequest` y a `ScanStatus`. La descripción se persiste en `active_scans` y se devuelve en la respuesta de estado.

**Archivo:** `webapp/api/scans.py`

---

### Fix 4 — Cancelación no quitaba el chip del bar ni manejaba el estado `cancelled` en el polling

**Síntoma A — chip persistente:** al pulsar "Cancelar Escaneo" desde el panel de progreso, la sección se ocultaba correctamente pero el chip en la barra de escaneos activos permanecía visible hasta el próximo ciclo de polling automático (~3 segundos), dando la sensación de que la cancelación no había surtido efecto.

**Causa A:** `cancelScan()` en `app.js` no llamaba a `pollActiveScans()` tras la cancelación exitosa. Esta función estaba encapsulada en un IIFE privado en `index.html` y no era accesible desde `app.js`.

**Corrección A:** `pollActiveScans` se expone como `window.pollActiveScans` al final del IIFE. `cancelScan()` la invoca tras ocultar el panel, actualizando el chip bar de forma inmediata.

**Síntoma B — "undefined" en progreso + panel no se cierra al cancelar desde el chip:** si el scan se cancelaba desde el botón `⛔` del chip mientras el polling del panel principal seguía corriendo, el panel permanecía visible mostrando el estado desactualizado. Además, si la petición de estado devolvía un error HTTP, `status.message` y `status.progress` eran `undefined` en JavaScript, mostrando literalmente "undefined" en la UI.

**Causa B:** `startProgressPolling()` no verificaba `response.ok` antes de parsear la respuesta, y no tenía rama para el estado `cancelled`.

**Corrección B:** añadido `if (!response.ok) return` antes del `JSON.parse`. Añadido `else if (status.status === 'cancelled')` que detiene el intervalo y oculta el panel de progreso.

**Archivos:** `webapp/static/js/app.js`, `webapp/templates/index.html`

---

### Fix 5 — Escaneo CIDR bloqueado + crash enmascarado como "herramienta no encontrada"

**Síntoma A — rendimiento:** un escaneo CIDR `/24` con perfil `quick` ejecutaba `nmap -sT --top-ports 100` sobre las 256 IPs (25.600 conexiones TCP), quedando bloqueado en el 10% durante más de 2 minutos sin avanzar.

**Corrección A:** cuando el target es CIDR, `run_scan` sustituye todos los comandos del perfil por un único `nmap -sn {target}` (ping scan), cuyo propósito es descubrir hosts activos rápidamente. El escaneo profundo de cada host se lanza desde la UI. Tiempo real: ~6 segundos para una red /24.

**Síntoma B — crash:** si el CIDR scan sí llegaba a ejecutar nmap, fallaba con el mensaje `"Herramienta 'nmap' no encontrada"`, siendo en realidad un error de escritura de archivo.

**Causa B:** el nombre de archivo de salida se construía con el target literal `172.20.0.0/24`, que contiene una barra — Python intentaba abrir `nmap_service_172.20.0.0/24.txt` como si `172.20.0.0` fuera un directorio. El `FileNotFoundError` era capturado por el handler de "herramienta no encontrada", ocultando la causa real.

**Corrección B:** `safe_target` reemplaza `/` por `_` antes de construir el nombre de archivo (`172.20.0.0_24`).

**Archivos:** `src/scanagent/scanner.py`

---

## Cambios en la API

| Endpoint | Tipo | Descripción |
|----------|------|-------------|
| `GET /api/scans/{scan_id}/hosts` | Nuevo | Devuelve los hosts activos descubiertos en un escaneo CIDR |
| `POST /api/scans/start` | Actualizado | Acepta campo `description` opcional |
| `GET /api/scans/status/{scan_id}` | Actualizado | Devuelve campo `description` en la respuesta |
| `GET /api/reports/{scan_id}` | Corregido | `created_at` ahora es ISO 8601 |

## Archivos modificados (fixes post-QA)

| Archivo | Cambio |
|---------|--------|
| `webapp/static/js/app.js` | `cancelScan()` llama a `window.pollActiveScans()` tras cancelación exitosa; `startProgressPolling()` añade guard `response.ok` y rama `cancelled` |
| `webapp/templates/index.html` | IIFE del bar expone `window.pollActiveScans` para acceso cross-script |

---

## Notas de actualización

No se requieren cambios en la configuración ni en los datos existentes. Los escaneos anteriores completados no tendrán datos de `active_hosts` — el campo devuelve una lista vacía para esos casos.

Para aplicar los cambios en un contenedor existente:

```bash
docker compose -f docker/docker-compose.yml --profile lab up -d --build
```

---

## Versiones anteriores

- [v3.0](CHANGELOG_v3.0.md) — Reportes profesionales e inteligencia de vulnerabilidades
- [v2.0](CHANGELOG_v2.0.md) — Interfaz web FastAPI
