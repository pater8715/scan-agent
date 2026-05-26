



# Plan de Mejoras — Scan Agent

**Proyecto:** Herramienta educativa de análisis de vulnerabilidades web y API REST  
**Contexto:** Clases con estudiantes de aplicaciones web y API REST  
**Versión actual:** 3.1.0  
**Fecha de análisis:** 2026-05-25  
**Autor:** Alberto Paternina León

---

## Estado del Proyecto

### Fortalezas actuales
- Arquitectura bien estructurada (~7,100 líneas de Python)
- Integración con 6 herramientas: nmap, nikto, gobuster, dirb, whatweb, curl
- 12 perfiles de escaneo predefinidos
- Mapeo a OWASP Top 10 **Web** 2021 y OWASP API Security Top 10 2023
- API REST con FastAPI y WebSockets
- Reportes en 4 formatos (HTML, JSON, TXT, Markdown) + formato educativo
- Base de datos SQLite con historial de escaneos y progreso de estudiantes
- Entorno de práctica con Juice Shop y DVWA
- Modo CTF con 8 desafíos gamificados
- Exportación SARIF compatible con GitHub Advanced Security

### Brechas críticas resueltas (Fases 1–7)
1. ✅ OWASP API Security Top 10 2023 implementado con pruebas activas
2. ✅ Base de conocimiento conectada a NVD, CISA KEV y OSV
3. ✅ OWASP ZAP integrado con perfiles pasivo y activo
4. ✅ Entorno de práctica con Juice Shop y DVWA
5. ✅ Reportes educativos con CWE, payloads de ejemplo y guías de remediación
6. ✅ Seguridad: autenticación API, rate limiting, validación de targets, logging JSON

### Brechas activas (Fases 8–10)
1. **Perfiles de escaneo con gaps técnicos** — 12 perfiles analizados; se identificaron comandos duplicados, timeouts inadecuados, puertos faltantes y herramientas ausentes
2. **Reportes estáticos** — las recomendaciones se embeben al momento del escaneo; si el catálogo o la base de datos de CVEs se actualiza, los reportes existentes no reflejan los cambios
3. **Perfiles todo-o-nada** — al iniciar un escaneo no es posible elegir qué fases/herramientas ejecutar; el perfil seleccionado siempre corre todos sus comandos, sin opción de personalización manual por sesión

---

## Fases de Trabajo

### FASE 1 — OWASP API Security Top 10 (2023)
**Prioridad:** CRÍTICA | **Estimado:** ~40h | **Estado:** ✅ Completado (2026-05-16)

La brecha más importante para el contexto educativo. La lista API Top 10 2023 es diferente
al OWASP Web Top 10 y cubre vulnerabilidades específicas de APIs REST.

| # | Tarea | Estado | Notas |
|---|-------|--------|-------|
| 1.1 | Crear módulo `src/scanagent/api_security_checker.py` | ✅ | ~430 líneas, pruebas activas vía urllib (stdlib) |
| 1.2 | Detectar BOLA/IDOR (API1:2023) — acceso cruzado de IDs | ✅ | Prueba IDs 1-100, detecta respuestas que difieren |
| 1.3 | Verificar Broken Authentication (API2:2023) — JWT none, fuerza bruta | ✅ | JWT alg=none + brute-force sin bloqueo |
| 1.4 | Detectar Broken Object Property Level Auth (API3:2023) | ✅ | Campos sensibles en respuestas + mass assignment |
| 1.5 | Probar ausencia de rate limiting (API4:2023) | ✅ | 20 peticiones rápidas + verificación de headers RL |
| 1.6 | Verificar Function Level Authorization (API5:2023) | ✅ | DELETE/PUT/PATCH sin auth + endpoints admin |
| 1.7 | Detectar Unrestricted Access a APIs sensibles (API6:2023) | ✅ | Checkout, transfer, payment, vote, coupon |
| 1.8 | Probar SSRF vía parámetros URL (API7:2023) | ✅ | Prueba params: url, callback, redirect, webhook |
| 1.9 | Detectar Security Misconfiguration (API8:2023) | ✅ | Headers, CORS, errores verbose, docs expuestas |
| 1.10 | Detectar Improper Inventory Management (API9:2023) | ✅ | Múltiples versiones activas + endpoints debug |
| 1.11 | Detectar Unsafe Consumption (API10:2023) | ✅ | Open redirect + nota de revisión manual |
| 1.12 | Actualizar `interpreter.py` para mapear a API Top 10 2023 | ✅ | Constantes OWASP_API_TOP_10, API_TO_CWE, método nuevo |
| 1.13 | Añadir perfil `api-owasp` en `scanner.py` | ✅ | Perfil con nmap, curl, gobuster optimizados para APIs |
| 1.14 | Actualizar `parser.py` para integrar hallazgos del checker | ✅ | Método `_parse_api_security()` integrado al pipeline |

---

### FASE 2 — Base de Conocimiento de Vulnerabilidades Actualizada
**Prioridad:** ALTA | **Estimado:** ~20h | **Estado:** ✅ Completado (2026-05-16)

Reemplazar el knowledge base hardcodeado por conexión a fuentes actualizadas.

| # | Tarea | Estado | Notas |
|---|-------|--------|-------|
| 2.1 | Crear módulo `src/scanagent/vuln_db.py` con caché SQLite | ✅ | NVD API 2.0 — lookup, parse, cache con TTL 24h |
| 2.2 | Integrar CISA KEV (Known Exploited Vulnerabilities Catalog) | ✅ | Feed completo ~1000 CVEs, TTL 12h, escala a CRITICA si KEV |
| 2.3 | Integrar OSV (osv.dev) para vulnerabilidades de librerías | ✅ | POST API, cache por package:ecosystem, TTL 24h |
| 2.4 | Añadir enriquecimiento en `interpreter.py` con `vuln_db` | ✅ | `_enrich_with_vuln_db()` — extrae CVE del texto, llama VulnDB |
| 2.5 | Añadir comando CLI `--update-db` en `agent.py` | ✅ | Actualiza KEV + purge expirados, verifica conectividad |
| 2.6 | Añadir tablas `cve_cache`, `kev_catalog`, `osv_cache` al schema | ✅ | 4 tablas nuevas + índices en `config/schema.sql` |

---

### FASE 3 — Integración OWASP ZAP
**Prioridad:** ALTA | **Estimado:** ~35h | **Estado:** ✅ Completado (2026-05-16)

ZAP es el estándar educativo para pruebas de seguridad web/API activas.

| # | Tarea | Estado | Notas |
|---|-------|--------|-------|
| 3.1 | Añadir servicio `zap` al `docker/docker-compose.yml` | ✅ | `ghcr.io/zaproxy/zaproxy:stable`, puerto 8090, perfil `lab` |
| 3.2 | Crear módulo `src/scanagent/zap_integration.py` | ✅ | Wrapper completo ZAP REST API, solo stdlib |
| 3.3 | Implementar escaneo pasivo ZAP como pre-paso | ✅ | Spider + passive scan, perfil `zap-passive` |
| 3.4 | Implementar escaneo activo ZAP (Active Scan) | ✅ | Spider + passive + active scan, perfil `zap-active` |
| 3.5 | Parsear resultados ZAP (JSON) en `parser.py` | ✅ | `_parse_zap_results()` integrado al pipeline |
| 3.6 | Crear perfiles `zap-passive` y `zap-active` en `scanner.py` | ✅ | ZAP invocado desde `agent.py` vía `ZAPIntegration` |
| 3.7 | Configurar políticas ZAP para entorno de práctica (evitar daño) | ✅ | `config/zap/lab-scan-policy.xml` — DoS desactivado |

---

### FASE 4 — Entorno de Práctica para Estudiantes
**Prioridad:** ALTA | **Estimado:** ~12h | **Estado:** ✅ Completado (2026-05-16)

**Recomendación: empezar por esta fase** — da a los estudiantes objetivos seguros de inmediato.

| # | Tarea | Estado | Notas |
|---|-------|--------|-------|
| 4.1 | Añadir OWASP Juice Shop al `docker-compose.yml` | ✅ | `bkimminich/juice-shop`, puerto 3000, perfil `lab` |
| 4.2 | Añadir DVWA al `docker-compose.yml` | ✅ | `ghcr.io/digininja/dvwa` + MariaDB, puerto 8081, perfil `lab` |
| 4.3 | Crear perfil `lab` en scanner que apunte a objetivos locales | ✅ | Escanea puertos 80,443,3000,8080,8081 con nikto y gobuster |
| 4.4 | Crear guía de ejercicios prácticos por vulnerabilidad | ✅ | `docs/guides/LAB_GUIDE.md` — cubre OWASP Top 10 con ejercicios paso a paso |
| 4.5 | Añadir target `make lab-start` en Makefile | ✅ | También: `lab-stop`, `lab-status`, `lab-scan-juice`, `lab-scan-dvwa` |

---

### FASE 5 — Reportes Educativos
**Prioridad:** MEDIA | **Estimado:** ~25h | **Estado:** ✅ Completado (2026-05-16)

Los reportes actuales son profesionales pero no pedagógicos.

| # | Tarea | Estado | Notas |
|---|-------|--------|-------|
| 5.1 | Añadir sección "¿Por qué es peligroso?" en cada vulnerabilidad | ✅ | `ReportGenerator.generate_educational_report()` |
| 5.2 | Incluir referencias a CWE (Common Weakness Enumeration) | ✅ | `OWASP_WEB_CWE` + `_enrich_educational()` en `interpreter.py` |
| 5.3 | Añadir ejemplos de payload/exploit educativos | ✅ | `EDUCATIONAL_DATA` — 15 entradas con payloads reales |
| 5.4 | Crear sección "Cómo remediarlo" con fragmentos de código | ✅ | Fragmentos por lenguaje en `EDUCATIONAL_DATA` |
| 5.5 | Añadir links a OWASP Cheat Sheet Series por vulnerabilidad | ✅ | `cheat_sheet_url` en `EDUCATIONAL_DATA`, botón en HTML |
| 5.6 | Crear modo de reporte `--format educational` | ✅ | `informe_educativo.html`, incluido en `--format all` |
| 5.7 | Añadir comparación de escaneos en dashboard (antes/después del fix) | ✅ | `_generate_comparison_widget()` con tabla delta + sparkline |

---

### FASE 6 — Seguridad y Arquitectura
**Prioridad:** MEDIA | **Estimado:** ~15h | **Estado:** ✅ Completado (2026-05-19)

Mejoras de seguridad en la propia herramienta.

| # | Tarea | Estado | Notas |
|---|-------|--------|-------|
| 6.1 | Eliminar `privileged: true` del docker-compose web | ✅ | Reemplazado con `cap_add: NET_RAW, NET_ADMIN` + `cap_drop: ALL` + `no-new-privileges` |
| 6.2 | Añadir autenticación a la API FastAPI (API key o JWT) | ✅ | `X-API-Key` header — se activa con env var `SCAN_AGENT_API_KEY`; sin ella, bypass en dev |
| 6.3 | Validar targets para evitar escanear IPs no autorizadas (whitelist) | ✅ | `validate_target()` en `scanner.py` — IPs RFC 1918 + hostnames `.local/.internal`; flag `ALLOW_PUBLIC_TARGETS=true` para lab externo |
| 6.4 | Implementar rate limiting en la API | ✅ | Rate limiter en memoria (sin deps externas): 30 req/60s por IP en endpoints de escaneo |
| 6.5 | Añadir logging estructurado en JSON para auditoría | ✅ | `src/scanagent/logging_config.py` — `JSONFormatter`, integrado en `agent.py` y `webapp/main.py` |
| 6.6 | Crear suite de tests automáticos con pytest | ✅ | `tests/` — 4 módulos: scanner validation (15 casos), interpreter educational (9 casos), logging config (3 casos), rate limiter (4 casos) |

---

### FASE 7 — Funcionalidades Avanzadas
**Prioridad:** BAJA | **Estimado:** ~30h | **Estado:** ✅ Completado (2026-05-19)

Mejoras opcionales para enriquecer la experiencia educativa.

| # | Tarea | Estado | Notas |
|---|-------|--------|-------|
| 7.1 | Análisis de dependencias Python/Node.js | ✅ | `dependency_scanner.py` — OSV API + `npm audit`; `--dep-scan DIR` en CLI; `make dep-scan` |
| 7.2 | Exportar resultados en formato SARIF 2.1.0 | ✅ | `sarif_exporter.py` — compatible GitHub Advanced Security; `--format sarif`; `make sarif-report` |
| 7.3 | Notificaciones webhook para vulnerabilidades críticas | ✅ | `notifier.py` — genérico + Slack; HMAC-SHA256; WEBHOOK_URL/SECRET/FORMAT/MIN_SEV env vars |
| 7.4 | Modo CTF para gamificar el aprendizaje | ✅ | `ctf_mode.py` + `config/ctf_challenges.json` — 8 desafíos, puntuación, bonus tiempo, pistas con penalización, scoreboard SQLite |
| 7.5 | Tracking de progreso por estudiante | ✅ | Tabla `student_progress` en schema.sql; `--student-id`/`STUDENT_ID`; progreso por escaneo con cobertura OWASP |

---

---

### FASE 8 — Correcciones de Perfiles de Escaneo
**Prioridad:** ALTA | **Estimado:** ~18h | **Estado:** ✅ Completado (2026-05-26)

Análisis de los 12 perfiles identificó comandos duplicados, timeouts inadecuados, puertos faltantes y ausencia de herramientas clave. Ver análisis completo en sesión del 2026-05-25.

#### 8.1 — Perfil `quick`
| # | Tarea | Estado |
|---|-------|--------|
| 8.1.1 | Agregar `-sV` para detección básica de versiones | ✅ |
| 8.1.2 | Ampliar puertos: reemplazar `--top-ports 100` por `--top-ports 200` + incluir 3000, 5000, 8000 explícitamente | ✅ |
| 8.1.3 | Agregar `curl -I https://{target}` como segundo curl | ✅ |
| 8.1.4 | Agregar `--script=http-headers` al nmap para obtener cabeceras básicas | ✅ |

#### 8.2 — Perfil `standard`
| # | Tarea | Estado |
|---|-------|--------|
| 8.2.1 | Reemplazar `--top-ports` implícito del segundo nmap por `-p-` para coherencia con el primero | ✅ |
| 8.2.2 | Separar `--script=vuln,safe` en dos comandos: uno `vuln` y uno `http-security-headers,http-headers` | ✅ |
| 8.2.3 | Aumentar timeout del primer nmap a 1800s o restringir a `--top-ports 1000` | ✅ |
| 8.2.4 | Agregar nikto como herramienta opcional | ✅ |

#### 8.3 — Perfil `full`
| # | Tarea | Estado |
|---|-------|--------|
| 8.3.1 | Reemplazar categoría `exploit` por `exploit,safe` o eliminarla para entorno educativo | ✅ |
| 8.3.2 | Agregar gobuster para HTTPS: `gobuster dir -u https://{target} -w ...` | ✅ |
| 8.3.3 | Cambiar wordlist de gobuster a `big.txt` o equivalente de SecLists | ✅ |
| 8.3.4 | Agregar `sslscan {target}` como herramienta optional | ✅ |
| 8.3.5 | Agregar `whatweb http://{target}` para fingerprinting de framework | ✅ |

#### 8.4 — Perfil `web`
| # | Tarea | Estado |
|---|-------|--------|
| 8.4.1 | Agregar puertos 3000, 5000, 8000, 9000 al scan nmap | ✅ |
| 8.4.2 | Agregar `wafw00f http://{target}` como primer paso | ✅ |
| 8.4.3 | Agregar `whatweb http://{target}` para fingerprinting | ✅ |
| 8.4.4 | Usar wordlist más completa en gobuster (`big.txt`) | ✅ |
| 8.4.5 | Agregar `http-cors` al segundo nmap NSE | ✅ |

#### 8.5 — Perfil `stealth`
| # | Tarea | Estado |
|---|-------|--------|
| 8.5.1 | Agregar `--randomize-hosts --data-length 24` al primer nmap | ✅ |
| 8.5.2 | Agregar `--source-port 53` para simular tráfico DNS | ✅ |
| 8.5.3 | Agregar curl con User-Agent personalizado: `curl -s -A "Mozilla/5.0" -I http://{target}` | ✅ |
| 8.5.4 | Cambiar scripts NSE de `vuln` a `default` para reducir firma de ataque | ✅ |

#### 8.6 — Perfil `network`
| # | Tarea | Estado |
|---|-------|--------|
| 8.6.1 | Reemplazar categoría `discovery` por scripts específicos: `smb*,ftp-anon,ssh-hostkey,nfs-showmount` | ✅ |
| 8.6.2 | Eliminar categoría `version` del segundo nmap (redundante con `-sV`) | ✅ |
| 8.6.3 | Agregar `enum4linux -a {target}` para enumeración SMB/NetBIOS | ✅ |
| 8.6.4 | Agregar `snmp-check {target}` para enumeración SNMP | ✅ |
| 8.6.5 | **Listado de IPs activas → Objetivos de Laboratorio:** cuando el target es un rango CIDR (ej: `172.20.0.0/24`), parsear la salida del `nmap -sn` y poblar automáticamente la sección "Objetivos de Laboratorio" en la UI con las IPs respondentes, mostrando hostname (si resuelve), MAC/vendor y un botón "Escanear este host" que lanza un nuevo escaneo sobre esa IP individual | ✅ |
| 8.6.6 | En `report_parser.py`, agregar método `_parse_host_discovery()` que extrae IPs activas de la salida de `nmap -sn` y las guarda en el campo `discovered_hosts` del resultado | ✅ |
| 8.6.7 | Crear endpoint `GET /api/lab/targets` en la webapp que retorna la lista de hosts activos del último escaneo de red, accesible desde el dashboard | ✅ |
| 8.6.8 | En la UI del dashboard, añadir sección "Objetivos de Laboratorio" que muestra la tabla de hosts descubiertos con: IP, hostname, vendor (MAC OUI), estado, y botón "Escanear" por cada host | ✅ |

#### 8.7 — Perfil `compliance`
| # | Tarea | Estado |
|---|-------|--------|
| 8.7.1 | **Eliminar el segundo nmap** (comandos idénticos al primero — 100% redundante) | ✅ |
| 8.7.2 | Agregar `curl -I http://{target}` para verificar redirección HTTP→HTTPS | ✅ |
| 8.7.3 | Agregar `sslscan {target}` para análisis TLS profundo (POODLE, BEAST, etc.) | ✅ |
| 8.7.4 | Agregar `http-cors,http-auth-finder` al nmap NSE | ✅ |

#### 8.8 — Perfil `api`
| # | Tarea | Estado |
|---|-------|--------|
| 8.8.1 | Agregar gobuster con wordlist de API endpoints | ✅ |
| 8.8.2 | Agregar curl para métodos PUT, DELETE, PATCH (`-X PUT/DELETE`) | ✅ |
| 8.8.3 | Agregar curl a endpoints de documentación: `/swagger.json`, `/api-docs`, `/graphql` | ✅ |
| 8.8.4 | Reemplazar `http-auth` por `http-auth-finder` en NSE | ✅ |

#### 8.9 — Perfil `api-owasp`
| # | Tarea | Estado |
|---|-------|--------|
| 8.9.1 | Reemplazar wordlist `common.txt` por wordlist específica de API endpoints | ✅ |
| 8.9.2 | Agregar curl para métodos REST: PUT, DELETE, OPTIONS | ✅ |
| 8.9.3 | Agregar curl a `/swagger.json`, `/api-docs`, `/graphiql`, `/api/v1/users` | ✅ |
| 8.9.4 | Agregar nikto básico como herramienta opcional | ✅ |

#### 8.10 — Perfil `lab`
| # | Tarea | Estado |
|---|-------|--------|
| 8.10.1 | Cambiar `nikto -timeout 3` por `nikto -timeout 10 -maxtime 120` | ✅ |
| 8.10.2 | Agregar extensiones a gobuster: `-x php,js,json,html` | ✅ |
| 8.10.3 | Agregar `http-vuln*` al nmap NSE | ✅ |
| 8.10.4 | Agregar curl específico por app del lab: `curl -s http://{target}:3000/api/SecurityQuestions` y `curl -s http://{target}:8081/setup.php` | ✅ |

#### 8.11 — Integración de nuevas herramientas
| # | Tarea | Estado |
|---|-------|--------|
| 8.11.1 | Agregar `whatweb` a la imagen Docker (Kali tiene paquete disponible) | ✅ |
| 8.11.2 | Agregar `wafw00f` a la imagen Docker | ✅ |
| 8.11.3 | Agregar `sslscan` a la imagen Docker (para perfiles compliance y full) | ✅ |
| 8.11.4 | Agregar wordlist de API endpoints de SecLists al contenedor | ✅ |
| 8.11.5 | Actualizar `report_parser.py` para parsear salida de `whatweb`, `wafw00f` y `sslscan` | ✅ |

---

### FASE 9 — Reportes Dinámicos con Actualización Automática
**Prioridad:** ALTA | **Estimado:** ~22h | **Estado:** ✅ Completada

Actualmente los reportes embeben las recomendaciones en el momento del escaneo. Si el catálogo `recommendations_catalog.json` o la base de datos NVD/CISA KEV se actualiza, los reportes guardados quedan desactualizados. Esta fase separa los hallazgos (inmutables) de las recomendaciones (consultadas dinámicamente en cada render).

**Principio de diseño:** Los hallazgos se guardan con su `vuln_id`. Las recomendaciones se resuelven desde el catálogo en tiempo de render — nunca embebidas en la DB.

#### 9.1 — Separación hallazgos vs recomendaciones en DB
| # | Tarea | Estado |
|---|-------|--------|
| 9.1.1 | Modificar el schema SQLite: tabla `scan_findings` almacena solo `vuln_id`, severidad, evidencia y metadatos raw — sin texto de recomendaciones | ✅ |
| 9.1.2 | Crear tabla `catalog_versions` con `(catalog_file, sha256_hash, updated_at)` para detectar cambios | ✅ |
| 9.1.3 | Migrar escaneos existentes: extraer `vuln_id` de findings guardados y eliminar campos `recommendation` embebidos | ⬜ (diferido) |

#### 9.2 — Resolución dinámica en tiempo de render
| # | Tarea | Estado |
|---|-------|--------|
| 9.2.1 | Refactorizar `report_parser.py`: `_apply_catalog()` se convierte en función stateless que recibe el catálogo actual en cada llamada — no cachea recomendaciones | ✅ |
| 9.2.2 | Crear `CatalogLoader` en `webapp/utils/` con caché LRU en memoria: recarga el catálogo si el `sha256` del archivo cambió desde la última lectura | ✅ |
| 9.2.3 | Inyectar `CatalogLoader` en `generate_professional_html_report()`, `generate_txt_report()` y `generate_markdown_report()` en `scans.py` | ✅ |
| 9.2.4 | Hacer lo mismo para enrichment de CVE/NVD: resolución desde `vuln_db.py` en tiempo de render, no embebido | ✅ |

#### 9.3 — Detección de cambios y auto-invalidación
| # | Tarea | Estado |
|---|-------|--------|
| 9.3.1 | Implementar `CatalogWatcher`: hilo background que monitorea `recommendations_catalog.json` con `watchdog` o polling SHA-256 cada 60s | ✅ |
| 9.3.2 | Cuando detecta cambio, actualizar hash en `catalog_versions` y emitir evento interno `catalog_updated` | ✅ |
| 9.3.3 | El evento `catalog_updated` marca en DB los reportes HTML cacheados como `stale=True` para que el siguiente render los regenere | ✅ |

#### 9.4 — Endpoint de refresco manual
| # | Tarea | Estado |
|---|-------|--------|
| 9.4.1 | Agregar endpoint `POST /api/reports/{scan_id}/refresh` en `scans.py` que regenera el reporte completo con el catálogo actual | ✅ |
| 9.4.2 | Agregar endpoint `GET /api/catalog/version` que retorna hash actual, fecha y número de entradas del catálogo | ✅ |
| 9.4.3 | Agregar endpoint `POST /api/catalog/reload` (auth requerida) para forzar recarga manual del catálogo sin reiniciar el servicio | ✅ |

#### 9.5 — Notificación en tiempo real via WebSocket
| # | Tarea | Estado |
|---|-------|--------|
| 9.5.1 | Cuando `CatalogWatcher` detecta un cambio, emitir mensaje WebSocket `{"event": "catalog_updated", "version": "...", "affected_findings": N}` a todos los clientes conectados | ✅ |
| 9.5.2 | En la UI (dashboard), mostrar banner: "El catálogo fue actualizado — los reportes reflejarán las nuevas recomendaciones en el próximo render" con botón "Actualizar ahora" | ✅ |
| 9.5.3 | El botón "Actualizar ahora" llama a `POST /api/reports/{id}/refresh` y recarga la vista del reporte sin recargar la página | ✅ |

#### 9.6 — Sincronización automática del catálogo con fuentes externas
| # | Tarea | Estado |
|---|-------|--------|
| 9.6.1 | Crear tarea background `catalog_sync.py`: cada 24h descarga actualizaciones de NVD/CISA KEV y las incorpora al catálogo local `recommendations_catalog.json` | ✅ |
| 9.6.2 | Implementar estrategia de merge: entradas nuevas se añaden, entradas existentes solo se actualizan si el hash del contenido cambió (preserva ediciones manuales) | ✅ |
| 9.6.3 | Registrar cada sincronización en tabla `catalog_sync_log` con `(timestamp, source, entries_added, entries_updated, entries_unchanged, error)` | ✅ |
| 9.6.4 | Exponer `GET /api/catalog/sync-log` para ver historial de sincronizaciones desde la UI | ✅ |

#### 9.7 — Gestión del catálogo desde la UI
| # | Tarea | Estado |
|---|-------|--------|
| 9.7.1 | Crear vista `/catalog` en la webapp que lista todas las entradas del catálogo con su `vuln_id`, severidad y número de recomendaciones | ✅ |
| 9.7.2 | Permitir editar recomendaciones de una entrada desde la UI (textarea + guardar → actualiza JSON → dispara `catalog_updated`) | ✅ |
| 9.7.3 | Mostrar en cada entrada: "Última actualización", "Fuente" (manual/NVD/CISA), "Usada en N reportes" | ✅ |
| 9.7.4 | Añadir botón "Forzar sincronización con NVD/CISA KEV" que llama a `catalog_sync.py` on-demand | ✅ |

---

---

### FASE 10 — Selección Manual de Fases por Escaneo
**Prioridad:** MEDIA | **Estimado:** ~20h | **Estado:** ✅ Completada

**Descripción de la mejora:**  
Al iniciar un escaneo, después de elegir el perfil, el usuario puede activar opcionalmente un panel "Configurar fases" que muestra cada herramienta/comando del perfil como una tarjeta con checkbox. Puede desmarcar las que no quiere ejecutar, ajustando el escaneo a su necesidad sin tener que crear un perfil nuevo. Si el panel no se activa, el comportamiento es idéntico al actual: se ejecutan todas las fases del perfil seleccionado.

**Valor pedagógico:** un profesor puede configurar ejercicios enfocados ("hoy solo trabajamos nikto, desmarca el resto"). Un estudiante puede aislar una herramienta para entender exactamente qué produce.

**Valor técnico:** reduce tiempo de escaneo cuando solo se necesita información parcial; permite reintentar una fase que falló sin repetir todo el perfil.

**Principio de diseño:** la selección de fases es por sesión — no modifica el perfil base, no requiere guardarlo. El perfil original queda intacto.

**Restricciones de diseño:**
- El orden de ejecución de los comandos no puede modificarse (algunos parsers dependen del orden: nmap antes que nikto).
- Targets CIDR siempre usan `nmap -sn` independientemente de la selección (lógica existente en `run_scan()`).
- Si se desmarcan comandos marcados como `required: True` en el perfil, se muestra una advertencia pero se permite continuar (el usuario sabe lo que hace).
- Al menos 1 fase debe quedar seleccionada para habilitar el botón "Iniciar Escaneo".

---

#### 10.1 — Capa Backend: `scanner.py` — filtrado de comandos
| # | Tarea | Archivo | Estado |
|---|-------|---------|--------|
| 10.1.1 | Añadir parámetro `steps_filter: Optional[List[int]] = None` a `run_scan()`. Cuando no es `None`, filtrar `commands_to_run` a los índices indicados antes de ejecutar. Los índices corresponden a la posición del comando en `profile.commands` (0-based). | `src/scanagent/scanner.py` | ✅ |
| 10.1.2 | Añadir lista `skipped_steps` al dict de resultados: registrar los comandos que se omitieron (índice, herramienta, args) para trazabilidad. | `src/scanagent/scanner.py` | ✅ |
| 10.1.3 | Ajustar el cálculo de progreso: el total de pasos para el porcentaje debe ser `len(filtered_commands)`, no `len(profile.commands)`, para que la barra refleje correctamente el progreso real. | `src/scanagent/scanner.py` | ✅ |

#### 10.2 — Capa Backend: `agent.py` — propagación del parámetro
| # | Tarea | Archivo | Estado |
|---|-------|---------|--------|
| 10.2.1 | Añadir `steps_filter: Optional[List[int]] = None` a la firma de `execute_scan()` y pasarlo a la llamada de `scanner.run_scan()`. | `src/scanagent/agent.py` | ✅ |

#### 10.3 — Capa Backend: `scans.py` — modelo de petición y endpoint
| # | Tarea | Archivo | Estado |
|---|-------|---------|--------|
| 10.3.1 | Añadir campo `selected_steps: Optional[List[int]] = Field(default=None, description="Índices de fases a ejecutar. None = todas.")` al modelo `ScanRequest`. | `webapp/api/scans.py` | ✅ |
| 10.3.2 | Validar en `start_scan()`: si `selected_steps` no es `None`, verificar que todos los índices estén en rango `[0, len(profile.commands) - 1]` y que la lista no esté vacía. Retornar HTTP 400 con mensaje claro si falla. | `webapp/api/scans.py` | ✅ |
| 10.3.3 | Propagar `selected_steps` a `execute_scan()` → `agent.execute_scan()`. Almacenar en `scan_status` para que el WebSocket pueda indicar qué fases se están ejecutando. | `webapp/api/scans.py` | ✅ |

#### 10.4 — Capa Backend: base de datos y metadatos
| # | Tarea | Archivo | Estado |
|---|-------|---------|--------|
| 10.4.1 | Añadir columna `custom_steps TEXT` (JSON) al schema de la tabla `scans`: almacena el array de índices seleccionados, o `NULL` si se usó el perfil completo. | `config/schema.sql` | ✅ |
| 10.4.2 | Al guardar el escaneo en DB, persistir `selected_steps` en `custom_steps` y también `skipped_steps` (lista de herramientas omitidas) como JSON en una columna `skipped_steps TEXT`. | `webapp/api/scans.py` | ✅ |
| 10.4.3 | Al guardar los metadatos en disco (`file_manager.save_scan_metadata()`), incluir `custom_steps`, `skipped_steps` y `is_custom_profile: bool` en el JSON de metadata. | `webapp/api/scans.py` | ✅ |

#### 10.5 — Capa Backend: reportes — reflejar fases ejecutadas
| # | Tarea | Archivo | Estado |
|---|-------|---------|--------|
| 10.5.1 | En `generate_professional_html_report()`, añadir una sección "Configuración del Escaneo" que muestre: perfil base usado, fases ejecutadas (lista verde con ✅) y fases omitidas (lista gris con ⊘). Solo visible si `is_custom_profile = True`. | `webapp/api/scans.py` | ✅ |
| 10.5.2 | En `generate_txt_report()` y `generate_markdown_report()`, añadir al encabezado del reporte la sección "Fases omitidas:" cuando aplique. | `webapp/api/scans.py` | ✅ |
| 10.5.3 | En el JSON report, añadir al objeto raíz `"scan_config": {"profile": "lab", "custom_steps": [0,1,3], "skipped": ["nikto"]}` para que consumidores externos tengan trazabilidad completa. | `webapp/api/scans.py` | ✅ |

#### 10.6 — Capa Frontend: panel "Configurar fases"
| # | Tarea | Archivo | Estado |
|---|-------|---------|--------|
| 10.6.1 | Después del selector de perfil y antes del formulario de objetivo, añadir un toggle `<button>⚙️ Configurar fases manualmente (opcional)</button>` que expande/colapsa el panel de selección. El toggle solo se muestra cuando hay un perfil seleccionado. | `webapp/templates/index.html` | ✅ |
| 10.6.2 | Al activar el toggle, llamar a `GET /api/profiles/{id}/detail` (endpoint ya existente con datos educativos) y renderizar la lista de fases. Mientras carga, mostrar skeleton. | `webapp/static/js/app.js` | ✅ |
| 10.6.3 | Cada fase se renderiza como una tarjeta con: checkbox (checked por defecto), icono + nombre de herramienta, propósito en una línea (`purpose`), badge Requerido/Opcional y badge de tiempo estimado derivado de `timeout_seconds`. | `webapp/static/js/app.js` | ✅ |
| 10.6.4 | Si se desmarca una fase con `required: true`, mostrar un aviso naranja debajo de la tarjeta: "⚠️ Esta fase es requerida por el perfil — omitirla puede generar un reporte incompleto". El checkbox sigue siendo interactivo (no se bloquea). | `webapp/static/js/app.js` | ✅ |
| 10.6.5 | En el pie del panel, mostrar dinámicamente: `N de M fases seleccionadas · ~X min estimados`. El tiempo total se recalcula cada vez que el usuario marca/desmarca un checkbox sumando los `timeout_seconds` de los seleccionados y convirtiéndolos a minutos. | `webapp/static/js/app.js` | ✅ |
| 10.6.6 | Deshabilitar el botón "Iniciar Escaneo" y mostrar tooltip "Debes seleccionar al menos una fase" cuando 0 checkboxes estén marcados. Volver a habilitar al marcar alguno. | `webapp/static/js/app.js` | ✅ |
| 10.6.7 | Al cerrar/colapsar el panel sin cambios (o al cambiar de perfil), restablecer la selección a "todas las fases" para no acumular configuraciones previas accidentalmente. | `webapp/static/js/app.js` | ✅ |

#### 10.7 — Capa Frontend: integración con el envío del formulario
| # | Tarea | Archivo | Estado |
|---|-------|---------|--------|
| 10.7.1 | Al construir el `ScanRequest` en el submit del formulario, leer los checkboxes del panel. Si el panel no fue activado o todos están marcados, enviar `selected_steps: null`. Si hay una selección parcial, enviar el array de índices (0-based) de los checkboxes marcados. | `webapp/static/js/app.js` | ✅ |
| 10.7.2 | Incluir en el mensaje de progreso WebSocket la fase que se está ejecutando: "Ejecutando fase 2/3: nikto" en lugar del genérico "Ejecutando nikto". | `webapp/static/js/app.js` | ✅ (via step_callback) |

#### 10.8 — Capa Frontend: historial y lista de escaneos
| # | Tarea | Archivo | Estado |
|---|-------|---------|--------|
| 10.8.1 | En la tabla de historial de escaneos, añadir un badge "⚙ personalizado" junto al nombre del perfil cuando el escaneo tiene `custom_steps` no nulo. Al pasar el cursor sobre el badge, mostrar tooltip con la lista de herramientas omitidas. | `webapp/templates/index.html` | ✅ |
| 10.8.2 | En la vista de detalle del reporte (panel de reportes), mostrar en el subtítulo del escaneo: "Perfil: lab · 3 de 5 fases ejecutadas" cuando aplique. | `webapp/templates/index.html` | ✅ |

#### 10.9 — Función avanzada: guardar configuraciones como presets (opcional)
| # | Tarea | Archivo | Estado |
|---|-------|---------|--------|
| 10.9.1 | Añadir botón "Guardar como preset..." en el pie del panel de selección. Al hacer clic, pedir un nombre (input inline) y guardar `{nombre, profile_id, selected_steps}` en `localStorage` del navegador. | `webapp/static/js/app.js` | ✅ |
| 10.9.2 | Al seleccionar un perfil, mostrar debajo del toggle "Configurar fases" los presets guardados para ese perfil como botones: "Aplicar preset: Solo nmap + curl". Al hacer clic, marcar automáticamente los checkboxes correspondientes. | `webapp/static/js/app.js` | ✅ |
| 10.9.3 | Añadir opción "Eliminar preset" con confirmación inline para cada preset guardado. | `webapp/static/js/app.js` | ✅ |

---

## Resumen de Prioridades

| Fase | Descripción | Prioridad | Esfuerzo | Estado |
|------|-------------|-----------|----------|--------|
| 4 | Entorno de práctica (Juice Shop + DVWA) | CRÍTICA | ~12h | ✅ |
| 1 | OWASP API Security Top 10 2023 | CRÍTICA | ~40h | ✅ |
| 2 | CVE/NVD actualizado | ALTA | ~20h | ✅ |
| 3 | Integración OWASP ZAP | ALTA | ~35h | ✅ |
| 5 | Reportes educativos | MEDIA | ~25h | ✅ |
| 6 | Seguridad y arquitectura | MEDIA | ~15h | ✅ |
| 7 | Funcionalidades avanzadas | BAJA | ~30h | ✅ |
| 8 | Correcciones de perfiles de escaneo | ALTA | ~18h | ✅ |
| 9 | Reportes dinámicos con actualización automática | ALTA | ~22h | ✅ |
| 10 | Selección manual de fases por escaneo | MEDIA | ~20h | ✅ |
| | **TOTAL** | | **~237h** | |

---

## Orden de Ejecución Recomendado

```
SEMANA 1-2:  Fase 4 — Entorno de práctica (resultado inmediato para clase)              ✅
SEMANA 3-6:  Fase 1 — OWASP API Top 10 2023 (diferenciador pedagógico clave)            ✅
SEMANA 7-8:  Fase 2 — Base CVE actualizada (credibilidad de resultados)                  ✅
SEMANA 9-11: Fase 3 — Integración ZAP (pruebas activas profundas)                       ✅
SEMANA 12-13: Fase 5 — Reportes educativos                                               ✅
SEMANA 14:   Fase 6 — Seguridad y arquitectura                                           ✅
SEMANA 15:   Fase 7 — Funcionalidades avanzadas                                          ✅
SEMANA 16:   Fase 8 — Correcciones de perfiles (calidad de datos del escaneo)            ✅
SEMANA 17-18: Fase 9 — Reportes dinámicos (actualización automática de catálogo)         ✅
SEMANA 19-20: Fase 10 — Selección manual de fases (configuración personalizada por sesión) ✅
```

**Justificación del orden Fase 8 → 9 → 10:**
- Fase 8 primero: corregir los perfiles garantiza que las fases que el usuario puede seleccionar en Fase 10 capturen datos de calidad.
- Fase 9 antes de 10: los datos educativos del perfil (`purpose`, `what_it_finds`) que enriquecen la UI de selección de fases (Fase 10) dependen de que el endpoint `/detail` esté maduro.
- Fase 10 al final del bloque activo: depende de que las correcciones (F8) y los datos educativos (F9 modal detail) estén completos para mostrar información útil en cada checkbox de fase.

---

## Registro de Cambios

| Fecha | Descripción | Fase |
|-------|-------------|------|
| 2026-05-16 | Análisis inicial del proyecto y creación del plan | — |
| 2026-05-16 | Implementación completa del entorno de laboratorio | 4 |
| 2026-05-16 | Implementación completa OWASP API Security Top 10 2023 | 1 |
| 2026-05-16 | Base de conocimiento CVE con NVD, CISA KEV y OSV | 2 |
| 2026-05-16 | Validación Fases 1, 2 y 4 — 8/8 tests pasados | — |
| 2026-05-16 | Fix UTF-8 en stdout Windows (agent.py) | — |
| 2026-05-16 | Implementación completa integración OWASP ZAP | 3 |
| 2026-05-16 | Implementación completa reportes educativos — 181/279 vulns enriquecidas en Juice Shop | 5 |
| 2026-05-19 | Implementación completa Seguridad y Arquitectura — privileged eliminado, API key auth, rate limiting, target validation, JSON logging, suite pytest | 6 |
| 2026-05-19 | Implementación completa Funcionalidades Avanzadas — dependency scanner, SARIF exporter, webhook notifier, CTF mode (8 desafíos), student progress tracking | 7 |
| 2026-05-25 | Análisis completo de 12 perfiles de escaneo — identificadas brechas en comandos, timeouts, puertos y herramientas faltantes | 8 |
| 2026-05-25 | Adición de Fase 8 (correcciones de perfiles) y Fase 9 (reportes dinámicos con catálogo auto-actualizable) al plan | — |
| 2026-05-25 | Adición de tarea 8.6.5: escaneo de red genera listado de IPs disponibles visible en sección "Objetivos de Laboratorio" de la UI | 8 |
| 2026-05-26 | Implementación completa Fase 8 — correcciones de 10 perfiles (8.1–8.10), 3 nuevas herramientas Docker (wafw00f, sslscan, enum4linux+snmp-check), 3 parsers nuevos (whatweb, wafw00f, sslscan), endpoint discovered-hosts, UI hosts activos con vendor MAC | 8 |
| 2026-05-26 | Implementación completa Fase 9 — CatalogLoader (SHA-256 cache), CatalogWatcher (polling 60s), CatalogSyncWorker (CISA KEV cada 24h), API catalog completa (version/reload/entries/sync-log/sync/refresh), tablas SQLite catalog_versions+catalog_sync_log, UI página Catálogo con filtros/edición modal, banner WS catalog_updated, WebSocket listener global | 9 |
| 2026-05-26 | Implementación completa Fase 10 — steps_filter en scanner.run_scan/agent.execute_scan, selected_steps en ScanRequest con validación de rango, skipped_steps en metadatos y JSON report, scan_config en reporte, panel UI "Configurar fases" con checkboxes/advertencias/footer dinámico, presets localStorage, badge historial, reseteo por cambio de perfil | 10 |
| 2026-05-25 | Modal de perfil enriquecido con contenido educativo: objetivos de aprendizaje, propósito por herramienta, qué detecta y referencia OWASP por cada comando | — |
| 2026-05-25 | Adición de Fase 10: selección manual de fases por escaneo — 9 subsecciones, 3 capas (backend scanner+agent+API, frontend panel+historial, presets opcionales) | 10 |

---

## Convenciones de Estado

- ⬜ Pendiente
- 🔄 En progreso
- ✅ Completado
- ❌ Descartado
- ⏸ Pausado