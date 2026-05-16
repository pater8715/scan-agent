



# Plan de Mejoras — Scan Agent

**Proyecto:** Herramienta educativa de análisis de vulnerabilidades web y API REST  
**Contexto:** Clases con estudiantes de aplicaciones web y API REST  
**Versión actual:** 3.0.0  
**Fecha de análisis:** 2026-05-16  
**Autor:** Alberto Paternina León

---

## Estado del Proyecto

### Fortalezas actuales
- Arquitectura bien estructurada (~7,100 líneas de Python)
- Integración con 6 herramientas: nmap, nikto, gobuster, dirb, whatweb, curl
- 8 perfiles de escaneo predefinidos
- Mapeo a OWASP Top 10 **Web** 2021
- API REST con FastAPI y WebSockets
- Reportes en 4 formatos (HTML, JSON, TXT, Markdown)
- Base de datos SQLite con historial de escaneos

### Brechas críticas identificadas
1. **OWASP API Security Top 10 2023 ausente** — la lista específica para APIs REST no está implementada
2. **Solo detección pasiva** — no hay pruebas activas de SQLi, XSS, IDOR, autenticación rota
3. **Knowledge base desactualizado** — hardcodeado, sin conexión a NVD/CVE/CISA KEV
4. **Sin integración OWASP ZAP** — el estándar educativo para pruebas web/API
5. **Reportes no pedagógicos** — no explican el "por qué", sin referencias CWE ni ejemplos de remediación
6. **Sin entorno de práctica controlado** — no hay DVWA ni Juice Shop integrado para practicar de forma segura

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
**Prioridad:** MEDIA | **Estimado:** ~15h | **Estado:** ⬜ Pendiente

Mejoras de seguridad en la propia herramienta.

| # | Tarea | Estado | Notas |
|---|-------|--------|-------|
| 6.1 | Eliminar `privileged: true` del docker-compose web | ⬜ | Reemplazar con capabilities mínimas |
| 6.2 | Añadir autenticación a la API FastAPI (API key o JWT) | ⬜ | Middleware en `webapp/main.py` |
| 6.3 | Validar targets para evitar escanear IPs no autorizadas (whitelist) | ⬜ | Input validation en `scanner.py` |
| 6.4 | Implementar rate limiting en la API con `slowapi` | ⬜ | `webapp/main.py` |
| 6.5 | Añadir logging estructurado en JSON para auditoría | ⬜ | Reemplazar prints por logger |
| 6.6 | Crear suite de tests automáticos con pytest | ⬜ | Directorio `tests/` |

---

### FASE 7 — Funcionalidades Avanzadas
**Prioridad:** BAJA | **Estimado:** ~30h | **Estado:** ⬜ Pendiente

Mejoras opcionales para enriquecer la experiencia educativa.

| # | Tarea | Estado | Notas |
|---|-------|--------|-------|
| 7.1 | Integrar análisis de dependencias con `safety` (Python) y `npm audit` | ⬜ | Nuevo módulo `dependency_scanner.py` |
| 7.2 | Exportar resultados en formato SARIF (estándar GitHub Advanced Security) | ⬜ | Nuevo exporter |
| 7.3 | Añadir notificaciones webhook para vulnerabilidades críticas | ⬜ | Módulo `notifier.py` |
| 7.4 | Crear modo "CTF" para gamificar el aprendizaje | ⬜ | Feature en la UI web |
| 7.5 | Reporte de progreso por estudiante (tracking de mejoras) | ⬜ | Dashboard update |

---

## Resumen de Prioridades

| Fase | Descripción | Prioridad | Esfuerzo | Estado |
|------|-------------|-----------|----------|--------|
| 4 | Entorno de práctica (Juice Shop + DVWA) | CRÍTICA | ~12h | ✅ |
| 1 | OWASP API Security Top 10 2023 | CRÍTICA | ~40h | ✅ |
| 2 | CVE/NVD actualizado | ALTA | ~20h | ✅ |
| 3 | Integración OWASP ZAP | ALTA | ~35h | ✅ |
| 5 | Reportes educativos | MEDIA | ~25h | ✅ |
| 6 | Seguridad y arquitectura | MEDIA | ~15h | ⬜ |
| 7 | Funcionalidades avanzadas | BAJA | ~30h | ⬜ |
| | **TOTAL** | | **~177h** | |

---

## Orden de Ejecución Recomendado

```
SEMANA 1-2:  Fase 4 — Entorno de práctica (resultado inmediato para clase)
SEMANA 3-6:  Fase 1 — OWASP API Top 10 2023 (diferenciador pedagógico clave)
SEMANA 7-8:  Fase 2 — Base CVE actualizada (credibilidad de resultados)
SEMANA 9-11: Fase 3 — Integración ZAP (pruebas activas profundas)
SEMANA 12-13: Fase 5 — Reportes educativos
SEMANA 14:   Fase 6 — Seguridad y arquitectura
SEMANA 15+:  Fase 7 — Funcionalidades avanzadas (según disponibilidad)
```

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

---

## Convenciones de Estado

- ⬜ Pendiente
- 🔄 En progreso
- ✅ Completado
- ❌ Descartado
- ⏸ Pausado