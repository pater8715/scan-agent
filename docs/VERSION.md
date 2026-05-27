# ScanAgent - Historial de Versiones

## v3.3.0 (2026-05-27) — Lanzador Windows, Compatibilidad Kali 2026 y Documentación

**Versión actual**

- ✅ `start.ps1` — Lanzador PowerShell interactivo con menú de perfiles y acciones (7 perfiles × 7 acciones)
- ✅ Dockerfile corregido para Kali Linux 2026.2 / Python 3.13 (5 fixes: libexpat, symlink python3, pip3, --ignore-installed, snmp-check)
- ✅ `scan-agent-analyzer` ya no hace loop: `restart: "no"` + `rglob` fallback en `_execute_parsing()`
- ✅ Makefile migrado a `docker compose` v2 con targets por perfil
- ✅ Manual de Usuario v3.3: ZAP port 8090, start.ps1, analyzer Exited(0) como normal, nota containerd

Ver detalles completos en [`docs/changelog/CHANGELOG_v3.3.md`](changelog/CHANGELOG_v3.3.md)

---

## v3.2.0 (2026-05-26) — Selección manual de fases, catálogo dinámico

- Panel de selección de fases por escaneo (UI)
- Presets de fases guardados en localStorage
- Badge "⚙ personalizado" en historial
- Catálogo de recomendaciones con editor y sincronización CISA KEV
- Notificación WebSocket al actualizar catálogo

---

## v3.1.0 (2026-05-23) — Hosts activos CIDR y cancelación de escaneos

- Panel "Hosts Descubiertos" tras escaneos de red CIDR
- Cancelación real de escaneos (termina proceso nmap subyacente)
- Barra de escaneos activos visible en todas las pestañas
- Endpoint `GET /api/scans/{scan_id}/hosts`
- Parser de cabeceras HTTP corregido

---

## v3.0.0 (2026-05-19) — Laboratorio completo, OWASP API Top 10, CVE integrado

- Entorno lab completo: Juice Shop + DVWA + ZAP + Scan Agent
- Cobertura OWASP API Security Top 10 (2023)
- Base de conocimiento CVE: NVD, CISA KEV, OSV con caché SQLite
- Red Docker estática `172.20.0.0/24` con IPs fijas
- Panel de Objetivos de Laboratorio en UI
- Perfiles de reporte específicos (web, network, api-owasp, compliance)

---

## v2.1.0 (2025-11-12) — File Retention Manager

- Sistema de retención de archivos en niveles (active/archived/metadata)
- Cleanup automático de archivos antiguos

---

## v2.0.0 (2025-11-11) — Interfaz Web

- Interfaz web con FastAPI
- Dashboard HTML con listado de escaneos
- API REST para gestión de escaneos
- Background tasks para escaneos asíncronos

---

## v1.0.0 (2025-11-10) — Release Inicial

- Escaneo básico con Nmap
- Generación de reportes simples
- CLI interface
- Soporte para múltiples perfiles (quick/standard/full)

---

**Versión actual:** 3.3.0  
**Última actualización:** 27 de mayo de 2026
