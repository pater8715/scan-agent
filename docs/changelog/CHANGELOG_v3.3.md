# CHANGELOG — Versión 3.3

**Fecha:** 2026-05-27  
**Tipo de release:** Minor — Mejoras de infraestructura Docker, lanzador Windows y documentación

---

## Resumen

La versión 3.3 añade un lanzador interactivo para Windows (`start.ps1`), corrige múltiples problemas de compatibilidad con Kali Linux 2026.2 / Python 3.13 en el Dockerfile, y actualiza toda la documentación del proyecto para reflejar el estado actual del entorno.

---

## Nuevas funcionalidades

### 1. Lanzador Windows `start.ps1`

Nuevo script PowerShell en la raíz del proyecto que proporciona una interfaz de menú interactivo para gestionar los perfiles de Docker Compose:

**7 perfiles disponibles:** `cli`, `web`, `lab`, `analyzer`, `zap`, `dev`, `all`  
**7 acciones disponibles:** `iniciar`, `detener`, `reiniciar`, `estado`, `logs`, `reconstruir`, `limpiar`

```powershell
# Menú interactivo
.\start.ps1

# Uso directo con parámetros
.\start.ps1 -Perfil lab -Accion iniciar
.\start.ps1 -Perfil web -Accion estado
.\start.ps1 -Perfil lab -Accion limpiar  # Pide confirmación s/N
```

**Características:**
- Colores ANSI en la terminal
- Validación de parámetros con `[ValidateSet(...)]`
- Verificación de Docker antes de ejecutar
- Muestra puertos accesibles tras iniciar
- `Reconstruir` usa `build` (sin `--no-cache`) para preservar caché de capas base
- `Limpiar` pide confirmación antes de eliminar contenedores, volúmenes e imágenes

### 2. Makefile actualizado a `docker compose` v2

- Migrado de `docker-compose` (v1) a `docker compose` (v2)
- Variable `COMPOSE = docker compose -f docker/docker-compose.yml`
- Nuevos targets por perfil: `up-web`, `up-lab`, `up-cli`, `up-analyzer`, `up-zap`, `up-dev`
- `down` usa `--profile all` para detener todos los servicios
- `clean-all` elimina volúmenes, imágenes y caché de build

---

## Correcciones de bugs

### Dockerfile — Compatibilidad con Kali Linux 2026.2 / Python 3.13

**Problema 1:** `libexpat1 2.8.0-1` generaba un 404 al instalar `git`, `vim` y `nano`.  
**Fix:** Eliminados del bloque de paquetes esenciales. No son necesarios en producción.

**Problema 2:** Herramientas opcionales (`snmp-check`, etc.) en un solo `apt install` — si alguna fallaba, **ninguna** se instalaba.  
**Fix:** Loop independiente con `|| echo "SKIP: $pkg"` por cada herramienta opcional:
```dockerfile
for pkg in nikto gobuster dirb sslscan enum4linux snmp-check whatweb wafw00f; do
    apt install -y --no-install-recommends $pkg 2>/dev/null || echo "SKIP: $pkg no disponible"
done
```

**Problema 3:** Kali 2026.2 instala Python 3.13 pero no crea el symlink `/usr/bin/python3`.  
**Fix:** RUN step que detecta y crea el symlink automáticamente.

**Problema 4:** `pip3` no existe en Kali 2026.2.  
**Fix:** Reemplazado por `python3 -m pip` en todas las invocaciones.

**Problema 5:** `jinja2` instalada por `apt` conflictuaba con la instalación vía pip (error `uninstall-no-record-file`), causando que `uvicorn` y otros paquetes no se instalaran.  
**Fix:** Añadido `--ignore-installed` al comando `python3 -m pip install`.

### `scan-agent-analyzer` — Loop de reinicio

**Problema:** `scan-agent-analyzer` se reiniciaba continuamente con `restart: unless-stopped`.  
**Fix:** Cambiado a `restart: "no"` en `docker-compose.yml`. El analyzer es un job de análisis por lotes: ejecuta una vez y termina con `Exited (0)`.

**Problema 2:** El analyzer no encontraba archivos `.txt` porque buscaba con `glob("*.txt")` (solo raíz) en lugar de `rglob("*.txt")` (recursivo, incluyendo subdirectorios `outputs/scan_XXXX/`).  
**Fix:** Implementado fallback a `rglob` con selección del subdirectorio más reciente.

---

## Documentación actualizada

### `docs/MANUAL_USUARIO.md` (v3.2 → v3.3)

- **Sección 1:** Añadidos puertos 8000 (API) y 8090 (ZAP) a la tabla de puertos libres
- **Sección 2:** `start.ps1` como lanzador recomendado en Windows; estado esperado actualizado con ZAP y `scan-agent-analyzer Exited (0)` como normal; ZAP añadido a tabla de accesos
- **Sección 3:** Diagrama de arquitectura actualizado con ZAP; `snmp-check` marcado como *opcional*; nota explicativa sobre herramientas opcionales
- **Sección 10:** Nueva entrada: `scan-agent-analyzer Exited (0)` es normal; nota sobre `docker rmi` en modo containerd; opción `start.ps1 -Accion limpiar` para Windows
- **Sección 11:** Nuevo bloque de referencia rápida para `start.ps1`; ZAP añadido a tabla de URLs

### `docs/guides/QUICKSTART_WEB.md`

- Añadido bloque Windows con `start.ps1` en el paso 1
- Nota sobre `scan-agent-analyzer Exited (0)` como normal en verificación de estado
- ZAP añadido a la tabla de URLs

### `README.md`

- Versión actualizada a 3.3
- Inicio Rápido: bloque Windows con `start.ps1`; ZAP añadido a la lista de accesos del lab
- Nueva sección `🖥️ Lanzador Windows (start.ps1)` con referencia completa de uso

---

## Archivos modificados

| Archivo | Tipo de cambio |
|---------|---------------|
| `start.ps1` | NUEVO — lanzador PowerShell interactivo |
| `docker/Dockerfile` | MODIFICADO — 5 fixes compatibilidad Kali 2026.2 |
| `docker/docker-compose.yml` | MODIFICADO — `restart: "no"` en analyzer |
| `src/scanagent/agent.py` | MODIFICADO — `rglob` fallback en `_execute_parsing()` |
| `Makefile` | MODIFICADO — migración a `docker compose` v2 + targets por perfil |
| `docs/MANUAL_USUARIO.md` | MODIFICADO — actualización general v3.2→v3.3 |
| `docs/guides/QUICKSTART_WEB.md` | MODIFICADO — start.ps1 + ZAP |
| `README.md` | MODIFICADO — versión, start.ps1, ZAP |
