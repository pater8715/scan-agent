# Anomalías Pendientes — Scan Agent

**Fecha de registro:** 2026-05-30  
**Contexto:** Detectadas durante sesión de escaneos de corroboración contra sitios en producción (Cloudflare Pages, Render.com, Netlify).

---

## ANO-01 — Falsos positivos en security headers por captura del redirect HTTP (RESUELTO)

**Estado:** ✅ Resuelto en commits `2533693`, `caf0db0`  
**Síntoma:** El scanner reportaba HSTS, CSP, X-Frame-Options, etc. como ausentes en sitios que sí los tienen.  
**Causa:** `curl -I http://` capturaba la respuesta del redirect 301 (sin security headers) en vez de la respuesta HTTPS final.  
**Fix aplicado:**  
- Añadir `-L` a todos los comandos `curl -I` para seguir redirects.  
- Resetear `results["headers"]` al inicio de cada respuesta HTTP en `parse_headers()` para conservar solo la final.  
- Añadir `curl -IL https://` como segundo comando en perfiles `web`, `standard`, `full`, `api`, `api-owasp`.

---

## ANO-02 — Crash de nmap NSE con wildcard `http-vuln*` (RESUELTO)

**Estado:** ✅ Resuelto en commit `ee31e6e`  
**Síntoma:** Escaneo abortaba tras nmap NSE con error `Assertion 'lua_status(L) == LUA_YIELD' failed` en `nse_nsock.cc`.  
**Causa:** El wildcard `http-vuln*` en el perfil `web` expandía demasiados scripts simultáneos causando un crash interno de nmap. Además el paso era `required: True`, abortando curl y el resto del scan.  
**Fix aplicado:**  
- Reemplazar `http-vuln*` por scripts específicos y estables: `http-security-headers`, `http-auth-finder`.  
- Cambiar `required: True` → `required: False` para el paso NSE en el perfil `web`.

---

## ANO-03 — Headers vacíos cuando CDN bloquea curl pero nmap NSE sí conecta (RESUELTO)

**Estado:** ✅ Resuelto en commit `bd1b216`  
**Síntoma:** Cuando Netlify bloquea curl por IP de datacenter, nmap NSE (puerto 443) sí captura los headers reales via `http-headers`, pero el parser no los extrae a `results["headers"]`.  
**Causa:** El routing de archivos en `parse_all_files()` enviaba los archivos `nmap_nse_*.txt` solo a `parse_nse_output()`, que almacena los findings pero no puebla el dict de cabeceras.  
**Fix aplicado:**  
- Añadir helper `_has_security_headers()`.  
- Llamar a `parse_headers()` sobre el contenido NSE cuando: (a) hay bloques `| http-headers:` y (b) no hay security headers en el dict actual.

---

## ANO-04 — Bloqueo total de Netlify: scan sin datos reporta Risk Level LOW ⚠️ PENDIENTE

**Estado:** ⚠️ Pendiente  
**Síntoma:** Cuando Netlify (u otro CDN) bloquea **todos** los puertos desde el IP del contenedor, el scan completa con 0 puertos, 0 headers y 0 hallazgos. El reporte muestra Risk Level: LOW / Risk Score: 0, lo que puede interpretarse erróneamente como "sitio seguro".  
**Causa:** El scanner no distingue entre "sitio sin vulnerabilidades" y "sitio inaccesible durante el scan".  
**Impacto:** Falso negativo global — el reporte no advierte que el scan no pudo recopilar datos.  
**Solución propuesta:**  
- Añadir validación post-scan: si `ports == 0` y `http_headers == {}` y `nikto_findings == []`, añadir hallazgo informativo de tipo `scan_data_unavailable` con severidad INFO.  
- Mostrar advertencia visible en el reporte HTML: "El scanner no pudo conectar al objetivo. Los resultados pueden estar incompletos."  
- Añadir campo `scan_quality` al JSON del reporte: `complete` / `partial` / `failed`.

---

## ANO-05 — `http-security-headers` NSE reporta HSTS ausente sobre HTTP ⚠️ PENDIENTE

**Estado:** ⚠️ Pendiente  
**Síntoma:** El script nmap `http-security-headers` corre sobre el endpoint HTTP (puerto 80) y reporta "HSTS not configured in HTTPS Server", generando un finding confuso en el reporte.  
**Causa:** El script evalúa el puerto HTTP que devuelve un redirect 301, no el endpoint HTTPS donde HSTS sí está presente.  
**Impacto:** Ruido en los findings de NSE; puede aumentar el risk score artificialmente.  
**Solución propuesta:**  
- Filtrar en `parse_nse_output()` los findings de `http-security-headers` que reporten ausencia de headers cuando el puerto analizado es 80 (HTTP).  
- O bien: configurar nmap para correr `http-security-headers` solo sobre puerto 443 usando `--script-args http.useragent=...` o separar el script a un comando nmap apuntando explícitamente a `{target}:443`.

---

## ANO-06 — Fingerprint nmap de puerto 80 contamina `http_headers` con headers del redirect ⚠️ PENDIENTE

**Estado:** ⚠️ Pendiente  
**Síntoma:** Cuando curl falla y el fallback es el fingerprint de nmap (`parse_nmap_fingerprint_for_headers()`), se extraen los headers de la respuesta HTTP de puerto 80 (Date, Server, Content-Length: 0) sin security headers, en lugar de los headers HTTPS.  
**Causa:** `parse_nmap_fingerprint_for_headers()` extrae de la primera respuesta del fingerprint TCP, que es siempre la de puerto 80.  
**Impacto:** `http_headers` queda con datos parciales/incorrectos → falsos positivos en security headers.  
**Solución propuesta:**  
- En `parse_nmap_fingerprint_for_headers()`: buscar específicamente el bloque de fingerprint correspondiente al puerto 443/SSL, no el primero encontrado.  
- O bien: marcar los headers del fingerprint como "de baja confianza" y no usarlos para evaluar security headers si ya hay datos NSE disponibles.
