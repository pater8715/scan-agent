# Guía de Laboratorio — Scan Agent

**Contexto:** Práctica de identificación de vulnerabilidades en aplicaciones web y APIs REST  
**Herramientas:** OWASP Juice Shop · DVWA · Scan Agent  
**Nivel:** Estudiantes de desarrollo web

---

## 1. Inicio del Entorno

El entorno de laboratorio levanta tres servicios con un solo comando:

```bash
make lab-start
```

| Servicio | URL | Descripción |
|----------|-----|-------------|
| Scan Agent Web UI | http://localhost:8080 | Herramienta de escaneo |
| OWASP Juice Shop | http://localhost:3000 | App web intencionalmente vulnerable |
| DVWA | http://localhost:8081 | App clásica de práctica de vulnerabilidades |

**Primera vez con DVWA:** Ingresa a http://localhost:8081/setup.php y haz clic en **"Create / Reset Database"**. Credenciales: `admin` / `password`.

Para detener el entorno:
```bash
make lab-stop
```

---

## 2. Primer Escaneo

### Desde la Web UI (recomendado para comenzar)

1. Abre http://localhost:8080
2. En "Target", escribe `juice-shop` (nombre del contenedor en la red interna)
3. Selecciona perfil **Lab**
4. Haz clic en "Start Scan"
5. Espera los resultados (~10-15 minutos)

### Desde la terminal

```bash
# Escanear Juice Shop
make lab-scan-juice

# Escanear DVWA
make lab-scan-dvwa
```

Los reportes se guardan en `./reports/`.

---

## 3. OWASP Juice Shop — Guía por Vulnerabilidades

Juice Shop es una aplicación NodeJS moderna con +100 retos de seguridad. Está basada en el **OWASP Top 10 2021**.

### A01 — Broken Access Control

**¿Qué es?** Un usuario puede acceder a recursos o funciones para los que no tiene permiso.

**Ejercicio:**
1. Regístrate como usuario normal en http://localhost:3000/#/register
2. Inicia sesión y observa el JWT en `localStorage` (F12 → Application → Local Storage)
3. Decodifica el JWT en https://jwt.io — nota el campo `role`
4. Busca la ruta `/administration` en el código fuente (F12 → Sources)
5. Intenta acceder directamente a http://localhost:3000/#/administration

**Qué buscar en el reporte de Scan Agent:** Rutas `/administration`, `/api/users` accesibles sin autenticación.

---

### A02 — Cryptographic Failures

**¿Qué es?** Datos sensibles transmitidos o almacenados sin cifrado adecuado.

**Ejercicio:**
1. Abre las DevTools (F12) → Network
2. Inicia sesión en Juice Shop
3. Observa la petición POST a `/rest/user/login`
4. Revisa si la contraseña se envía en texto claro o cifrada
5. Inspecciona los headers de respuesta — ¿hay `Strict-Transport-Security`?

**Qué buscar en el reporte:** Headers de seguridad faltantes (`HSTS`, `X-Content-Type-Options`, `Content-Security-Policy`).

---

### A03 — Injection (SQL Injection)

**¿Qué es?** Entrada del usuario se interpreta como código SQL.

**Ejercicio en Juice Shop:**
1. Ve a la pantalla de login: http://localhost:3000/#/login
2. En el campo email escribe: `' OR 1=1--`
3. En contraseña escribe cualquier cosa
4. Observa qué ocurre

**Ejercicio en DVWA (nivel Low):**
1. Ingresa a http://localhost:8081/vulnerabilities/sqli/
2. En el campo User ID escribe: `1' OR '1'='1`
3. Observa la respuesta con todos los usuarios

**Ejercicio más avanzado en DVWA:**
```
1' UNION SELECT user,password FROM users--
```

**Qué buscar en el reporte:** Nikto identifica endpoints con posible SQLi en los resultados del escaneo.

---

### A05 — Security Misconfiguration

**¿Qué es?** Configuraciones por defecto inseguras, puertos abiertos innecesarios, headers faltantes.

**Ejercicio:**
1. Corre el escaneo con `make lab-scan-juice`
2. Abre el reporte HTML en `./reports/`
3. Identifica los headers HTTP faltantes
4. Compara con la lista de headers recomendados:
   - `Content-Security-Policy`
   - `X-Frame-Options`
   - `X-Content-Type-Options`
   - `Strict-Transport-Security`
   - `Permissions-Policy`

**Reto adicional:** ¿Puedes encontrar el archivo `/ftp/` en Juice Shop? Pista: usa Gobuster o busca en el reporte de directorios descubiertos.

---

### A06 — Vulnerable and Outdated Components

**¿Qué es?** Uso de librerías o frameworks con vulnerabilidades conocidas.

**Ejercicio:**
1. Abre http://localhost:3000/package.json (¡Juice Shop expone esto!)
2. Identifica las versiones de dependencias
3. Busca en https://osv.dev si alguna tiene CVEs conocidos
4. Compara con lo que detecta el reporte de Scan Agent

---

### A07 — Identification and Authentication Failures

**¿Qué es?** Autenticación débil, sesiones mal gestionadas, recuperación de contraseña insegura.

**Ejercicio en Juice Shop:**
1. Ve a http://localhost:3000/#/forgot-password
2. Ingresa el email `admin@juice-sh.op`
3. Observa la pregunta de seguridad — ¿qué tan fácil es adivinar la respuesta?
4. Pista: el nombre de la mascota favorita del admin está en una reseña de producto

**Ejercicio en DVWA — Brute Force:**
1. Ve a http://localhost:8081/vulnerabilities/brute/
2. Prueba combinaciones comunes: `admin/admin`, `admin/password`, `user/user`
3. Observa que no hay protección contra intentos múltiples

---

### A10 — Server-Side Request Forgery (SSRF)

**¿Qué es?** El servidor hace peticiones HTTP a URLs controladas por el atacante.

**Ejercicio conceptual:**
1. En Juice Shop, busca funcionalidades que acepten URLs como entrada
2. La función de "Track Orders" acepta un patrón de URL
3. Intenta manipular el parámetro para apuntar a `http://localhost:3000/api/users`

---

## 4. DVWA — Guía por Módulo

DVWA tiene niveles de dificultad: **Low → Medium → High → Impossible**.

Siempre empieza en **Low** para entender el concepto, luego sube el nivel para ver cómo se mitiga.

Para cambiar el nivel: http://localhost:8081/security.php

### XSS Reflejado (Reflected XSS)

```
Ruta: http://localhost:8081/vulnerabilities/xss_r/
```

**Nivel Low:**
1. En el campo "What's your name?" escribe: `<script>alert('XSS')</script>`
2. Si aparece una alerta, el XSS funciona

**Nivel Medium (bypass del filtro):**
El filtro bloquea `<script>` en minúsculas. Prueba:
```
<SCRIPT>alert('XSS')</SCRIPT>
<img src=x onerror="alert('XSS')">
```

**Qué aprender:** Por qué hay que sanitizar y escapar todas las entradas de usuario antes de renderizarlas en HTML.

---

### XSS Almacenado (Stored XSS)

```
Ruta: http://localhost:8081/vulnerabilities/xss_s/
```

**Nivel Low:**
1. En el campo "Message" escribe: `<script>alert('Stored XSS')</script>`
2. Haz clic en "Sign Guestbook"
3. Recarga la página — el script se ejecuta cada vez que alguien visita

**Qué aprender:** El XSS almacenado es más peligroso porque afecta a todos los visitantes.

---

### Command Injection

```
Ruta: http://localhost:8081/vulnerabilities/exec/
```

**Nivel Low:**
1. En el campo de IP escribe: `127.0.0.1`
2. Observa el output (hace ping)
3. Ahora escribe: `127.0.0.1; id`
4. Luego: `127.0.0.1; cat /etc/passwd`

**Qué aprender:** Nunca pasar input del usuario directamente a funciones de sistema (`exec`, `system`, `shell_exec`).

---

### File Upload

```
Ruta: http://localhost:8081/vulnerabilities/upload/
```

**Nivel Low:**
1. Crea un archivo `shell.php` con:
   ```php
   <?php echo shell_exec($_GET['cmd']); ?>
   ```
2. Súbelo a través del formulario
3. Accede a: `http://localhost:8081/hackable/uploads/shell.php?cmd=id`

**Qué aprender:** Validar tipo de archivo en el servidor, no solo en el cliente.

---

### CSRF

```
Ruta: http://localhost:8081/vulnerabilities/csrf/
```

**Nivel Low:**
1. Inicia sesión con `admin/password`
2. Ve al módulo CSRF
3. Abre las DevTools y observa el formulario de cambio de contraseña
4. Nota que no hay token CSRF en el formulario
5. Un atacante podría crear una página que cambie tu contraseña sin que lo sepas

---

## 5. Interpretación de Reportes

Cuando el escaneo finalice, el reporte incluye:

### Severidades

| Nivel | CVSS | Descripción |
|-------|------|-------------|
| CRITICAL | 9.0-10.0 | Explotable de forma inmediata, requiere atención urgente |
| HIGH | 7.0-8.9 | Vulnerabilidad seria, debe corregirse pronto |
| MEDIUM | 4.0-6.9 | Riesgo significativo, planificar corrección |
| LOW | 0.1-3.9 | Riesgo menor, corregir cuando sea posible |
| INFO | 0.0 | Información útil, no es vulnerabilidad directa |

### Qué hacer con cada hallazgo

1. **Leer la descripción** — entender qué detectó la herramienta
2. **Verificar manualmente** — confirmar que no es un falso positivo
3. **Reproducir la vulnerabilidad** — siguiendo los ejercicios de esta guía
4. **Aplicar la remediación** — que aparece al final de cada hallazgo en el reporte
5. **Re-escanear** — verificar que la corrección fue efectiva

---

## 6. Comparar Antes y Después

Un ejercicio valioso es:

1. Escanear la app → guardar reporte inicial
2. Aplicar una corrección de seguridad
3. Escanear de nuevo → comparar los reportes

**Ejemplo con DVWA:**
- Escanearlo en nivel **Low** → anotar hallazgos
- Cambiar a nivel **High** → escanear de nuevo
- Observar cómo los hallazgos cambian

---

## 7. Comandos de Referencia Rápida

```bash
# Iniciar todo el laboratorio
make lab-start

# Ver estado de los contenedores
make lab-status

# Escanear Juice Shop
make lab-scan-juice

# Escanear DVWA
make lab-scan-dvwa

# Ver logs de Juice Shop
docker logs juice-shop -f

# Ver logs de DVWA
docker logs dvwa -f

# Acceso a shell del contenedor (para exploración avanzada)
docker exec -it juice-shop /bin/sh
docker exec -it dvwa /bin/bash

# Detener el laboratorio
make lab-stop
```

---

## 8. Recursos Adicionales

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10 2023](https://owasp.org/www-project-api-security/)
- [OWASP Juice Shop — Solving Guide](https://pwning.owasp-juice.shop)
- [DVWA Documentación](https://github.com/digininja/DVWA)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) (laboratorios gratuitos)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [CWE List](https://cwe.mitre.org/data/index.html)

---

*Guía creada para uso educativo en entorno controlado. Las técnicas aquí descritas deben practicarse únicamente en sistemas propios o con autorización explícita.*
