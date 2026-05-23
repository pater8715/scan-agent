# Inicio Rápido — Scan Agent Web

## Instrucciones en 3 pasos

### 1. Arrancar el laboratorio

```bash
# Con Make (recomendado)
make lab-start

# O directamente con Docker Compose
docker compose -f docker/docker-compose.yml --profile lab up -d
```

### 2. Verificar que todo está corriendo

```bash
make lab-status
```

Todos los contenedores deben mostrar `Up`. El servicio web estará disponible en:

### 3. Abrir el navegador

**http://localhost:8080**

---

## URLs importantes

| Recurso | URL |
|---------|-----|
| Interfaz Web | http://localhost:8080 |
| API Docs (Swagger) | http://localhost:8080/api/docs |
| Health Check | http://localhost:8080/health |
| Juice Shop | http://localhost:3000 |
| DVWA | http://localhost:8081 |

---

## Cómo usar la interfaz web

### Paso 1 — Lanzar un escaneo

1. Abre http://localhost:8080
2. Escribe el target: `juice-shop` o `dvwa` (dentro de Docker usa el nombre del contenedor)
3. Selecciona el perfil deseado (recomendado: **lab** para el laboratorio)
4. Haz clic en **Start Scan**

### Paso 2 — Seguir el progreso

- La barra de progreso muestra las fases del escaneo en tiempo real
- Los escaneos activos aparecen como chips en la barra superior
- Para cancelar en cualquier momento: botón **Cancelar** en el formulario o `⛔` en el chip del escaneo activo

### Paso 3 — Ver los resultados

1. Al terminar, el resultado aparece automáticamente
2. Descarga el reporte en el formato que prefieras: HTML, JSON, TXT, Markdown
3. El reporte HTML es el más completo

### Paso 4 — Escaneo de red (CIDR)

Para descubrir todos los hosts activos en la red del lab:

1. Target: `172.20.0.0/24`
2. Perfil: `network`
3. Al terminar aparece el panel **"Hosts Descubiertos"** con una tarjeta por host
4. Desde ahí puedes lanzar un escaneo profundo sobre cualquier host con el perfil que elijas

---

## Cancelar escaneos

Puedes cancelar un escaneo activo de tres formas:

| Desde dónde | Cómo |
|-------------|------|
| Formulario principal | Botón **Cancelar** mientras el escaneo corre |
| Barra de escaneos activos | Botón `⛔` en el chip del escaneo |
| Historial | Botón `⛔ Cancelar` en escaneos con estado `running` o `pending` |

La cancelación es inmediata — termina el proceso subyacente y el estado pasa a `cancelled`.

---

## Perfiles disponibles

| Perfil | Descripción | Tiempo estimado |
|--------|-------------|-----------------|
| `quick` | Puertos comunes + versiones | 2-5 min |
| `lab` | Optimizado para Juice Shop y DVWA | 10-15 min |
| `network` | Descubrimiento de hosts en la red | 2-5 min |
| `web` | HTTP/HTTPS + nikto + gobuster | 10-20 min |
| `api-owasp` | OWASP API Security Top 10 2023 | 10-20 min |
| `full` | Análisis exhaustivo | 30-60 min |

---

## Solución de problemas

### No se puede acceder a http://localhost:8080

```bash
# Ver estado de los contenedores
make lab-status

# Ver logs del contenedor web
docker logs scan-agent-web --tail 50
```

### El escaneo falla o no produce resultados

Confirma que el target está corriendo:

```bash
docker exec scan-agent-web curl -s -o /dev/null -w "%{http_code}" http://juice-shop:3000
# Debe responder 200
```

Usa el nombre del contenedor como target (`juice-shop`, `dvwa`), no `localhost`.

### El panel de hosts descubiertos no aparece

El panel solo se muestra si el escaneo CIDR encontró hosts activos y el perfil fue `network`. Verifica que el target sea un rango CIDR válido (ej: `172.20.0.0/24`).

---

## Documentación completa

- [Manual de usuario completo](../MANUAL_USUARIO.md)
- [Guía Docker](../DOCKER.md)
- [API Docs en vivo](http://localhost:8080/api/docs)
