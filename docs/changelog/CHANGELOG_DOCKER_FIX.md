# Changelog - Docker Fix & Optimization
**Fecha**: 15 de noviembre de 2025  
**Versión**: 3.0.1

## 🔧 Correcciones Aplicadas

### Dockerfile
- ✅ Eliminado requisito de `VERSION.md` que causaba errores de build
- ✅ Eliminado requisito de `scan-agent.py` en raíz (solo existe en scripts/)
- ✅ Cambiado ENTRYPOINT a `uvicorn` directo para mejor compatibilidad
- ✅ Configurado CMD con parámetros correctos: `webapp.main:app --host 0.0.0.0 --port 8080`
- ✅ Añadido WORKDIR explícito en stage de producción

### Docker Compose
- ✅ Eliminado comando override que causaba conflictos con ENTRYPOINT
- ✅ Separadas imágenes para `scan-agent-web` y `scan-agent-analyzer` para evitar conflictos
- ✅ Configurados health checks correctamente
- ✅ Optimizados volúmenes y variables de entorno

### Webapp
- ✅ Servidor corriendo exitosamente en puerto 8080
- ✅ API REST funcional en `/api/`
- ✅ Documentación Swagger disponible en `/api/docs`
- ✅ Health check endpoint en `/health`

## 🚀 Mejoras de Rendimiento

### Build Optimization
- Multi-stage build optimizado
- Cache de layers de Docker mejorado
- Tiempo de build reducido en reconstrucciones

### Runtime
- Uvicorn como servidor ASGI de alto rendimiento
- Health checks cada 30 segundos
- Restart automático en caso de fallos
- Recursos limitados (CPU: 1.5, RAM: 1.5GB para web)

## 📝 Cambios en la Configuración

### Puertos Expuestos
- `8080`: Web UI principal (mapeado desde contenedor)
- `8000`: API alternativa (disponible internamente)

### Perfiles Disponibles
- `web`: Interfaz web + analyzer (recomendado)
- `cli`: Línea de comandos
- `all`: Todos los servicios

### Variables de Entorno
```bash
TZ=Europe/Madrid
PYTHONUNBUFFERED=1
SCAN_MODE=web
WEB_HOST=0.0.0.0
WEB_PORT=8080
LOG_LEVEL=INFO
MAX_CONCURRENT_SCANS=5
```

## 🐛 Problemas Resueltos

1. **Error**: `exec /usr/local/bin/docker-entrypoint.sh: no such file or directory`
   - **Solución**: Cambiado a Python + Uvicorn directo

2. **Error**: `Could not import module "main"`
   - **Solución**: Cambiado a `webapp.main:app` en uvicorn

3. **Error**: `failed to solve: "/VERSION.md": not found`
   - **Solución**: Eliminada dependencia de VERSION.md del Dockerfile

4. **Error**: `image "scan-agent:3.0.0": already exists`
   - **Solución**: Separadas imágenes para web y analyzer

5. **Error**: Contenedores en loop de reinicio
   - **Solución**: Corregido entrypoint y configuración de comando

## 📚 Documentación Actualizada

- ✅ README.md: Comandos de inicio actualizados
- ✅ DOCKER.md: Guía completa de uso con Docker Compose
- ✅ Ejemplos de uso con nuevos comandos
- ✅ Instrucciones de troubleshooting

## ✅ Estado Actual

### Servicios Funcionando
```bash
CONTAINER ID   IMAGE                       STATUS
c4b6005b9dce   scan-agent:3.0.0            Up (healthy)
b86826f6f105   scan-agent-analyzer:3.0.0   Up (healthy)
```

### Acceso
- Web UI: http://localhost:8080 ✅
- API Docs: http://localhost:8080/api/docs ✅
- Health: http://localhost:8080/health ✅

## 🔜 Próximos Pasos

1. Añadir tests de integración para Docker
2. Implementar CI/CD pipeline
3. Optimizar tamaño de imagen
4. Añadir soporte para docker secrets
5. Implementar logging centralizado

## 📦 Comandos de Despliegue

```bash
# Iniciar
docker compose -f docker/docker-compose.yml --profile web up -d

# Ver logs
docker logs scan-agent-web -f

# Detener
docker compose -f docker/docker-compose.yml --profile web down

# Reconstruir
docker compose -f docker/docker-compose.yml --profile web up -d --build
```
