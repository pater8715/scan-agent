# Inicio Rápido - Scan Agent Web

## 🚀 Instrucciones de 3 Pasos

### 1️⃣ Instalar Dependencias

```bash
cd /home/clase/scan-agent
pip3 install -r webapp/requirements.txt
```

### 2️⃣ Iniciar Servidor

```bash
./start-web.sh
```

### 3️⃣ Abrir Navegador

Visita: **http://localhost:8000**

---

## 📖 URLs Importantes

| Recurso | URL |
|---------|-----|
| **Interfaz Web** | http://localhost:8000 |
| **API Docs (Swagger)** | http://localhost:8000/api/docs |
| **ReDoc** | http://localhost:8000/api/redoc |
| **Health Check** | http://localhost:8000/health |

---

## 🎯 Cómo Usar la Interfaz Web

### Paso 1: Seleccionar Perfil
1. Abre http://localhost:8000
2. Revisa los 4 perfiles disponibles
3. Haz clic en el que desees (se marcará con ✓)

### Paso 2: Configurar Objetivo
1. Ingresa la IP o dominio a escanear
2. Selecciona formatos de reporte
3. Decide si guardar en base de datos

### Paso 3: Ejecutar
1. Clic en "Iniciar Escaneo"
2. Observa la barra de progreso
3. Espera a que complete

### Paso 4: Resultados
1. Ver resumen de vulnerabilidades
2. Descargar reportes
3. O iniciar nuevo escaneo

---

## ⚙️ Opciones Avanzadas

### Cambiar Puerto

```bash
cd webapp
uvicorn main:app --host 0.0.0.0 --port 9000
```

### Modo Desarrollo (auto-reload)

```bash
cd webapp
python3 main.py
```

### Modo Producción

```bash
cd webapp
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## 🔧 Troubleshooting

### Error: ModuleNotFoundError: No module named 'fastapi'

**Solución**: Instalar dependencias
```bash
pip3 install -r webapp/requirements.txt
```

### Error: Address already in use

**Solución**: El puerto 8000 está ocupado
```bash
# Usar otro puerto
uvicorn main:app --port 9000

# O matar el proceso
lsof -ti:8000 | xargs kill -9
```

### No se ven los escaneos en el historial

**Solución**: Verificar que la base de datos existe
```bash
ls -la scanagent.db
# Si no existe, ejecuta un escaneo primero desde CLI o web
```

---

## 📚 Documentación Completa

Para más detalles, consulta:
- [Documentación Completa](docs/WEB_IMPLEMENTATION.md)
- [README Principal](README.md)

---

## 💡 Tips

1. **Primera vez**: Usa el perfil "Quick" para probar rápidamente
2. **Targets seguros**: Prueba con `scanme.nmap.org` (dominio de prueba oficial)
3. **Historial**: Todos los escaneos se guardan automáticamente si marcas la opción
4. **API**: Puedes usar la API directamente con cURL o Python (ver docs)

---

## ⚠️ Importante

- **No escanees objetivos sin permiso**: Ilegal en la mayoría de países
- **Solo red local**: Por defecto el servidor escucha en 0.0.0.0 (todas las interfaces)
- **Sin autenticación**: No expongas a Internet sin implementar seguridad
- **Requiere permisos**: Algunos escaneos requieren sudo (el sistema lo indicará)

---

**¿Problemas?** Abre un issue en el repositorio o revisa los logs del servidor.
