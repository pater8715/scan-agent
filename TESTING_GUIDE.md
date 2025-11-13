# 🧪 Guía de Pruebas - Scan Agent Web

## Objetivo

Verificar que la interfaz web funciona correctamente antes de usar en producción.

---

## ✅ Checklist de Pruebas

### 1. Instalación

- [ ] Dependencias web instaladas correctamente
  ```bash
  pip3 install -r webapp/requirements.txt
  ```
  
- [ ] No hay errores de instalación
- [ ] Todas las librerías se instalaron (fastapi, uvicorn, jinja2, pydantic)

### 2. Inicio del Servidor

- [ ] El script de inicio funciona
  ```bash
  ./start-web.sh
  ```
  
- [ ] El servidor inicia sin errores
- [ ] Muestra el mensaje de bienvenida con URLs
- [ ] No hay warnings críticos en la consola

### 3. Acceso a la Interfaz

- [ ] La página principal carga en http://localhost:8000
- [ ] Se muestran los 4 perfiles de escaneo (Quick, Standard, Full, Web-Full)
- [ ] El diseño se ve correctamente (sin CSS roto)
- [ ] Los botones de navegación funcionan

### 4. Documentación de la API

- [ ] Swagger UI accesible en http://localhost:8000/api/docs
- [ ] Muestra todos los endpoints (scans, profiles, reports)
- [ ] Se puede expandir y probar endpoints
- [ ] ReDoc accesible en http://localhost:8000/api/redoc

### 5. Perfiles de Escaneo

- [ ] Al hacer clic en un perfil, se marca con ✓
- [ ] Aparece el formulario de configuración
- [ ] La información de cada perfil es correcta (tiempo, herramientas)
- [ ] Solo se puede seleccionar un perfil a la vez

### 6. Formulario de Configuración

- [ ] Campo "Objetivo" acepta IPs válidas (ej: 192.168.1.1)
- [ ] Campo "Objetivo" acepta dominios válidos (ej: ejemplo.com)
- [ ] Validación en tiempo real funciona (mensaje de error para inputs inválidos)
- [ ] Se pueden seleccionar múltiples formatos de reporte
- [ ] Checkbox "Guardar en BD" funciona
- [ ] Botón "Restablecer" limpia el formulario

### 7. Ejecución de Escaneo (TEST)

**⚠️ IMPORTANTE**: Para pruebas, usa objetivos seguros como:
- `scanme.nmap.org` (servidor oficial de pruebas de Nmap)
- `127.0.0.1` (tu propia máquina)

Pasos:
- [ ] Selecciona perfil "Quick"
- [ ] Ingresa objetivo: `scanme.nmap.org`
- [ ] Selecciona formato: JSON y HTML
- [ ] Marca "Guardar en BD"
- [ ] Clic en "Iniciar Escaneo"

**Verificar:**
- [ ] El formulario se oculta
- [ ] Aparece la barra de progreso
- [ ] El scan_id se muestra correctamente
- [ ] El objetivo y perfil se muestran
- [ ] La barra de progreso se actualiza (0% → 10% → ... → 100%)

### 8. Monitoreo de Progreso

- [ ] El porcentaje aumenta gradualmente
- [ ] El mensaje de estado cambia ("Iniciando...", "Escaneando...", etc.)
- [ ] La barra tiene animación suave
- [ ] No hay errores en la consola del navegador (F12)

### 9. Resultados del Escaneo

- [ ] Al completar, se oculta la barra de progreso
- [ ] Se muestra la sección de resultados
- [ ] Aparecen las estadísticas (vulnerabilidades encontradas)
- [ ] Los botones "Ver Reporte" y "Nuevo Escaneo" funcionan

### 10. Historial de Escaneos

- [ ] Clic en "📋 Historial" en el menú superior
- [ ] Se muestra la tabla con escaneos
- [ ] El escaneo recién ejecutado aparece en la lista
- [ ] La búsqueda filtra correctamente
- [ ] El filtro por estado funciona
- [ ] Botón "Actualizar" recarga la lista

### 11. Descarga de Reportes

- [ ] En el historial, clic en "Ver Reporte" de un escaneo
- [ ] Se descarga el archivo HTML
- [ ] El archivo se abre correctamente en el navegador
- [ ] Contiene los datos del escaneo
- [ ] También se pueden descargar otros formatos (JSON, TXT)

### 12. Responsive Design

- [ ] La interfaz se adapta al cambiar tamaño de ventana
- [ ] En móvil (< 768px), el menú se reorganiza
- [ ] Los botones son clickeables en pantallas pequeñas
- [ ] No hay scroll horizontal inesperado

### 13. Manejo de Errores

**Prueba 1: Objetivo inválido**
- [ ] Ingresa "objetivo-invalido!!!"
- [ ] Verifica que muestra mensaje de error
- [ ] No permite enviar el formulario

**Prueba 2: Sin formato seleccionado**
- [ ] Deselecciona todos los formatos
- [ ] Intenta iniciar escaneo
- [ ] Verifica que muestra error toast

**Prueba 3: Escaneo de objetivo inexistente**
- [ ] Escanea IP inexistente: `192.0.2.1` (rango reservado)
- [ ] Verifica que el escaneo falla gracefully
- [ ] El estado se marca como "failed"

### 14. Notificaciones Toast

- [ ] Al iniciar escaneo: "Escaneo iniciado correctamente" (verde)
- [ ] Al completar: "Escaneo completado exitosamente" (verde)
- [ ] Al fallar: Error con mensaje descriptivo (rojo)
- [ ] Los toasts desaparecen automáticamente después de 5 segundos

### 15. API Health Check

- [ ] http://localhost:8000/health devuelve JSON
- [ ] Contiene `{"status": "healthy", "version": "1.0.0"}`

---

## 🐛 Problemas Comunes y Soluciones

### Error: No se pueden instalar las dependencias

**Síntoma**: `pip3 install` falla

**Solución**:
```bash
# Actualizar pip
python3 -m pip install --upgrade pip

# Intentar de nuevo
pip3 install -r webapp/requirements.txt
```

### Error: Puerto 8000 en uso

**Síntoma**: "Address already in use"

**Solución**:
```bash
# Opción 1: Usar otro puerto
cd webapp
uvicorn main:app --port 9000

# Opción 2: Matar proceso en puerto 8000
lsof -ti:8000 | xargs kill -9
```

### Error: ModuleNotFoundError

**Síntoma**: "No module named 'scanagent'"

**Solución**:
```bash
# Verificar que estás en el directorio correcto
cd /home/clase/scan-agent

# El servidor debe ejecutarse desde webapp/
cd webapp
python3 main.py
```

### Error: Herramientas no encontradas

**Síntoma**: El escaneo falla con "nmap not found"

**Solución**:
```bash
# Instalar herramientas necesarias
sudo apt install -y nmap nikto gobuster curl
```

### No se ven los escaneos en el historial

**Síntoma**: La tabla está vacía

**Solución**:
- Verifica que marcaste "Guardar en BD" al ejecutar el escaneo
- Ejecuta al menos un escaneo completo
- Recarga la página

---

## 📊 Resultado Esperado

Al finalizar todas las pruebas, deberías tener:

✅ **Servidor funcionando** en http://localhost:8000  
✅ **Al menos 1 escaneo completado** en el historial  
✅ **Reportes descargables** en formato HTML y JSON  
✅ **Interfaz responsive** que funciona en diferentes tamaños  
✅ **Sin errores** en la consola del navegador  

---

## 🎯 Prueba de Integración Completa

### Escenario: Nuevo usuario ejecuta su primer escaneo

1. **Setup** (2 minutos)
   ```bash
   cd /home/clase/scan-agent
   pip3 install -r webapp/requirements.txt
   ./start-web.sh
   ```

2. **Ejecutar escaneo** (10 minutos)
   - Abrir http://localhost:8000
   - Seleccionar perfil "Quick"
   - Ingresar `scanme.nmap.org`
   - Marcar JSON y HTML
   - Iniciar escaneo
   - Esperar a que complete (~5-10 min)

3. **Revisar resultados** (2 minutos)
   - Ver resumen de vulnerabilidades
   - Descargar reporte HTML
   - Abrir en navegador
   - Verificar contenido

4. **Verificar historial** (1 minuto)
   - Ir a "Historial"
   - Buscar por `scanme.nmap.org`
   - Ver que aparece el escaneo
   - Estado: "Completado"

**Tiempo total**: ~15 minutos

---

## ✅ Certificación de Calidad

Si todas las pruebas pasan, la aplicación está lista para:

- ✅ Uso en entorno de desarrollo
- ✅ Demos y presentaciones
- ✅ Pruebas de usuario
- ⚠️ **NO** para producción sin implementar seguridad (auth, HTTPS, rate limiting)

---

## 📝 Reporte de Pruebas

Al terminar, documenta:

1. **Fecha de prueba**: __________
2. **Versión testeada**: Web UI v1.0
3. **Sistema operativo**: Linux / Windows / macOS
4. **Navegador**: Chrome / Firefox / Safari / Edge
5. **Pruebas pasadas**: ___ / 15
6. **Problemas encontrados**: 
   - 
   - 
7. **Notas adicionales**:
   - 

---

## 🚀 Siguiente Paso

Una vez que todas las pruebas pasen, puedes:

1. Usar la aplicación para escaneos reales
2. Implementar mejoras de la Fase 2 (WebSocket, dashboard)
3. Configurar para producción con autenticación
4. Compartir con otros usuarios

---

**Última actualización**: 13 de Noviembre, 2025  
**Versión**: 1.0
