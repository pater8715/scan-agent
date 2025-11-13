# 🔧 Solución: Error de Entorno Externamente Gestionado

## 🚨 Problema

Al intentar instalar dependencias con `pip3 install`, recibes el error:

```
error: externally-managed-environment
× This environment is externally managed
```

## ✅ Solución Implementada

Este proyecto ahora utiliza **entornos virtuales** automáticamente para evitar conflictos con el sistema.

---

## 🚀 Inicio Rápido (3 pasos)

### 1️⃣ Setup Inicial (Solo primera vez)

```bash
# Opción A: Script automático (Recomendado)
chmod +x setup-venv.sh
./setup-venv.sh
```

**O si prefieres hacerlo manualmente:**

```bash
# Opción B: Manual
sudo apt update
sudo apt install python3-venv python3-full
python3 -m venv venv
source venv/bin/activate
pip install -r webapp/requirements.txt
deactivate
```

### 2️⃣ Iniciar Servidor

```bash
chmod +x start-web.sh
./start-web.sh
```

El script `start-web.sh` automáticamente:
- ✅ Crea el entorno virtual (si no existe)
- ✅ Lo activa
- ✅ Instala/actualiza dependencias
- ✅ Inicia el servidor

### 3️⃣ Acceder a la Aplicación

Abre tu navegador en: **http://localhost:8000**

---

## 🛑 Detener el Servidor

```bash
# Opción 1: En la terminal donde corre
Ctrl + C

# Opción 2: Script automático
chmod +x stop-web.sh
./stop-web.sh
```

---

## 📚 Explicación Técnica

### ¿Por qué este error?

Python 3.12+ en Ubuntu 24.04 implementa **PEP 668**, que previene la instalación de paquetes globales para proteger el sistema operativo de conflictos de dependencias.

### ¿Qué es un entorno virtual?

Un **entorno virtual** (venv) es un directorio aislado que contiene:
- Una copia de Python
- Bibliotecas específicas del proyecto
- Sin afectar el sistema global

### Ventajas de usar venv

✅ **Aislamiento**: Cada proyecto tiene sus propias dependencias  
✅ **Seguridad**: No rompe paquetes del sistema  
✅ **Portabilidad**: Fácil de recrear en otra máquina  
✅ **Versiones**: Puedes tener diferentes versiones de las mismas librerías  

---

## 🔧 Comandos Útiles

### Ver qué hay instalado en el venv
```bash
source venv/bin/activate
pip list
deactivate
```

### Actualizar una dependencia específica
```bash
source venv/bin/activate
pip install --upgrade fastapi
deactivate
```

### Regenerar el entorno virtual
```bash
rm -rf venv/
./setup-venv.sh
```

### Exportar dependencias actuales
```bash
source venv/bin/activate
pip freeze > webapp/requirements.txt
deactivate
```

---

## 🗂️ Estructura de Archivos

```
scan-agent/
├── venv/                      # Entorno virtual (auto-generado)
│   ├── bin/                  # Ejecutables (python, pip, uvicorn)
│   ├── lib/                  # Librerías instaladas
│   └── pyvenv.cfg           # Configuración
│
├── webapp/                   # Código de la aplicación
│   ├── requirements.txt     # Dependencias del proyecto
│   └── ...
│
├── setup-venv.sh            # Setup inicial del venv
├── start-web.sh             # Inicia con venv automático
└── stop-web.sh              # Detiene el servidor
```

---

## ❓ Troubleshooting

### Problema: "python3-venv no está instalado"

**Solución:**
```bash
sudo apt update
sudo apt install python3-venv python3-full
```

### Problema: "Permission denied" al ejecutar scripts

**Solución:**
```bash
chmod +x setup-venv.sh start-web.sh stop-web.sh
```

### Problema: El venv no se activa

**Solución:**
```bash
# Asegúrate de estar en el directorio correcto
cd /home/clase/scan-agent

# Activa manualmente
source venv/bin/activate

# Verifica que está activo (debe aparecer (venv) en el prompt)
```

### Problema: Dependencias no se instalan

**Solución:**
```bash
# Elimina y recrea el venv
rm -rf venv/
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r webapp/requirements.txt
```

### Problema: "No module named 'fastapi'"

**Solución:**
```bash
# Asegúrate de que el venv está activo
source venv/bin/activate

# Reinstala dependencias
pip install -r webapp/requirements.txt

# Verifica
python3 -c "import fastapi; print(fastapi.__version__)"
```

---

## 🎓 Buenas Prácticas

### ✅ DO (Hacer)
- Activar el venv antes de instalar paquetes
- Usar `./start-web.sh` para iniciar el servidor
- Mantener `requirements.txt` actualizado
- Ignorar `venv/` en `.gitignore`

### ❌ DON'T (No hacer)
- Instalar paquetes con `sudo pip`
- Usar `--break-system-packages`
- Subir `venv/` a Git
- Mezclar entornos globales y virtuales

---

## 📖 Referencias

- [PEP 668 - Marking Python base environments as "externally managed"](https://peps.python.org/pep-0668/)
- [Python venv Documentation](https://docs.python.org/3/library/venv.html)
- [FastAPI Deployment](https://fastapi.tiangolo.com/deployment/)

---

## ✅ Checklist de Verificación

Antes de reportar un problema, verifica:

- [ ] Python 3.8+ instalado: `python3 --version`
- [ ] python3-venv instalado: `dpkg -l | grep python3-venv`
- [ ] Scripts son ejecutables: `ls -la *.sh`
- [ ] Estás en el directorio correcto: `pwd` → `/home/clase/scan-agent`
- [ ] El venv existe: `ls -la venv/`
- [ ] Las dependencias están instaladas: `source venv/bin/activate && pip list`

---

**¡Listo! Ahora puedes usar Scan Agent Web sin problemas de permisos.** 🎉
