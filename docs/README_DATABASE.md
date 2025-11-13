# 🗄️ Scan Agent - Guía de Base de Datos

## 📖 Índice

1. [Introducción](#introducción)
2. [Arquitectura de Base de Datos](#arquitectura-de-base-de-datos)
3. [Instalación y Configuración](#instalación-y-configuración)
4. [Uso Básico](#uso-básico)
5. [Consultas SQL](#consultas-sql)
6. [API Python](#api-python)
7. [Dashboard HTML](#dashboard-html)
8. [Integración con Docker](#integración-con-docker)
9. [Troubleshooting](#troubleshooting)
10. [Mejores Prácticas](#mejores-prácticas)

---

## 📌 Introducción

A partir de la **versión 2.1.0**, Scan Agent incluye un sistema de persistencia de datos basado en **SQLite** que permite:

✅ Almacenar histórico completo de escaneos  
✅ Organizar escaneos por IP objetivo  
✅ Comparar resultados entre diferentes fechas  
✅ Generar dashboard interactivo HTML  
✅ Consultas y análisis avanzados  

### Ventajas del Sistema de BD

- **Sin configuración**: SQLite no requiere servidor
- **Portátil**: Un solo archivo `.db` contiene todo
- **Rápido**: Ideal para <100K escaneos
- **Integrado**: Funciona automáticamente

---

## 🏗️ Arquitectura de Base de Datos

### Diagrama ER

```
┌─────────────┐       ┌─────────────────┐       ┌──────────────────┐
│   targets   │◄─────►│     scans       │◄─────►│ vulnerabilities  │
│             │       │                 │       │                  │
│ - ip        │       │ - target_ip     │       │ - scan_id        │
│ - hostname  │       │ - scan_date     │       │ - title          │
│ - total_scans       │ - profile       │       │ - severity       │
└─────────────┘       │ - status        │       │ - cvss_score     │
                      │ - total_vulns   │       └──────────────────┘
                      └─────────────────┘
                             │
                             ▼
                      ┌─────────────────┐
                      │  parsed_data    │
                      │                 │
                      │ - scan_id       │
                      │ - data_type     │
                      │ - json_data     │
                      └─────────────────┘
```

### Tablas Principales

#### 1. **scans**
Almacena metadata de cada escaneo realizado.

```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_ip TEXT NOT NULL,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    profile_used TEXT NOT NULL,
    duration_seconds INTEGER,
    status TEXT NOT NULL,  -- completed, failed, partial
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    max_cvss_score REAL DEFAULT 0.0,
    files_processed INTEGER DEFAULT 0,
    tools_used TEXT
);
```

#### 2. **vulnerabilities**
Almacena cada vulnerabilidad detectada.

```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,  -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score REAL,
    cvss_vector TEXT,
    category TEXT,
    owasp_mapping TEXT,
    cve_id TEXT,
    affected_component TEXT,
    evidence TEXT,
    recommendation TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
```

#### 3. **targets**
Mantiene registro de IPs únicas escaneadas.

```sql
CREATE TABLE targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    hostname TEXT,
    first_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_scans INTEGER DEFAULT 1,
    last_scan_id INTEGER,
    FOREIGN KEY (last_scan_id) REFERENCES scans(id)
);
```

#### 4. **parsed_data**
Almacena datos completos en formato JSON.

```sql
CREATE TABLE parsed_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    data_type TEXT NOT NULL,  -- 'parsed', 'analysis', 'raw'
    json_data TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
```

### Tablas Adicionales

- **services**: Puertos y servicios descubiertos
- **endpoints**: URLs y directorios encontrados
- **headers**: Headers HTTP analizados
- **scan_files**: Referencias a archivos generados

Ver [`schema.sql`](schema.sql) para el esquema completo.

---

## 🚀 Instalación y Configuración

### Inicialización Automática

La base de datos se crea automáticamente en la primera ejecución:

```bash
python3 agent.py --scan --target 192.168.1.100 --profile quick
```

Esto genera:
- `scan_agent.db` - Base de datos SQLite
- `reports/dashboard.html` - Dashboard interactivo

### Inicialización Manual

```bash
# Crear BD desde schema.sql
sqlite3 scan_agent.db < schema.sql

# Verificar tablas creadas
sqlite3 scan_agent.db ".tables"
```

### Ubicación de Archivos

```
scan-agent/
├── scan_agent.db          # Base de datos SQLite
├── schema.sql             # Esquema de BD
├── database.py            # Módulo de gestión
├── dashboard_generator.py # Generador de dashboard
└── reports/
    └── dashboard.html     # Dashboard generado
```

---

## 💻 Uso Básico

### Modo Automático (Recomendado)

El sistema de BD funciona automáticamente:

```bash
# 1. Ejecutar escaneo (guarda en BD automáticamente)
python3 agent.py --scan --target 192.168.1.100 --profile standard

# 2. El dashboard se actualiza automáticamente
firefox reports/dashboard.html
```

### Deshabilitar Base de Datos

Si solo quieres los informes sin BD:

```bash
python3 agent.py --scan --target 192.168.1.100 --profile quick --no-db
```

### Análisis de Datos Existentes

```bash
# Analizar outputs existentes y guardar en BD
python3 agent.py --outputs-dir ./outputs --format html

# Sin BD
python3 agent.py --outputs-dir ./outputs --format html --no-db
```

---

## 🔍 Consultas SQL

### Consultas Básicas

#### Listar todos los escaneos

```sql
SELECT id, target_ip, scan_date, profile_used, total_vulnerabilities, status
FROM scans
ORDER BY scan_date DESC
LIMIT 10;
```

#### Buscar escaneos de una IP específica

```sql
SELECT id, scan_date, profile_used, total_vulnerabilities, critical_count
FROM scans
WHERE target_ip = '192.168.1.100'
ORDER BY scan_date DESC;
```

#### Obtener vulnerabilidades críticas

```sql
SELECT s.target_ip, s.scan_date, v.title, v.cvss_score
FROM vulnerabilities v
JOIN scans s ON v.scan_id = s.id
WHERE v.severity = 'CRITICAL'
ORDER BY v.cvss_score DESC;
```

### Consultas Avanzadas

#### Top 10 IPs más vulnerables

```sql
SELECT 
    target_ip,
    SUM(total_vulnerabilities) as total_vulns,
    SUM(critical_count) as critical,
    COUNT(*) as scans_count
FROM scans
GROUP BY target_ip
ORDER BY total_vulns DESC
LIMIT 10;
```

#### Comparar escaneos de la misma IP

```sql
SELECT 
    s1.scan_date as fecha_anterior,
    s1.total_vulnerabilities as vulns_anterior,
    s2.scan_date as fecha_actual,
    s2.total_vulnerabilities as vulns_actual,
    (s2.total_vulnerabilities - s1.total_vulnerabilities) as diferencia
FROM scans s1
JOIN scans s2 ON s1.target_ip = s2.target_ip
WHERE s1.target_ip = '192.168.1.100'
  AND s1.scan_date < s2.scan_date
ORDER BY s2.scan_date DESC
LIMIT 5;
```

#### Estadísticas por perfil de escaneo

```sql
SELECT 
    profile_used,
    COUNT(*) as total_scans,
    AVG(total_vulnerabilities) as avg_vulns,
    AVG(duration_seconds) as avg_duration_sec
FROM scans
WHERE status = 'completed'
GROUP BY profile_used
ORDER BY total_scans DESC;
```

#### Vulnerabilidades más comunes

```sql
SELECT 
    title,
    COUNT(*) as occurrences,
    AVG(cvss_score) as avg_cvss,
    GROUP_CONCAT(DISTINCT category) as categories
FROM vulnerabilities
WHERE severity IN ('CRITICAL', 'HIGH')
GROUP BY title
ORDER BY occurrences DESC
LIMIT 20;
```

### Vistas Predefinidas

El esquema incluye vistas útiles:

```sql
-- Escaneos recientes
SELECT * FROM v_recent_scans LIMIT 10;

-- Vulnerabilidades críticas
SELECT * FROM v_critical_vulnerabilities LIMIT 20;

-- Resumen de objetivos
SELECT * FROM v_target_summary;
```

---

## 🐍 API Python

### Usar DatabaseManager

```python
from database import DatabaseManager

# Inicializar
db = DatabaseManager()

# Obtener todos los objetivos
targets = db.get_targets()
for target in targets:
    print(f"{target['ip_address']}: {target['total_scans']} escaneos")

# Obtener escaneos de una IP
scans = db.get_scans_by_ip('192.168.1.100')
for scan in scans:
    print(f"ID: {scan['id']}, Fecha: {scan['scan_date']}, Vulns: {scan['total_vulnerabilities']}")

# Obtener detalles completos de un escaneo
scan_detail = db.get_scan_detail(scan_id=1)
print(f"Vulnerabilidades: {len(scan_detail['vulnerabilities'])}")

# Estadísticas generales
stats = db.get_statistics()
print(f"Total escaneos: {stats['total_scans']}")
print(f"Total vulnerabilidades: {stats['total_vulnerabilities']}")

# Cerrar conexión
db.close()
```

### Context Manager

```python
from database import DatabaseManager

with DatabaseManager() as db:
    # Obtener escaneos recientes
    recent = db.get_recent_scans(limit=5)
    
    for scan in recent:
        print(f"{scan['target_ip']} - {scan['scan_date']}")
    
    # Vulnerabilidades críticas
    critical = db.get_critical_vulnerabilities(limit=10)
    for vuln in critical:
        print(f"{vuln['title']} (CVSS: {vuln['cvss_score']})")

# Conexión se cierra automáticamente
```

### Guardar Escaneo Manualmente

```python
from database import DatabaseManager
import json

db = DatabaseManager()

# Cargar datos
with open('parsed_data.json') as f:
    parsed_data = json.load(f)

with open('analysis.json') as f:
    analysis_data = json.load(f)

# Guardar en BD
scan_id = db.save_scan(
    target_ip='192.168.1.100',
    profile_used='standard',
    duration_seconds=900,
    status='completed',
    analysis_data=analysis_data,
    parsed_data=parsed_data,
    files_processed=5,
    tools_used=['nmap', 'nikto', 'gobuster']
)

print(f"Escaneo guardado con ID: {scan_id}")
```

---

## 🎨 Dashboard HTML

### Características del Dashboard

El dashboard generado (`reports/dashboard.html`) incluye:

- ✅ **Sidebar**: Lista de IPs escaneadas con contador de escaneos
- ✅ **Timeline**: Vista cronológica de escaneos por IP
- ✅ **Cards de escaneo**: Información detallada de cada escaneo
- ✅ **Códigos de color**: Por severidad (CRITICAL = rojo, HIGH = naranja, etc.)
- ✅ **Links**: Clic en escaneo → abre informe completo
- ✅ **Responsive**: Funciona en móviles y tablets
- ✅ **Sin dependencias**: HTML/CSS/JS vanilla

### Navegación

```
1. Abrir dashboard.html
2. Seleccionar IP en el sidebar (izquierda)
3. Ver timeline de escaneos (centro)
4. Clic en "Ver Informe Completo" → abre informe_tecnico_N.html
5. Clic en "← Volver al Dashboard" → regresa al dashboard
```

### Estructura del Dashboard

```html
┌──────────────────────────────────────────────┐
│  📊 Scan Agent Dashboard                     │
│  Objetivos: 5 | Escaneos: 23 | Vulns: 145   │
├─────────────┬────────────────────────────────┤
│ 🎯 Objetivos│ 📍 Historial de 192.168.1.100 │
│             │                                │
│ 192.168.1.100│ ┌──────────────────────────┐ │
│   [CRITICAL]│ │ 📅 12/11/2025 10:30      │ │
│   10 scans  │ │ Perfil: standard         │ │
│             │ │ Vulnerabilidades: 15     │ │
│ 10.0.0.50   │ │ [Ver Informe Completo →] │ │
│   [HIGH]    │ └──────────────────────────┘ │
│   5 scans   │                                │
│             │ ┌──────────────────────────┐ │
│             │ │ 📅 11/11/2025 15:20      │ │
│             │ │ ...                      │ │
└─────────────┴────────────────────────────────┘
```

---

## 🐳 Integración con Docker

### Persistencia de Datos

Montar volumen para preservar la BD:

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  -v $(pwd)/reports:/scan-agent/reports \
  -v $(pwd)/scan_agent.db:/scan-agent/scan_agent.db \
  scan-agent:2.1.0 \
  --scan --target 192.168.1.100 --profile standard
```

### Docker Compose

```yaml
version: '3.8'

services:
  scan-agent:
    image: scan-agent:2.1.0
    volumes:
      - ./outputs:/scan-agent/outputs
      - ./reports:/scan-agent/reports
      - ./scan_agent.db:/scan-agent/scan_agent.db
    command: --scan --target 192.168.1.100 --profile quick
```

### Deshabilitar BD en Docker

```bash
docker run --rm \
  -v $(pwd)/outputs:/scan-agent/outputs \
  scan-agent:2.1.0 \
  --scan --target 192.168.1.100 --profile quick --no-db
```

---

## 🔧 Troubleshooting

### Error: "database is locked"

**Causa**: Múltiples procesos accediendo a SQLite simultáneamente.

**Solución**:
```bash
# Cerrar otros procesos usando la BD
lsof scan_agent.db

# O usar timeout en Python
db = DatabaseManager()
db.conn.execute("PRAGMA busy_timeout = 5000")  # 5 segundos
```

### Error: "table already exists"

**Causa**: Intentando ejecutar `schema.sql` sobre BD existente.

**Solución**:
```bash
# Respaldar BD actual
mv scan_agent.db scan_agent_backup.db

# Crear nueva BD
python3 agent.py --scan --target 127.0.0.1 --profile quick
```

### BD corrupta

```bash
# Verificar integridad
sqlite3 scan_agent.db "PRAGMA integrity_check;"

# Si está corrupta, exportar datos
sqlite3 scan_agent.db ".dump" > backup.sql

# Crear nueva BD e importar
rm scan_agent.db
sqlite3 scan_agent.db < backup.sql
```

### Dashboard no muestra datos

**Verificar**:
```python
from database import DatabaseManager

db = DatabaseManager()
stats = db.get_statistics()
print(stats)  # Debe mostrar datos

targets = db.get_targets()
print(f"Targets: {len(targets)}")
```

### Archivos HTML con nombres incorrectos

**Causa**: `scan_id` no se pasó a `generate_html_report()`.

**Solución**: Verificar que `agent.py` pasa `scan_id`:
```python
self.report_generator.generate_html_report(output_file, scan_id=scan_id)
```

---

## ✅ Mejores Prácticas

### 1. Backups Regulares

```bash
# Backup diario
cp scan_agent.db backups/scan_agent_$(date +%Y%m%d).db

# Backup comprimido
sqlite3 scan_agent.db ".dump" | gzip > backup_$(date +%Y%m%d).sql.gz
```

### 2. Limpieza de Datos Antiguos

```sql
-- Eliminar escaneos > 90 días
DELETE FROM scans WHERE scan_date < datetime('now', '-90 days');

-- Vacuum para recuperar espacio
VACUUM;
```

### 3. Índices para Performance

Ya incluidos en `schema.sql`:
```sql
CREATE INDEX idx_scans_target_ip ON scans(target_ip);
CREATE INDEX idx_scans_scan_date ON scans(scan_date DESC);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
```

### 4. Monitoreo de Tamaño

```bash
# Ver tamaño de BD
ls -lh scan_agent.db

# Ver estadísticas de tablas
sqlite3 scan_agent.db "SELECT name, COUNT(*) FROM sqlite_master WHERE type='table' GROUP BY name;"
```

### 5. Exportar Datos

```bash
# Exportar a CSV
sqlite3 scan_agent.db <<EOF
.headers on
.mode csv
.output scans_export.csv
SELECT * FROM scans;
.quit
EOF

# Exportar a JSON (via Python)
python3 -c "
from database import DatabaseManager
import json

db = DatabaseManager()
scans = db.get_all_scans(limit=1000)
with open('scans.json', 'w') as f:
    json.dump(scans, f, indent=2)
print('Exportado a scans.json')
"
```

---

## 📊 Ejemplos de Análisis

### Análisis de Tendencias

```sql
-- Evolución de vulnerabilidades por mes
SELECT 
    strftime('%Y-%m', scan_date) as mes,
    COUNT(*) as escaneos,
    AVG(total_vulnerabilities) as promedio_vulns,
    SUM(critical_count) as total_criticas
FROM scans
WHERE status = 'completed'
GROUP BY mes
ORDER BY mes DESC;
```

### Comparación de Perfiles

```sql
-- Eficacia de perfiles de escaneo
SELECT 
    profile_used,
    COUNT(*) as usos,
    AVG(total_vulnerabilities) as avg_vulns_detectadas,
    AVG(duration_seconds) as avg_duracion_seg,
    ROUND(AVG(total_vulnerabilities) * 1.0 / AVG(duration_seconds), 4) as vulns_por_segundo
FROM scans
WHERE status = 'completed'
GROUP BY profile_used
ORDER BY vulns_por_segundo DESC;
```

### Matriz de Riesgo

```python
from database import DatabaseManager
import json

db = DatabaseManager()
targets = db.get_targets()

risk_matrix = []
for target in targets:
    scans = db.get_scans_by_ip(target['ip_address'])
    if not scans:
        continue
    
    latest = scans[0]
    risk_score = (
        latest['critical_count'] * 10 +
        latest['high_count'] * 5 +
        latest['medium_count'] * 2 +
        latest['low_count'] * 1
    )
    
    risk_matrix.append({
        'ip': target['ip_address'],
        'risk_score': risk_score,
        'critical': latest['critical_count'],
        'high': latest['high_count'],
        'last_scan': latest['scan_date']
    })

# Ordenar por riesgo
risk_matrix.sort(key=lambda x: x['risk_score'], reverse=True)

print("Top 10 Objetivos de Mayor Riesgo:")
for i, item in enumerate(risk_matrix[:10], 1):
    print(f"{i}. {item['ip']}: Score {item['risk_score']} (C:{item['critical']}, H:{item['high']})")
```

---

## 📚 Referencias

- [SQLite Documentation](https://www.sqlite.org/docs.html)
- [Schema SQL](schema.sql)
- [Database Module](database.py)
- [Dashboard Generator](dashboard_generator.py)
- [README Principal](README.md)

---

**Versión**: 2.1.0  
**Actualizado**: 12 de Noviembre de 2025  
**Autor**: Scan Agent Team
