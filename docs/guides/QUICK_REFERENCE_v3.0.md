# 📖 ScanAgent v3.0 - Quick Reference Guide

## 🚀 Inicio Rápido

### Iniciar el Servidor
```bash
cd /home/clase/scan-agent
./start-web.sh
```

### Abrir Dashboard
```
http://localhost:8000
```

### Ejecutar Test de Validación
```bash
./test_scan.sh
```

---

## 📊 Estructura de Risk Scoring

### Niveles de Severidad
- **CRITICAL** 🔴 - Score >= 100
- **HIGH** 🟠 - Score >= 50
- **MEDIUM** 🟡 - Score >= 20
- **LOW** 🟢 - Score < 20

### Puntuación por Hallazgo
- Puerto de alto riesgo (FTP, Telnet, SMB, etc.): **+30 puntos**
- Puerto de riesgo medio (SSH, HTTP): **+15 puntos**
- Versión vulnerable conocida: **+50 puntos**
- Puerto no común: **+5 puntos**
- Hallazgo de Nikto (critical/vulnerable): **+20 puntos**
- Hallazgo de Nikto (warning/security): **+10 puntos**

---

## 🔍 Puertos Clasificados

### Alto Riesgo (CRITICAL - +30 pts)
| Puerto | Servicio | Riesgo |
|--------|----------|--------|
| 21 | FTP | Protocolo sin cifrar |
| 23 | Telnet | Protocolo sin cifrar |
| 445 | SMB | Riesgo de ransomware |
| 3306 | MySQL | Base de datos expuesta |
| 5432 | PostgreSQL | Base de datos expuesta |
| 27017 | MongoDB | Base de datos expuesta |
| 3389 | RDP | Acceso remoto expuesto |
| 5900 | VNC | Acceso remoto sin cifrar |
| 6379 | Redis | Sin autenticación por defecto |
| 9200 | Elasticsearch | API expuesta |
| 11211 | Memcached | Sin autenticación |

### Riesgo Medio (MEDIUM - +15 pts)
| Puerto | Servicio | Riesgo |
|--------|----------|--------|
| 22 | SSH | Puerto de administración |
| 80 | HTTP | Sin cifrado |
| 8080 | HTTP-ALT | Sin cifrado |
| 8000 | HTTP-DEV | Servidor de desarrollo |

---

## 🐛 Versiones Vulnerables Conocidas

### OpenSSH
- **6.6** → CVE-2016-0777, CVE-2016-0778
- **7.2** → CVE-2016-10009, CVE-2016-10010

### Apache
- **2.4.7** → CVE-2017-15710, CVE-2017-15715
- **2.4.49** → CVE-2021-41773, CVE-2021-42013

---

## 📁 Ubicación de Archivos

### Reportes Generados
```
reports/scan_{id}.html   # Reporte profesional HTML
reports/scan_{id}.json   # Datos estructurados JSON
reports/scan_{id}.txt    # Reporte ASCII art
reports/scan_{id}.md     # Reporte Markdown
```

### Archivos Raw de Escaneo
```
outputs/scan_{id}/nmap_service_{target}.txt
outputs/scan_{id}/headers_{target}.txt
```

### Metadata
```
storage/metadata/{id}.json
```

---

## 🔧 Módulos Principales

### ScanResultParser
```python
from webapp.utils.report_parser import ScanResultParser

parser = ScanResultParser()
parsed_data = parser.parse_all_files(output_path, target)
```

**Métodos:**
- `parse_all_files(output_path, target)` - Parsea todos los archivos
- `parse_nmap_output(content)` - Extrae puertos, servicios, OS
- `parse_headers(content)` - Extrae headers HTTP
- `parse_nikto_output(content)` - Extrae hallazgos de Nikto
- `parse_directory_scan(content)` - Extrae directorios descubiertos

### VulnerabilityAnalyzer
```python
from webapp.utils.report_parser import VulnerabilityAnalyzer

analyzer = VulnerabilityAnalyzer(parsed_data)
analysis = analyzer.analyze()
```

**Métodos:**
- `analyze()` - Ejecuta análisis completo
- `_analyze_ports()` - Clasifica puertos por riesgo
- `_analyze_versions()` - Detecta versiones vulnerables
- `_analyze_nikto()` - Procesa hallazgos de Nikto
- `_calculate_risk_level()` - Calcula nivel de riesgo
- `_generate_summary()` - Genera resumen de hallazgos

---

## 🎨 Estructura de Datos

### Parsed Data (ScanResultParser)
```json
{
  "target": "scanme.nmap.org",
  "host_up": true,
  "latency_ms": 156,
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh",
      "version": "6.6.1",
      "product": "OpenSSH"
    }
  ],
  "os": "Linux 3.X|4.X",
  "http_headers": {},
  "directories": [],
  "nikto_findings": []
}
```

### Analysis Result (VulnerabilityAnalyzer)
```json
{
  "findings": [
    {
      "severity": "MEDIUM",
      "title": "Puerto 22 expuesto - SSH",
      "description": "Se detectó el servicio ssh...",
      "port": 22,
      "service": "ssh",
      "version": "6.6.1",
      "recommendations": ["..."],
      "cves": []
    }
  ],
  "risk_score": 30,
  "risk_level": "MEDIUM",
  "recommendations": ["..."]
}
```

### Final Scan Data
```json
{
  "scan_id": "3e84e079",
  "target": "scanme.nmap.org",
  "profile": "quick",
  "timestamp": "2025-11-13T10:59:18.618329",
  "host_info": {},
  "ports": [...],
  "vulnerabilities": [...],
  "risk_score": 30,
  "risk_level": "MEDIUM",
  "recommendations": [...],
  "summary": {
    "total_ports": 2,
    "open_ports": 2,
    "critical_findings": 0,
    "high_findings": 0,
    "medium_findings": 2,
    "low_findings": 0,
    "info_findings": 0
  }
}
```

---

## 🌐 API Endpoints

### Iniciar Escaneo
```bash
POST /api/scans/start
Content-Type: application/json

{
  "target": "scanme.nmap.org",
  "profile": "quick",
  "output_formats": ["json", "html", "txt", "md"]
}
```

### Ver Estado
```bash
GET /api/scans/status/{scan_id}
```

### Listar Escaneos
```bash
GET /api/scans/list?limit=20
```

### Ver Reporte
```bash
GET /api/scans/report/{scan_id}/{format}
```

---

## 🛠️ Comandos Útiles

### Reiniciar Servidor
```bash
pkill -f "uvicorn webapp.main:app"
cd /home/clase/scan-agent
./start-web.sh
```

### Ver Logs del Servidor
```bash
tail -f /home/clase/scan-agent/server.log
```

### Limpiar Caché de Python
```bash
cd /home/clase/scan-agent
rm -rf webapp/__pycache__ webapp/api/__pycache__ webapp/utils/__pycache__
```

### Listar Reportes Recientes
```bash
ls -lht reports/ | head -20
```

### Ver Escaneos Activos
```bash
ls -lh storage/metadata/
```

---

## 🎯 Perfiles de Escaneo

| Perfil | Tiempo | Herramientas | Uso |
|--------|--------|--------------|-----|
| **quick** | 5-10 min | nmap, curl | Reconocimiento rápido |
| **standard** | 15-20 min | nmap, nikto, curl | Escaneo estándar |
| **full** | 30-60 min | nmap, nikto, gobuster, curl | Análisis completo |
| **web-full** | 20-30 min | nikto, gobuster, curl | Pentesting web |

---

## 🐛 Troubleshooting

### Error: "Address already in use"
```bash
lsof -ti:8000 | xargs kill -9
./start-web.sh
```

### Error: "Reportes no se generan"
Verificar logs:
```bash
tail -100 server.log | grep "Error"
```

### Error: "Parser missing argument"
Asegurar que se pasa `target`:
```python
parsed_data = parser.parse_all_files(output_path, target)
```

### Error: "Severidad inconsistente"
Normalizar a uppercase:
```python
severity.upper() == "CRITICAL"
```

---

## 📚 Documentación Adicional

- **CHANGELOG v3.0:** `docs/changelog/CHANGELOG_v3.0.md`
- **Implementation Summary:** `IMPLEMENTATION_SUMMARY_v3.0.md`
- **Version History:** `VERSION.md`
- **README Principal:** `README.md`
- **Web Implementation:** `docs/WEB_IMPLEMENTATION.md`

---

## ✅ Checklist Pre-Deploy

- [ ] Servidor iniciado sin errores
- [ ] Dashboard accesible en http://localhost:8000
- [ ] Test de escaneo ejecutado con éxito
- [ ] 4 formatos de reporte generados
- [ ] Risk score calculado correctamente
- [ ] Hallazgos clasificados por severidad
- [ ] Recomendaciones presentes en reportes
- [ ] CSS renderiza correctamente en HTML
- [ ] Logs del servidor sin errores críticos

---

**Versión:** 3.0.0  
**Última Actualización:** 13 de Noviembre, 2025

**Happy Scanning! 🔍🛡️**
