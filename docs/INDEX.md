╔══════════════════════════════════════════════════════════════════════════════╗
║                         SCAN AGENT v2.0.0 - ÍNDICE                           ║
║              Agente de Análisis de Vulnerabilidades Web                      ║
║                      🆕 AHORA CON CAPACIDAD DE ESCANEO                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

📂 UBICACIÓN: /home/clase/scan-agent/

═══════════════════════════════════════════════════════════════════════════════
🆕 NOVEDADES v2.0
═══════════════════════════════════════════════════════════════════════════════

✨ NUEVAS FUNCIONALIDADES:
   • Ejecución automática de escaneos (nmap, nikto, gobuster, curl)
   • 8 perfiles de escaneo predefinidos (quick, standard, full, web, etc.)
   • Workflow completo: Escaneo → Parsing → Análisis → Informes
   • Verificación automática de herramientas instaladas
   • Gestión inteligente de timeouts y procesos

═══════════════════════════════════════════════════════════════════════════════
🚀 INICIO RÁPIDO
═══════════════════════════════════════════════════════════════════════════════

MODO ESCANEO (v2.0 - NUEVO):
1. Listar perfiles disponibles:
   $ python3 agent.py --list-profiles

2. Ejecutar escaneo rápido:
   $ python3 agent.py --scan --target 192.168.1.100 --profile quick

3. Analizar resultados:
   $ python3 agent.py --outputs-dir ./outputs --format html

4. Ver informe:
   $ firefox informe_tecnico.html

MODO ANÁLISIS (v1.0 - archivos existentes):
1. Navegar al proyecto:
   $ cd /home/clase/scan-agent

2. Ejecutar el agente:
   $ python3 agent.py

3. Ver informe HTML:
   $ firefox informe_tecnico.html

═══════════════════════════════════════════════════════════════════════════════
📚 ARCHIVOS PRINCIPALES
═══════════════════════════════════════════════════════════════════════════════

🎯 EJECUCIÓN:
   agent.py                    - ARCHIVO PRINCIPAL - Ejecutar este (v2.0)

📝 MÓDULOS CORE:
   parser.py                   - Parsing de archivos de herramientas
   interpreter.py              - Análisis y clasificación de vulnerabilidades
   report_generator.py         - Generación de informes en múltiples formatos
   scanner.py                  - 🆕 Ejecución de escaneos (NUEVO v2.0)

📖 DOCUMENTACIÓN:
   README.md                   - 📘 LEER PRIMERO - Guía completa actualizada v2.0
   GUIA_ESCANEO.md            - 🆕 Guía detallada de perfiles de escaneo
   RESUMEN.md                  - Resumen técnico del proyecto
   INDEX.txt                   - Este archivo - Índice de navegación

💡 EJEMPLOS:
   EJEMPLOS.sh                 - Script interactivo con ejemplos v1.0
   EJEMPLOS_v2.sh             - 🆕 Script con ejemplos de escaneo v2.0
   ejemplo_parsed_data.json    - Ejemplo de JSON parseado
   ejemplo_analysis.json       - Ejemplo de análisis completo

📦 CONFIGURACIÓN:
   requirements.txt            - Dependencias del proyecto

═══════════════════════════════════════════════════════════════════════════════
📂 DIRECTORIOS
═══════════════════════════════════════════════════════════════════════════════

outputs/                       - Archivos .txt de escaneo (INPUT/OUTPUT)
                                 • Creado automáticamente por --scan
                                 • O coloca archivos manualmente para análisis
                                 
                                 Archivos generados por escaneo:
                                 • nmap_service_<target>.txt
                                 • nmap_nse_<target>.txt
                                 • nikto_<target>.txt
                                 • headers_<target>.txt
                                 • curl_verbose_<target>.txt
                                 • gobuster_<target>.txt

═══════════════════════════════════════════════════════════════════════════════
📄 ARCHIVOS GENERADOS (después de ejecutar)
═══════════════════════════════════════════════════════════════════════════════

INTERMEDIOS:
   parsed_data.json            - Datos parseados en formato JSON
   analysis.json               - Análisis completo en formato JSON

INFORMES FINALES:
   informe_tecnico.txt         - Informe en texto plano
   informe_tecnico.json        - Informe estructurado en JSON
   informe_tecnico.html        - ⭐ Informe web interactivo (RECOMENDADO)
   informe_tecnico.md          - Informe en formato Markdown

═══════════════════════════════════════════════════════════════════════════════
📋 COMANDOS COMUNES
═══════════════════════════════════════════════════════════════════════════════

🆕 COMANDOS v2.0 - ESCANEO:

# Listar perfiles disponibles
python3 agent.py --list-profiles

# Ver detalles de un perfil
python3 agent.py --show-profile web

# Escaneo rápido (5 min)
python3 agent.py --scan --target 192.168.1.100 --profile quick

# Escaneo estándar (15 min)
python3 agent.py --scan --target example.com --profile standard

# Escaneo completo (30-60 min)
python3 agent.py --scan --target 10.0.0.50 --profile full --verbose

# Escaneo web (20-30 min)
python3 agent.py --scan --target webapp.com --profile web

# Escaneo sigiloso (requiere sudo)
sudo python3 agent.py --scan --target IP --profile stealth

# Escaneo de red (requiere sudo)
sudo python3 agent.py --scan --target IP --profile network

# Ejecutar script de ejemplos v2.0
./EJEMPLOS_v2.sh

📊 COMANDOS v1.0 - ANÁLISIS:

# Ver ayuda completa
python3 agent.py --help

# Ejecución básica (genera todos los formatos)
python3 agent.py

# Solo generar HTML (más rápido)
python3 agent.py --format html

# Modo verbose (ver detalles del proceso)
python3 agent.py --verbose

# Especificar IP manualmente
python3 agent.py --target-ip 192.168.1.100

# Especificar directorio de archivos
python3 agent.py --outputs-dir /ruta/a/escaneos

# Ver versión
python3 agent.py --version

# Ejecutar script de ejemplos v1.0
./EJEMPLOS.sh

═══════════════════════════════════════════════════════════════════════════════
🎯 PERFILES DE ESCANEO v2.0
═══════════════════════════════════════════════════════════════════════════════

quick       - ⚡ ~5 min     Reconocimiento rápido
standard    - ⚙️  ~15 min    Análisis equilibrado (RECOMENDADO)
full        - 🔥 30-60 min  Pentesting exhaustivo
web         - 🌐 20-30 min  Aplicaciones web
stealth     - 🥷 30-45 min  Evasión IDS/IPS (requiere sudo)
network     - 🔌 ~40 min    Infraestructura de red (requiere sudo)
compliance  - ✅ ~10 min    Verificación de configuraciones seguras
api         - 🔗 ~15 min    Testing de APIs REST/SOAP

Ver detalles: GUIA_ESCANEO.md

═══════════════════════════════════════════════════════════════════════════════
🔍 ¿QUÉ LEER SEGÚN TU NECESIDAD?
═══════════════════════════════════════════════════════════════════════════════

📌 QUIERO EJECUTAR ESCANEOS (v2.0):
   → Leer: GUIA_ESCANEO.md
   → Ejecutar: python3 agent.py --list-profiles
   → Ejemplo: ./EJEMPLOS_v2.sh

📌 QUIERO EMPEZAR A USAR EL AGENTE (análisis):
   → Leer: README.md (sección "Uso Básico")
   → Ejecutar: ./EJEMPLOS.sh

📌 NECESITO ENTENDER CÓMO FUNCIONA:
   → Leer: README.md (sección "Arquitectura")
   → Leer: RESUMEN.md (sección "Módulos Desarrollados")

📌 QUIERO VER EJEMPLOS DE SALIDA:
   → Abrir: ejemplo_parsed_data.json
   → Abrir: ejemplo_analysis.json
   → Ejecutar: python3 agent.py
   → Ver: informe_tecnico.html

📌 NECESITO RESOLVER UN PROBLEMA:
   → Leer: README.md (sección "Solución de Problemas")
   → Ejecutar con: python3 agent.py --verbose

📌 QUIERO INTEGRAR CON OTRAS HERRAMIENTAS:
   → Leer: README.md (sección "Formatos de Salida")
   → Usar formato: python3 agent.py --format json

📌 NECESITO REFERENCIA RÁPIDA:
   → Este archivo: INDEX.txt
   → Ayuda: python3 agent.py --help

═══════════════════════════════════════════════════════════════════════════════
🎯 FLUJO DE TRABAJO TÍPICO
═══════════════════════════════════════════════════════════════════════════════

PASO 1: Realizar escaneos con herramientas
   $ nmap -sV -p- TARGET -oN outputs/nmap_service_TARGET.txt
   $ nikto -h http://TARGET -o outputs/nikto_TARGET.txt
   $ gobuster dir -u http://TARGET -w wordlist.txt -o outputs/gobuster_TARGET.txt
   (etc.)

PASO 2: Ejecutar el agente
   $ cd /home/clase/scan-agent
   $ python3 agent.py

PASO 3: Revisar informes
   $ firefox informe_tecnico.html
   # o
   $ cat informe_tecnico.txt

PASO 4: Implementar recomendaciones
   (Ver sección "Recomendaciones" del informe)

═══════════════════════════════════════════════════════════════════════════════
📊 ESTRUCTURA DEL CÓDIGO
═══════════════════════════════════════════════════════════════════════════════

agent.py (370 líneas)
├── ScanAgent                  - Clase principal
│   ├── run()                  - Flujo completo de ejecución
│   ├── _execute_parsing()     - Fase 1: Parsing
│   ├── _execute_interpretation() - Fase 2: Análisis
│   └── _execute_report_generation() - Fase 3: Informes

parser.py (504 líneas)
├── ScanParser                 - Parser de herramientas
│   ├── parse_all()            - Orquestador de parsing
│   ├── _parse_nmap_service()  - Puertos y servicios
│   ├── _parse_nmap_nse()      - Scripts NSE
│   ├── _parse_nikto()         - Vulnerabilidades Nikto
│   ├── _parse_gobuster()      - Rutas descubiertas
│   ├── _parse_headers()       - Headers HTTP
│   └── _parse_curl_verbose()  - Info detallada curl

interpreter.py (604 líneas)
├── VulnerabilityInterpreter   - Análisis de vulnerabilidades
│   ├── analyze()              - Análisis completo
│   ├── _analyze_attack_surface() - Superficie de ataque
│   ├── _detect_technologies() - Detección de stack
│   ├── _process_vulnerabilities() - Clasificación
│   ├── _classify_risks()      - Distribución de riesgos
│   └── _generate_recommendations() - Recomendaciones

report_generator.py (900 líneas)
├── ReportGenerator            - Generación de informes
│   ├── generate_all_reports() - Todos los formatos
│   ├── generate_txt_report()  - Texto plano
│   ├── generate_json_report() - JSON estructurado
│   ├── generate_html_report() - HTML interactivo
│   └── generate_markdown_report() - Markdown

═══════════════════════════════════════════════════════════════════════════════
🛠️ CARACTERÍSTICAS TÉCNICAS
═══════════════════════════════════════════════════════════════════════════════

✅ Lenguaje: Python 3.12+
✅ Dependencias: Solo bibliotecas estándar (json, re, pathlib, argparse)
✅ Líneas de código: 2,378
✅ Documentación: 1,393 líneas
✅ Herramientas soportadas: 6 (Nmap, NSE, Nikto, Gobuster, Curl, Headers)
✅ Formatos de salida: 4 (TXT, JSON, HTML, MD)
✅ Clasificación: CVSS 3.1 y OWASP Top 10 2021
✅ Arquitectura: Modular y extensible

═══════════════════════════════════════════════════════════════════════════════
📞 AYUDA Y SOPORTE
═══════════════════════════════════════════════════════════════════════════════

❓ ¿Tienes preguntas?
   → Revisa: README.md (sección "Solución de Problemas")
   → Ejecuta: python3 agent.py --help

🐛 ¿Encontraste un error?
   → Ejecuta con --verbose para ver detalles
   → Revisa los archivos intermedios (parsed_data.json, analysis.json)

💡 ¿Quieres contribuir?
   → Revisa: README.md (sección "Contribuir")
   → Revisa: RESUMEN.md (sección "Próximas Mejoras Sugeridas")

═══════════════════════════════════════════════════════════════════════════════
✅ CHECKLIST DE USO
═══════════════════════════════════════════════════════════════════════════════

Antes de ejecutar el agente, asegúrate de:

[ ] Tener Python 3.12 o superior instalado
[ ] Estar en el directorio /home/clase/scan-agent
[ ] Tener archivos .txt en el directorio outputs/
[ ] Los archivos siguen el formato: herramienta_IP.txt
[ ] Tener permisos de ejecución en agent.py

Después de ejecutar:

[ ] Revisar parsed_data.json (datos parseados)
[ ] Revisar analysis.json (análisis completo)
[ ] Abrir informe_tecnico.html en navegador
[ ] Leer el Resumen Ejecutivo del informe
[ ] Implementar recomendaciones de corto plazo

═══════════════════════════════════════════════════════════════════════════════
🎉 ¡LISTO PARA USAR!
═══════════════════════════════════════════════════════════════════════════════

El proyecto está completo y funcional. Puedes comenzar a usarlo ejecutando:

    cd /home/clase/scan-agent
    python3 agent.py

Para más información, consulta README.md

═══════════════════════════════════════════════════════════════════════════════

Scan Agent v1.0.0 | Desarrollado con ❤️ | Python 3.12+ | MIT License

═══════════════════════════════════════════════════════════════════════════════
