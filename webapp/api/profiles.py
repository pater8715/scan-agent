"""
Profiles API Router
===================
Endpoints para obtener información sobre perfiles de escaneo disponibles.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import sys
from pathlib import Path

src_path = Path(__file__).parent.parent.parent / "src"
sys.path.insert(0, str(src_path))

from scanagent.scanner import VulnerabilityScanner

router = APIRouter()


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

class ScanProfileInfo(BaseModel):
    id: str
    name: str
    description: str
    estimated_time: str
    tools: List[str]
    requires_sudo: bool


class ProfileParameter(BaseModel):
    name: str
    type: str
    label: str
    description: str
    required: bool
    default: str = ""


# ---------------------------------------------------------------------------
# Metadatos educativos por herramienta / patrón de argumentos
# ---------------------------------------------------------------------------

# Tiempo estimado por perfil
_TIME_ESTIMATES: Dict[str, str] = {
    'quick':       '5-10 minutos',
    'standard':    '15-20 minutos',
    'full':        '30-60 minutos',
    'web':         '20-30 minutos',
    'stealth':     '30-45 minutos',
    'network':     '40 minutos',
    'compliance':  '10 minutos',
    'api':         '15 minutos',
    'api-owasp':   '20-30 minutos',
    'zap-passive': '10-15 minutos',
    'zap-active':  '30-60 minutos',
    'voip':        '15-25 minutos',
    'lab':         '10-15 minutos',
}

# Icono por herramienta
_TOOL_ICONS: Dict[str, str] = {
    'nmap':     '🔍',
    'curl':     '🌐',
    'nikto':    '🕷️',
    'gobuster': '📂',
    'dirb':     '📂',
    'zap':      '🛡️',
}

# Objetivos de aprendizaje + contexto por perfil
PROFILE_EDUCATION: Dict[str, Dict[str, Any]] = {
    'quick': {
        "learning_objectives": [
            "Identificar qué puertos y servicios expone el objetivo en segundos",
            "Comprender qué información revelan los 100 puertos más comunes de Internet",
            "Obtener una primera imagen de la superficie de ataque antes de un análisis profundo",
        ],
        "when_to_use": "Reconocimiento inicial, triage o cuando el tiempo es muy limitado.",
        "limitations": "No detecta versiones de software ni vulnerabilidades. Puede pasar por alto servicios en puertos no estándar (8080, 3000, etc.).",
    },
    'standard': {
        "learning_objectives": [
            "Detectar versiones exactas de software para correlacionar con CVEs conocidos",
            "Identificar vulnerabilidades con scripts NSE de categoría 'vuln'",
            "Cubrir todos los 65,535 puertos TCP para no perder servicios en puertos no estándar",
        ],
        "when_to_use": "Auditoría completa donde se dispone de 15-30 minutos. Balance entre profundidad y tiempo.",
        "limitations": "No incluye análisis web detallado (nikto, gobuster). El escaneo completo de puertos puede ser lento en redes congestionadas.",
    },
    'full': {
        "learning_objectives": [
            "Realizar el reconocimiento más completo posible sobre el objetivo",
            "Combinar detección de versiones, OS fingerprinting y scripts de vulnerabilidad",
            "Auditar la configuración SSH a nivel criptográfico: algoritmos KEX débiles, cifrados obsoletos, SSHv1 y métodos de autenticación",
            "Entender la diferencia entre escaneo pasivo (lectura de banners) y activo (scripts vuln/exploit)",
        ],
        "when_to_use": "Auditorías exhaustivas en entornos de laboratorio donde el tiempo no es una restricción.",
        "limitations": (
            "Muy ruidoso y fácilmente detectable. La categoría 'exploit' puede modificar el estado del objetivo — solo para entornos autorizados. "
            "La auditoría SSH solo cubre el puerto 22 por defecto; si SSH corre en un puerto no estándar, ajustar con selected_steps."
        ),
    },
    'web': {
        "learning_objectives": [
            "Identificar vulnerabilidades específicas de aplicaciones web (XSS, SQLi, misconfig)",
            "Enumerar directorios y archivos ocultos que el servidor no enlaza públicamente",
            "Auditar cabeceras HTTP de seguridad (CSP, HSTS, X-Frame-Options, CORS)",
        ],
        "when_to_use": "Cuando el objetivo principal es una aplicación web. Complementa el escaneo de red con pruebas de capa 7.",
        "limitations": "Solo cubre puertos 80, 443, 8080, 8443. Los puertos 3000, 5000, 8000 (Node.js, Flask) quedan fuera del alcance.",
    },
    'stealth': {
        "learning_objectives": [
            "Comprender cómo un SYN scan evita dejar registros en los logs del servicio",
            "Entender el uso de fragmentación de paquetes para evadir firewalls básicos",
            "Relacionar velocidad de escaneo (timing T1-T5) con probabilidad de detección",
        ],
        "when_to_use": "Simulaciones de reconocimiento sigiloso (pentesting con constraint de detección). Requiere autorización explícita.",
        "limitations": "IDS/IPS modernos detectan SYN scans y fragmentación. No incluye análisis web. Muy lento por diseño.",
    },
    'network': {
        "learning_objectives": [
            "Mapear la infraestructura completa de un segmento de red",
            "Identificar el sistema operativo de los hosts para correlacionar con vulnerabilidades específicas de SO",
            "Descubrir servicios de red internos (SMB, NFS, RPC, SNMP) frecuentemente mal configurados",
        ],
        "when_to_use": "Auditorías de infraestructura de red interna. Requiere privilegios root para OS detection.",
        "limitations": "Los scripts 'discovery' pueden generar tráfico multicast ruidoso. OS detection en Docker puede dar resultados incorrectos.",
    },
    'compliance': {
        "learning_objectives": [
            "Verificar el cumplimiento de mejores prácticas TLS/SSL (ciphers, versiones, caducidad del certificado)",
            "Auditar la presencia y correcta configuración de cabeceras de seguridad HTTP",
            "Relacionar cada hallazgo con un control de seguridad estándar (OWASP, CWE)",
        ],
        "when_to_use": "Revisiones de cumplimiento, preparación para auditorías de seguridad, verificación post-despliegue.",
        "limitations": "No realiza pruebas activas de vulnerabilidades. Solo verifica configuración y certificados.",
    },
    'api': {
        "learning_objectives": [
            "Identificar puertos donde corren servicios de API REST (3000, 5000, 8000, 8080)",
            "Verificar qué métodos HTTP acepta la API y si están correctamente protegidos",
            "Detectar políticas CORS permisivas que expongan la API a ataques desde otros orígenes",
        ],
        "when_to_use": "Auditoría inicial de APIs REST o SOAP. Punto de partida antes de pruebas OWASP API Top 10 más profundas.",
        "limitations": "No descubre endpoints de API (sin gobuster). Solo verifica la raíz del servicio, no rutas específicas.",
    },
    'api-owasp': {
        "learning_objectives": [
            "Aplicar activamente las 10 categorías del OWASP API Security Top 10 (2023)",
            "Descubrir endpoints no documentados que podrían exponer datos sensibles",
            "Evaluar los controles de autenticación, CORS y rate-limiting de la API",
        ],
        "when_to_use": "Evaluación de seguridad enfocada en APIs. El perfil más completo para análisis OWASP API 2023.",
        "limitations": "Gobuster con wordlist básica puede no cubrir endpoints específicos de la aplicación. Complementar con pruebas manuales.",
    },
    'zap-passive': {
        "learning_objectives": [
            "Entender el concepto de escaneo pasivo: observar tráfico sin enviar payloads de ataque",
            "Conocer cómo ZAP realiza spider del sitio y analiza cada respuesta HTTP",
            "Identificar vulnerabilidades sin riesgo de afectar el estado de la aplicación",
        ],
        "when_to_use": "Primer análisis de una aplicación web desconocida. Seguro para entornos casi-producción.",
        "limitations": "No detecta vulnerabilidades que requieren interacción activa (SQLi, XSS avanzado). Depende de que ZAP esté en ejecución.",
    },
    'zap-active': {
        "learning_objectives": [
            "Comprender la diferencia entre escaneo pasivo (observar) y activo (atacar y observar la respuesta)",
            "Identificar vulnerabilidades como SQLi, XSS, CSRF mediante envío real de payloads",
            "Entender por qué el escaneo activo solo debe usarse en entornos de laboratorio autorizados",
        ],
        "when_to_use": "Pruebas de penetración completas en entornos de laboratorio (Juice Shop, DVWA). Nunca en producción sin autorización explícita.",
        "limitations": "Puede modificar datos en la aplicación. Genera tráfico muy ruidoso. Requiere contenedor ZAP activo.",
    },
    'voip': {
        "learning_objectives": [
            "Comprender por qué SIP usa UDP y cómo esto lo hace invisible a escaneos TCP estándar",
            "Identificar los puertos críticos de Asterisk: SIP (5060), IAX2 (4569), AMI (5038), ARI (8088), STUN/TURN (3478)",
            "Evaluar los riesgos de exponer AMI sin autenticación o ARI sin TLS",
            "Usar scripts NSE especializados para enumerar usuarios y métodos SIP",
        ],
        "when_to_use": "Auditorías de servidores VoIP, PBX con Asterisk/FreePBX o cualquier infraestructura de comunicaciones unificadas.",
        "limitations": (
            "El escaneo UDP (-sU) es significativamente más lento que TCP y puede producir falsos negativos "
            "si el firewall filtra ICMP unreachable (nmap asume el puerto 'open|filtered'). "
            "Los scripts sip-enum-users pueden ser bloqueados por fail2ban. "
            "Los puertos RTP (10000-20000 UDP) no se escanean por su amplitud."
        ),
    },
    'lab': {
        "learning_objectives": [
            "Practicar reconocimiento sobre aplicaciones intencionalmente vulnerables (Juice Shop y DVWA)",
            "Relacionar los hallazgos del escaneo con las vulnerabilidades conocidas de cada app de laboratorio",
            "Ejecutar un ciclo completo: descubrimiento → análisis web → enumeración de rutas → verificación de cabeceras",
        ],
        "when_to_use": "Sesiones de clase y práctica. Optimizado para el entorno Docker local del laboratorio.",
        "limitations": "nikto con timeout corto puede perder hallazgos en apps JavaScript (Juice Shop usa Angular con renderizado del lado del cliente).",
    },
}


def _get_command_education(tool: str, args: str) -> Dict[str, Any]:
    """
    Retorna metadatos educativos para un comando según la herramienta y sus argumentos.
    Identifica el propósito, explicación pedagógica, qué detecta y referencia OWASP.
    """
    if tool == 'nmap':
        # SSL / compliance
        if 'ssl-cert' in args or 'ssl-enum-ciphers' in args:
            return {
                "purpose": "Auditoría de configuración TLS/SSL y cabeceras de seguridad HTTP",
                "explanation": (
                    "ssl-cert extrae el certificado X.509 del servidor: verifica validez, fecha de expiración "
                    "y autoridad certificadora (CA). ssl-enum-ciphers lista todos los algoritmos de cifrado "
                    "soportados e identifica los débiles (RC4, DES, export ciphers, SSLv2/v3). "
                    "http-security-headers verifica la presencia de cabeceras como HSTS, CSP, X-Frame-Options, "
                    "X-Content-Type-Options y Referrer-Policy."
                ),
                "what_it_finds": [
                    "Certificados expirados, autofirmados o con CN incorrecto",
                    "Algoritmos de cifrado débiles o desactualizados (RC4, DES, SSLv3)",
                    "Ausencia de HSTS, CSP, X-Frame-Options, X-Content-Type-Options",
                    "Versiones TLS inseguras habilitadas (TLS 1.0, TLS 1.1)",
                ],
                "owasp_ref": "A02: Cryptographic Failures | A05: Security Misconfiguration",
                "difficulty": "básico",
            }

        # Exhaustivo con OS (-A)
        if '-A' in args:
            return {
                "purpose": "Reconocimiento exhaustivo: versiones, OS, traceroute y scripts agresivos",
                "explanation": (
                    "-A es un atajo que combina: -sV (detección de versiones), -O (fingerprinting de sistema "
                    "operativo mediante análisis de la pila TCP/IP), --traceroute (ruta de red al host) y "
                    "-sC (scripts NSE por defecto). Con -p- escanea los 65,535 puertos TCP. "
                    "Es el escaneo más completo pero también el más lento y fácilmente detectable."
                ),
                "what_it_finds": [
                    "Versiones exactas de cada servicio",
                    "Sistema operativo y versión del kernel",
                    "Ruta de red hasta el objetivo (traceroute)",
                    "Configuraciones por defecto inseguras",
                ],
                "owasp_ref": "A06: Vulnerable and Outdated Components | A05: Security Misconfiguration",
                "difficulty": "avanzado",
            }

        # OS detection sin -A (network profile)
        if '-O' in args:
            return {
                "purpose": "Detección de sistema operativo e infraestructura de red",
                "explanation": (
                    "-O utiliza fingerprinting de la pila TCP/IP (TTL, tamaño de ventana, flags) para inferir "
                    "el sistema operativo del host. -sV detecta versiones exactas de cada servicio. "
                    "-sC ejecuta scripts NSE de reconocimiento seguros. Requiere permisos root (raw sockets). "
                    "Conocer el SO permite correlacionar con vulnerabilidades específicas de plataforma."
                ),
                "what_it_finds": [
                    "Sistema operativo y versión del kernel",
                    "Versiones exactas de servicios",
                    "Banners de servicios con información de configuración",
                    "Recursos compartidos (SMB, NFS, RPC)",
                ],
                "owasp_ref": "A05: Security Misconfiguration | A06: Vulnerable and Outdated Components",
                "difficulty": "intermedio",
            }

        # Stealth SYN scan
        if '-sS' in args:
            return {
                "purpose": "Escaneo TCP sigiloso (SYN scan) con fragmentación de paquetes",
                "explanation": (
                    "-sS (SYN scan o 'half-open') envía un paquete SYN y analiza la respuesta sin completar "
                    "el handshake TCP de tres vías. Esto evita que la conexión quede registrada en los logs del "
                    "servicio destino. -f fragmenta los paquetes en trozos pequeños para evadir firewalls que "
                    "inspeccionan paquetes completos. -T2 ralentiza el envío para reducir la firma en IDS/IPS. "
                    "Requiere privilegios root para crear raw sockets."
                ),
                "what_it_finds": [
                    "Puertos abiertos con menor rastro en logs de aplicación",
                    "Comportamiento del firewall frente a SYN sin ACK",
                    "Filtrado de paquetes fragmentados",
                ],
                "owasp_ref": "Técnica de reconocimiento — contexto: pentesting autorizado o análisis forense",
                "difficulty": "avanzado",
            }

        # Scripts vuln + exploit
        if 'exploit' in args:
            return {
                "purpose": "Scripts NSE de vulnerabilidades, exploits, autenticación y descubrimiento de red",
                "explanation": (
                    "'vuln' verifica CVEs documentados en los servicios detectados. "
                    "'exploit' intenta explotar activamente las vulnerabilidades encontradas — "
                    "SOLO para entornos de laboratorio con autorización explícita, puede modificar el objetivo. "
                    "'auth' prueba credenciales por defecto (admin/admin, root/root, etc.) y configuraciones de "
                    "autenticación débil. 'discovery' recopila información de la red: ARP, mDNS, NetBIOS, RPC."
                ),
                "what_it_finds": [
                    "CVEs confirmados activamente explotables",
                    "Credenciales por defecto sin cambiar",
                    "Servicios con autenticación débil o sin autenticación",
                    "Mapeo completo de servicios de la red",
                ],
                "owasp_ref": "A07: Identification and Authentication Failures | A06: Vulnerable and Outdated Components",
                "difficulty": "avanzado",
            }

        # vuln + safe (sin exploit)
        if 'vuln' in args and 'safe' in args:
            return {
                "purpose": "Detección de vulnerabilidades con scripts seguros (no intrusivos)",
                "explanation": (
                    "La categoría 'vuln' ejecuta scripts que verifican vulnerabilidades conocidas (CVEs) "
                    "comparando la versión detectada contra bases de datos de exploits. "
                    "La restricción 'safe' garantiza que ningún script genere denegación de servicio ni "
                    "modifique el estado del objetivo — ideal para entornos donde hay que ser responsable. "
                    "Detecta desde Heartbleed y Shellshock hasta vulnerabilidades de SMB como MS17-010 (EternalBlue)."
                ),
                "what_it_finds": [
                    "CVEs verificados de forma no intrusiva",
                    "Servicios con versiones afectadas por vulnerabilidades críticas",
                    "Configuraciones inseguras documentadas públicamente",
                ],
                "owasp_ref": "A06: Vulnerable and Outdated Components | A05: Security Misconfiguration",
                "difficulty": "intermedio",
            }

        # vuln solo
        if 'vuln' in args:
            return {
                "purpose": "Detección activa de vulnerabilidades conocidas con NSE",
                "explanation": (
                    "Ejecuta los scripts de la categoría 'vuln' del Nmap Scripting Engine. Cada script "
                    "verifica una vulnerabilidad específica: ms17-010 (EternalBlue/WannaCry), heartbleed "
                    "(OpenSSL), shellshock (bash CGI), smb-vuln-ms08-067, http-csrf, sql-injection básico, etc. "
                    "Con -T2 el envío es más lento para reducir la probabilidad de detección por IDS."
                ),
                "what_it_finds": [
                    "CVEs activos verificados en los servicios",
                    "Vulnerabilidades de SMB, HTTP, SSL y otros protocolos",
                    "Servicios con exposición pública de exploits conocidos",
                ],
                "owasp_ref": "A06: Vulnerable and Outdated Components",
                "difficulty": "intermedio",
            }

        # HTTP enum + vuln scripts (perfil web y lab)
        if 'http-enum' in args and 'http-auth-finder' in args:
            return {
                "purpose": "Enumeración web y análisis de autenticación HTTP (NSE)",
                "explanation": (
                    "http-enum compara más de 2,000 rutas conocidas contra el servidor y detecta aplicaciones "
                    "web por sus archivos característicos (WordPress: wp-login.php, Joomla: administrator/, etc.). "
                    "http-headers captura y analiza todas las cabeceras de respuesta para auditar políticas de seguridad. "
                    "http-methods lista los métodos HTTP habilitados — PUT y DELETE sin restricción son vectores de "
                    "escritura arbitraria. http-auth-finder identifica el mecanismo de autenticación (Basic, Digest, "
                    "Bearer, NTLM, Form) para enfocar pruebas posteriores."
                ),
                "what_it_finds": [
                    "Rutas de administración y CMS expuestas",
                    "Métodos HTTP peligrosos habilitados (PUT, DELETE)",
                    "Tipo de autenticación requerida",
                    "Cabeceras de seguridad presentes o ausentes",
                ],
                "owasp_ref": "A01: Broken Access Control | A07: Identification and Authentication Failures | A05: Security Misconfiguration",
                "difficulty": "básico",
            }

        # HTTP enum + vuln* (perfil web)
        if 'http-enum' in args and 'http-vuln' in args:
            return {
                "purpose": "Enumeración HTTP exhaustiva y detección de vulnerabilidades web con NSE",
                "explanation": (
                    "http-enum detecta directorios y aplicaciones por rutas características. "
                    "http-vuln* ejecuta todos los scripts de vulnerabilidades HTTP: http-vuln-cve2017-5638 "
                    "(Apache Struts), http-vuln-cve2014-3704 (Drupal), http-shellshock, http-csrf, "
                    "http-sql-injection básico, entre otros. http-methods verifica qué verbos acepta el servidor. "
                    "http-headers audita las cabeceras de seguridad de cada servicio detectado."
                ),
                "what_it_finds": [
                    "CVEs específicos de servidores web (Apache, Nginx, IIS)",
                    "Directorios y aplicaciones web identificadas",
                    "Métodos HTTP inseguros habilitados",
                    "Cabeceras de seguridad ausentes o mal configuradas",
                ],
                "owasp_ref": "A01: Broken Access Control | A05: Security Misconfiguration | A06: Vulnerable and Outdated Components",
                "difficulty": "intermedio",
            }

        # HTTP methods + cors (API profiles)
        if 'http-methods' in args and 'http-cors' in args:
            return {
                "purpose": "Análisis de seguridad de APIs REST: métodos HTTP, autenticación y política CORS",
                "explanation": (
                    "http-methods interroga cada endpoint para listar los verbos HTTP aceptados. "
                    "Métodos PUT/DELETE/PATCH sin autenticación permiten modificar o eliminar recursos "
                    "arbitrariamente (OWASP API5: Broken Function Level Authorization). "
                    "http-auth-finder detecta el mecanismo de autenticación en uso. "
                    "http-cors verifica si 'Access-Control-Allow-Origin: *' permite peticiones desde cualquier "
                    "origen, exponiendo la API a ataques de CSRF y robo de datos entre dominios. "
                    "http-security-headers audita cabeceras de seguridad de la respuesta."
                ),
                "what_it_finds": [
                    "Métodos HTTP peligrosos sin restricción (PUT, DELETE sin auth)",
                    "Política CORS permisiva (origen wildcard *)",
                    "Mecanismo de autenticación débil o ausente",
                    "Cabeceras de seguridad de la API ausentes",
                ],
                "owasp_ref": "API5:2023 Broken Function Level Authorization | API2:2023 Broken Authentication | API8:2023 Security Misconfiguration",
                "difficulty": "intermedio",
            }

        # Discovery scripts
        if 'discovery' in args:
            return {
                "purpose": "Descubrimiento activo de servicios de red e infraestructura",
                "explanation": (
                    "La categoría 'discovery' ejecuta scripts de reconocimiento activo: resolución DNS inversa, "
                    "enumeración NetBIOS/SMB (recursos compartidos, usuarios, grupos), descubrimiento de servicios "
                    "NFS (montajes exportados) y RPC (servicios registrados en portmapper). "
                    "Permite mapear la infraestructura completa del segmento y encontrar servicios internos "
                    "frecuentemente mal configurados en redes corporativas."
                ),
                "what_it_finds": [
                    "Nombres de host y registros DNS",
                    "Recursos compartidos SMB/CIFS sin autenticación",
                    "Montajes NFS accesibles sin restricción de IP",
                    "Servicios RPC expuestos (mountd, nfs, etc.)",
                ],
                "owasp_ref": "A05: Security Misconfiguration — exposición de servicios de red internos",
                "difficulty": "intermedio",
            }

        # Auditoría SSH profunda
        if 'ssh2-enum-algos' in args or 'sshv1' in args:
            return {
                "purpose": "Auditoría profunda de SSH: algoritmos criptográficos, versión del protocolo y métodos de autenticación",
                "explanation": (
                    "ssh2-enum-algos negocia la sesión SSH sin autenticarse y extrae las listas completas de "
                    "algoritmos soportados en cuatro categorías: intercambio de claves (KEX), cifrado simétrico, "
                    "códigos de autenticación de mensaje (MAC) y compresión. Algoritmos débiles comunes: "
                    "diffie-hellman-group1-sha1 (512 bits, vulnerable a Logjam), arcfour (RC4, prohibido por RFC 8758), "
                    "3des-cbc (DES triple, cuello de botella), hmac-md5 (colisiones MD5). "
                    "sshv1 detecta si el servidor acepta el protocolo SSH-1 (1995), que tiene vulnerabilidades "
                    "criptográficas fundamentales que permiten MITM sin que el cliente lo detecte. "
                    "ssh-auth-methods revela si se acepta autenticación por contraseña (vector de fuerza bruta) "
                    "o solo por clave pública. ssh-hostkey extrae el tipo de clave del host (RSA/ECDSA/Ed25519) "
                    "y su tamaño en bits — RSA menor a 2048 bits es inseguro según NIST SP 800-131A."
                ),
                "what_it_finds": [
                    "Algoritmos KEX débiles: diffie-hellman-group1-sha1 (Logjam), group14-sha1",
                    "Cifrados obsoletos: 3des-cbc, arcfour, blowfish-cbc, cast128-cbc",
                    "MACs inseguros: hmac-md5, hmac-sha1-96, umac-64",
                    "SSH protocolo versión 1 habilitado (permite MITM activo)",
                    "Autenticación por contraseña activa (brute-force posible)",
                    "Claves RSA del host menores a 2048 bits",
                ],
                "owasp_ref": "A02: Cryptographic Failures — algoritmos criptográficos débiles o deprecados",
                "difficulty": "intermedio",
            }

        # UDP VoIP: SIP + IAX2 + STUN/TURN
        if '-sU' in args and 'sip-enum' not in args:
            return {
                "purpose": "Escaneo UDP de puertos VoIP: SIP (5060), IAX2 (4569), STUN/TURN (3478)",
                "explanation": (
                    "SIP (Session Initiation Protocol) es el protocolo estándar para VoIP y usa UDP/5060 "
                    "por defecto. Los escaneos TCP convencionales no lo detectan jamás. "
                    "-sU envía una sonda UDP a cada puerto; si el objetivo responde con un paquete ICMP "
                    "Port Unreachable el puerto está cerrado; si no hay respuesta se marca open|filtered. "
                    "IAX2 (Inter-Asterisk eXchange v2) es el protocolo nativo de Asterisk en UDP/4569. "
                    "STUN/TURN en UDP/3478 permite a los clientes VoIP detrás de NAT descubrir su IP pública "
                    "y establecer canales de media (RTP). Expuesto sin controles, un servidor STUN puede ser "
                    "usado para ataques de amplificación UDP."
                ),
                "what_it_finds": [
                    "Servidor SIP activo en UDP/5060 (invisible a escaneos TCP)",
                    "Protocolo IAX2 de Asterisk en UDP/4569",
                    "Servicio STUN/TURN en UDP/3478 — amplificación UDP si es open relay",
                    "Versión del servidor SIP/Asterisk mediante fingerprinting de respuesta",
                ],
                "owasp_ref": "A05: Security Misconfiguration — servicios VoIP expuestos sin restricción",
                "difficulty": "intermedio",
            }

        # NSE SIP: sip-enum-users + sip-methods
        if 'sip-enum-users' in args or 'sip-methods' in args:
            return {
                "purpose": "Enumeración de usuarios SIP y métodos soportados por el servidor",
                "explanation": (
                    "sip-enum-users envía peticiones REGISTER/OPTIONS al servidor Asterisk con "
                    "nombres de usuario comunes (admin, asterisk, 1000, 1001…) y analiza las respuestas: "
                    "un '401 Unauthorized' confirma que el usuario existe, mientras '403 Forbidden' "
                    "o '404 Not Found' indica que no. Este comportamiento diferencial permite enumerar "
                    "extensiones válidas sin conocer contraseñas — información necesaria para ataques "
                    "de fuerza bruta sobre cuentas SIP. "
                    "sip-methods lista los verbos SIP aceptados (INVITE, REGISTER, OPTIONS, BYE, CANCEL): "
                    "un servidor que acepta INVITE sin autenticación permite originar llamadas arbitrarias."
                ),
                "what_it_finds": [
                    "Extensiones SIP válidas (útiles para ataques de fuerza bruta posterior)",
                    "Métodos SIP habilitados sin autenticación (INVITE peligroso)",
                    "Versión y software del servidor SIP (Asterisk, FreeSWITCH, etc.)",
                    "Política de autenticación: ¿exige credenciales en REGISTER?",
                ],
                "owasp_ref": "A07: Identification and Authentication Failures — enumeración de cuentas SIP",
                "difficulty": "avanzado",
            }

        # Detección de versión en puertos específicos (sin scripts)
        if '-sV' in args and '--script' not in args:
            ports_desc = "web comunes"
            if '8081' in args:
                ports_desc = "del laboratorio (Juice Shop :3000, DVWA :8081)"
            elif '3000' in args:
                ports_desc = "web + APIs (Node.js :3000, Flask :5000/:8000)"
            return {
                "purpose": f"Detección de servicios y versiones en puertos {ports_desc}",
                "explanation": (
                    "-sV realiza fingerprinting de versión enviando sondas a cada puerto abierto y "
                    "comparando las respuestas contra la base de datos de 11,000+ firmas de nmap. "
                    "Conocer la versión exacta del software es el paso previo indispensable para buscar "
                    "CVEs: sin versión, no hay correlación con vulnerabilidades conocidas. "
                    "Limitar los puertos al rango relevante reduce el tiempo sin sacrificar cobertura."
                ),
                "what_it_finds": [
                    "Software exacto y versión en cada puerto (Apache 2.4.52, nginx 1.18.0, etc.)",
                    "Frameworks de aplicación identificados",
                    "Servicios en puertos no estándar pero conocidos",
                ],
                "owasp_ref": "A06: Vulnerable and Outdated Components — prerequisito para correlación con CVEs",
                "difficulty": "básico",
            }

        # Quick scan (--top-ports)
        if '--top-ports' in args:
            return {
                "purpose": "Descubrimiento rápido de los puertos y servicios más comunes",
                "explanation": (
                    "nmap mantiene estadísticas de frecuencia de uso de cada puerto basadas en millones de "
                    "escaneos reales. --top-ports 100 cubre ~99% de los servicios que se encuentran en la "
                    "práctica. -Pn omite el ping de descubrimiento de host (asume activo), útil cuando el "
                    "objetivo filtra ICMP. -sT (TCP Connect) usa la llamada al sistema connect() del SO, "
                    "no requiere root a diferencia de SYN scan."
                ),
                "what_it_finds": [
                    "Puertos TCP más comunes abiertos (SSH, HTTP, HTTPS, SMB, FTP, etc.)",
                    "Presencia de servicios básicos como primer inventario",
                ],
                "owasp_ref": "A05: Security Misconfiguration — reconocimiento de superficie de ataque inicial",
                "difficulty": "básico",
            }

        # Full port + version + scripts (standard)
        if '-sV' in args and '-sC' in args and '-p-' in args:
            return {
                "purpose": "Escaneo completo de versiones y scripts NSE en todos los puertos TCP",
                "explanation": (
                    "-sV fingerprints cada servicio para obtener versión exacta. "
                    "-sC ejecuta los scripts NSE clasificados como 'default': son seguros, útiles y no "
                    "intrusivos. Entre ellos: extracción de certificados SSL, detección de banners, "
                    "verificación de autenticación anónima FTP, enumeración de recursos SMB, etc. "
                    "-p- garantiza cubrir todos los 65,535 puertos TCP para no pasar por alto servicios "
                    "ocultos en puertos no estándar (un backdoor en 31337, un admin panel en 8888, etc.)."
                ),
                "what_it_finds": [
                    "Todos los servicios TCP activos en cualquier puerto",
                    "Versiones exactas de software",
                    "Configuraciones por defecto detectables por scripts NSE",
                    "Certificados SSL y banners de servicio",
                ],
                "owasp_ref": "A06: Vulnerable and Outdated Components | A05: Security Misconfiguration",
                "difficulty": "intermedio",
            }

        return {
            "purpose": "Reconocimiento de red con Nmap",
            "explanation": (
                "Nmap (Network Mapper) es el estándar de facto en auditorías de red. Combina "
                "descubrimiento de hosts, escaneo de puertos, detección de versiones y un motor "
                "de scripting extensible (NSE) para identificar la superficie de ataque del objetivo."
            ),
            "what_it_finds": ["Puertos y servicios activos", "Información de configuración de red"],
            "owasp_ref": "A05: Security Misconfiguration",
            "difficulty": "básico",
        }

    # -----------------------------------------------------------------------
    elif tool == 'curl':
        if 'Accept: application/json' in args or 'application/json' in args:
            return {
                "purpose": "Verificación de respuesta HTTP simulando un cliente de API REST",
                "explanation": (
                    "La cabecera 'Accept: application/json' le indica al servidor que el cliente espera JSON. "
                    "Esto puede alterar el comportamiento de la API: algunas devuelven más información de error "
                    "en formato JSON que en HTML, lo que puede revelar detalles del stack interno. "
                    "La respuesta también incluye cabeceras de seguridad (CORS, Content-Type, X-RateLimit) "
                    "que permiten evaluar la configuración de la API sin ejecutar ningún ataque."
                ),
                "what_it_finds": [
                    "Cabeceras CORS de la API (Access-Control-Allow-Origin, Methods)",
                    "Información del servidor/framework en headers (X-Powered-By, Server)",
                    "Configuración de rate limiting (X-RateLimit-Limit, Retry-After)",
                    "Tipo de contenido real devuelto vs el esperado",
                ],
                "owasp_ref": "API8:2023 Security Misconfiguration | API4:2023 Unrestricted Resource Consumption",
                "difficulty": "básico",
            }

        if '-I' in args:
            return {
                "purpose": "Inspección de cabeceras HTTP de seguridad (petición HEAD)",
                "explanation": (
                    "Una petición HEAD es idéntica a GET pero el servidor solo devuelve las cabeceras, "
                    "sin el cuerpo de la respuesta. Esto la hace muy eficiente para auditar configuraciones. "
                    "Las cabeceras revelan: versión del servidor y framework (útil para buscar CVEs), "
                    "políticas de seguridad (HSTS obliga HTTPS, CSP restringe scripts, X-Frame-Options "
                    "previene clickjacking), configuración de cookies (HttpOnly evita robo via XSS, "
                    "Secure garantiza transmisión cifrada) y directivas de caché."
                ),
                "what_it_finds": [
                    "Server header: versión de software expuesta al atacante",
                    "Ausencia de HSTS (permite downgrade a HTTP)",
                    "Falta de CSP (permite XSS sin restricción)",
                    "Cookies sin HttpOnly o Secure flag",
                    "X-Frame-Options ausente (vulnerable a clickjacking)",
                ],
                "owasp_ref": "A05: Security Misconfiguration — cabeceras de seguridad HTTP",
                "difficulty": "básico",
            }

        if '-v' in args:
            return {
                "purpose": "Inspección completa de la conexión: TLS, cabeceras de solicitud y respuesta",
                "explanation": (
                    "El modo verbose (-v) expone todo el intercambio HTTP: la negociación TLS "
                    "(versión del protocolo, cipher suite elegido, certificado del servidor), "
                    "las cabeceras exactas enviadas en la solicitud y todas las cabeceras de la "
                    "respuesta del servidor. Permite verificar qué información revela el servidor "
                    "sobre su configuración interna (X-Powered-By, X-Generator, X-Debug, etc.) "
                    "y auditar la calidad de la configuración TLS en detalle."
                ),
                "what_it_finds": [
                    "Versión TLS negociada y cipher suite elegido",
                    "Cabeceras de respuesta completas incluyendo custom headers",
                    "Información interna revelada en headers (framework, versión, debug info)",
                    "Comportamiento del servidor ante conexiones sin cifrar",
                ],
                "owasp_ref": "A02: Cryptographic Failures | A05: Security Misconfiguration",
                "difficulty": "básico",
            }

        return {
            "purpose": "Verificación de respuesta HTTP del servidor",
            "explanation": (
                "curl es una herramienta de línea de comandos para transferencia de datos sobre "
                "múltiples protocolos. En auditorías de seguridad se usa para hacer peticiones HTTP "
                "manuales, verificar respuestas del servidor y auditar cabeceras sin depender de un browser."
            ),
            "what_it_finds": ["Respuesta del servidor", "Cabeceras HTTP"],
            "owasp_ref": "A05: Security Misconfiguration",
            "difficulty": "básico",
        }

    # -----------------------------------------------------------------------
    elif tool == 'nikto':
        if '-Tuning' in args:
            return {
                "purpose": "Análisis web exhaustivo con todas las categorías de prueba activadas",
                "explanation": (
                    "Nikto verifica más de 6,700 problemas documentados en servidores web. "
                    "Con -Tuning 123456789ab activa todas las categorías: "
                    "1=Inyección de archivos, 2=Configuración incorrecta del servidor, "
                    "3=Divulgación de información, 4=Inyección XSS/HTML, "
                    "5=Inclusión remota de archivos, 6=Denegación de servicio, "
                    "7=Autenticación remota, 8=Inyección SQL básica, "
                    "9=Inyección de comandos remotos, a=Autenticación bypass, "
                    "b=Identificación de software. Genera muchas peticiones HTTP — visible en logs."
                ),
                "what_it_finds": [
                    "Archivos peligrosos: .git, .env, backup.zip, phpinfo.php, .DS_Store",
                    "Versiones de servidor con CVEs conocidos",
                    "Métodos HTTP peligrosos habilitados",
                    "Cabeceras de seguridad ausentes",
                    "Vectores básicos de XSS, SQLi y path traversal",
                ],
                "owasp_ref": "A03: Injection | A05: Security Misconfiguration | A06: Vulnerable and Outdated Components",
                "difficulty": "intermedio",
            }

        if '-timeout' in args:
            timeout_val = args.split('-timeout')[1].strip().split()[0] if '-timeout' in args else '?'
            return {
                "purpose": f"Análisis web rápido (timeout {timeout_val}s por petición) para entorno de laboratorio",
                "explanation": (
                    "Versión de Nikto optimizada para velocidad en entornos de práctica. "
                    f"El parámetro -timeout {timeout_val} define el tiempo máximo de espera por petición; "
                    "un valor bajo reduce la duración total pero puede perder hallazgos en aplicaciones "
                    "lentas (Juice Shop usa Angular: el renderizado inicial puede tardar más). "
                    "Ideal para un análisis rápido antes de explorar manualmente la aplicación."
                ),
                "what_it_finds": [
                    "Vulnerabilidades web más evidentes en tiempo reducido",
                    "Archivos peligrosos expuestos",
                    "Configuraciones básicas incorrectas del servidor",
                ],
                "owasp_ref": "A05: Security Misconfiguration | A06: Vulnerable and Outdated Components",
                "difficulty": "básico",
            }

        return {
            "purpose": "Análisis de vulnerabilidades en servidores web",
            "explanation": (
                "Nikto es un escáner de vulnerabilidades web de código abierto que verifica el servidor "
                "contra una base de datos de más de 6,700 elementos problemáticos: archivos peligrosos, "
                "versiones vulnerables y configuraciones incorrectas. Es fácilmente detectable por WAF e IDS "
                "— solo usar en entornos donde está autorizado."
            ),
            "what_it_finds": [
                "Archivos sensibles expuestos",
                "Configuraciones peligrosas del servidor",
                "Versiones vulnerables del software web",
            ],
            "owasp_ref": "A05: Security Misconfiguration",
            "difficulty": "básico",
        }

    # -----------------------------------------------------------------------
    elif tool == 'gobuster':
        if '-x json' in args:
            return {
                "purpose": "Descubrimiento de endpoints de API REST por fuerza bruta",
                "explanation": (
                    "Gobuster enumera URLs sistemáticamente, probando cada entrada de la wordlist. "
                    "Con -x json añade la extensión .json a cada ruta, buscando endpoints que devuelvan "
                    "datos JSON: /api/v1/users.json, /config.json, /swagger.json, etc. "
                    "Permite descubrir endpoints no documentados en el swagger/OpenAPI oficial — "
                    "los olvidados son frecuentemente los menos asegurados (OWASP API9: Improper Inventory Management)."
                ),
                "what_it_finds": [
                    "Endpoints de API sin documentar (shadow APIs)",
                    "Versiones de API obsoletas aún activas (/v1, /v2, /beta)",
                    "Rutas de administración de la API",
                    "Archivos de configuración en formato JSON expuestos",
                ],
                "owasp_ref": "API9:2023 Improper Inventory Management | API1:2023 Broken Object Level Authorization",
                "difficulty": "intermedio",
            }

        if '-x' in args:
            exts = args.split('-x')[1].strip().split()[0] if '-x' in args else ''
            return {
                "purpose": f"Enumeración de directorios y archivos con extensiones {exts}",
                "explanation": (
                    "Gobuster realiza fuerza bruta de rutas HTTP combinando cada entrada de la wordlist "
                    f"con las extensiones especificadas ({exts}). Esto multiplica la cobertura: por cada "
                    "ruta en la lista prueba también login.php, login.html, login.txt, etc. "
                    "Detecta archivos que existen en el servidor pero no están enlazados en la aplicación: "
                    "paneles de administración, backups, archivos de configuración y código fuente expuesto."
                ),
                "what_it_finds": [
                    "Archivos PHP de configuración o debug expuestos",
                    "Páginas de administración sin enlace público",
                    "Backups de código fuente (.php.bak, config.php.old)",
                    "Documentación interna accesible",
                ],
                "owasp_ref": "A01: Broken Access Control — recursos accesibles sin autorización",
                "difficulty": "intermedio",
            }

        return {
            "purpose": "Descubrimiento de directorios y archivos ocultos por fuerza bruta HTTP",
            "explanation": (
                "Gobuster prueba cada ruta de la wordlist contra el servidor HTTP y registra las que "
                "devuelven código 200 (encontrado), 301/302 (redirección) u otros códigos no-404. "
                "Descubre recursos que el desarrollador olvidó proteger o eliminar: "
                ".git/ (repositorio con historial del código), /admin/ (panel sin auth), "
                "/backup/ (archivos descargables), /.env (credenciales de producción)."
            ),
            "what_it_finds": [
                "Directorios ocultos: /admin/, /backup/, /uploads/, /internal/",
                "Repositorios de código expuestos: /.git/, /.svn/",
                "Archivos de configuración: /.env, /config.php, /web.config",
                "Paneles de administración sin enlace en la UI",
            ],
            "owasp_ref": "A01: Broken Access Control | A05: Security Misconfiguration",
            "difficulty": "básico",
        }

    # Fallback genérico
    return {
        "purpose": f"Análisis de seguridad con {tool}",
        "explanation": (
            f"{tool} es una herramienta de seguridad que amplía la cobertura del análisis "
            "para este perfil de escaneo."
        ),
        "what_it_finds": ["Información de seguridad del objetivo"],
        "owasp_ref": "—",
        "difficulty": "—",
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", response_model=List[ScanProfileInfo])
async def get_profiles():
    """Obtiene la lista de todos los perfiles de escaneo disponibles."""
    scanner = VulnerabilityScanner()
    profiles_info = []

    for profile_id, profile in scanner.PROFILES.items():
        tools = list(set(cmd['tool'] for cmd in profile.commands))
        profiles_info.append(ScanProfileInfo(
            id=profile_id,
            name=profile.name,
            description=profile.description,
            estimated_time=_TIME_ESTIMATES.get(profile_id, 'Variable'),
            tools=tools,
            requires_sudo=profile.requires_sudo,
        ))

    return profiles_info


@router.get("/{profile_id}", response_model=ScanProfileInfo)
async def get_profile(profile_id: str):
    """Obtiene información básica de un perfil específico."""
    scanner = VulnerabilityScanner()

    if profile_id not in scanner.PROFILES:
        raise HTTPException(status_code=404, detail="Perfil no encontrado")

    profile = scanner.PROFILES[profile_id]
    tools = list(set(cmd['tool'] for cmd in profile.commands))

    return ScanProfileInfo(
        id=profile_id,
        name=profile.name,
        description=profile.description,
        estimated_time=_TIME_ESTIMATES.get(profile_id, 'Variable'),
        tools=tools,
        requires_sudo=profile.requires_sudo,
    )


@router.get("/{profile_id}/detail")
async def get_profile_detail(profile_id: str):
    """
    Retorna información completa del perfil con contenido educativo:
    objetivos de aprendizaje, propósito de cada herramienta, qué detecta
    y referencia a la categoría OWASP correspondiente.
    """
    scanner = VulnerabilityScanner()

    if profile_id not in scanner.PROFILES:
        raise HTTPException(status_code=404, detail="Perfil no encontrado")

    profile = scanner.PROFILES[profile_id]
    education = PROFILE_EDUCATION.get(profile_id, {})

    commands_detail = []
    for cmd in profile.commands:
        tool = cmd['tool']
        args = cmd.get('args', '')
        edu = _get_command_education(tool, args)
        commands_detail.append({
            "tool": tool,
            "icon": _TOOL_ICONS.get(tool, '⚙️'),
            "args": args,
            "full_command": f"{tool} {args}",
            "output_file": cmd.get("output", ""),
            "timeout_seconds": cmd.get("timeout", 300),
            "required": cmd.get("required", True),
            "sudo": cmd.get("sudo", False),
            # campos educativos
            "purpose": edu.get("purpose", ""),
            "explanation": edu.get("explanation", ""),
            "what_it_finds": edu.get("what_it_finds", []),
            "owasp_ref": edu.get("owasp_ref", ""),
            "difficulty": edu.get("difficulty", ""),
        })

    return {
        "id": profile_id,
        "name": profile.name,
        "description": profile.description,
        "estimated_time": _TIME_ESTIMATES.get(profile_id, 'Variable'),
        "requires_sudo": profile.requires_sudo,
        # metadatos educativos del perfil
        "learning_objectives": education.get("learning_objectives", []),
        "when_to_use": education.get("when_to_use", ""),
        "limitations": education.get("limitations", ""),
        "commands": commands_detail,
    }


@router.get("/{profile_id}/parameters", response_model=List[ProfileParameter])
async def get_profile_parameters(profile_id: str):
    """Obtiene los parámetros configurables de un perfil."""
    parameters = [
        ProfileParameter(
            name="target",
            type="text",
            label="Objetivo",
            description="Dirección IP o dominio a escanear",
            required=True,
            default="",
        ),
        ProfileParameter(
            name="output_formats",
            type="multiselect",
            label="Formatos de Reporte",
            description="Selecciona los formatos en los que deseas el reporte",
            required=False,
            default="json,html",
        ),
        ProfileParameter(
            name="save_to_db",
            type="boolean",
            label="Guardar en Base de Datos",
            description="Almacenar resultados en la base de datos local",
            required=False,
            default="true",
        ),
    ]

    return parameters
