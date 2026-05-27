#!/usr/bin/env python3
"""
Scanner Module - Scan Agent v2.0
=================================
Módulo de ejecución de escaneos de vulnerabilidades con perfiles predefinidos.

Autor: Scan Agent Team
Versión: 2.0.0
"""

import subprocess
import os
import sys
import re
import ipaddress
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import shlex

logger = logging.getLogger("scan_agent.scanner")


class ScanProfile:
    """Define un perfil de escaneo con comandos específicos"""
    
    def __init__(self, name: str, description: str, commands: List[Dict]):
        self.name = name
        self.description = description
        self.commands = commands
        self.requires_sudo = any(cmd.get('sudo', False) for cmd in commands)


class VulnerabilityScanner:
    """Ejecutor de escaneos de vulnerabilidades"""
    
    # Definición de perfiles de escaneo
    PROFILES = {
        'quick': ScanProfile(
            name='Quick Scan',
            description='Escaneo rápido de puertos y servicios básicos (5 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-Pn -sT -sV -p1-1024,3000,5000,8000,8080,8443 --script=http-headers {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 300,
                    'required': True
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I https://{target}',
                    'output': 'headers_https_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),

        'standard': ScanProfile(
            name='Standard Scan',
            description='Escaneo completo con detección de versiones y scripts básicos (15 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -sC --top-ports 1000 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 1800,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=vuln --top-ports 1000 {target}',
                    'output': 'nmap_vuln_{target}.txt',
                    'timeout': 600,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=http-security-headers,http-headers --top-ports 1000 {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 300,
                    'required': False
                },
                {
                    'tool': 'nikto',
                    'args': '-h http://{target} -timeout 10 -maxtime 180',
                    'output': 'nikto_{target}.txt',
                    'timeout': 240,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-v http://{target}',
                    'output': 'curl_verbose_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),

        'full': ScanProfile(
            name='Full Scan',
            description='Escaneo exhaustivo con todas las herramientas (30-60 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -sC -A -p- {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 1800,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=vuln,auth,discovery,safe {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 1200,
                    'required': True
                },
                {
                    'tool': 'whatweb',
                    'args': 'http://{target}',
                    'output': 'whatweb_{target}.txt',
                    'timeout': 60,
                    'required': False
                },
                {
                    'tool': 'nikto',
                    'args': '-h http://{target}',
                    'output': 'nikto_{target}.txt',
                    'timeout': 1800,
                    'required': False
                },
                {
                    'tool': 'gobuster',
                    'args': 'dir -u http://{target} -w /usr/share/dirb/wordlists/big.txt -q',
                    'output': 'gobuster_{target}.txt',
                    'timeout': 900,
                    'required': False
                },
                {
                    'tool': 'gobuster',
                    'args': 'dir -u https://{target} -w /usr/share/dirb/wordlists/big.txt -q -k',
                    'output': 'gobuster_https_{target}.txt',
                    'timeout': 900,
                    'required': False
                },
                {
                    'tool': 'sslscan',
                    'args': '{target}',
                    'output': 'sslscan_{target}.txt',
                    'timeout': 120,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-v http://{target}',
                    'output': 'curl_verbose_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),

        'web': ScanProfile(
            name='Web Application Scan',
            description='Escaneo enfocado en aplicaciones web (20-30 min aprox)',
            commands=[
                {
                    'tool': 'wafw00f',
                    'args': 'http://{target}',
                    'output': 'wafw00f_{target}.txt',
                    'timeout': 60,
                    'required': False
                },
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,3000,5000,8000,8080,8443,9000 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 300,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=http-enum,http-headers,http-methods,http-vuln*,http-cors {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 600,
                    'required': True
                },
                {
                    'tool': 'whatweb',
                    'args': 'http://{target}',
                    'output': 'whatweb_{target}.txt',
                    'timeout': 60,
                    'required': False
                },
                {
                    'tool': 'nikto',
                    'args': '-h http://{target} -Tuning 123456789ab',
                    'output': 'nikto_{target}.txt',
                    'timeout': 1800,
                    'required': False
                },
                {
                    'tool': 'gobuster',
                    'args': 'dir -u http://{target} -w /usr/share/dirb/wordlists/big.txt -x php,html,txt -q',
                    'output': 'gobuster_{target}.txt',
                    'timeout': 1200,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-v http://{target}',
                    'output': 'curl_verbose_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),

        'stealth': ScanProfile(
            name='Stealth Scan',
            description='Escaneo sigiloso para evadir detección (30-45 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sT -sV -T2 --randomize-hosts {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 1800,
                    'required': True,
                },
                {
                    'tool': 'nmap',
                    'args': '--script=default -T2 --source-port 53 {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 1200,
                    'required': True,
                },
                {
                    'tool': 'curl',
                    'args': '-s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -I http://{target}',
                    'output': 'headers_stealth_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),

        'network': ScanProfile(
            name='Network Infrastructure Scan',
            description='Escaneo de infraestructura de red completa (40 min aprox, requiere sudo)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -sC -O -p- {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 2400,
                    'required': True,
                    'sudo': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=default,smb-enum-shares,smb-enum-users,ftp-anon,ssh-hostkey,nfs-showmount {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 1800,
                    'required': True
                },
                {
                    'tool': 'enum4linux',
                    'args': '-a {target}',
                    'output': 'enum4linux_{target}.txt',
                    'timeout': 300,
                    'required': False
                },
                {
                    'tool': 'snmp-check',
                    'args': '{target}',
                    'output': 'snmp_{target}.txt',
                    'timeout': 120,
                    'required': False
                }
            ]
        ),

        'compliance': ScanProfile(
            name='Compliance & Best Practices',
            description='Verificación de cumplimiento y mejores prácticas (10 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV --script=ssl-cert,ssl-enum-ciphers,http-security-headers,http-cors,http-auth-finder {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 600,
                    'required': True
                },
                {
                    'tool': 'sslscan',
                    'args': '{target}',
                    'output': 'sslscan_{target}.txt',
                    'timeout': 120,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_http_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I https://{target}',
                    'output': 'headers_https_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),

        'api': ScanProfile(
            name='API Security Scan',
            description='Escaneo enfocado en APIs REST/SOAP (15 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,8080,8443,3000,5000,8000 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 300,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=http-methods,http-auth-finder,http-cors {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 300,
                    'required': True
                },
                {
                    'tool': 'gobuster',
                    'args': 'dir -u http://{target} -w /usr/share/wordlists/api-endpoints.txt -q -t 20 -x json',
                    'output': 'gobuster_api_{target}.txt',
                    'timeout': 600,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I -H "Accept: application/json" http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-X PUT -I -H "Accept: application/json" http://{target}/api/test',
                    'output': 'curl_put_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-X DELETE -I -H "Accept: application/json" http://{target}/api/test',
                    'output': 'curl_delete_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-X PATCH -I -H "Accept: application/json" http://{target}/api/test',
                    'output': 'curl_patch_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-s http://{target}/swagger.json http://{target}/api-docs http://{target}/graphql',
                    'output': 'curl_apidocs_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
            ]
        ),

        'api-owasp': ScanProfile(
            name='OWASP API Security Top 10 (2023)',
            description='Verificación activa de las 10 categorías OWASP API Security Top 10 2023 (20-30 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,8080,8443,3000,5000,8000,9000 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 300,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=http-methods,http-auth,http-auth-finder,http-cors,http-security-headers {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 300,
                    'required': False
                },
                {
                    'tool': 'gobuster',
                    'args': 'dir -u http://{target} -w /usr/share/wordlists/api-endpoints.txt -q -t 20 -x json',
                    'output': 'gobuster_{target}.txt',
                    'timeout': 600,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I -H "Accept: application/json" http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-X PUT -I -H "Accept: application/json" http://{target}/api/test',
                    'output': 'curl_put_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-X DELETE -I -H "Accept: application/json" http://{target}/api/v1/resource',
                    'output': 'curl_delete_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-X OPTIONS -I http://{target}/api/v1/users',
                    'output': 'curl_options_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-s http://{target}/swagger.json http://{target}/api-docs http://{target}/graphiql',
                    'output': 'curl_apidocs_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'nikto',
                    'args': '-h http://{target} -timeout 10 -maxtime 120',
                    'output': 'nikto_{target}.txt',
                    'timeout': 180,
                    'required': False
                }
            ]
        ),

        'zap-passive': ScanProfile(
            name='ZAP Passive Scan',
            description='Spider + escaneo pasivo con OWASP ZAP (sin tráfico activo de ataque) (10-15 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,3000,8080,8081 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 120,
                    'required': True
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
                # ZAP se ejecuta desde agent.py vía ZAPIntegration (no como subprocess)
            ]
        ),

        'zap-active': ScanProfile(
            name='ZAP Active Scan',
            description='Spider + escaneo pasivo + escaneo activo con OWASP ZAP (30-60 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,3000,8080,8081 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 120,
                    'required': True
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                }
                # ZAP active scan se ejecuta desde agent.py vía ZAPIntegration
            ]
        ),

        'lab': ScanProfile(
            name='Lab Environment Scan',
            description='Escaneo para entornos de práctica (Juice Shop en :3000, DVWA en :8081) - ideal para clases (10-15 min aprox)',
            commands=[
                {
                    'tool': 'nmap',
                    'args': '-sV -p80,443,3000,8080,8081 {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 120,
                    'required': True
                },
                {
                    'tool': 'nmap',
                    'args': '--script=http-enum,http-headers,http-methods,http-auth-finder,http-vuln* {target}',
                    'output': 'nmap_nse_{target}.txt',
                    'timeout': 180,
                    'required': False
                },
                {
                    'tool': 'nikto',
                    'args': '-h http://{target} -timeout 10 -maxtime 120',
                    'output': 'nikto_{target}.txt',
                    'timeout': 180,
                    'required': False
                },
                {
                    'tool': 'gobuster',
                    'args': 'dir -u http://{target} -w /usr/share/dirb/wordlists/common.txt -q -t 20 -x php,js,json,html',
                    'output': 'gobuster_{target}.txt',
                    'timeout': 300,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-I http://{target}',
                    'output': 'headers_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-v http://{target}',
                    'output': 'curl_verbose_{target}.txt',
                    'timeout': 30,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-s http://{target}:3000/api/SecurityQuestions',
                    'output': 'curl_juiceshop_{target}.txt',
                    'timeout': 15,
                    'required': False
                },
                {
                    'tool': 'curl',
                    'args': '-s http://{target}:8081/setup.php',
                    'output': 'curl_dvwa_{target}.txt',
                    'timeout': 15,
                    'required': False
                }
            ]
        )
    }
    
    def __init__(self, verbose: bool = False):
        """
        Inicializa el escáner de vulnerabilidades.
        
        Args:
            verbose: Mostrar información detallada
        """
        self.output_dir = None  # Se configurará en run_scan
        self.verbose = verbose
        self._current_process = None  # Proceso subprocess activo (para cancelación)
        self.results = {
            'started_at': None,
            'finished_at': None,
            'profile_used': None,
            'target': None,
            'commands_executed': [],
            'commands_failed': [],
            'outputs_generated': []
        }
    
    # Rangos privados permitidos por defecto
    _PRIVATE_NETS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
    ]
    _HOSTNAME_RE = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)"
        r"(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))*$"
    )
    _LOCAL_SUFFIXES = (".local", ".lan", ".internal", ".corp", ".test")

    @classmethod
    def normalize_target(cls, target: str) -> tuple:
        """Normaliza el target extrayendo hostname y puerto opcionales.

        Acepta:
          hostname | hostname:port | 192.168.1.0/24 (CIDR)
          http://hostname | http://hostname:port/path
        Retorna: (hostname_o_cidr, port_int_or_None)
        """
        had_protocol = "://" in target

        # Strip protocol
        if had_protocol:
            target = target.split("://", 1)[1]

        # Strip path/query SOLO si venía con protocolo (URL path, no CIDR)
        if had_protocol:
            target = target.split("/")[0].split("?")[0]
        else:
            # Sin protocolo: puede ser CIDR (10.1.11.0/24) — preservar la barra
            target = target.split("?")[0].rstrip("/")

        # Extract port (solo si no es CIDR, que también usa ":")
        if ":" in target and "/" not in target:
            host, port_str = target.rsplit(":", 1)
            try:
                port = int(port_str)
                if not 1 <= port <= 65535:
                    raise ValueError(f"Puerto fuera de rango: {port_str}")
                return host, port
            except (ValueError, OverflowError) as exc:
                if "Puerto" in str(exc):
                    raise

        return target, None

    @classmethod
    def validate_target(cls, target: str) -> None:
        """Valida que el target sea una IP privada/local o un hostname local autorizado.

        Acepta formatos: hostname, hostname:port, http://hostname, http://hostname:port
        Lanza ValueError si el target no está permitido.
        Establece ALLOW_PUBLIC_TARGETS=true en el entorno para habilitar IPs públicas.
        """
        allow_public = os.environ.get("ALLOW_PUBLIC_TARGETS", "").lower() == "true"

        # Sanity check: evitar inyección de comandos
        if not target or len(target) > 512:
            raise ValueError(f"Target inválido: '{target}'")
        if any(c in target for c in (";", "&", "|", "`", "$", "\n", "\r")):
            raise ValueError(f"Target contiene caracteres no permitidos: '{target}'")

        # Normalizar: extraer hostname y puerto
        hostname, _port = cls.normalize_target(target)

        # Soporte de rangos CIDR (ej: 192.168.1.0/24) — siempre privados
        if "/" in hostname:
            try:
                net = ipaddress.ip_network(hostname, strict=False)
                if net.is_private or net.is_loopback:
                    return
                if allow_public:
                    return
                raise ValueError(
                    f"Red '{hostname}' es pública. "
                    "Establece ALLOW_PUBLIC_TARGETS=true para escanear redes públicas."
                )
            except ValueError as exc:
                if "Red" in str(exc):
                    raise

        # Intentar parsear como dirección IP
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback or ip.is_private:
                return  # siempre permitido
            if allow_public:
                return
            raise ValueError(
                f"Target '{hostname}' es una IP pública. "
                "Solo se permiten IPs privadas/locales en este entorno. "
                "Establece ALLOW_PUBLIC_TARGETS=true para habilitar IPs públicas."
            )
        except ValueError as exc:
            if "Target" in str(exc):
                raise

        # Es un hostname: validar formato
        if not cls._HOSTNAME_RE.match(hostname):
            raise ValueError(f"Hostname inválido: '{hostname}'")

        if hostname.lower() == "localhost":
            return
        if any(hostname.lower().endswith(s) for s in cls._LOCAL_SUFFIXES):
            return
        # Hostnames sin punto son siempre locales (Docker service names, /etc/hosts, LAN)
        if "." not in hostname:
            return
        if allow_public:
            return

        raise ValueError(
            f"Hostname '{hostname}' parece externo. "
            "Establece ALLOW_PUBLIC_TARGETS=true para escanear hosts no locales."
        )

    def check_tool_availability(self, tool: str) -> bool:
        """Verifica si una herramienta está disponible en el sistema"""
        try:
            result = subprocess.run(
                ['which', tool],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            available = result.returncode == 0
            
            if self.verbose:
                status = "✅ Disponible" if available else "❌ No encontrada"
                print(f"  [{tool}] {status}")
            
            return available
        except Exception as e:
            if self.verbose:
                print(f"  [{tool}] ❌ Error al verificar: {str(e)}")
            return False
    
    def check_all_tools(self, profile: ScanProfile) -> Dict[str, bool]:
        """Verifica disponibilidad de todas las herramientas del perfil"""
        if self.verbose:
            print(f"\n🔍 Verificando herramientas requeridas para '{profile.name}'...")
        
        tools = {}
        for cmd in profile.commands:
            tool = cmd['tool']
            if tool not in tools:
                tools[tool] = self.check_tool_availability(tool)
        
        return tools
    
    def execute_command(self, command: Dict, target: str) -> bool:
        """Ejecuta un comando individual del escaneo"""
        tool = command['tool']

        # Separar hostname y puerto para sustituir correctamente en las plantillas
        hostname, port = self.__class__.normalize_target(target)
        http_target = f"{hostname}:{port}" if port else hostname

        args_template = command['args']
        # Herramientas HTTP (curl, gobuster, nikto, wafw00f) necesitan hostname:port
        # Herramientas de red (nmap) solo aceptan hostname; el puerto se inyecta en -p
        _http_tools = {"curl", "wget", "gobuster", "dirb", "whatweb", "nikto", "wafw00f"}
        if tool in _http_tools:
            args = args_template.format(target=http_target)
        else:
            args = args_template.format(target=hostname)
            # Si el target especifica un puerto concreto, añadirlo a la lista -p de nmap
            # para que el servicio no quede excluido por los puertos fijos del perfil.
            # Lookbehind negativo evita engancharse en --top-ports (donde "-p" está
            # precedido por una letra/guion, no por espacio o inicio de cadena).
            if port:
                _PORT_RE = re.compile(r'(?<![a-zA-Z\-])-p(\S+)')
                def _inject_port(m):
                    ports = m.group(1).split(',')
                    if str(port) not in ports:
                        ports.append(str(port))
                    return f"-p{','.join(ports)}"
                if _PORT_RE.search(args):
                    args = _PORT_RE.sub(_inject_port, args, count=1)
                else:
                    args += f' -p{port}'

        # Nombre de archivo seguro: sin "://" ni barras (CIDR usa "/")
        safe_target = hostname.replace("/", "_") + (f"_{port}" if port else "")
        output_file = os.path.join(
            self.output_dir,
            command['output'].format(target=safe_target)
        )
        timeout = command.get('timeout', 300)
        use_sudo = command.get('sudo', False)

        # Si el proceso ya corre como root, sudo es innecesario (y falla en Docker)
        import os as _os
        if use_sudo and _os.getuid() == 0:
            use_sudo = False

        # Construir comando completo
        full_command = f"{tool} {args}"
        if use_sudo:
            full_command = f"sudo {full_command}"
        
        if self.verbose:
            print(f"\n⚙️  Ejecutando: {full_command}")
            print(f"   Timeout: {timeout}s")
            print(f"   Salida: {output_file}")
        
        try:
            # Ejecutar comando
            start_time = datetime.now()
            
            process = subprocess.Popen(
                shlex.split(full_command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self._current_process = process

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                if self.verbose:
                    print(f"   ⚠️  Comando excedió timeout de {timeout}s")
                return False
            finally:
                self._current_process = None
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Guardar salida
            with open(output_file, 'w') as f:
                f.write(stdout)
                if stderr:
                    f.write("\n\n=== STDERR ===\n")
                    f.write(stderr)
            
            # Registrar resultado
            self.results['commands_executed'].append({
                'tool': tool,
                'command': full_command,
                'output_file': output_file,
                'duration': duration,
                'returncode': returncode
            })
            
            self.results['outputs_generated'].append(output_file)
            
            if self.verbose:
                status = "✅" if returncode == 0 else "⚠️"
                print(f"   {status} Completado en {duration:.2f}s (código: {returncode})")
            
            return returncode == 0
            
        except FileNotFoundError:
            if self.verbose:
                print(f"   ❌ Herramienta '{tool}' no encontrada")
            self.results['commands_failed'].append({
                'tool': tool,
                'reason': 'Tool not found'
            })
            return False
            
        except Exception as e:
            if self.verbose:
                print(f"   ❌ Error: {str(e)}")
            self.results['commands_failed'].append({
                'tool': tool,
                'reason': str(e)
            })
            return False
    
    def run_scan(self, target: str, profile_name: str, output_dir: str = "./outputs",
                 step_callback=None, steps_filter=None) -> tuple:
        """Ejecuta un perfil de escaneo completo

        Args:
            target: IP o dominio objetivo
            profile_name: Nombre del perfil a ejecutar
            output_dir: Directorio donde guardar los archivos (default: ./outputs)
            step_callback: Función opcional(paso, total, herramienta, éxito) llamada tras cada paso

        Returns:
            tuple: (success: bool, generated_files: list)
        """

        # Validar target antes de cualquier otra operación
        self.validate_target(target)

        # Configurar directorio de salida
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Validar perfil
        if profile_name not in self.PROFILES:
            raise ValueError(f"Perfil '{profile_name}' no existe. Perfiles disponibles: {', '.join(self.PROFILES.keys())}")

        profile = self.PROFILES[profile_name]

        # Para targets CIDR, usar siempre ping scan (-sn) en lugar de los comandos
        # del perfil. El objetivo de un scan CIDR es descubrir hosts activos
        # rápidamente; el escaneo profundo se lanza desde la UI sobre cada host.
        hostname, _port = self.__class__.normalize_target(target)
        is_cidr = "/" in hostname
        if is_cidr:
            commands_to_run = [
                {
                    'tool': 'nmap',
                    'args': '-sn {target}',
                    'output': 'nmap_service_{target}.txt',
                    'timeout': 120,
                    'required': True,
                }
            ]
        else:
            commands_to_run = profile.commands
            # Aplicar filtro de pasos cuando el usuario eligió una selección parcial
            if steps_filter is not None:
                valid_indices = set(steps_filter)
                skipped = [
                    {"index": i, "tool": c["tool"], "args": c.get("args", "")}
                    for i, c in enumerate(commands_to_run)
                    if i not in valid_indices
                ]
                commands_to_run = [
                    c for i, c in enumerate(commands_to_run)
                    if i in valid_indices
                ]
                self.results["skipped_steps"] = skipped
            else:
                self.results["skipped_steps"] = []

        # Inicializar resultados
        self.results['started_at'] = datetime.now()
        self.results['profile_used'] = profile_name
        self.results['target'] = target

        print("=" * 80)
        print(f"INICIANDO ESCANEO: {profile.name}")
        print("=" * 80)
        print(f"Target: {target}")
        print(f"Perfil: {profile.name}")
        if is_cidr:
            print("Modo: descubrimiento de red (nmap -sn)")
        print(f"Comandos a ejecutar: {len(commands_to_run)}")
        print(f"Directorio de salida: {self.output_dir}")
        print("=" * 80)

        # Verificar herramientas usando los comandos efectivos
        temp_profile = ScanProfile(profile.name, profile.description, commands_to_run)
        tools_status = self.check_all_tools(temp_profile)
        missing_required = []

        for cmd in commands_to_run:
            tool = cmd['tool']
            if cmd.get('required', False) and not tools_status.get(tool, False):
                missing_required.append(tool)

        if missing_required:
            print(f"\nERROR: Faltan herramientas requeridas: {', '.join(missing_required)}")
            print("\nPara instalarlas:")
            for tool in missing_required:
                if tool == 'nmap':
                    print("  sudo apt-get install nmap")
                elif tool == 'nikto':
                    print("  sudo apt-get install nikto")
                elif tool == 'gobuster':
                    print("  sudo apt-get install gobuster")
            return self.results

        # Advertencia sobre sudo
        if profile.requires_sudo and not is_cidr:
            print("\nADVERTENCIA: Este perfil requiere privilegios de sudo")
            print("   Algunos comandos necesitan permisos elevados")

        # Ejecutar comandos
        print(f"\nIniciando escaneo...")

        successful = 0
        failed = 0

        total_commands = len(commands_to_run)
        for i, command in enumerate(commands_to_run, 1):
            tool = command['tool']

            # Verificar si la herramienta está disponible
            if not tools_status.get(tool, False):
                if self.verbose:
                    print(f"\n[{i}/{total_commands}] Saltando '{tool}' (no disponible)")
                failed += 1
                continue

            if self.verbose:
                print(f"\n[{i}/{total_commands}] Ejecutando {tool}...")

            success = self.execute_command(command, target)

            if step_callback:
                try:
                    step_callback(i, total_commands, tool, success)
                except Exception:
                    pass

            if success:
                successful += 1
            else:
                failed += 1
                if command.get('required', False):
                    print(f"\n❌ ERROR CRÍTICO: Comando requerido falló: {tool}")
                    break
        
        # Finalizar
        self.results['finished_at'] = datetime.now()
        duration = (self.results['finished_at'] - self.results['started_at']).total_seconds()
        
        print("\n" + "=" * 80)
        print("✅ ESCANEO COMPLETADO")
        print("=" * 80)
        print(f"Duración total: {duration:.2f}s")
        print(f"Comandos exitosos: {successful}")
        print(f"Comandos fallidos: {failed}")
        print(f"Archivos generados: {len(self.results['outputs_generated'])}")
        print("\nArchivos de salida:")
        for output in self.results['outputs_generated']:
            print(f"  📄 {output}")
        print("=" * 80)
        
        # Retornar tupla (success, files)
        # Considerar exitoso si se generó al menos un archivo
        success = len(self.results['outputs_generated']) > 0 and successful > 0
        return success, self.results['outputs_generated']
    
    @staticmethod
    def list_profiles():
        """Lista todos los perfiles disponibles"""
        print("\n" + "=" * 80)
        print("📋 PERFILES DE ESCANEO DISPONIBLES")
        print("=" * 80)
        
        for name, profile in VulnerabilityScanner.PROFILES.items():
            print(f"\n🔹 {name.upper()}")
            print(f"   Nombre: {profile.name}")
            print(f"   Descripción: {profile.description}")
            print(f"   Comandos: {len(profile.commands)}")
            if profile.requires_sudo:
                print(f"   ⚠️  Requiere sudo")
            
            print(f"   Herramientas:")
            tools = list(set(cmd['tool'] for cmd in profile.commands))
            for tool in sorted(tools):
                print(f"      • {tool}")
        
        print("\n" + "=" * 80)
    
    @staticmethod
    def show_profile_details(profile_name: str):
        """Muestra detalles de un perfil específico"""
        if profile_name not in VulnerabilityScanner.PROFILES:
            print(f"❌ Perfil '{profile_name}' no existe")
            return
        
        profile = VulnerabilityScanner.PROFILES[profile_name]
        
        print("\n" + "=" * 80)
        print(f"📋 DETALLES DEL PERFIL: {profile.name.upper()}")
        print("=" * 80)
        print(f"Nombre: {profile.name}")
        print(f"Descripción: {profile.description}")
        print(f"Total de comandos: {len(profile.commands)}")
        if profile.requires_sudo:
            print("⚠️  Requiere privilegios de sudo")
        
        print("\n📝 COMANDOS A EJECUTAR:\n")
        
        for i, cmd in enumerate(profile.commands, 1):
            print(f"{i}. {cmd['tool'].upper()}")
            print(f"   Comando: {cmd['args']}")
            print(f"   Salida: {cmd['output']}")
            print(f"   Timeout: {cmd.get('timeout', 300)}s")
            print(f"   Requerido: {'Sí' if cmd.get('required', False) else 'No'}")
            if cmd.get('sudo', False):
                print(f"   Sudo: Sí")
            print()
        
        print("=" * 80)


if __name__ == '__main__':
    """Función principal para testing del scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Scanner de Vulnerabilidades - Módulo de Ejecución'
    )
    
    parser.add_argument(
        '--list-profiles',
        action='store_true',
        help='Lista todos los perfiles disponibles'
    )
    
    parser.add_argument(
        '--show-profile',
        type=str,
        metavar='PROFILE',
        help='Muestra detalles de un perfil específico'
    )
    
    parser.add_argument(
        '--target',
        type=str,
        metavar='IP',
        help='IP o dominio objetivo'
    )
    
    parser.add_argument(
        '--profile',
        type=str,
        choices=list(VulnerabilityScanner.PROFILES.keys()),
        default='standard',
        help='Perfil de escaneo a utilizar'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='./outputs',
        help='Directorio para archivos de salida'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Modo verbose (más detalles)'
    )
    
    args = parser.parse_args()
    
    # Listar perfiles
    if args.list_profiles:
        VulnerabilityScanner.list_profiles()
        sys.exit(0)
    
    # Mostrar detalles de perfil
    if args.show_profile:
        VulnerabilityScanner.show_profile_details(args.show_profile)
        sys.exit(0)
    
    # Ejecutar escaneo
    if not args.target:
        print("❌ ERROR: Debe especificar un target con --target")
        parser.print_help()
        sys.exit(1)
    
    scanner = VulnerabilityScanner(
        output_dir=args.output_dir,
        verbose=args.verbose
    )
    
    scanner.run_scan(args.target, args.profile)
