"""
Report Parser
=============
Parsea archivos raw de escaneo y extrae información estructurada.

Autor: Scan Agent Team
Versión: 2.0.0
"""

import json
import re
from typing import Dict, List, Optional
from pathlib import Path


class ScanResultParser:
    """Parser inteligente de resultados de escaneo"""

    def __init__(self):
        self.results = {
            "target": "",
            "scan_date": "",
            "host_up": False,
            "latency_ms": None,
            "ports": [],
            "os": "Unknown",
            "os_cpe": "",
            "http_info": {},
            "headers": {},
            "nikto_findings": [],
            "directories": [],
            "raw_files": [],
            "nse_findings": [],
            "active_hosts": []
        }

    def parse_all_files(self, output_path: Path, target: str) -> Dict:
        self.results["target"] = target

        if not output_path.exists():
            return self.results

        for file in output_path.glob("*"):
            if not file.is_file():
                continue

            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                filename_lower = file.name.lower()

                if 'nmap' in filename_lower:
                    self.parse_nmap_output(content)
                    if 'nse' in filename_lower or 'vuln' in filename_lower:
                        self.parse_nse_output(content, file.name)
                elif 'header' in filename_lower or 'curl' in filename_lower:
                    self.parse_headers(content)
                elif 'nikto' in filename_lower:
                    self.parse_nikto_output(content)
                elif 'gobuster' in filename_lower or 'dirb' in filename_lower:
                    self.parse_directory_scan(content)
                elif 'whatweb' in filename_lower:
                    self.parse_whatweb_output(content)
                elif 'wafw00f' in filename_lower:
                    self.parse_wafw00f_output(content)
                elif 'sslscan' in filename_lower:
                    self.parse_sslscan_output(content)

                self.results["raw_files"].append({
                    "filename": file.name,
                    "content": content[:3000]
                })

            except Exception as e:
                print(f"⚠️  Error procesando {file.name}: {e}")

        return self.results

    def _parse_nmap_hosts(self, content: str):
        """Extrae lista de hosts activos del output nmap (para escaneos CIDR o multi-host)."""
        host_re = re.compile(
            r'Nmap scan report for (?:([^\s(]+) \()?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?'
        )
        matches = list(host_re.finditer(content))
        if not matches:
            return

        for i, m in enumerate(matches):
            hostname = m.group(1) or ""
            ip = m.group(2)
            block_start = m.start()
            block_end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
            block = content[block_start:block_end]

            if "Host is up" not in block:
                continue

            latency_ms = None
            lat_m = re.search(r'Host is up \(([0-9.]+)s latency\)', block)
            if lat_m:
                latency_ms = round(float(lat_m.group(1)) * 1000, 1)

            ports = []
            for pm in re.finditer(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', block):
                ports.append({
                    "port": int(pm.group(1)),
                    "protocol": pm.group(2),
                    "service": pm.group(3)
                })

            if not any(h["ip"] == ip for h in self.results["active_hosts"]):
                self.results["active_hosts"].append({
                    "ip": ip,
                    "hostname": hostname,
                    "latency_ms": latency_ms,
                    "open_ports": ports
                })

    def parse_nmap_output(self, content: str):
        # Escaneo de descubrimiento (-sn): poblar discovered_hosts con MAC/vendor
        if "Host is up" in content and not re.search(r'\d+/(tcp|udp)\s+open', content):
            discovered = self._parse_host_discovery(content)
            if discovered:
                existing_ips = {h["ip"] for h in self.results.get("active_hosts", [])}
                for h in discovered:
                    if h["ip"] not in existing_ips:
                        self.results["active_hosts"].append(h)
                        existing_ips.add(h["ip"])

        # Extraer hosts activos (escaneos CIDR / multi-host)
        self._parse_nmap_hosts(content)

        if "Host is up" in content:
            self.results["host_up"] = True
            latency_match = re.search(r'Host is up \(([0-9.]+)s latency\)', content)
            if latency_match:
                self.results["latency_ms"] = int(float(latency_match.group(1)) * 1000)

        port_pattern = r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+?))?(?:\n|$)'
        for match in re.finditer(port_pattern, content):
            port_num = match.group(1)
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)
            version_info = match.group(5).strip() if match.group(5) else ""

            if state.lower() == 'open':
                port_data = {
                    "port": int(port_num),
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": version_info if version_info else "Unknown",
                    "product": "",
                    "extra_info": ""
                }
                version_match = re.search(r'([A-Za-z0-9\-\.]+)\s+([\d\.]+)', version_info) if version_info else None
                if version_match:
                    port_data["product"] = version_match.group(1)
                    port_data["version"] = version_match.group(2)

                if not any(p["port"] == int(port_num) for p in self.results["ports"]):
                    self.results["ports"].append(port_data)

        os_patterns = [
            r'Service Info: OS: ([^;]+)',
            r'Running: ([^,\n]+)',
            r'OS details: ([^\n]+)'
        ]
        for pattern in os_patterns:
            os_match = re.search(pattern, content)
            if os_match and self.results["os"] == "Unknown":
                self.results["os"] = os_match.group(1).strip()
                break

        cpe_match = re.search(r'CPE: (cpe:[^\s]+)', content)
        if cpe_match:
            self.results["os_cpe"] = cpe_match.group(1)

    def parse_nse_output(self, content: str, filename: str):
        """Parsea output de scripts NSE de nmap y extrae hallazgos estructurados."""
        current_script = None
        current_lines = []

        nse_block_pattern = re.compile(r'^\| ([a-z][a-z0-9\-]+):', re.MULTILINE)

        for match in nse_block_pattern.finditer(content):
            script_name = match.group(1)
            start = match.start()
            end_match = nse_block_pattern.search(content, match.end())
            block_end = end_match.start() if end_match else len(content)
            block = content[start:block_end]

            self.results["nse_findings"].append({
                "script": script_name,
                "output": block[:500],
                "filename": filename
            })

        # Cabecera de servidor desde NSE
        server_match = re.search(r'\|_http-server-header:\s*(.+)', content)
        if server_match:
            self.results["http_info"]["server"] = server_match.group(1).strip()

    def parse_headers(self, content: str):
        """
        Parsea cabeceras HTTP de output curl verbose o nmap http-headers.
        Solo extrae cabeceras reales de la respuesta HTTP, ignorando cuerpo y metadata.
        """
        lines = content.split('\n')
        in_response = False

        for line in lines:
            # curl verbose: inicio de respuesta HTTP
            if line.startswith('< HTTP/') or line.startswith('HTTP/1') or line.startswith('HTTP/2'):
                in_response = True
                continue

            # Cabeceras nmap: formato "| http-headers:" con "|   Header: value"
            if line.strip().startswith('| http-headers:'):
                in_response = True
                continue

            # Fin de cabeceras curl verbose: línea "<" sola o línea vacía después de estar en headers
            if in_response and line.strip() in ('< ', '<', ''):
                in_response = False
                continue

            # Solo procesar líneas de respuesta curl verbose (empiezan con "<")
            if in_response and line.startswith('< '):
                line = line[2:].strip()
            elif in_response and line.startswith('|   '):
                # Formato nmap http-headers
                line = line[4:].strip()
            elif in_response and line.startswith('*') or (in_response and line.startswith('>')):
                # Metadata o request headers de curl verbose — ignorar
                continue
            elif not in_response:
                continue

            if ':' in line:
                try:
                    key, _, value = line.partition(':')
                    key = key.strip()
                    value = value.strip()
                    # Filtrar líneas que no son cabeceras HTTP reales
                    if key and value and len(key) < 60 and not key.startswith(('*', '>', '<', ' ')):
                        self.results["headers"][key] = value
                        if key.lower() == 'server':
                            self.results["http_info"]["server"] = value
                        if key.lower() == 'x-powered-by':
                            self.results["http_info"]["powered_by"] = value
                except Exception:
                    pass

    def parse_nikto_output(self, content: str):
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('+'):
                finding = line[1:].strip()
                # Omitir líneas de error, advertencia o muy cortas
                if (finding and not finding.startswith('-') and len(finding) > 15
                        and not finding.upper().startswith('ERROR:')
                        and not finding.upper().startswith('WARNING:')
                        and not finding.upper().startswith('NOTICE:')):
                    self.results["nikto_findings"].append(finding)

    def parse_directory_scan(self, content: str):
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if '(Status:' in line or 'CODE:' in line:
                self.results["directories"].append(line)

    def parse_whatweb_output(self, content: str):
        """Parsea salida de whatweb — extrae tecnologías detectadas."""
        if "whatweb_findings" not in self.results:
            self.results["whatweb_findings"] = []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            status_m = re.search(r'\[(\d{3})[^\]]*\]', line)
            status = int(status_m.group(1)) if status_m else None
            techs = re.findall(r'([A-Za-z][A-Za-z0-9_\-\.]+)\[([^\]]+)\]', line)
            entry = {
                "raw": line[:300],
                "http_status": status,
                "technologies": [{"name": t[0], "version": t[1]} for t in techs if t[0] not in ("http", "https")]
            }
            if entry["technologies"] or entry["http_status"]:
                self.results["whatweb_findings"].append(entry)
                if "http_info" not in self.results:
                    self.results["http_info"] = {}
                for tech in entry["technologies"]:
                    if tech["name"].lower() in ("httpserver", "server"):
                        self.results["http_info"]["server"] = tech["version"]
                    if tech["name"].lower() in ("title",):
                        self.results["http_info"]["title"] = tech["version"]
                    if tech["name"].lower() in ("x-powered-by",):
                        self.results["http_info"]["powered_by"] = tech["version"]

    def parse_wafw00f_output(self, content: str):
        """Parsea salida de wafw00f — detecta presencia y nombre de WAF."""
        if "waf_info" not in self.results:
            self.results["waf_info"] = {"detected": False, "name": None, "raw": ""}

        self.results["waf_info"]["raw"] = content[:500]
        content_lower = content.lower()

        if "no waf detected" in content_lower or "generic detection" in content_lower:
            self.results["waf_info"]["detected"] = False
            return

        m = re.search(r'is behind\s+(.+?)\s+(?:WAF|web application firewall)', content, re.IGNORECASE)
        if m:
            self.results["waf_info"]["detected"] = True
            self.results["waf_info"]["name"] = m.group(1).strip()
            return

        if "waf" in content_lower and any(w in content_lower for w in ("detected", "identified", "found")):
            self.results["waf_info"]["detected"] = True

    def parse_sslscan_output(self, content: str):
        """Parsea salida de sslscan — extrae protocolos habilitados y debilidades TLS."""
        if "ssl_info" not in self.results:
            self.results["ssl_info"] = {
                "protocols": {},
                "weak_ciphers": [],
                "certificate": {},
                "issues": []
            }

        ssl = self.results["ssl_info"]

        for line in content.splitlines():
            stripped = line.strip()

            # Protocolos habilitados/deshabilitados
            proto_m = re.match(r'(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s+(enabled|disabled)', stripped, re.IGNORECASE)
            if proto_m:
                proto, state = proto_m.group(1), proto_m.group(2).lower()
                ssl["protocols"][proto] = state == "enabled"
                if state == "enabled" and proto in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
                    ssl["issues"].append(f"Protocolo inseguro habilitado: {proto}")

            # Cifrados débiles
            if re.search(r'\b(DES|RC4|EXPORT|NULL|anon|IDEA)\b', stripped):
                ssl["weak_ciphers"].append(stripped[:120])

            # Fechas de certificado
            exp_m = re.search(r'Not valid after\s*:\s*(.+)', stripped, re.IGNORECASE)
            if exp_m:
                ssl["certificate"]["expires"] = exp_m.group(1).strip()
            cn_m = re.search(r'Subject:\s*(.+)', stripped, re.IGNORECASE)
            if cn_m:
                ssl["certificate"]["subject"] = cn_m.group(1).strip()

    def _parse_host_discovery(self, content: str) -> List[Dict]:
        """Extrae hosts activos de salida nmap -sn, incluyendo MAC/vendor si disponible."""
        discovered = []
        host_re = re.compile(
            r'Nmap scan report for (?:([^\s(]+)\s*\()?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?'
        )
        mac_re = re.compile(r'MAC Address:\s*([0-9A-Fa-f:]{17})\s*(?:\(([^)]+)\))?')

        matches = list(host_re.finditer(content))
        for i, m in enumerate(matches):
            hostname = m.group(1) or ""
            ip = m.group(2)
            block_start = m.start()
            block_end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
            block = content[block_start:block_end]

            if "Host is up" not in block:
                continue

            latency_ms = None
            lat_m = re.search(r'Host is up \(([0-9.]+)s latency\)', block)
            if lat_m:
                latency_ms = round(float(lat_m.group(1)) * 1000, 1)

            mac_info = mac_re.search(block)
            mac = mac_info.group(1) if mac_info else None
            vendor = mac_info.group(2) if mac_info else None

            discovered.append({
                "ip": ip,
                "hostname": hostname,
                "latency_ms": latency_ms,
                "mac": mac,
                "vendor": vendor,
                "open_ports": []
            })

        return discovered


class VulnerabilityAnalyzer:
    """Analiza resultados y clasifica severidad según perfil de escaneo"""

    HIGH_RISK_PORTS = {
        21: "FTP - Protocolo inseguro",
        23: "Telnet - Sin cifrado",
        25: "SMTP - Potencial relay abierto",
        110: "POP3 - Sin cifrado",
        143: "IMAP - Sin cifrado",
        445: "SMB - Vulnerable a ataques de red",
        3306: "MySQL - Base de datos expuesta",
        3389: "RDP - Expuesto a ataques de fuerza bruta",
        5432: "PostgreSQL - Base de datos expuesta",
        6379: "Redis - Sin autenticación por defecto",
        27017: "MongoDB - Base de datos expuesta",
        2049: "NFS - Compartición de archivos insegura",
        161: "SNMP - Posible información del sistema"
    }

    MEDIUM_RISK_PORTS = {
        22: "SSH - Puerto de administración remota",
        80: "HTTP - Comunicación sin cifrado",
        8080: "HTTP-ALT - Sin cifrado",
        8000: "HTTP-DEV - Posible servidor de desarrollo",
        8443: "HTTPS-ALT - Puerto alternativo HTTPS"
    }

    VULNERABLE_VERSIONS = {
        "OpenSSH": {
            "6.6": ["CVE-2016-0777", "CVE-2016-0778"],
            "7.2": ["CVE-2016-10009", "CVE-2016-10010"]
        },
        "Apache": {
            "2.4.7": ["CVE-2017-15710", "CVE-2017-15715"],
            "2.4.49": ["CVE-2021-41773", "CVE-2021-42013"]
        }
    }

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "HIGH",
            "title": "Cabecera HSTS ausente (Strict-Transport-Security)",
            "description": "La cabecera HTTP Strict-Transport-Security no está configurada. Esto permite ataques de degradación de protocolo (SSL stripping) y robo de cookies en tránsito.",
            "recommendations": [
                "Configurar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "Verificar que el sitio funcione correctamente en HTTPS antes de activar HSTS para evitar bloqueos."
            ]
        },
        "Content-Security-Policy": {
            "severity": "HIGH",
            "title": "Política de Seguridad de Contenido ausente (CSP)",
            "description": "La cabecera Content-Security-Policy no está definida. Sin CSP, la aplicación es vulnerable a ataques de Cross-Site Scripting (XSS) e inyección de contenido malicioso.",
            "recommendations": [
                "Definir una política CSP estricta: Content-Security-Policy: default-src 'self'; script-src 'self'",
                "Usar 'report-uri' o 'report-to' para monitorear violaciones de CSP antes de aplicar la política en modo enforce.",
                "Evitar 'unsafe-inline' y 'unsafe-eval' en la directiva script-src."
            ]
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "title": "Protección contra Clickjacking ausente (X-Frame-Options)",
            "description": "Sin la cabecera X-Frame-Options, la aplicación puede ser embebida en iframes de sitios maliciosos, habilitando ataques de clickjacking y robo de credenciales.",
            "recommendations": [
                "Configurar: X-Frame-Options: DENY (recomendado) o SAMEORIGIN",
                "Alternativamente, usar la directiva CSP frame-ancestors para mayor control granular."
            ]
        },
        "X-Content-Type-Options": {
            "severity": "MEDIUM",
            "title": "Protección contra MIME-Sniffing ausente (X-Content-Type-Options)",
            "description": "Sin esta cabecera, los navegadores pueden interpretar archivos con un tipo MIME diferente al declarado, lo que puede permitir ataques de ejecución de contenido.",
            "recommendations": [
                "Configurar: X-Content-Type-Options: nosniff",
                "Asegurarse de que todos los recursos se sirvan con el Content-Type correcto."
            ]
        },
        "X-XSS-Protection": {
            "severity": "LOW",
            "title": "Filtro XSS del navegador no configurado (X-XSS-Protection)",
            "description": "Esta cabecera activa el filtro XSS integrado en navegadores legacy. Su ausencia puede facilitar ataques XSS reflejados en clientes con navegadores antiguos.",
            "recommendations": [
                "Configurar: X-XSS-Protection: 1; mode=block",
                "Implementar una política CSP robusta como protección principal contra XSS."
            ]
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "title": "Política de Referrer no configurada (Referrer-Policy)",
            "description": "Sin esta cabecera, el navegador puede enviar la URL completa como referrer a sitios externos, filtrando parámetros sensibles de la URL como tokens o IDs de sesión.",
            "recommendations": [
                "Configurar: Referrer-Policy: strict-origin-when-cross-origin",
                "Para mayor privacidad, usar 'no-referrer' si no se necesita información de referrer en solicitudes cross-origin."
            ]
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "title": "Política de Permisos del navegador ausente (Permissions-Policy)",
            "description": "Sin esta cabecera, no se controla el acceso de la página a APIs sensibles del navegador como cámara, micrófono o geolocalización.",
            "recommendations": [
                "Configurar: Permissions-Policy: geolocation=(), microphone=(), camera=()",
                "Revisar qué APIs del navegador utiliza la aplicación y denegar explícitamente las que no se necesiten."
            ]
        }
    }

    SENSITIVE_PATHS = {
        "/.git": "CRITICAL",
        "/.env": "CRITICAL",
        "/.env.local": "CRITICAL",
        "/.env.production": "CRITICAL",
        "/backup": "HIGH",
        "/backups": "HIGH",
        "/dump": "HIGH",
        "/db": "HIGH",
        "/admin": "HIGH",
        "/administrator": "HIGH",
        "/wp-admin": "HIGH",
        "/wp-login.php": "HIGH",
        "/phpmyadmin": "HIGH",
        "/console": "HIGH",
        "/manager": "HIGH",
        "/server-status": "HIGH",
        "/server-info": "HIGH",
        "/config": "MEDIUM",
        "/configuration": "MEDIUM",
        "/swagger": "MEDIUM",
        "/swagger-ui": "MEDIUM",
        "/api-docs": "MEDIUM",
        "/openapi": "MEDIUM",
        "/.htaccess": "MEDIUM",
        "/.htpasswd": "HIGH",
        "/logs": "MEDIUM",
        "/log": "MEDIUM",
        "/debug": "MEDIUM",
        "/test": "LOW",
        "/api/v1": "INFO",
        "/api/v2": "INFO",
    }

    def __init__(self, scan_results: Dict, profile: str = "web",
                 catalog: Optional[Dict] = None):
        self.results = scan_results
        self.profile = profile.lower() if profile else "web"
        self.findings = []
        self.risk_score = 0
        # Si se pasa catálogo externo (ej: desde CatalogLoader), úsarlo directamente.
        # Si no, cargar desde disco como siempre (comportamiento legacy).
        self._catalog = catalog if catalog is not None else self._load_catalog()
        # Instance-level copies; catalog overrides on top of class defaults
        self._high_risk_ports = dict(self.HIGH_RISK_PORTS)
        self._medium_risk_ports = dict(self.MEDIUM_RISK_PORTS)
        self._security_headers = {k: dict(v) for k, v in self.SECURITY_HEADERS.items()}
        self._sensitive_paths = dict(self.SENSITIVE_PATHS)
        self._nikto_keywords: Dict = {
            "CRITICAL": (["sql injection", "remote code execution", "rce", "arbitrary file"], 35),
            "HIGH": (["vulnerable", "exploit", "xss", "cross-site scripting", "directory traversal", "lfi", "rfi"], 20),
            "MEDIUM": (["security", "warning", "disclosure", "exposed", "insecure cookie", "missing"], 8),
            "LOW": ([], 3),
        }
        if self._catalog:
            self._apply_catalog()

    @staticmethod
    def _load_catalog() -> Optional[Dict]:
        catalog_path = Path(__file__).parent.parent.parent / "data" / "recommendations_catalog.json"
        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _apply_catalog(self):
        catalog = self._catalog
        for port_str, port_data in catalog.get("ports", {}).items():
            try:
                port_num = int(port_str)
                risk = port_data.get("risk_level", "")
                desc = port_data.get("description", "")
                if risk == "HIGH" and desc:
                    self._high_risk_ports[port_num] = desc
                    self._medium_risk_ports.pop(port_num, None)
                elif risk == "MEDIUM" and desc:
                    self._medium_risk_ports[port_num] = desc
                    self._high_risk_ports.pop(port_num, None)
            except (ValueError, KeyError):
                pass

        for header, header_data in catalog.get("security_headers", {}).items():
            entry = dict(header_data)
            # Normalizar: si el catálogo usa "recommendation" (singular), convertir a lista
            if "recommendation" in entry and "recommendations" not in entry:
                entry["recommendations"] = [entry.pop("recommendation")]
            elif "recommendation" in entry:
                entry.pop("recommendation")
            if header in self._security_headers:
                self._security_headers[header].update(entry)
            else:
                self._security_headers[header] = entry

        for path, path_data in catalog.get("sensitive_paths", {}).items():
            severity = path_data.get("severity")
            if severity:
                self._sensitive_paths[path] = severity

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            kw = catalog.get("nikto_severity_keywords", {}).get(sev)
            if kw is not None:
                _, score = self._nikto_keywords[sev]
                self._nikto_keywords[sev] = (kw, score)

    def analyze(self) -> Dict:
        # Análisis de infraestructura (todos los perfiles)
        self._analyze_ports()
        self._analyze_versions()

        # Análisis web (web, api-owasp, compliance)
        if self.profile in ("web", "api-owasp", "compliance"):
            self._analyze_web_security_headers()
            self._analyze_nikto_findings()
            self._analyze_sensitive_directories()
            self._analyze_nse_web_scripts()

        # Análisis específico API OWASP
        if self.profile == "api-owasp":
            self._analyze_api_owasp()

        # Para network, análisis de Nikto se omite pero NSE sí se incluye
        if self.profile == "network":
            self._analyze_nse_web_scripts()

        risk_level = self._calculate_risk_level()
        return {
            "findings": self.findings,
            "risk_score": self.risk_score,
            "risk_level": risk_level,
            "summary": self._generate_summary(),
            "recommendations": self._generate_recommendations()
        }

    def _analyze_ports(self):
        catalog_ports = self._catalog.get("ports", {}) if self._catalog else {}

        for port in self.results.get("ports", []):
            port_num = port["port"]
            service = port["service"]
            catalog_entry = catalog_ports.get(str(port_num), {})

            severity = "INFO"
            title = f"Puerto {port_num}/{port['protocol']} abierto ({service})"
            description = f"Se detectó el servicio {service} escuchando en el puerto {port_num}."
            recommendations = []
            cves = catalog_entry.get("cves", [])

            if port_num in self._high_risk_ports:
                severity = "CRITICAL"
                desc_tag = self._high_risk_ports[port_num]
                title = f"Puerto de alto riesgo expuesto: {port_num} - {desc_tag}"
                description = f"El puerto {port_num} ({service}) está abierto y representa un riesgo alto de seguridad. {desc_tag}."
                recommendations = catalog_entry.get("recommendations") or [
                    f"Cerrar el puerto {port_num} si el servicio no es estrictamente necesario.",
                    "Implementar reglas de firewall para restringir el acceso solo a IPs autorizadas.",
                    "Usar VPN o túnel cifrado para acceso a servicios administrativos."
                ]
                self.risk_score += 30
            elif port_num in self._medium_risk_ports:
                severity = "MEDIUM"
                desc_tag = self._medium_risk_ports[port_num]
                title = f"Puerto de riesgo medio expuesto: {port_num} - {desc_tag}"
                description = f"El puerto {port_num} ({service}) está abierto. {desc_tag}."
                recommendations = catalog_entry.get("recommendations") or [
                    "Implementar cifrado (HTTPS/TLS) si aún no está habilitado.",
                    "Restringir el acceso por IP mediante firewall.",
                    "Usar autenticación robusta con múltiples factores."
                ]
                self.risk_score += 15
            else:
                severity = "LOW" if port_num > 1024 else "MEDIUM"
                recommendations = catalog_entry.get("recommendations") or [
                    "Verificar que el servicio sea estrictamente necesario.",
                    "Mantener el software del servicio actualizado."
                ]
                self.risk_score += 5

            self.findings.append({
                "vuln_id": f"port_{port_num}",
                "severity": severity,
                "title": title,
                "description": description,
                "port": port_num,
                "service": service,
                "version": port.get("version", "Unknown"),
                "category": "infrastructure",
                "recommendations": recommendations,
                "cves": cves
            })

    def _analyze_versions(self):
        for port in self.results.get("ports", []):
            version_info = port.get("version", "")
            for product, vuln_versions in self.VULNERABLE_VERSIONS.items():
                if product in version_info:
                    for version, cves in vuln_versions.items():
                        if version in version_info:
                            self.findings.append({
                                "vuln_id": f"version_{product.lower()}_{version.replace('.', '_')}",
                                "severity": "CRITICAL",
                                "title": f"Versión vulnerable detectada: {product} {version}",
                                "description": f"Se detectó {product} versión {version} con vulnerabilidades conocidas y explotables.",
                                "port": port["port"],
                                "service": port["service"],
                                "version": version_info,
                                "category": "vulnerable-software",
                                "recommendations": [
                                    f"Actualizar {product} a la última versión estable de forma inmediata.",
                                    "Aplicar parches de seguridad del proveedor.",
                                    "Revisar logs del sistema para detectar posibles explotaciones previas."
                                ],
                                "cves": cves
                            })
                            self.risk_score += 50

    def _analyze_web_security_headers(self):
        """Analiza cabeceras de seguridad HTTP"""
        headers = self.results.get("headers", {})
        if not headers:
            return

        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, info in self._security_headers.items():
            if header.lower() not in headers_lower:
                severity = info["severity"]
                score_map = {"HIGH": 15, "MEDIUM": 8, "LOW": 3}
                self.risk_score += score_map.get(severity, 2)
                # Soportar tanto "recommendations" (lista) como "recommendation" (singular legacy)
                recs = info.get("recommendations") or [info.get("recommendation", "")]
                self.findings.append({
                    "vuln_id": f"header_{header.lower().replace('-', '_')}",
                    "severity": severity,
                    "title": info["title"],
                    "description": info["description"],
                    "port": 443 if "strict-transport-security" in headers_lower else 80,
                    "service": "https" if "strict-transport-security" in headers_lower else "http",
                    "version": "",
                    "category": "web-headers",
                    "recommendations": recs,
                    "cves": []
                })

        # Divulgación de tecnología del servidor
        server = headers_lower.get("server", "")
        powered_by = headers_lower.get("x-powered-by", "")

        if server and any(c.isdigit() for c in server):
            self.findings.append({
                "severity": "LOW",
                "title": f"Divulgación de versión del servidor web: {server}",
                "description": f"La cabecera 'Server' revela la tecnología y versión exacta del servidor: '{server}'. Esta información es útil para atacantes que buscan exploits específicos.",
                "port": 80,
                "service": "http",
                "version": server,
                "category": "web-headers",
                "recommendations": [
                    "Configurar el servidor para ocultar o reemplazar la cabecera 'Server' con un valor genérico.",
                    "Ejemplo en Apache: ServerTokens Prod | En Nginx: server_tokens off;"
                ],
                "cves": []
            })
            self.risk_score += 3

        if powered_by:
            self.findings.append({
                "severity": "LOW",
                "title": f"Divulgación de tecnología backend: X-Powered-By: {powered_by}",
                "description": f"La cabecera 'X-Powered-By' revela el framework o lenguaje backend: '{powered_by}'. Esto facilita la identificación de vulnerabilidades específicas.",
                "port": 80,
                "service": "http",
                "version": powered_by,
                "category": "web-headers",
                "recommendations": [
                    "Eliminar la cabecera X-Powered-By de las respuestas HTTP.",
                    "Ejemplo en PHP: expose_php = Off | En Express.js: app.disable('x-powered-by')"
                ],
                "cves": []
            })
            self.risk_score += 3

    @staticmethod
    def _enrich_nikto_finding(finding: str):
        """Devuelve (descripción explicativa, recomendaciones específicas) para un hallazgo de Nikto."""
        fl = finding.lower()

        # Software desactualizado
        if "outdated" in fl or "deprecated" in fl:
            m = re.search(r'^(?:\[\d+\]\s+)?([A-Za-z0-9_/\-\.]+(?:\s+[A-Za-z0-9_/\-\.]+)?)\s+appears to be outdated', finding, re.IGNORECASE)
            prod = m.group(1) if m else "El software del servidor"
            return (
                f"{prod} está desactualizado. Las versiones antiguas contienen vulnerabilidades conocidas "
                f"sin parche que pueden ser explotadas remotamente. Detalle: {finding}",
                [
                    f"Actualizar {prod} a la última versión estable disponible.",
                    "Suscribirse a los boletines de seguridad del proveedor para recibir alertas de CVEs.",
                    "Revisar el historial de CVEs de esta versión para verificar si el sistema pudo haber sido comprometido."
                ]
            )

        # Listado de directorios habilitado
        if "directory indexing" in fl or ("index of" in fl and "found" in fl):
            m = re.search(r'(/[^\s:,]+)', finding)
            path = m.group(1) if m else "un directorio del servidor"
            return (
                f"El listado de directorios está habilitado en '{path}'. Cualquier visitante puede ver y descargar "
                f"todos los archivos del directorio, incluyendo potencialmente código fuente, backups o configuraciones. Detalle: {finding}",
                [
                    f"Deshabilitar el listado de directorios para '{path}'.",
                    "En Apache: añadir 'Options -Indexes' en el bloque <Directory> correspondiente.",
                    "En Nginx: eliminar 'autoindex on;' de la configuración del servidor."
                ]
            )

        # Cookies inseguras
        if "httponly" in fl or "secure flag" in fl or ("cookie" in fl and any(w in fl for w in ("insecure", "without", "no httponly", "no secure"))):
            return (
                "Las cookies del servidor carecen de atributos de seguridad. Sin 'HttpOnly', scripts JavaScript "
                "maliciosos pueden robar la cookie de sesión (explotable con XSS). Sin 'Secure', las cookies "
                f"se transmiten en texto plano por HTTP. Detalle: {finding}",
                [
                    "Añadir el atributo 'HttpOnly' a todas las cookies de sesión para bloquear el acceso desde JavaScript.",
                    "Añadir el atributo 'Secure' para que las cookies solo viajen por conexiones HTTPS.",
                    "Configurar 'SameSite=Strict' o 'SameSite=Lax' para proteger contra ataques CSRF."
                ]
            )

        # XSS
        if "xss" in fl or "cross-site scripting" in fl:
            return (
                "Posible vulnerabilidad de Cross-Site Scripting (XSS). Un atacante podría inyectar código "
                "JavaScript que se ejecuta en el navegador de otros usuarios, permitiendo robo de cookies, "
                f"suplantación de identidad o redireccionamiento malicioso. Detalle: {finding}",
                [
                    "Escapar todos los datos de entrada antes de incluirlos en el HTML de respuesta.",
                    "Implementar una política Content-Security-Policy (CSP) que restrinja la ejecución de scripts inline.",
                    "Usar funciones de escape según el contexto: HTML, atributos, JavaScript o URL."
                ]
            )

        # SQL Injection
        if "sql injection" in fl or "sqli" in fl:
            return (
                "Posible vulnerabilidad de inyección SQL. Un atacante podría manipular las consultas a la base de datos "
                f"para extraer, modificar o eliminar datos, e incluso ejecutar comandos en el sistema operativo. Detalle: {finding}",
                [
                    "Usar consultas parametrizadas (prepared statements) en lugar de concatenar strings en SQL.",
                    "Validar estrictamente el tipo y formato de todos los parámetros de entrada.",
                    "Aplicar el principio de menor privilegio: las cuentas de base de datos no deben tener permisos de DROP o ALTER."
                ]
            )

        # Directory Traversal / LFI / RFI
        if any(k in fl for k in ("directory traversal", "path traversal", " lfi", " rfi", "local file", "remote file")):
            return (
                "Posible vulnerabilidad de Directory Traversal o inclusión de archivos (LFI/RFI). Un atacante podría "
                "acceder a archivos fuera del directorio web, como /etc/passwd, claves SSH o archivos de configuración "
                f"con credenciales de base de datos. Detalle: {finding}",
                [
                    "Validar que las rutas de archivo no contengan '../', './/' ni variantes codificadas (%2e%2e).",
                    "Usar rutas absolutas definidas en el código y listas blancas de archivos permitidos.",
                    "Asegurarse de que el proceso del servidor web solo tenga acceso al directorio necesario."
                ]
            )

        # RCE / ejecución remota de código
        if any(k in fl for k in ("remote code execution", " rce", "arbitrary code", "arbitrary file", "arbitrary command")):
            return (
                "Posible vulnerabilidad de ejecución remota de código (RCE). Esta es una de las vulnerabilidades "
                "más críticas: un atacante podría ejecutar comandos arbitrarios en el servidor y tomar control completo "
                f"del sistema. Detalle: {finding}",
                [
                    "Aplicar el parche o actualización del proveedor de forma inmediata — esta vulnerabilidad es de prioridad máxima.",
                    "Revisar logs de acceso para detectar si ya ha sido explotada.",
                    "Considerar aislar o apagar el servidor afectado hasta aplicar la corrección."
                ]
            )

        # Divulgación de servidor / tecnología
        if "x-powered-by" in fl or ("retrieved" in fl and "header" in fl) or \
                ("server" in fl and any(k in fl for k in ("apache", "nginx", "iis", "php", "tomcat"))):
            return (
                "El servidor está revelando información sobre su tecnología y versión exacta a través de cabeceras HTTP. "
                "Esta información facilita a los atacantes identificar exploits específicos para la versión detectada. "
                f"Detalle: {finding}",
                [
                    "Ocultar o generalizar la cabecera 'Server': en Apache → ServerTokens Prod; en Nginx → server_tokens off.",
                    "Eliminar la cabecera 'X-Powered-By': en PHP → expose_php = Off; en Express.js → app.disable('x-powered-by').",
                    "Usar un WAF para filtrar cabeceras de respuesta que revelen información de versión."
                ]
            )

        # Archivos de backup o datos sensibles
        if any(k in fl for k in (".bak", ".old", ".backup", ".sql", ".tar", ".zip", ".gz", "backup", "dump", ".orig", ".copy")):
            m = re.search(r'(/[^\s:,]+)', finding)
            path = m.group(1) if m else "el servidor"
            return (
                f"Se encontró un archivo potencialmente sensible accesible en '{path}'. Archivos de backup, "
                "volcados de base de datos o copias de código pueden contener credenciales, datos de usuarios "
                f"o configuraciones de producción. Detalle: {finding}",
                [
                    f"Eliminar o restringir el acceso al archivo '{path}' de forma inmediata.",
                    "Revisar el contenido del archivo para determinar qué datos pudieron haberse expuesto.",
                    "Configurar el servidor para bloquear extensiones sensibles: .bak, .sql, .tar, .orig, .copy."
                ]
            )

        # Panel de administración o login
        if any(k in fl for k in ("admin", "login", "panel", "phpmyadmin", "wp-admin", "dashboard", "manager")):
            m = re.search(r'(/[^\s:,]+)', finding)
            path = m.group(1) if m else "una ruta de administración"
            return (
                f"Se encontró una interfaz de administración o página de login en '{path}'. Las interfaces "
                "administrativas expuestas son objetivos frecuentes de ataques de fuerza bruta y pueden ser "
                f"punto de entrada para comprometer el sistema. Detalle: {finding}",
                [
                    f"Restringir el acceso a '{path}' con autenticación multifactor (MFA) o lista blanca de IPs.",
                    "Configurar bloqueo de cuenta tras múltiples intentos fallidos consecutivos.",
                    "Considerar mover la URL de administración a una ruta no predecible."
                ]
            )

        # Métodos HTTP peligrosos
        if any(k in fl for k in ("http put", "http delete", "http trace", "http options", "allowed methods", "allow: ")):
            return (
                "El servidor tiene habilitados métodos HTTP potencialmente peligrosos. PUT permite subir archivos "
                "arbitrarios, DELETE eliminar recursos del servidor, TRACE puede usarse para robar cookies (XST). "
                f"Detalle: {finding}",
                [
                    "Deshabilitar los métodos HTTP innecesarios (PUT, DELETE, TRACE, OPTIONS, CONNECT).",
                    "En Apache: usar <LimitExcept GET POST> Deny from all </LimitExcept> en la configuración.",
                    "Verificar que el servidor no permita la subida de archivos ejecutables mediante PUT."
                ]
            )

        # Open redirect
        if "redirect" in fl and any(k in fl for k in ("open", "unvalidated", "external")):
            return (
                "Posible vulnerabilidad de redirección abierta. Un atacante puede usar el servidor como trampolín "
                "para redirigir a víctimas hacia sitios maliciosos, con una URL aparentemente legítima "
                f"para mayor credibilidad en ataques de phishing. Detalle: {finding}",
                [
                    "Validar que las redirecciones solo apunten a dominios en una lista blanca de confianza.",
                    "Evitar usar parámetros de URL sin validar para determinar el destino de redirecciones.",
                    "Mostrar una página de confirmación antes de redirigir a URLs externas."
                ]
            )

        # Referencias OSVDB explícitas
        osvdb_nums = re.findall(r'OSVDB-(\d+)', finding, re.IGNORECASE)
        if osvdb_nums:
            refs = ", ".join(f"OSVDB-{n}" for n in osvdb_nums)
            return (
                f"Nikto identificó una vulnerabilidad o configuración insegura con referencia a {refs}. "
                f"Descripción del hallazgo: {finding}",
                [
                    f"Buscar las referencias {refs} en la base de datos NVD (nvd.nist.gov) o MITRE para conocer el impacto exacto.",
                    "Aplicar el parche o la configuración correctiva recomendada por el proveedor.",
                    "Verificar si la versión actual del software ya incluye la corrección."
                ]
            )

        # Exposición de información genérica
        if any(k in fl for k in ("disclosure", "exposed", "reveals", "information", "leaks", "found")):
            return (
                f"El servidor está exponiendo información que podría ser aprovechada por un atacante para planificar "
                f"un ataque más dirigido. Detalle: {finding}",
                [
                    "Revisar la configuración del servidor para minimizar la información expuesta en respuestas HTTP.",
                    "Aplicar el principio de mínima exposición: no revelar versiones, rutas internas ni mensajes de error detallados.",
                    "Consultar la guía OWASP de configuración segura del servidor web."
                ]
            )

        # Fallback: al menos explica el origen y proporciona el hallazgo completo
        return (
            f"Nikto reportó el siguiente hallazgo de seguridad en el servidor web: {finding}",
            [
                "Investigar este hallazgo para determinar su impacto real en el sistema.",
                "Consultar la documentación del servidor web y las guías de hardening de OWASP para mitigarlo."
            ]
        )

    def _analyze_nikto_findings(self):
        """Analiza hallazgos de Nikto con clasificación mejorada"""
        nikto_findings = self.results.get("nikto_findings", [])

        for finding in nikto_findings[:20]:
            finding_lower = finding.lower()
            severity = "LOW"
            score_add = 3

            for sev, (keywords, score) in self._nikto_keywords.items():
                if any(kw in finding_lower for kw in keywords):
                    severity = sev
                    score_add = score
                    break

            description, recommendations = self._enrich_nikto_finding(finding)
            self.risk_score += score_add
            # ID basado en severidad y primeras palabras del hallazgo para identificación única
            nikto_slug = re.sub(r'[^a-z0-9]+', '_', finding[:40].lower()).strip('_')
            self.findings.append({
                "vuln_id": f"nikto_{severity.lower()}_{nikto_slug}",
                "severity": severity,
                "title": f"Hallazgo Nikto: {finding[:80]}",
                "description": description,
                "port": 80,
                "service": "http",
                "version": "",
                "category": "web-nikto",
                "recommendations": recommendations,
                "cves": []
            })

    def _analyze_sensitive_directories(self):
        """Analiza directorios/rutas sensibles encontradas"""
        directories = self.results.get("directories", [])
        if not directories:
            return

        score_map = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 2}

        catalog_paths = self._catalog.get("sensitive_paths", {}) if self._catalog else {}

        for dir_entry in directories:
            dir_lower = dir_entry.lower()
            for sensitive_path, severity in self._sensitive_paths.items():
                if sensitive_path.lower() in dir_lower:
                    self.risk_score += score_map.get(severity, 2)

                    descriptions = {
                        "CRITICAL": f"Se encontró acceso al recurso altamente sensible '{sensitive_path}'. Esto puede exponer código fuente, credenciales o configuración de la aplicación.",
                        "HIGH": f"Se encontró acceso al recurso '{sensitive_path}'. Este recurso puede permitir acceso administrativo no autorizado o exposición de datos.",
                        "MEDIUM": f"Se encontró el recurso '{sensitive_path}' accesible. Podría exponer información de configuración o documentación interna.",
                        "LOW": f"Se encontró el recurso '{sensitive_path}'. Revisar si su exposición es intencional.",
                        "INFO": f"Se encontró el endpoint '{sensitive_path}'. Documentar y verificar su protección."
                    }

                    catalog_recs = catalog_paths.get(sensitive_path, {}).get("recommendations")
                    recommendations = catalog_recs or [
                        f"Bloquear el acceso público a '{sensitive_path}' mediante reglas del servidor o WAF.",
                        "Verificar que no exista información sensible en este recurso y eliminarlo si no es necesario."
                    ]

                    path_slug = sensitive_path.replace('/', '_').replace('.', '').strip('_')
                    self.findings.append({
                        "vuln_id": f"path_{path_slug}",
                        "severity": severity,
                        "title": f"Recurso sensible expuesto: {sensitive_path}",
                        "description": descriptions.get(severity, f"Recurso encontrado: {sensitive_path}. Detalle: {dir_entry}"),
                        "port": 80,
                        "service": "http",
                        "version": "",
                        "category": "web-directories",
                        "recommendations": recommendations,
                        "cves": []
                    })
                    break

    def _analyze_nse_web_scripts(self):
        """Extrae hallazgos de scripts NSE de nmap"""
        nse_findings = self.results.get("nse_findings", [])

        vuln_indicators = [
            ("VULNERABLE", "CRITICAL", 40, "Vulnerabilidad confirmada por script NSE"),
            ("sql injection", "CRITICAL", 35, "Posible inyección SQL detectada"),
            ("cross-site scripting", "HIGH", 25, "Posible XSS detectado"),
            ("xss", "HIGH", 25, "Posible XSS detectado"),
            ("directory listing", "MEDIUM", 10, "Listado de directorios habilitado"),
            ("email disclosure", "LOW", 5, "Exposición de direcciones de email"),
            ("open redirect", "MEDIUM", 10, "Posible redirección abierta"),
        ]

        reported_scripts = set()
        for nse in nse_findings:
            script = nse.get("script", "")
            output = nse.get("output", "").lower()
            filename = nse.get("filename", "")

            if script in reported_scripts:
                continue

            for indicator, severity, score, label in vuln_indicators:
                if indicator.lower() in output:
                    reported_scripts.add(script)
                    self.risk_score += score
                    script_slug = re.sub(r'[^a-z0-9]+', '_', script.lower()).strip('_')
                    self.findings.append({
                        "vuln_id": f"nse_{script_slug}",
                        "severity": severity,
                        "title": f"Script NSE '{script}': {label}",
                        "description": f"El script NSE de nmap '{script}' reportó: {label}. Salida (extracto): {nse.get('output', '')[:300]}",
                        "port": 80,
                        "service": "http",
                        "version": "",
                        "category": "nse-scripts",
                        "recommendations": [
                            "Validar manualmente este hallazgo en el entorno de la aplicación.",
                            "Consultar la documentación del script NSE para detalles de la vulnerabilidad."
                        ],
                        "cves": []
                    })
                    break

    def _analyze_api_owasp(self):
        """Mapea hallazgos al OWASP API Security Top 10 2023"""
        headers = self.results.get("headers", {})
        headers_lower = {k.lower(): v for k, v in headers.items()}
        directories = self.results.get("directories", [])
        dirs_text = " ".join(directories).lower()

        # API7 - CORS Wildcard
        cors = headers_lower.get("access-control-allow-origin", "")
        if cors == "*":
            self.findings.append({
                "vuln_id": "owasp_api7_cors_wildcard",
                "severity": "HIGH",
                "title": "OWASP API7 - CORS Wildcard: Access-Control-Allow-Origin: *",
                "description": "La API permite solicitudes de cualquier origen (CORS wildcard '*'). Esto puede permitir que scripts maliciosos de cualquier dominio accedan a datos de la API en nombre de usuarios autenticados.",
                "port": 80,
                "service": "http",
                "version": "",
                "category": "api-owasp",
                "owasp_category": "API7:2023 - Security Misconfiguration",
                "recommendations": [
                    "Restringir Access-Control-Allow-Origin a dominios específicos de confianza.",
                    "Nunca usar '*' en APIs que manejan datos sensibles o requieren autenticación.",
                    "Implementar una whitelist de orígenes permitidos en la configuración CORS."
                ],
                "cves": []
            })
            self.risk_score += 20

        # API2 - Autenticación
        has_auth_header = any(h in headers_lower for h in ["www-authenticate", "x-api-key"])
        has_auth_scheme = "authorization" in headers_lower
        if not has_auth_header and not has_auth_scheme:
            self.findings.append({
                "vuln_id": "owasp_api2_broken_auth",
                "severity": "MEDIUM",
                "title": "OWASP API2 - Sin indicadores de autenticación en respuestas",
                "description": "No se detectaron cabeceras de autenticación (WWW-Authenticate, X-Api-Key) en las respuestas del servidor. Esto puede indicar endpoints sin protección de autenticación.",
                "port": 80,
                "service": "http",
                "version": "",
                "category": "api-owasp",
                "owasp_category": "API2:2023 - Broken Authentication",
                "recommendations": [
                    "Implementar autenticación JWT u OAuth 2.0 para todos los endpoints de la API.",
                    "Validar tokens en cada solicitud y verificar su expiración.",
                    "Implementar autenticación multifactor para operaciones críticas de la API."
                ],
                "cves": []
            })
            self.risk_score += 10

        # API4 - Rate Limiting
        has_rate_limit = any(h in headers_lower for h in [
            "x-ratelimit-limit", "x-rate-limit-limit", "retry-after",
            "ratelimit-limit", "x-ratelimit-remaining"
        ])
        if not has_rate_limit:
            self.findings.append({
                "vuln_id": "owasp_api4_rate_limiting",
                "severity": "MEDIUM",
                "title": "OWASP API4 - Sin Rate Limiting detectado",
                "description": "No se detectaron cabeceras de limitación de solicitudes (X-RateLimit-Limit, Retry-After). Sin rate limiting, la API es vulnerable a ataques de fuerza bruta, enumeración de recursos y denegación de servicio.",
                "port": 80,
                "service": "http",
                "version": "",
                "category": "api-owasp",
                "owasp_category": "API4:2023 - Unrestricted Resource Consumption",
                "recommendations": [
                    "Implementar rate limiting por IP y por usuario/API key.",
                    "Añadir cabeceras de respuesta: X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After.",
                    "Considerar API gateway con rate limiting integrado (Kong, AWS API Gateway, Nginx)."
                ],
                "cves": []
            })
            self.risk_score += 10

        # API9 - Documentación expuesta
        doc_paths = ["/swagger", "/swagger-ui", "/api-docs", "/openapi", "/redoc"]
        for doc_path in doc_paths:
            if doc_path in dirs_text:
                doc_slug = doc_path.strip('/').replace('-', '_')
                self.findings.append({
                    "vuln_id": f"owasp_api9_docs_{doc_slug}",
                    "severity": "MEDIUM",
                    "title": f"OWASP API9 - Documentación API expuesta: {doc_path}",
                    "description": f"Se encontró documentación de la API accesible públicamente en '{doc_path}'. La exposición pública de Swagger/OpenAPI revela todos los endpoints, parámetros y modelos de datos de la API a potenciales atacantes.",
                    "port": 80,
                    "service": "http",
                    "version": "",
                    "category": "api-owasp",
                    "owasp_category": "API9:2023 - Improper Inventory Management",
                    "recommendations": [
                        "Restringir el acceso a la documentación de la API solo a usuarios autenticados.",
                        "Deshabilitar o proteger el acceso a swagger/openapi en entornos de producción.",
                        "Implementar autenticación básica o token ante de acceder a /swagger-ui y /api-docs."
                    ],
                    "cves": []
                })
                self.risk_score += 8
                break

        # API8 - Cabeceras de seguridad (ya analizadas pero con contexto OWASP)
        missing_security_headers = [
            h for h in ["content-security-policy", "strict-transport-security"]
            if h not in headers_lower
        ]
        if missing_security_headers:
            self.findings.append({
                "vuln_id": "owasp_api8_security_config",
                "severity": "MEDIUM",
                "title": "OWASP API8 - Configuración de seguridad HTTP incompleta",
                "description": f"Faltan cabeceras de seguridad críticas: {', '.join(missing_security_headers)}. Las APIs mal configuradas son vulnerables a ataques de inyección de contenido y robo de sesión.",
                "port": 80,
                "service": "http",
                "version": "",
                "category": "api-owasp",
                "owasp_category": "API8:2023 - Security Misconfiguration",
                "recommendations": [
                    "Aplicar todas las cabeceras de seguridad HTTP recomendadas (OWASP Secure Headers Project).",
                    "Usar HTTPS exclusivamente y configurar HSTS.",
                    "Revisar la configuración de CORS, autenticación y autorización en todos los endpoints."
                ],
                "cves": []
            })

    def _generate_recommendations(self) -> List[str]:
        """Genera recomendaciones según el perfil de escaneo"""
        recommendations = []
        port_numbers = {p["port"] for p in self.results.get("ports", [])}
        high_risk_open = [p for p in self.results.get("ports", []) if p["port"] in self._high_risk_ports]
        has_critical = any(f["severity"] == "CRITICAL" for f in self.findings)
        has_high = any(f["severity"] == "HIGH" for f in self.findings)
        has_nikto = bool(self.results.get("nikto_findings"))
        headers = self.results.get("headers", {})
        headers_lower = {k.lower() for k in headers}

        catalog_globals = (
            self._catalog.get("global_recommendations", []) if self._catalog else []
        )
        catalog_profile_recs = (
            self._catalog.get("profile_recommendations", {}).get(self.profile, [])
            if self._catalog else []
        )

        if self.risk_score >= 100:
            recommendations.append(
                "URGENTE: Se detectaron vulnerabilidades críticas. Tomar acción inmediata antes de continuar operando el sistema en producción."
            )

        if has_critical:
            recommendations.append(
                "Parchear o mitigar de inmediato todas las vulnerabilidades críticas identificadas en este reporte."
            )
            recommendations.append(
                "Revisar los registros (logs) del sistema para detectar posibles compromisos o accesos no autorizados previos."
            )

        if has_high:
            recommendations.append(
                "Planificar la remediación de vulnerabilidades de severidad alta en un plazo máximo de 30 días."
            )

        # Recomendaciones condicionales por perfil (lógica de detección se mantiene)
        if self.profile in ("web", "api-owasp", "compliance"):
            if "content-security-policy" not in headers_lower:
                recommendations.append(
                    "Implementar una política Content-Security-Policy (CSP) estricta para prevenir ataques XSS e inyección de contenido."
                )
            if "strict-transport-security" not in headers_lower:
                recommendations.append(
                    "Habilitar HTTPS y configurar la cabecera HSTS (Strict-Transport-Security) para forzar conexiones cifradas."
                )
            if has_nikto or any(f["category"] == "web-headers" for f in self.findings):
                recommendations.append(
                    "Aplicar el conjunto completo de cabeceras de seguridad HTTP recomendadas por OWASP Secure Headers Project."
                )
            if any(f["category"] == "web-directories" for f in self.findings):
                recommendations.append(
                    "Revisar y bloquear el acceso a recursos sensibles encontrados durante el escaneo de directorios."
                )

        if self.profile == "network":
            if high_risk_open:
                port_list = ", ".join(str(p["port"]) for p in high_risk_open)
                recommendations.append(
                    f"Cerrar o proteger mediante firewall los puertos de alto riesgo expuestos: {port_list}."
                )
            if 22 in port_numbers:
                recommendations.append(
                    "Configurar SSH para autenticación exclusivamente por clave pública y deshabilitar el acceso mediante contraseña (PasswordAuthentication no)."
                )
            if 80 in port_numbers:
                recommendations.append(
                    "Migrar servicios HTTP (puerto 80) a HTTPS e implementar redirección automática."
                )

        # Recomendaciones del catálogo por perfil (estáticas, actualizables via update_catalog.py)
        added = set(recommendations)
        for rec in catalog_profile_recs:
            if rec not in added:
                recommendations.append(rec)
                added.add(rec)

        # Recomendaciones globales siempre presentes (del catálogo si está disponible)
        if catalog_globals:
            for rec in catalog_globals:
                if rec not in added:
                    recommendations.append(rec)
        else:
            recommendations.append(
                "Establecer un proceso regular de actualizaciones y parcheo de seguridad para todos los servicios expuestos."
            )
            recommendations.append(
                "Realizar escaneos de vulnerabilidades periódicos (mínimo mensual) y pruebas de penetración anuales."
            )
            recommendations.append(
                "Implementar monitoreo continuo y alertas tempranas para detectar actividad anómala en los sistemas."
            )

        return recommendations

    def _calculate_risk_level(self) -> str:
        if self.risk_score >= 100:
            return "CRITICAL"
        elif self.risk_score >= 50:
            return "HIGH"
        elif self.risk_score >= 20:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_summary(self) -> Dict:
        categories = {}
        for f in self.findings:
            cat = f.get("category", "general")
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in self.findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in self.findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in self.findings if f["severity"] == "LOW"),
            "info": sum(1 for f in self.findings if f["severity"] == "INFO"),
            "open_ports": len(self.results.get("ports", [])),
            "host_status": "activo" if self.results.get("host_up") else "desconocido",
            "categories": categories
        }
