"""
Report Parser
=============
Parsea archivos raw de escaneo y extrae información estructurada.

Autor: Scan Agent Team
Versión: 1.0.0
"""

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
            "raw_files": []
        }
    
    def parse_all_files(self, output_path: Path, target: str) -> Dict:
        """
        Parsea todos los archivos en el directorio de output.
        
        Args:
            output_path: Directorio con archivos de escaneo
            target: Objetivo escaneado
            
        Returns:
            Diccionario con información estructurada
        """
        self.results["target"] = target
        
        if not output_path.exists():
            return self.results
        
        for file in output_path.glob("*"):
            if not file.is_file():
                continue
            
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Identificar tipo de archivo y parsear
                filename_lower = file.name.lower()
                
                if 'nmap' in filename_lower:
                    self.parse_nmap_output(content)
                elif 'header' in filename_lower:
                    self.parse_headers(content)
                elif 'nikto' in filename_lower:
                    self.parse_nikto_output(content)
                elif 'gobuster' in filename_lower or 'dirb' in filename_lower:
                    self.parse_directory_scan(content)
                
                # Guardar archivo raw (limitado a 2000 chars)
                self.results["raw_files"].append({
                    "filename": file.name,
                    "content": content[:2000]
                })
                
            except Exception as e:
                print(f"⚠️  Error procesando {file.name}: {e}")
        
        return self.results
    
    def parse_nmap_output(self, content: str):
        """
        Parsea output de nmap y extrae información detallada.
        
        Extrae:
        - Estado del host
        - Latencia
        - Puertos abiertos con servicios y versiones
        - Sistema operativo
        - CPE (Common Platform Enumeration)
        """
        # Detectar si el host está up
        if "Host is up" in content:
            self.results["host_up"] = True
            
            # Extraer latencia
            latency_match = re.search(r'Host is up \(([0-9.]+)s latency\)', content)
            if latency_match:
                latency_seconds = float(latency_match.group(1))
                self.results["latency_ms"] = int(latency_seconds * 1000)
        
        # Extraer puertos abiertos con detalles
        # Formato: 22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
        port_pattern = r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+?))?(?:\n|$)'
        
        for match in re.finditer(port_pattern, content):
            port_num = match.group(1)
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)
            version_info = match.group(5).strip() if match.group(5) else ""
            
            # Solo agregar puertos abiertos
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
                
                # Intentar extraer producto y versión específica
                if version_info:
                    # Patrón: Apache httpd 2.4.7 ((Ubuntu))
                    version_pattern = r'([A-Za-z0-9\-\.]+)\s+([\d\.]+)'
                    version_match = re.search(version_pattern, version_info)
                    if version_match:
                        port_data["product"] = version_match.group(1)
                        port_data["version"] = version_match.group(2)
                
                self.results["ports"].append(port_data)
        
        # Detectar sistema operativo
        os_patterns = [
            r'Service Info: OS: ([^;]+)',
            r'Running: ([^,\n]+)',
            r'OS details: ([^\n]+)'
        ]
        
        for pattern in os_patterns:
            os_match = re.search(pattern, content)
            if os_match:
                self.results["os"] = os_match.group(1).strip()
                break
        
        # Extraer CPE si está disponible
        cpe_match = re.search(r'CPE: (cpe:[^\s]+)', content)
        if cpe_match:
            self.results["os_cpe"] = cpe_match.group(1)
    
    def parse_headers(self, content: str):
        """
        Parsea cabeceras HTTP capturadas.
        
        Extrae:
        - Todas las cabeceras HTTP
        - Información del servidor
        - Tecnologías detectadas
        """
        lines = content.split('\n')
        
        for line in lines:
            # Ignorar líneas de separación y stderr
            if line.startswith('===') or not line.strip():
                continue
            
            # Parsear cabeceras formato "Key: Value"
            if ':' in line:
                try:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key and value:
                        self.results["headers"][key] = value
                        
                        # Detectar servidor web
                        if key.lower() == 'server':
                            self.results["http_info"]["server"] = value
                        
                        # Detectar tecnologías
                        if key.lower() == 'x-powered-by':
                            self.results["http_info"]["powered_by"] = value
                except:
                    pass
    
    def parse_nikto_output(self, content: str):
        """
        Parsea output de Nikto web scanner.
        
        Extrae:
        - Vulnerabilidades encontradas
        - Archivos/directorios sensibles
        - Configuraciones inseguras
        """
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Líneas de hallazgos empiezan con +
            if line.startswith('+'):
                # Limpiar el prefijo +
                finding = line[1:].strip()
                
                # Filtrar líneas de progreso y headers
                if finding and not finding.startswith('-') and len(finding) > 10:
                    self.results["nikto_findings"].append(finding)
    
    def parse_directory_scan(self, content: str):
        """
        Parsea output de gobuster/dirb.
        
        Extrae:
        - Directorios encontrados
        - Códigos de estado HTTP
        - Tamaños de respuesta
        """
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Gobuster: /admin (Status: 200) [Size: 1234]
            # Dirb: + http://example.com/admin/ (CODE:200|SIZE:1234)
            
            if '(Status:' in line or 'CODE:' in line:
                self.results["directories"].append(line)


class VulnerabilityAnalyzer:
    """Analiza resultados y clasifica severidad"""
    
    # Base de conocimiento de puertos de riesgo
    HIGH_RISK_PORTS = {
        21: "FTP - Protocolo inseguro",
        23: "Telnet - Sin cifrado",
        25: "SMTP - Potencial relay",
        110: "POP3 - Sin cifrado",
        143: "IMAP - Sin cifrado",
        445: "SMB - Vulnerable a ataques",
        3306: "MySQL - Base de datos expuesta",
        3389: "RDP - Ataque por fuerza bruta",
        5432: "PostgreSQL - Base de datos expuesta",
        6379: "Redis - Sin autenticación por defecto",
        27017: "MongoDB - Base de datos expuesta"
    }
    
    MEDIUM_RISK_PORTS = {
        22: "SSH - Puerto de administración",
        80: "HTTP - Sin cifrado",
        8080: "HTTP-ALT - Sin cifrado",
        8000: "HTTP-DEV - Servidor de desarrollo"
    }
    
    # Versiones vulnerables conocidas
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
    
    def __init__(self, scan_results: Dict):
        self.results = scan_results
        self.findings = []
        self.risk_score = 0
    
    def analyze(self) -> Dict:
        """
        Analiza los resultados y genera hallazgos clasificados.
        
        Returns:
            Diccionario con hallazgos clasificados por severidad
        """
        # Analizar puertos abiertos
        self._analyze_ports()
        
        # Analizar versiones de software
        self._analyze_versions()
        
        # Analizar hallazgos de Nikto
        self._analyze_nikto_findings()
        
        # Calcular nivel de riesgo general
        risk_level = self._calculate_risk_level()
        
        return {
            "findings": self.findings,
            "risk_score": self.risk_score,
            "risk_level": risk_level,
            "summary": self._generate_summary()
        }
    
    def _analyze_ports(self):
        """Analiza puertos abiertos y su riesgo"""
        for port in self.results.get("ports", []):
            port_num = port["port"]
            service = port["service"]
            
            severity = "INFO"
            title = f"Puerto {port_num}/{port['protocol']} abierto ({service})"
            description = f"Se detectó el servicio {service} escuchando en el puerto {port_num}"
            recommendations = []
            
            # Clasificar por riesgo
            if port_num in self.HIGH_RISK_PORTS:
                severity = "CRITICAL"
                title = f"Puerto {port_num} expuesto - {self.HIGH_RISK_PORTS[port_num]}"
                description = f"El puerto {port_num} ({service}) está abierto y representa un riesgo alto de seguridad."
                recommendations = [
                    f"Considerar cerrar el puerto {port_num} si no es necesario",
                    "Implementar firewall restrictivo",
                    "Usar VPN para acceso administrativo"
                ]
                self.risk_score += 30
                
            elif port_num in self.MEDIUM_RISK_PORTS:
                severity = "MEDIUM"
                title = f"Puerto {port_num} expuesto - {self.MEDIUM_RISK_PORTS[port_num]}"
                recommendations = [
                    "Implementar cifrado (HTTPS/SSH)",
                    "Restringir acceso por IP",
                    "Usar autenticación robusta"
                ]
                self.risk_score += 15
            
            else:
                # Puerto no común
                if port_num > 1024:
                    severity = "LOW"
                else:
                    severity = "MEDIUM"
                recommendations = [
                    "Verificar que el servicio sea necesario",
                    "Mantener el software actualizado"
                ]
                self.risk_score += 5
            
            self.findings.append({
                "severity": severity,
                "title": title,
                "description": description,
                "port": port_num,
                "service": service,
                "version": port.get("version", "Unknown"),
                "recommendations": recommendations,
                "cves": []
            })
    
    def _analyze_versions(self):
        """Analiza versiones de software en busca de vulnerabilidades"""
        for port in self.results.get("ports", []):
            version_info = port.get("version", "")
            
            # Buscar versiones vulnerables conocidas
            for product, vuln_versions in self.VULNERABLE_VERSIONS.items():
                if product in version_info:
                    for version, cves in vuln_versions.items():
                        if version in version_info:
                            self.findings.append({
                                "severity": "CRITICAL",
                                "title": f"🔴 Versión Vulnerable: {product} {version}",
                                "description": f"Se detectó {product} {version} que tiene vulnerabilidades conocidas",
                                "port": port["port"],
                                "service": port["service"],
                                "version": version_info,
                                "recommendations": [
                                    f"Actualizar {product} a la última versión estable",
                                    "Aplicar parches de seguridad inmediatamente",
                                    "Revisar logs en busca de actividad sospechosa"
                                ],
                                "cves": cves
                            })
                            self.risk_score += 50
    
    def _analyze_nikto_findings(self):
        """Analiza hallazgos de Nikto"""
        nikto_findings = self.results.get("nikto_findings", [])
        
        for finding in nikto_findings[:10]:  # Limitar a 10 hallazgos
            # Clasificar severidad basado en palabras clave
            severity = "LOW"
            
            if any(keyword in finding.lower() for keyword in ['critical', 'vulnerable', 'exploit']):
                severity = "HIGH"
                self.risk_score += 20
            elif any(keyword in finding.lower() for keyword in ['warning', 'security', 'risk']):
                severity = "MEDIUM"
                self.risk_score += 10
            else:
                self.risk_score += 5
            
            self.findings.append({
                "severity": severity,
                "title": "Hallazgo de Nikto",
                "description": finding,
                "port": 80,  # Asumimos HTTP
                "service": "http",
                "version": "",
                "recommendations": [
                    "Revisar la configuración del servidor web",
                    "Aplicar mejores prácticas de seguridad"
                ],
                "cves": []
            })
    
    def _calculate_risk_level(self) -> str:
        """Calcula el nivel de riesgo general basado en el score"""
        if self.risk_score >= 100:
            return "CRITICAL"
        elif self.risk_score >= 50:
            return "HIGH"
        elif self.risk_score >= 20:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_summary(self) -> Dict:
        """Genera resumen de hallazgos"""
        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in self.findings if f["severity"] == "LOW")
        info = sum(1 for f in self.findings if f["severity"] == "INFO")
        
        return {
            "total_findings": len(self.findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "open_ports": len(self.results.get("ports", [])),
            "host_status": "up" if self.results.get("host_up") else "down"
        }
