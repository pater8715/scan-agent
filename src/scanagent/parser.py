#!/usr/bin/env python3
"""
Parser Module - Scan Agent
===========================
Módulo encargado de parsear archivos de salida de herramientas de pentesting
y convertirlos en una estructura JSON unificada.

Herramientas soportadas:
- Nmap (service scan y NSE scripts)
- Headers HTTP
- Curl verbose
- Gobuster
- Nikto

Autor: Scan Agent Team
Versión: 1.0.0
"""

import re
import json
from typing import Dict, List, Any, Optional
from pathlib import Path


class ScanParser:
    """
    Clase principal para parsear archivos de escaneo de vulnerabilidades.
    """
    
    def __init__(self, outputs_dir: str = "./outputs"):
        """
        Inicializa el parser.
        
        Args:
            outputs_dir: Directorio donde se encuentran los archivos de salida
        """
        self.outputs_dir = Path(outputs_dir)
        self.parsed_data = {
            "servicios_detectados": [],
            "versiones": {},
            "puertos": [],
            "rutas_descubiertas": [],
            "errores_http": [],
            "vulnerabilidades_nikto": [],
            "indicadores_owasp_top10": [],
            "metadata_http": {}
        }
    
    def parse_all(self, target_ip: str = None) -> Dict[str, Any]:
        """
        Parsea todos los archivos disponibles en el directorio de salida.
        
        Args:
            target_ip: IP objetivo del escaneo (se detecta automáticamente si no se provee)
        
        Returns:
            Diccionario con todos los datos parseados
        """
        if not self.outputs_dir.exists():
            raise FileNotFoundError(f"El directorio {self.outputs_dir} no existe")
        
        # Detectar IP objetivo automáticamente si no se provee
        if not target_ip:
            target_ip = self._detect_target_ip()
        
        self.parsed_data["target_ip"] = target_ip
        
        # Parsear cada tipo de archivo
        self._parse_nmap_service(target_ip)
        self._parse_nmap_nse(target_ip)
        self._parse_headers(target_ip)
        self._parse_curl_verbose(target_ip)
        self._parse_gobuster(target_ip)
        self._parse_nikto(target_ip)
        
        return self.parsed_data
    
    def _detect_target_ip(self) -> Optional[str]:
        """
        Detecta la IP objetivo buscando en los nombres de archivos.
        
        Returns:
            IP detectada o None si no se encuentra
        """
        for file in self.outputs_dir.glob("*.txt"):
            # Buscar patrón de IP en el nombre del archivo
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', file.name)
            if match:
                return match.group(1)
        return "unknown"
    
    def _parse_nmap_service(self, target_ip: str) -> None:
        """
        Parsea el archivo nmap_service_*.txt que contiene información de servicios.
        """
        file_pattern = f"nmap_service_{target_ip}.txt"
        file_path = self.outputs_dir / file_pattern
        
        if not file_path.exists():
            print(f"[WARN] Archivo no encontrado: {file_pattern}")
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parsear puertos abiertos
            # Formato típico: 80/tcp   open  http    Apache httpd 2.4.41
            port_pattern = r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)?'
            
            for match in re.finditer(port_pattern, content):
                port_num = match.group(1)
                protocol = match.group(2)
                state = match.group(3)
                service = match.group(4)
                version_info = match.group(5).strip() if match.group(5) else ""
                
                if state == "open":
                    port_entry = {
                        "puerto": int(port_num),
                        "protocolo": protocol,
                        "servicio": service,
                        "estado": state,
                        "version": version_info
                    }
                    
                    self.parsed_data["puertos"].append(port_entry)
                    self.parsed_data["servicios_detectados"].append({
                        "nombre": service,
                        "puerto": int(port_num),
                        "version": version_info
                    })
                    
                    # Extraer versiones
                    if version_info:
                        self.parsed_data["versiones"][service] = version_info
            
            print(f"[OK] Parseado: {file_pattern} - {len(self.parsed_data['puertos'])} puertos encontrados")
            
        except Exception as e:
            print(f"[ERROR] Al parsear {file_pattern}: {str(e)}")
    
    def _parse_nmap_nse(self, target_ip: str) -> None:
        """
        Parsea el archivo nmap_nse_*.txt que contiene resultados de scripts NSE.
        """
        file_pattern = f"nmap_nse_{target_ip}.txt"
        file_path = self.outputs_dir / file_pattern
        
        if not file_path.exists():
            print(f"[WARN] Archivo no encontrado: {file_pattern}")
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Buscar vulnerabilidades detectadas por NSE scripts
            vuln_patterns = [
                r'VULNERABLE:',
                r'CVE-\d{4}-\d+',
                r'http-sql-injection',
                r'http-csrf',
                r'ssl-.*-vulnerable'
            ]
            
            for pattern in vuln_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Extraer contexto alrededor de la vulnerabilidad
                    start = max(0, match.start() - 100)
                    end = min(len(content), match.end() + 200)
                    context = content[start:end].strip()
                    
                    self.parsed_data["indicadores_owasp_top10"].append({
                        "fuente": "nmap_nse",
                        "tipo": pattern,
                        "contexto": context[:500]  # Limitar tamaño
                    })
            
            # Buscar información de SSL/TLS
            if "ssl" in content.lower() or "tls" in content.lower():
                ssl_match = re.search(r'(TLSv\d\.\d|SSLv\d)', content)
                if ssl_match:
                    self.parsed_data["metadata_http"]["ssl_version"] = ssl_match.group(1)
            
            print(f"[OK] Parseado: {file_pattern}")
            
        except Exception as e:
            print(f"[ERROR] Al parsear {file_pattern}: {str(e)}")
    
    def _parse_headers(self, target_ip: str) -> None:
        """
        Parsea el archivo headers_*.txt que contiene headers HTTP.
        """
        file_pattern = f"headers_{target_ip}.txt"
        file_path = self.outputs_dir / file_pattern
        
        if not file_path.exists():
            print(f"[WARN] Archivo no encontrado: {file_pattern}")
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            headers = {}
            
            # Parsear headers HTTP
            # Formato: Header-Name: Value
            header_pattern = r'^([A-Za-z0-9-]+):\s*(.+)$'
            
            for line in content.split('\n'):
                match = re.match(header_pattern, line.strip())
                if match:
                    header_name = match.group(1)
                    header_value = match.group(2).strip()
                    headers[header_name] = header_value
            
            self.parsed_data["metadata_http"]["headers"] = headers
            
            # Detectar tecnologías desde headers
            if "Server" in headers:
                server_info = headers["Server"]
                self.parsed_data["versiones"]["Server"] = server_info
                
                # Detectar tipo de servidor
                if "apache" in server_info.lower():
                    self.parsed_data["servicios_detectados"].append({
                        "nombre": "Apache",
                        "puerto": 80,
                        "version": server_info
                    })
                elif "nginx" in server_info.lower():
                    self.parsed_data["servicios_detectados"].append({
                        "nombre": "Nginx",
                        "puerto": 80,
                        "version": server_info
                    })
            
            # Detectar headers de seguridad faltantes (OWASP Top 10)
            security_headers = [
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Content-Security-Policy",
                "X-XSS-Protection"
            ]
            
            missing_headers = [h for h in security_headers if h not in headers]
            
            if missing_headers:
                self.parsed_data["indicadores_owasp_top10"].append({
                    "fuente": "headers_http",
                    "tipo": "missing_security_headers",
                    "headers_faltantes": missing_headers,
                    "severidad": "media",
                    "owasp_category": "A05:2021 - Security Misconfiguration"
                })
            
            # Detectar X-Powered-By (información sensible)
            if "X-Powered-By" in headers:
                self.parsed_data["indicadores_owasp_top10"].append({
                    "fuente": "headers_http",
                    "tipo": "information_disclosure",
                    "detalle": f"X-Powered-By revelado: {headers['X-Powered-By']}",
                    "severidad": "baja",
                    "owasp_category": "A05:2021 - Security Misconfiguration"
                })
            
            print(f"[OK] Parseado: {file_pattern} - {len(headers)} headers encontrados")
            
        except Exception as e:
            print(f"[ERROR] Al parsear {file_pattern}: {str(e)}")
    
    def _parse_curl_verbose(self, target_ip: str) -> None:
        """
        Parsea el archivo curl_verbose_*.txt que contiene información detallada de curl.
        """
        file_pattern = f"curl_verbose_{target_ip}.txt"
        file_path = self.outputs_dir / file_pattern
        
        if not file_path.exists():
            print(f"[WARN] Archivo no encontrado: {file_pattern}")
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extraer código de respuesta HTTP
            http_code_match = re.search(r'HTTP/[\d.]+\s+(\d+)\s+(.+)', content)
            if http_code_match:
                code = int(http_code_match.group(1))
                message = http_code_match.group(2).strip()
                
                self.parsed_data["metadata_http"]["http_response_code"] = code
                self.parsed_data["metadata_http"]["http_response_message"] = message
                
                # Detectar errores HTTP
                if code >= 400:
                    self.parsed_data["errores_http"].append({
                        "codigo": code,
                        "mensaje": message,
                        "fuente": "curl_verbose"
                    })
            
            # Detectar información SSL/TLS
            if "SSL connection" in content or "TLS" in content:
                tls_match = re.search(r'(TLSv[\d.]+)', content)
                if tls_match:
                    self.parsed_data["metadata_http"]["tls_version"] = tls_match.group(1)
                
                cipher_match = re.search(r'Cipher:\s*(.+)', content)
                if cipher_match:
                    self.parsed_data["metadata_http"]["cipher"] = cipher_match.group(1).strip()
            
            # Detectar redirects
            if "Location:" in content:
                location_match = re.search(r'Location:\s*(.+)', content)
                if location_match:
                    self.parsed_data["metadata_http"]["redirect_location"] = location_match.group(1).strip()
            
            print(f"[OK] Parseado: {file_pattern}")
            
        except Exception as e:
            print(f"[ERROR] Al parsear {file_pattern}: {str(e)}")
    
    def _parse_gobuster(self, target_ip: str) -> None:
        """
        Parsea el archivo gobuster_*.txt que contiene rutas descubiertas.
        """
        file_pattern = f"gobuster_{target_ip}.txt"
        file_path = self.outputs_dir / file_pattern
        
        if not file_path.exists():
            print(f"[WARN] Archivo no encontrado: {file_pattern}")
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parsear rutas descubiertas
            # Formato típico: /admin (Status: 200) [Size: 1234]
            path_pattern = r'(/[\w\-/._]*)\s+\(Status:\s*(\d+)\)\s*(?:\[Size:\s*(\d+)\])?'
            
            for match in re.finditer(path_pattern, content):
                path = match.group(1)
                status_code = int(match.group(2))
                size = int(match.group(3)) if match.group(3) else None
                
                ruta_entry = {
                    "ruta": path,
                    "codigo_http": status_code,
                    "tamano": size
                }
                
                self.parsed_data["rutas_descubiertas"].append(ruta_entry)
                
                # Detectar rutas sensibles (OWASP Top 10 - Broken Access Control)
                rutas_sensibles = [
                    '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
                    '/config', '/backup', '/database', '/db', '/.git', '/.env',
                    '/api', '/swagger', '/graphql'
                ]
                
                if any(sensitive in path.lower() for sensitive in rutas_sensibles):
                    self.parsed_data["indicadores_owasp_top10"].append({
                        "fuente": "gobuster",
                        "tipo": "ruta_sensible_expuesta",
                        "ruta": path,
                        "codigo_http": status_code,
                        "severidad": "alta" if status_code == 200 else "media",
                        "owasp_category": "A01:2021 - Broken Access Control"
                    })
            
            print(f"[OK] Parseado: {file_pattern} - {len(self.parsed_data['rutas_descubiertas'])} rutas encontradas")
            
        except Exception as e:
            print(f"[ERROR] Al parsear {file_pattern}: {str(e)}")
    
    def _parse_nikto(self, target_ip: str) -> None:
        """
        Parsea el archivo nikto_*.txt que contiene vulnerabilidades detectadas por Nikto.
        """
        file_pattern = f"nikto_{target_ip}.txt"
        file_path = self.outputs_dir / file_pattern
        
        if not file_path.exists():
            print(f"[WARN] Archivo no encontrado: {file_pattern}")
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parsear líneas de vulnerabilidades de Nikto
            # Formato típico: + OSVDB-XXXX: /path: Description
            vuln_pattern = r'\+\s+(OSVDB-\d+)?:?\s*([^\:]+):\s*(.+)'
            
            for match in re.finditer(vuln_pattern, content):
                osvdb_id = match.group(1) if match.group(1) else "N/A"
                location = match.group(2).strip()
                description = match.group(3).strip()
                
                vuln_entry = {
                    "id_osvdb": osvdb_id,
                    "ubicacion": location,
                    "descripcion": description,
                    "fuente": "nikto"
                }
                
                self.parsed_data["vulnerabilidades_nikto"].append(vuln_entry)
                
                # Clasificar según severidad basada en palabras clave
                severidad = "media"
                if any(word in description.lower() for word in ['critical', 'sql injection', 'rce', 'remote code']):
                    severidad = "critica"
                elif any(word in description.lower() for word in ['high', 'xss', 'csrf', 'authentication']):
                    severidad = "alta"
                elif any(word in description.lower() for word in ['info', 'information', 'disclosure']):
                    severidad = "baja"
                
                # Agregar a indicadores OWASP
                self.parsed_data["indicadores_owasp_top10"].append({
                    "fuente": "nikto",
                    "tipo": "vulnerabilidad_nikto",
                    "osvdb_id": osvdb_id,
                    "descripcion": description,
                    "ubicacion": location,
                    "severidad": severidad
                })
            
            # Detectar versión del servidor desde Nikto
            server_match = re.search(r'Server:\s*(.+)', content)
            if server_match:
                self.parsed_data["versiones"]["Server_Nikto"] = server_match.group(1).strip()
            
            print(f"[OK] Parseado: {file_pattern} - {len(self.parsed_data['vulnerabilidades_nikto'])} vulnerabilidades encontradas")
            
        except Exception as e:
            print(f"[ERROR] Al parsear {file_pattern}: {str(e)}")
    
    def save_json(self, output_file: str = "parsed_data.json") -> str:
        """
        Guarda los datos parseados en formato JSON.
        
        Args:
            output_file: Nombre del archivo de salida
        
        Returns:
            Ruta del archivo guardado
        """
        output_path = self.outputs_dir.parent / output_file
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.parsed_data, f, indent=2, ensure_ascii=False)
            
            print(f"[OK] JSON guardado en: {output_path}")
            return str(output_path)
            
        except Exception as e:
            print(f"[ERROR] Al guardar JSON: {str(e)}")
            raise
    
    def get_data(self) -> Dict[str, Any]:
        """
        Retorna los datos parseados.
        
        Returns:
            Diccionario con todos los datos parseados
        """
        return self.parsed_data


if __name__ == "__main__":
    # Ejemplo de uso del parser
    parser = ScanParser("./outputs")
    
    print("=" * 60)
    print("SCAN AGENT - PARSER MODULE")
    print("=" * 60)
    
    try:
        data = parser.parse_all()
        json_file = parser.save_json()
        
        print("\n" + "=" * 60)
        print("RESUMEN DEL PARSEO:")
        print("=" * 60)
        print(f"Target IP: {data.get('target_ip', 'unknown')}")
        print(f"Servicios detectados: {len(data['servicios_detectados'])}")
        print(f"Puertos abiertos: {len(data['puertos'])}")
        print(f"Rutas descubiertas: {len(data['rutas_descubiertas'])}")
        print(f"Vulnerabilidades Nikto: {len(data['vulnerabilidades_nikto'])}")
        print(f"Indicadores OWASP: {len(data['indicadores_owasp_top10'])}")
        print(f"Errores HTTP: {len(data['errores_http'])}")
        print(f"\nJSON guardado en: {json_file}")
        
    except Exception as e:
        print(f"\n[ERROR FATAL] {str(e)}")
        exit(1)
