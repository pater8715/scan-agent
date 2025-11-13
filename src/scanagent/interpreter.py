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
from typing import Dict, List, Any, Tuple
from datetime import datetime


class VulnerabilityInterpreter:
    """
    Clase para interpretar y clasificar vulnerabilidades detectadas.
    """
    
    # Mapeo de categorías OWASP Top 10 2021
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
    
    # Mapeo de severidad a score CVSS
    CVSS_SEVERITY = {
        "none": (0.0, 0.0),
        "baja": (0.1, 3.9),
        "media": (4.0, 6.9),
        "alta": (7.0, 8.9),
        "critica": (9.0, 10.0)
    }
    
    def __init__(self, parsed_data: Dict[str, Any]):
        """
        Inicializa el intérprete con datos parseados.
        
        Args:
            parsed_data: Datos en formato JSON del parser
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
        
        # 4. Clasificar riesgos
        self._classify_risks()
        
        # 5. Generar recomendaciones
        recommendations = self._generate_recommendations()
        
        # 6. Compilar análisis completo
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
        
        # Procesar indicadores OWASP
        for indicator in self.data.get("indicadores_owasp_top10", []):
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
