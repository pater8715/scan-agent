#!/usr/bin/env python3
"""
Report Generator Module - Scan Agent
=====================================
Módulo encargado de generar informes técnicos profesionales en múltiples formatos.

Formatos soportados:
- TXT (texto plano estructurado)
- JSON (formato estructurado para integración)
- HTML (reporte web interactivo)
- Markdown (documentación técnica)

Autor: Scan Agent Team
Versión: 1.0.0
"""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    """
    Generador de informes técnicos de vulnerabilidades.
    """
    
    def __init__(self, analysis_data: Dict[str, Any]):
        """
        Inicializa el generador de informes.
        
        Args:
            analysis_data: Datos del análisis de vulnerabilidades
        """
        self.analysis = analysis_data
        self.metadata = analysis_data.get("metadata", {})
        self.resumen = analysis_data.get("resumen_ejecutivo", {})
        self.superficie = analysis_data.get("superficie_ataque", {})
        self.tecnologias = analysis_data.get("tecnologias_detectadas", {})
        self.vulnerabilidades = analysis_data.get("vulnerabilidades", [])
        self.riesgos = analysis_data.get("resumen_riesgos", {})
        self.recomendaciones = analysis_data.get("recomendaciones", {})
    
    def generate_all_reports(self, output_dir: str = ".") -> Dict[str, str]:
        """
        Genera todos los formatos de informes.
        
        Args:
            output_dir: Directorio donde guardar los informes
        
        Returns:
            Diccionario con las rutas de los archivos generados
        """
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        generated_files = {}
        
        # Generar cada formato
        generated_files["txt"] = self.generate_txt_report(str(output_path / "informe_tecnico.txt"))
        generated_files["json"] = self.generate_json_report(str(output_path / "informe_tecnico.json"))
        generated_files["html"] = self.generate_html_report(str(output_path / "informe_tecnico.html"))
        generated_files["md"] = self.generate_markdown_report(str(output_path / "informe_tecnico.md"))
        
        return generated_files
    
    def generate_txt_report(self, output_file: str) -> str:
        """
        Genera informe en formato texto plano.
        """
        lines = []
        
        # Cabecera
        lines.append("=" * 80)
        lines.append("INFORME TÉCNICO DE ANÁLISIS DE VULNERABILIDADES")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Fecha de Generación: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Target IP: {self.metadata.get('target_ip', 'N/A')}")
        lines.append(f"Total de Vulnerabilidades: {self.metadata.get('total_vulnerabilities', 0)}")
        lines.append("")
        
        # Resumen Ejecutivo
        lines.append("=" * 80)
        lines.append("1. RESUMEN EJECUTIVO")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Nivel de Riesgo General: {self.resumen.get('nivel_riesgo_general', 'N/A')}")
        lines.append(f"Indicador: {self.resumen.get('indicador_color', 'N/A').upper()}")
        lines.append("")
        lines.append("Distribución de Vulnerabilidades:")
        lines.append(f"  - Críticas: {self.resumen.get('vulnerabilidades_criticas', 0)}")
        lines.append(f"  - Altas:    {self.resumen.get('vulnerabilidades_altas', 0)}")
        lines.append(f"  - Medias:   {self.riesgos.get('media', 0)}")
        lines.append(f"  - Bajas:    {self.riesgos.get('baja', 0)}")
        lines.append("")
        lines.append(f"Recomendación General:")
        lines.append(f"  {self.resumen.get('recomendacion_general', 'N/A')}")
        lines.append("")
        
        # Principales Riesgos
        if self.resumen.get('principales_riesgos'):
            lines.append("Principales Riesgos Identificados:")
            for i, riesgo in enumerate(self.resumen.get('principales_riesgos', []), 1):
                lines.append(f"  {i}. {riesgo}")
            lines.append("")
        
        # Superficie de Ataque
        lines.append("=" * 80)
        lines.append("2. MAPA DE SUPERFICIE DE ATAQUE")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Puertos Expuestos: {self.superficie.get('puertos_expuestos', 0)}")
        lines.append(f"Servicios Activos: {self.superficie.get('servicios_activos', 0)}")
        lines.append(f"Endpoints Descubiertos: {self.superficie.get('endpoints_descubiertos', 0)}")
        lines.append("")
        
        # Detalles de puertos
        puertos_detalles = self.superficie.get('detalles_puertos', [])
        if puertos_detalles:
            lines.append("Puertos Detectados:")
            lines.append("-" * 80)
            for puerto in puertos_detalles:
                critico_mark = "[CRÍTICO]" if puerto.get('critico') else ""
                lines.append(f"  Puerto {puerto.get('puerto')}/{puerto.get('protocolo', 'tcp')} - "
                           f"{puerto.get('servicio', 'unknown')} {critico_mark}")
                if puerto.get('version'):
                    lines.append(f"    Versión: {puerto.get('version')}")
                if puerto.get('razon'):
                    lines.append(f"    Riesgo: {puerto.get('razon')}")
            lines.append("")
        
        # Rutas críticas
        rutas_criticas = self.superficie.get('rutas_criticas', [])
        if rutas_criticas:
            lines.append("Rutas Críticas Expuestas:")
            lines.append("-" * 80)
            for ruta in rutas_criticas:
                accesible = "ACCESIBLE" if ruta.get('accesible') else "PROTEGIDA"
                lines.append(f"  {ruta.get('ruta')} - HTTP {ruta.get('codigo_http')} [{accesible}]")
            lines.append("")
        
        # Tecnologías Detectadas
        lines.append("=" * 80)
        lines.append("3. TECNOLOGÍAS DETECTADAS")
        lines.append("=" * 80)
        lines.append("")
        
        # Servidor Web
        if self.tecnologias.get('servidor_web'):
            server = self.tecnologias['servidor_web']
            vuln_mark = "[POTENCIALMENTE VULNERABLE]" if server.get('potencialmente_vulnerable') else ""
            lines.append(f"Servidor Web: {server.get('nombre')} {vuln_mark}")
            lines.append(f"  Versión: {server.get('version')}")
            lines.append("")
        
        # Lenguajes
        if self.tecnologias.get('lenguajes'):
            lines.append("Lenguajes/Frameworks:")
            for lang in self.tecnologias['lenguajes']:
                lines.append(f"  - {lang.get('nombre')}: {lang.get('version')}")
            lines.append("")
        
        # Bases de datos
        if self.tecnologias.get('bases_datos'):
            lines.append("Bases de Datos Detectadas:")
            for db in self.tecnologias['bases_datos']:
                lines.append(f"  - {db.get('nombre')} (Puerto {db.get('puerto')})")
                if db.get('version'):
                    lines.append(f"    Versión: {db.get('version')}")
            lines.append("")
        
        # SSL/TLS
        if self.tecnologias.get('ssl_tls'):
            ssl = self.tecnologias['ssl_tls']
            seguro_mark = "[SEGURO]" if ssl.get('seguro') else "[INSEGURO]"
            lines.append(f"SSL/TLS: {ssl.get('version')} {seguro_mark}")
            lines.append("")
        
        # Vulnerabilidades Detalladas
        lines.append("=" * 80)
        lines.append("4. VULNERABILIDADES DETALLADAS")
        lines.append("=" * 80)
        lines.append("")
        
        # Agrupar por severidad
        for severidad in ['critica', 'alta', 'media', 'baja']:
            vulns_por_severidad = [v for v in self.vulnerabilidades if v.get('severidad') == severidad]
            
            if vulns_por_severidad:
                lines.append(f"\n{severidad.upper()} - {len(vulns_por_severidad)} vulnerabilidad(es)")
                lines.append("-" * 80)
                
                for vuln in vulns_por_severidad:
                    lines.append(f"\nID: {vuln.get('id')}")
                    lines.append(f"Título: {vuln.get('titulo')}")
                    lines.append(f"CVSS Score: {vuln.get('cvss_score')} / 10.0")
                    lines.append(f"Categoría OWASP: {vuln.get('owasp_category')}")
                    lines.append(f"Fuente: {vuln.get('fuente')}")
                    
                    if vuln.get('ubicacion'):
                        lines.append(f"Ubicación: {vuln.get('ubicacion')}")
                    
                    lines.append(f"\nDescripción:")
                    desc = vuln.get('descripcion', 'N/A')
                    # Limitar descripción para legibilidad
                    if len(desc) > 500:
                        desc = desc[:500] + "..."
                    lines.append(f"  {desc}")
                    
                    lines.append(f"\nRecomendación:")
                    lines.append(f"  {vuln.get('recomendacion', 'N/A')}")
                    lines.append("")
        
        # Riesgos Clasificados
        lines.append("=" * 80)
        lines.append("5. RESUMEN DE RIESGOS CLASIFICADOS (CVSS 3.1)")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Total de Vulnerabilidades: {self.riesgos.get('total', 0)}")
        lines.append("")
        lines.append("Distribución por Severidad:")
        lines.append(f"  CRÍTICA (9.0-10.0): {self.riesgos.get('critica', 0)} vulnerabilidades")
        lines.append(f"  ALTA    (7.0-8.9):  {self.riesgos.get('alta', 0)} vulnerabilidades")
        lines.append(f"  MEDIA   (4.0-6.9):  {self.riesgos.get('media', 0)} vulnerabilidades")
        lines.append(f"  BAJA    (0.1-3.9):  {self.riesgos.get('baja', 0)} vulnerabilidades")
        lines.append("")
        
        # Recomendaciones
        lines.append("=" * 80)
        lines.append("6. RECOMENDACIONES DE MITIGACIÓN")
        lines.append("=" * 80)
        lines.append("")
        
        # Corto plazo
        lines.append("CORTO PLAZO (Inmediato - 1 semana):")
        lines.append("-" * 80)
        for rec in self.recomendaciones.get('corto_plazo', []):
            lines.append(f"  • {rec}")
        lines.append("")
        
        # Mediano plazo
        lines.append("MEDIANO PLAZO (1-4 semanas):")
        lines.append("-" * 80)
        for rec in self.recomendaciones.get('mediano_plazo', []):
            lines.append(f"  • {rec}")
        lines.append("")
        
        # Largo plazo
        lines.append("LARGO PLAZO (1-6 meses):")
        lines.append("-" * 80)
        for rec in self.recomendaciones.get('largo_plazo', []):
            lines.append(f"  • {rec}")
        lines.append("")
        
        # Pie de página
        lines.append("=" * 80)
        lines.append("FIN DEL INFORME")
        lines.append("=" * 80)
        lines.append("")
        lines.append("Generado por Scan Agent v1.0.0")
        lines.append(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Guardar archivo
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        print(f"[OK] Informe TXT generado: {output_file}")
        return output_file
    
    def generate_json_report(self, output_file: str) -> str:
        """
        Genera informe en formato JSON estructurado.
        """
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "generator": "Scan Agent v1.0.0",
                "target_ip": self.metadata.get('target_ip'),
                "total_vulnerabilities": self.metadata.get('total_vulnerabilities')
            },
            "executive_summary": self.resumen,
            "attack_surface": self.superficie,
            "technologies": self.tecnologias,
            "vulnerabilities": self.vulnerabilidades,
            "risk_summary": self.riesgos,
            "recommendations": self.recomendaciones
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"[OK] Informe JSON generado: {output_file}")
        return output_file
    
    def generate_html_report(self, output_file: str, scan_id: Optional[int] = None) -> str:
        """
        Genera informe en formato HTML interactivo.
        
        Args:
            output_file: Nombre del archivo de salida
            scan_id: ID del escaneo en BD (para renombrar archivo)
        
        Returns:
            Ruta del archivo generado
        """
        # Si hay scan_id, usar nombre personalizado
        if scan_id is not None:
            output_path = Path(output_file)
            output_file = str(output_path.parent / f"informe_tecnico_{scan_id}.html")
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Informe de Vulnerabilidades - {self.metadata.get('target_ip', 'N/A')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f4f4f4;
            padding: 20px;
        }}
        .dashboard-link {{
            position: fixed;
            top: 20px;
            right: 20px;
            background: #667eea;
            color: white;
            padding: 10px 20px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            transition: all 0.3s;
            z-index: 1000;
        }}
        .dashboard-link:hover {{
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            border-radius: 8px;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 4px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            border-left: 4px solid #3498db;
            padding-left: 10px;
        }}
        h3 {{
            color: #7f8c8d;
            margin-top: 20px;
            margin-bottom: 10px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: white;
            border: none;
        }}
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .metadata-item {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
        }}
        .metadata-label {{
            font-weight: bold;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .metadata-value {{
            font-size: 1.2em;
            color: #2c3e50;
            margin-top: 5px;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.1em;
        }}
        .risk-critico {{
            background: #e74c3c;
            color: white;
        }}
        .risk-alto {{
            background: #e67e22;
            color: white;
        }}
        .risk-medio {{
            background: #f39c12;
            color: white;
        }}
        .risk-bajo {{
            background: #27ae60;
            color: white;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-box {{
            background: #3498db;
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-box.critica {{ background: #e74c3c; }}
        .stat-box.alta {{ background: #e67e22; }}
        .stat-box.media {{ background: #f39c12; }}
        .stat-box.baja {{ background: #27ae60; }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .vulnerability {{
            background: #fff;
            border: 1px solid #ddd;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 15px 0;
            border-radius: 5px;
        }}
        .vulnerability.critica {{ border-left-color: #e74c3c; }}
        .vulnerability.alta {{ border-left-color: #e67e22; }}
        .vulnerability.media {{ border-left-color: #f39c12; }}
        .vulnerability.baja {{ border-left-color: #27ae60; }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .vuln-title {{
            font-weight: bold;
            font-size: 1.1em;
            color: #2c3e50;
        }}
        .cvss-score {{
            background: #34495e;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
        }}
        .vuln-meta {{
            display: flex;
            gap: 15px;
            margin: 10px 0;
            flex-wrap: wrap;
        }}
        .vuln-meta span {{
            background: #ecf0f1;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 0.9em;
        }}
        .vuln-description {{
            margin: 15px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        .vuln-recommendation {{
            margin-top: 15px;
            padding: 15px;
            background: #d1ecf1;
            border-left: 3px solid #0c5460;
            border-radius: 3px;
        }}
        .recommendations {{
            margin: 20px 0;
        }}
        .rec-section {{
            margin: 15px 0;
            padding: 20px;
            border-radius: 5px;
        }}
        .rec-section.corto {{ background: #fee; border-left: 4px solid #e74c3c; }}
        .rec-section.mediano {{ background: #fef5e7; border-left: 4px solid #f39c12; }}
        .rec-section.largo {{ background: #e8f8f5; border-left: 4px solid #27ae60; }}
        .rec-section h3 {{
            margin-top: 0;
        }}
        ul {{
            margin-left: 20px;
            margin-top: 10px;
        }}
        li {{
            margin: 8px 0;
        }}
        .port-table, .tech-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        .port-table th, .port-table td, .tech-table th, .tech-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .port-table th, .tech-table th {{
            background: #34495e;
            color: white;
        }}
        .port-table tr:hover, .tech-table tr:hover {{
            background: #f5f5f5;
        }}
        .critical-port {{
            background: #ffe6e6 !important;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ddd;
            text-align: center;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Informe Técnico de Análisis de Vulnerabilidades</h1>
            <p>Generado por Scan Agent v1.0.0</p>
            <p>Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="metadata">
            <div class="metadata-item">
                <div class="metadata-label">Target IP</div>
                <div class="metadata-value">{self.metadata.get('target_ip', 'N/A')}</div>
            </div>
            <div class="metadata-item">
                <div class="metadata-label">Total Vulnerabilidades</div>
                <div class="metadata-value">{self.metadata.get('total_vulnerabilities', 0)}</div>
            </div>
            <div class="metadata-item">
                <div class="metadata-label">Nivel de Riesgo</div>
                <div class="metadata-value">
                    <span class="risk-badge risk-{self.resumen.get('indicador_color', 'bajo')}">
                        {self.resumen.get('nivel_riesgo_general', 'N/A')}
                    </span>
                </div>
            </div>
        </div>

        <h2>📋 Resumen Ejecutivo</h2>
        <p><strong>Recomendación General:</strong> {self.resumen.get('recomendacion_general', 'N/A')}</p>
        
        <div class="stats">
            <div class="stat-box critica">
                <div class="stat-number">{self.riesgos.get('critica', 0)}</div>
                <div class="stat-label">CRÍTICAS</div>
            </div>
            <div class="stat-box alta">
                <div class="stat-number">{self.riesgos.get('alta', 0)}</div>
                <div class="stat-label">ALTAS</div>
            </div>
            <div class="stat-box media">
                <div class="stat-number">{self.riesgos.get('media', 0)}</div>
                <div class="stat-label">MEDIAS</div>
            </div>
            <div class="stat-box baja">
                <div class="stat-number">{self.riesgos.get('baja', 0)}</div>
                <div class="stat-label">BAJAS</div>
            </div>
        </div>

        {self._generate_top_risks_html()}

        <h2>🎯 Superficie de Ataque</h2>
        <div class="metadata">
            <div class="metadata-item">
                <div class="metadata-label">Puertos Expuestos</div>
                <div class="metadata-value">{self.superficie.get('puertos_expuestos', 0)}</div>
            </div>
            <div class="metadata-item">
                <div class="metadata-label">Servicios Activos</div>
                <div class="metadata-value">{self.superficie.get('servicios_activos', 0)}</div>
            </div>
            <div class="metadata-item">
                <div class="metadata-label">Endpoints Descubiertos</div>
                <div class="metadata-value">{self.superficie.get('endpoints_descubiertos', 0)}</div>
            </div>
        </div>

        {self._generate_ports_table_html()}
        {self._generate_critical_paths_html()}

        <h2>💻 Tecnologías Detectadas</h2>
        {self._generate_technologies_html()}

        <h2>🔐 Vulnerabilidades Detalladas</h2>
        {self._generate_vulnerabilities_html()}

        <h2>✅ Recomendaciones de Mitigación</h2>
        <div class="recommendations">
            {self._generate_recommendations_html()}
        </div>

        <div class="footer">
            <p><strong>Scan Agent v2.1.0</strong></p>
            <p>Informe generado automáticamente el {datetime.now().strftime('%Y-%m-%d a las %H:%M:%S')}</p>
        </div>
    </div>
    
    <!-- Enlace al dashboard -->
    <a href="dashboard.html" class="dashboard-link">⬅ Volver al Dashboard</a>
</body>
</html>"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"[OK] Informe HTML generado: {output_file}")
        return output_file
    
    def generate_markdown_report(self, output_file: str) -> str:
        """
        Genera informe en formato Markdown.
        """
        md_lines = []
        
        # Título
        md_lines.append(f"# Informe Técnico de Análisis de Vulnerabilidades")
        md_lines.append("")
        md_lines.append(f"**Generado por:** Scan Agent v1.0.0  ")
        md_lines.append(f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        md_lines.append(f"**Target IP:** {self.metadata.get('target_ip', 'N/A')}  ")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")
        
        # Resumen Ejecutivo
        md_lines.append("## 📋 Resumen Ejecutivo")
        md_lines.append("")
        md_lines.append(f"**Nivel de Riesgo General:** {self.resumen.get('nivel_riesgo_general', 'N/A')}")
        md_lines.append("")
        md_lines.append("### Distribución de Vulnerabilidades")
        md_lines.append("")
        md_lines.append("| Severidad | Cantidad |")
        md_lines.append("|-----------|----------|")
        md_lines.append(f"| 🔴 Crítica | {self.riesgos.get('critica', 0)} |")
        md_lines.append(f"| 🟠 Alta    | {self.riesgos.get('alta', 0)} |")
        md_lines.append(f"| 🟡 Media   | {self.riesgos.get('media', 0)} |")
        md_lines.append(f"| 🟢 Baja    | {self.riesgos.get('baja', 0)} |")
        md_lines.append("")
        md_lines.append(f"**Recomendación General:**  ")
        md_lines.append(f"{self.resumen.get('recomendacion_general', 'N/A')}")
        md_lines.append("")
        
        # Principales Riesgos
        if self.resumen.get('principales_riesgos'):
            md_lines.append("### Principales Riesgos Identificados")
            md_lines.append("")
            for i, riesgo in enumerate(self.resumen.get('principales_riesgos', []), 1):
                md_lines.append(f"{i}. {riesgo}")
            md_lines.append("")
        
        # Superficie de Ataque
        md_lines.append("## 🎯 Superficie de Ataque")
        md_lines.append("")
        md_lines.append(f"- **Puertos Expuestos:** {self.superficie.get('puertos_expuestos', 0)}")
        md_lines.append(f"- **Servicios Activos:** {self.superficie.get('servicios_activos', 0)}")
        md_lines.append(f"- **Endpoints Descubiertos:** {self.superficie.get('endpoints_descubiertos', 0)}")
        md_lines.append("")
        
        # Tecnologías
        md_lines.append("## 💻 Tecnologías Detectadas")
        md_lines.append("")
        if self.tecnologias.get('servidor_web'):
            server = self.tecnologias['servidor_web']
            md_lines.append(f"**Servidor Web:** {server.get('nombre')} - {server.get('version')}")
            md_lines.append("")
        
        # Vulnerabilidades
        md_lines.append("## 🔐 Vulnerabilidades Detalladas")
        md_lines.append("")
        
        for severidad in ['critica', 'alta', 'media', 'baja']:
            vulns = [v for v in self.vulnerabilidades if v.get('severidad') == severidad]
            if vulns:
                emoji = {'critica': '🔴', 'alta': '🟠', 'media': '🟡', 'baja': '🟢'}.get(severidad, '⚪')
                md_lines.append(f"### {emoji} {severidad.upper()} ({len(vulns)})")
                md_lines.append("")
                
                for vuln in vulns:
                    md_lines.append(f"#### {vuln.get('titulo')}")
                    md_lines.append("")
                    md_lines.append(f"- **ID:** {vuln.get('id')}")
                    md_lines.append(f"- **CVSS Score:** {vuln.get('cvss_score')} / 10.0")
                    md_lines.append(f"- **Categoría OWASP:** {vuln.get('owasp_category')}")
                    md_lines.append(f"- **Fuente:** {vuln.get('fuente')}")
                    if vuln.get('ubicacion'):
                        md_lines.append(f"- **Ubicación:** `{vuln.get('ubicacion')}`")
                    md_lines.append("")
                    md_lines.append(f"**Recomendación:** {vuln.get('recomendacion', 'N/A')}")
                    md_lines.append("")
        
        # Recomendaciones
        md_lines.append("## ✅ Recomendaciones de Mitigación")
        md_lines.append("")
        
        md_lines.append("### 🔴 Corto Plazo (Inmediato - 1 semana)")
        md_lines.append("")
        for rec in self.recomendaciones.get('corto_plazo', []):
            md_lines.append(f"- {rec}")
        md_lines.append("")
        
        md_lines.append("### 🟡 Mediano Plazo (1-4 semanas)")
        md_lines.append("")
        for rec in self.recomendaciones.get('mediano_plazo', []):
            md_lines.append(f"- {rec}")
        md_lines.append("")
        
        md_lines.append("### 🟢 Largo Plazo (1-6 meses)")
        md_lines.append("")
        for rec in self.recomendaciones.get('largo_plazo', []):
            md_lines.append(f"- {rec}")
        md_lines.append("")
        
        # Footer
        md_lines.append("---")
        md_lines.append("")
        md_lines.append(f"*Generado por Scan Agent v1.0.0 el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(md_lines))
        
        print(f"[OK] Informe Markdown generado: {output_file}")
        return output_file
    
    # Métodos auxiliares para HTML
    
    def _generate_top_risks_html(self) -> str:
        """Genera sección HTML de principales riesgos."""
        if not self.resumen.get('principales_riesgos'):
            return ""
        
        html = "<h3>🎯 Principales Riesgos Identificados</h3><ul>"
        for riesgo in self.resumen.get('principales_riesgos', []):
            html += f"<li>{riesgo}</li>"
        html += "</ul>"
        return html
    
    def _generate_ports_table_html(self) -> str:
        """Genera tabla HTML de puertos."""
        puertos = self.superficie.get('detalles_puertos', [])
        if not puertos:
            return ""
        
        html = "<h3>Puertos Detectados</h3>"
        html += '<table class="port-table"><thead><tr>'
        html += '<th>Puerto</th><th>Servicio</th><th>Versión</th><th>Estado</th>'
        html += '</tr></thead><tbody>'
        
        for puerto in puertos:
            row_class = 'critical-port' if puerto.get('critico') else ''
            html += f'<tr class="{row_class}">'
            html += f"<td>{puerto.get('puerto')}</td>"
            html += f"<td>{puerto.get('servicio', 'N/A')}</td>"
            html += f"<td>{puerto.get('version', 'N/A')}</td>"
            estado = "⚠️ CRÍTICO" if puerto.get('critico') else "✅ Normal"
            html += f"<td>{estado}</td>"
            html += '</tr>'
        
        html += '</tbody></table>'
        return html
    
    def _generate_critical_paths_html(self) -> str:
        """Genera sección HTML de rutas críticas."""
        rutas = self.superficie.get('rutas_criticas', [])
        if not rutas:
            return ""
        
        html = "<h3>⚠️ Rutas Críticas Expuestas</h3><ul>"
        for ruta in rutas:
            accesible = "🔴 ACCESIBLE" if ruta.get('accesible') else "🟢 PROTEGIDA"
            html += f"<li><code>{ruta.get('ruta')}</code> - HTTP {ruta.get('codigo_http')} [{accesible}]</li>"
        html += "</ul>"
        return html
    
    def _generate_technologies_html(self) -> str:
        """Genera sección HTML de tecnologías."""
        html = ""
        
        if self.tecnologias.get('servidor_web'):
            server = self.tecnologias['servidor_web']
            vuln_mark = " ⚠️ POTENCIALMENTE VULNERABLE" if server.get('potencialmente_vulnerable') else ""
            html += f"<p><strong>Servidor Web:</strong> {server.get('nombre')} - {server.get('version')}{vuln_mark}</p>"
        
        if self.tecnologias.get('bases_datos'):
            html += "<h3>Bases de Datos</h3><ul>"
            for db in self.tecnologias['bases_datos']:
                html += f"<li>{db.get('nombre')} (Puerto {db.get('puerto')})"
                if db.get('version'):
                    html += f" - {db.get('version')}"
                html += "</li>"
            html += "</ul>"
        
        return html if html else "<p>No se detectaron tecnologías específicas</p>"
    
    def _generate_vulnerabilities_html(self) -> str:
        """Genera sección HTML de vulnerabilidades."""
        html = ""
        
        for severidad in ['critica', 'alta', 'media', 'baja']:
            vulns = [v for v in self.vulnerabilidades if v.get('severidad') == severidad]
            
            if vulns:
                html += f"<h3>{severidad.upper()} ({len(vulns)})</h3>"
                
                for vuln in vulns:
                    html += f'<div class="vulnerability {severidad}">'
                    html += '<div class="vuln-header">'
                    html += f'<div class="vuln-title">{vuln.get("titulo")}</div>'
                    html += f'<div class="cvss-score">CVSS: {vuln.get("cvss_score")}</div>'
                    html += '</div>'
                    
                    html += '<div class="vuln-meta">'
                    html += f'<span><strong>ID:</strong> {vuln.get("id")}</span>'
                    html += f'<span><strong>Categoría OWASP:</strong> {vuln.get("owasp_category")}</span>'
                    html += f'<span><strong>Fuente:</strong> {vuln.get("fuente")}</span>'
                    html += '</div>'
                    
                    desc = vuln.get('descripcion', 'N/A')
                    if len(desc) > 500:
                        desc = desc[:500] + "..."
                    html += f'<div class="vuln-description"><strong>Descripción:</strong><br>{desc}</div>'
                    
                    html += f'<div class="vuln-recommendation"><strong>💡 Recomendación:</strong><br>{vuln.get("recomendacion", "N/A")}</div>'
                    html += '</div>'
        
        return html if html else "<p>No se detectaron vulnerabilidades</p>"
    
    def _generate_recommendations_html(self) -> str:
        """Genera sección HTML de recomendaciones."""
        html = ""
        
        sections = [
            ('corto', 'Corto Plazo (Inmediato - 1 semana)', '🔴'),
            ('mediano', 'Mediano Plazo (1-4 semanas)', '🟡'),
            ('largo', 'Largo Plazo (1-6 meses)', '🟢')
        ]
        
        for key, title, emoji in sections:
            recs = self.recomendaciones.get(f'{key}_plazo', [])
            if recs:
                html += f'<div class="rec-section {key}">'
                html += f'<h3>{emoji} {title}</h3><ul>'
                for rec in recs:
                    html += f'<li>{rec}</li>'
                html += '</ul></div>'
        
        return html


if __name__ == "__main__":
    # Ejemplo de uso del generador de informes
    import sys
    
    print("=" * 60)
    print("SCAN AGENT - REPORT GENERATOR MODULE")
    print("=" * 60)
    
    # Cargar análisis
    analysis_file = "analysis.json"
    
    try:
        with open(analysis_file, 'r', encoding='utf-8') as f:
            analysis_data = json.load(f)
        
        # Crear generador de informes
        generator = ReportGenerator(analysis_data)
        
        print("\n[*] Generando informes en múltiples formatos...")
        files = generator.generate_all_reports()
        
        print("\n" + "=" * 60)
        print("INFORMES GENERADOS:")
        print("=" * 60)
        for format_type, file_path in files.items():
            print(f"  {format_type.upper()}: {file_path}")
        
    except FileNotFoundError:
        print(f"\n[ERROR] No se encontró el archivo {analysis_file}")
        print("Ejecuta primero interpreter.py para generar el análisis")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
