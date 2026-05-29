"""
Report Builder
==============
Generadores de reportes profesionales en múltiples formatos (HTML, TXT, Markdown).

Este módulo es parte del PIPELINE WEB (moderno). Se encarga exclusivamente de
transformar el diccionario `scan_data` producido por `generate_basic_reports()`
en documentos legibles para el usuario final.

Separado de `webapp/api/scans.py` para respetar el Principio de Responsabilidad
Única: las rutas API gestionan el ciclo de vida del escaneo; este módulo genera
la presentación de los resultados.

Funciones públicas:
    generate_basic_reports()            — orquesta parseo + análisis + formato
    generate_professional_html_report() — reporte HTML completo con estilos
    generate_professional_txt_report()  — reporte TXT en texto plano
    generate_professional_md_report()   — reporte Markdown
"""

from datetime import datetime
import json
from pathlib import Path
from typing import List

from webapp.utils.report_parser import ScanResultParser, VulnerabilityAnalyzer
from webapp.utils.catalog_loader import catalog_loader


# ---------------------------------------------------------------------------
# Orquestador principal
# ---------------------------------------------------------------------------

def generate_basic_reports(scan_id: str, target: str, profile: str,
                           output_dir: str, formats: List[str]) -> List[str]:
    """
    Genera reportes profesionales usando ScanResultParser y VulnerabilityAnalyzer.
    Parsea archivos raw del escaneo y crea reportes estructurados con análisis de riesgo.
    """
    reports = []
    report_dir = Path("./reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    output_path = Path(output_dir)

    # Parsear archivos raw usando el parser
    parser = ScanResultParser()
    parsed_data = parser.parse_all_files(output_path, target)

    # Analizar vulnerabilidades con catálogo actual (resolución dinámica en tiempo de render)
    current_catalog = catalog_loader.get()
    analyzer = VulnerabilityAnalyzer(parsed_data, profile=profile, catalog=current_catalog)
    analysis = analyzer.analyze()

    # Construir host_info desde campos planos del parser
    host_info = {
        "status": "activo" if parsed_data.get("host_up") else "desconocido",
        "latency": f"{parsed_data['latency_ms']} ms" if parsed_data.get("latency_ms") else "N/A",
        "os": parsed_data.get("os", "Unknown"),
        "os_cpe": parsed_data.get("os_cpe", "")
    }

    # Crear estructura de datos completa con secciones por perfil
    scan_data = {
        "scan_id": scan_id,
        "target": target,
        "profile": profile,
        "timestamp": datetime.now().isoformat(),
        "catalog_sha256": catalog_loader.sha256(),
        "host_info": host_info,
        "ports": parsed_data.get("ports", []),
        "active_hosts": parsed_data.get("active_hosts", []),
        "http_headers": parsed_data.get("headers", {}),
        "nikto_findings": parsed_data.get("nikto_findings", []),
        "directories": parsed_data.get("directories", []),
        "nse_findings": parsed_data.get("nse_findings", []),
        "whatweb_findings": parsed_data.get("whatweb_findings", []),
        "waf_info": parsed_data.get("waf_info", {}),
        "ssl_info": parsed_data.get("ssl_info", {}),
        "vulnerabilities": analysis.get("findings", []),
        "risk_score": analysis.get("risk_score", 0),
        "risk_level": analysis.get("risk_level", "Unknown"),
        "recommendations": analysis.get("recommendations", []),
        "summary": {
            "total_ports": len(parsed_data.get("ports", [])),
            "open_ports": len([p for p in parsed_data.get("ports", []) if p.get("state") == "open"]),
            "critical_findings": len([f for f in analysis.get("findings", []) if f.get("severity", "").upper() == "CRITICAL"]),
            "high_findings": len([f for f in analysis.get("findings", []) if f.get("severity", "").upper() == "HIGH"]),
            "medium_findings": len([f for f in analysis.get("findings", []) if f.get("severity", "").upper() == "MEDIUM"]),
            "low_findings": len([f for f in analysis.get("findings", []) if f.get("severity", "").upper() == "LOW"]),
            "info_findings": len([f for f in analysis.get("findings", []) if f.get("severity", "").upper() == "INFO"]),
            "web_findings": len([f for f in analysis.get("findings", []) if f.get("category", "").startswith("web")]),
            "api_findings": len([f for f in analysis.get("findings", []) if f.get("category", "") == "api-owasp"]),
        }
    }

    # Generar reportes en formatos solicitados
    for fmt in formats:
        try:
            report_path = report_dir / f"scan_{scan_id}.{fmt}"

            if fmt == "json":
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(scan_data, f, indent=2, ensure_ascii=False)
                reports.append(str(report_path))

            elif fmt == "html":
                html_content = generate_professional_html_report(scan_data)
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                reports.append(str(report_path))

            elif fmt == "txt":
                txt_content = generate_professional_txt_report(scan_data)
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(txt_content)
                reports.append(str(report_path))

            elif fmt == "md":
                md_content = generate_professional_md_report(scan_data)
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(md_content)
                reports.append(str(report_path))

        except Exception as e:
            print(f"❌ Error generando reporte {fmt}: {e}")
            import traceback
            traceback.print_exc()

    return reports


# ---------------------------------------------------------------------------
# Helpers HTML internos
# ---------------------------------------------------------------------------

def _html_severity_badge(severity: str) -> str:
    colors = {"CRITICAL": "#d32f2f", "HIGH": "#f57c00", "MEDIUM": "#fbc02d", "LOW": "#689f38", "INFO": "#1976d2"}
    color = colors.get(severity.upper(), "#757575")
    return f'<span style="background:{color};color:white;padding:2px 10px;border-radius:10px;font-size:0.8em;font-weight:bold;">{severity}</span>'


def _generate_headers_table_html(headers: dict) -> str:
    """Genera tabla de cabeceras de seguridad HTTP presente/ausente."""
    required = list(VulnerabilityAnalyzer.SECURITY_HEADERS.keys())
    headers_lower = {k.lower(): v for k, v in headers.items()}
    html = """
            <div class="section">
                <h2>🔒 Análisis de Cabeceras de Seguridad HTTP</h2>
                <table>
                    <thead><tr><th>Cabecera</th><th>Estado</th><th>Valor Detectado / Recomendación</th></tr></thead>
                    <tbody>
"""
    for header in required:
        info = VulnerabilityAnalyzer.SECURITY_HEADERS[header]
        val = headers_lower.get(header.lower(), None)
        if val:
            status = '✅ Presente'
            display = val[:100] if len(val) > 100 else val
            row_style = 'background:#f0fff4;'
        else:
            status = '❌ Ausente'
            # Soportar tanto "recommendations" (lista) como "recommendation" (singular legacy)
            recs = info.get("recommendations") or [info.get("recommendation", "")]
            display = f'<em style="color:#777;">{recs[0]}</em>'
            row_style = 'background:#fff5f5;'
        html += f"""
                        <tr style="{row_style}">
                            <td><code>{header}</code></td>
                            <td>{status}</td>
                            <td style="font-size:0.88em;">{display}</td>
                        </tr>
"""
    # Server/X-Powered-By disclosure
    for h in ["server", "x-powered-by"]:
        val = headers_lower.get(h, None)
        if val:
            html += f"""
                        <tr style="background:#fffde7;">
                            <td><code>{h}</code></td>
                            <td>⚠️ Divulgación</td>
                            <td style="font-size:0.88em;color:#e65100;"><strong>{val}</strong> — Ocultar para evitar fingerprinting</td>
                        </tr>
"""
    html += """
                    </tbody>
                </table>
            </div>
"""
    return html


def _generate_directories_html(directories: list) -> str:
    if not directories:
        return ""
    html = """
            <div class="section">
                <h2>📂 Directorios y Recursos Encontrados</h2>
                <table>
                    <thead><tr><th>#</th><th>Recurso / Ruta</th><th>Detalle</th></tr></thead>
                    <tbody>
"""
    for i, d in enumerate(directories[:50], 1):
        style = ""
        if any(s in d.lower() for s in ["/.git", "/.env", "/backup", "/dump"]):
            style = "background:#fff0f0;"
        elif any(s in d.lower() for s in ["/admin", "/wp-admin", "/phpmyadmin", "/console"]):
            style = "background:#fff3e0;"
        html += f"""
                        <tr style="{style}">
                            <td>{i}</td>
                            <td><code style="font-size:0.9em;">{d[:120]}</code></td>
                            <td style="font-size:0.85em;color:#555;">{"⚠️ Ruta sensible" if style else "Encontrado"}</td>
                        </tr>
"""
    html += """
                    </tbody>
                </table>
            </div>
"""
    return html


def _generate_owasp_api_table_html(vulnerabilities: list) -> str:
    """Genera sección de resumen OWASP API Top 10."""
    owasp_categories = {
        "API1:2023": ("Broken Object Level Authorization", "Permite que atacantes accedan a objetos de otros usuarios manipulando el ID del recurso."),
        "API2:2023": ("Broken Authentication", "Mecanismos de autenticación implementados incorrectamente."),
        "API3:2023": ("Broken Object Property Level Authorization", "Exposición innecesaria de propiedades de objetos."),
        "API4:2023": ("Unrestricted Resource Consumption", "Sin límite de solicitudes, quota o throttling."),
        "API5:2023": ("Broken Function Level Authorization", "Políticas de autorización complejas que llevan a acceso incorrecto a funciones."),
        "API6:2023": ("Unrestricted Access to Sensitive Business Flows", "Acceso sin restricción a flujos de negocio sensibles."),
        "API7:2023": ("Server Side Request Forgery", "Permite a atacantes forzar al servidor a realizar solicitudes a recursos internos."),
        "API8:2023": ("Security Misconfiguration", "Configuración insegura de seguridad en cualquier nivel."),
        "API9:2023": ("Improper Inventory Management", "Endpoints obsoletos o sin documentar exponen la API."),
        "API10:2023": ("Unsafe Consumption of APIs", "Confianza sin validación en datos de APIs externas."),
    }

    # Determinar qué categorías tienen hallazgos
    found_categories = set()
    for v in vulnerabilities:
        owasp_cat = v.get("owasp_category", "")
        for cat_key in owasp_categories:
            if cat_key in owasp_cat:
                found_categories.add(cat_key)

    html = """
            <div class="section">
                <h2>🔐 OWASP API Security Top 10 &mdash; 2023</h2>
                <table>
                    <thead><tr><th>Categoría</th><th>Nombre</th><th>Estado</th><th>Descripción</th></tr></thead>
                    <tbody>
"""
    for cat_key, (name, desc) in owasp_categories.items():
        if cat_key in found_categories:
            status = '⚠️ Hallazgo detectado'
            row_style = 'background:#fff3e0;'
        else:
            status = '✅ Sin evidencia'
            row_style = ''
        html += f"""
                        <tr style="{row_style}">
                            <td><strong>{cat_key}</strong></td>
                            <td>{name}</td>
                            <td>{status}</td>
                            <td style="font-size:0.85em;color:#555;">{desc}</td>
                        </tr>
"""
    html += """
                    </tbody>
                </table>
                <p style="font-size:0.82em;color:#888;margin-top:10px;">
                    ℹ️ Los hallazgos se basan en evidencia observada (cabeceras, respuestas, endpoints encontrados).
                    Una prueba de penetración manual es necesaria para validar cada categoría completamente.
                </p>
            </div>
"""
    return html


def _generate_nikto_html(nikto_findings: list) -> str:
    if not nikto_findings:
        return ""
    html = """
            <div class="section">
                <h2>🕷️ Hallazgos de Escáner Web (Nikto)</h2>
                <table>
                    <thead><tr><th>#</th><th>Hallazgo</th></tr></thead>
                    <tbody>
"""
    for i, f in enumerate(nikto_findings[:30], 1):
        style = ""
        if any(kw in f.lower() for kw in ["vulnerabl", "exploit", "xss", "injection"]):
            style = "background:#fff0f0;"
        html += f"""
                        <tr style="{style}">
                            <td>{i}</td>
                            <td style="font-size:0.88em;">{f[:200]}</td>
                        </tr>
"""
    html += """
                    </tbody>
                </table>
            </div>
"""
    return html


def _generate_profile_html_sections(scan_data: dict) -> str:
    """Genera secciones HTML adicionales según el perfil de escaneo."""
    profile = (scan_data.get("profile") or "web").lower()
    headers = scan_data.get("http_headers", {})
    directories = scan_data.get("directories", [])
    vulnerabilities = scan_data.get("vulnerabilities", [])

    html = ""

    # Sección de cabeceras de seguridad HTTP para web, api-owasp, compliance
    if profile in ("web", "api-owasp", "compliance") and headers:
        html += _generate_headers_table_html(headers)

    # Tabla OWASP API Top 10 para api-owasp
    if profile == "api-owasp":
        html += _generate_owasp_api_table_html(vulnerabilities)

    # Nota: los hallazgos Nikto ya se muestran como tarjetas individuales en la
    # sección "Hallazgos de Seguridad". No se repite la tabla cruda aquí para
    # evitar redundancia en el reporte.

    # Directorios encontrados para web y api-owasp
    if profile in ("web", "api-owasp") and directories:
        html += _generate_directories_html(directories)

    return html


def _profile_label(profile: str) -> tuple:
    """Devuelve (etiqueta, icono, descripción) para el perfil dado."""
    profiles = {
        "web": ("Análisis Web", "🌐", "Vulnerabilidades de aplicaciones web, cabeceras HTTP y directorios"),
        "network": ("Análisis de Red / Infraestructura", "🖧", "Puertos abiertos, servicios, OS y riesgos de infraestructura"),
        "api-owasp": ("Seguridad de API - OWASP Top 10", "🔌", "Vulnerabilidades de API según OWASP API Security Top 10 2023"),
        "compliance": ("Auditoría de Cumplimiento", "✅", "Cabeceras de seguridad, SSL/TLS y buenas prácticas de configuración"),
    }
    return profiles.get(profile.lower() if profile else "", (profile, "🔍", "Escaneo de seguridad"))


# ---------------------------------------------------------------------------
# Generadores de formato
# ---------------------------------------------------------------------------

def generate_professional_html_report(scan_data: dict) -> str:
    """Genera un reporte HTML profesional con secciones específicas por perfil."""
    scan_id = scan_data.get("scan_id", "Unknown")
    target = scan_data.get("target", "Unknown")
    profile = scan_data.get("profile", "Unknown")
    timestamp = scan_data.get("timestamp", "")
    risk_level = scan_data.get("risk_level", "Unknown")
    risk_score = scan_data.get("risk_score", 0)
    summary = scan_data.get("summary", {})
    profile_label, profile_icon, profile_desc = _profile_label(profile)

    # Color del badge según riesgo
    risk_colors = {
        "CRITICAL": "#d32f2f",
        "HIGH": "#f57c00",
        "MEDIUM": "#fbc02d",
        "LOW": "#689f38",
        "INFO": "#1976d2",
        "Unknown": "#757575"
    }
    risk_color = risk_colors.get(risk_level, "#757575")

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad - {scan_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            position: relative;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 8px 20px;
            border-radius: 25px;
            background: {risk_color};
            color: white;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .content {{
            padding: 40px;
        }}
        .executive-summary {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 30px;
            border-left: 5px solid {risk_color};
        }}
        .executive-summary h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .stat-label {{
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-top: 5px;
        }}
        .severity-critical {{ color: #d32f2f; }}
        .severity-high {{ color: #f57c00; }}
        .severity-medium {{ color: #fbc02d; }}
        .severity-low {{ color: #689f38; }}
        .severity-info {{ color: #1976d2; }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.6em;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
        }}
        .info-item {{
            display: flex;
            flex-direction: column;
        }}
        .info-label {{
            font-weight: 600;
            color: #495057;
            font-size: 0.85em;
            text-transform: uppercase;
            margin-bottom: 5px;
        }}
        .info-value {{
            color: #212529;
            font-size: 1.1em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: #34495e;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ecf0f1;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .finding-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .finding-critical {{ border-left-color: #d32f2f; }}
        .finding-high {{ border-left-color: #f57c00; }}
        .finding-medium {{ border-left-color: #fbc02d; }}
        .finding-low {{ border-left-color: #689f38; }}
        .finding-info {{ border-left-color: #1976d2; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .finding-title {{
            font-weight: 600;
            font-size: 1.1em;
            color: #2c3e50;
        }}
        .finding-severity {{
            padding: 4px 12px;
            border-radius: 12px;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .recommendation {{
            background: #e8f5e9;
            padding: 15px;
            border-radius: 6px;
            margin-top: 10px;
            border-left: 3px solid #4caf50;
        }}
        .recommendation-title {{
            font-weight: 600;
            color: #2e7d32;
            margin-bottom: 5px;
        }}
        .collapsible {{
            background: #ecf0f1;
            cursor: pointer;
            padding: 15px;
            border: none;
            text-align: left;
            width: 100%;
            font-size: 1em;
            font-weight: 600;
            border-radius: 6px;
            margin-top: 20px;
        }}
        .collapsible:hover {{
            background: #d5dbdb;
        }}
        .collapsible-content {{
            display: none;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 0 0 6px 6px;
        }}
        .footer {{
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }}
        .filter-chip {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 5px 14px;
            border-radius: 20px;
            border: 2px solid;
            background: transparent;
            font-size: 0.82em;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.15s, color 0.15s;
        }}
        .chip-badge {{
            display: inline-block;
            background: rgba(0,0,0,0.12);
            border-radius: 10px;
            padding: 1px 7px;
            font-size: 0.85em;
        }}
        #findings-filter-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
            margin-bottom: 18px;
            padding: 14px 16px;
            background: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
        }}
        #cat-filter {{
            padding: 6px 12px;
            border: 1px solid #cbd5e0;
            border-radius: 6px;
            background: #fff;
            font-size: 0.88em;
            color: #2d3748;
            cursor: pointer;
            margin-left: auto;
        }}
        #no-findings-msg {{
            display: none;
            padding: 24px;
            text-align: center;
            color: #94a3b8;
            background: #f8f9fa;
            border-radius: 8px;
            border: 1px dashed #cbd5e0;
        }}
        @media print {{
            body {{ background: white; padding: 0; }}
            .container {{ box-shadow: none; }}
            .collapsible-content {{ display: block !important; }}
            #findings-filter-bar {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{profile_icon} Reporte de Seguridad</h1>
            <div class="subtitle">{profile_label} &mdash; {profile_desc}</div>
        </div>

        <div class="content">
            <!-- Resumen Ejecutivo -->
            <div class="executive-summary">
                <h2>📊 Resumen Ejecutivo</h2>
                <div style="margin-bottom: 20px;">
                    <strong>Nivel de Riesgo:</strong> <span class="risk-badge">{risk_level}</span>
                    <span style="margin-left: 20px;"><strong>Puntuación de Riesgo:</strong> {risk_score}/100</span>
                </div>

                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{summary.get('total_ports', 0)}</div>
                        <div class="stat-label">Puertos Totales</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{summary.get('open_ports', 0)}</div>
                        <div class="stat-label">Puertos Abiertos</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value severity-critical">{summary.get('critical_findings', 0)}</div>
                        <div class="stat-label">Críticos</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value severity-high">{summary.get('high_findings', 0)}</div>
                        <div class="stat-label">Altos</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value severity-medium">{summary.get('medium_findings', 0)}</div>
                        <div class="stat-label">Medios</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value severity-low">{summary.get('low_findings', 0)}</div>
                        <div class="stat-label">Bajos</div>
                    </div>
                </div>
            </div>

            <!-- Información del Escaneo -->
            <div class="section">
                <h2>ℹ️ Información del Escaneo</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Scan ID</div>
                        <div class="info-value">{scan_id}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Objetivo</div>
                        <div class="info-value">{target}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Perfil de Escaneo</div>
                        <div class="info-value">{profile_icon} {profile_label}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Fecha de Análisis</div>
                        <div class="info-value">{timestamp[:19].replace('T', ' ')}</div>
                    </div>
                </div>
            </div>
"""

    # Información del Host
    host_info = scan_data.get("host_info", {})
    if host_info:
        html += """
            <!-- Información del Host -->
            <div class="section">
                <h2>🖥️ Información del Host</h2>
                <div class="info-grid">
"""
        if host_info.get("status"):
            html += f"""
                    <div class="info-item">
                        <div class="info-label">Estado</div>
                        <div class="info-value">{host_info['status']}</div>
                    </div>
"""
        if host_info.get("latency"):
            html += f"""
                    <div class="info-item">
                        <div class="info-label">Latencia</div>
                        <div class="info-value">{host_info['latency']}</div>
                    </div>
"""
        if host_info.get("os"):
            html += f"""
                    <div class="info-item">
                        <div class="info-label">Sistema Operativo</div>
                        <div class="info-value">{host_info['os']}</div>
                    </div>
"""
        html += """
                </div>
            </div>
"""

    # Puertos y Servicios
    ports = scan_data.get("ports", [])
    if ports:
        html += """
            <!-- Puertos y Servicios -->
            <div class="section">
                <h2>🔌 Puertos y Servicios Detectados</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Puerto</th>
                            <th>Estado</th>
                            <th>Servicio</th>
                            <th>Versión</th>
                        </tr>
                    </thead>
                    <tbody>
"""
        for port in ports:
            html += f"""
                        <tr>
                            <td><strong>{port.get('port', 'N/A')}</strong></td>
                            <td>{port.get('state', 'N/A')}</td>
                            <td>{port.get('service', 'N/A')}</td>
                            <td>{port.get('version', 'N/A')}</td>
                        </tr>
"""
        html += """
                    </tbody>
                </table>
            </div>
"""

    # Hallazgos de Seguridad
    vulnerabilities = scan_data.get("vulnerabilities", [])
    if vulnerabilities:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        severity_colors_inline = {
            "CRITICAL": "#d32f2f",
            "HIGH": "#f57c00",
            "MEDIUM": "#fbc02d",
            "LOW": "#689f38",
            "INFO": "#1976d2"
        }
        severity_labels = {
            "CRITICAL": "Crítico",
            "HIGH": "Alto",
            "MEDIUM": "Medio",
            "LOW": "Bajo",
            "INFO": "Info"
        }
        category_labels = {
            "infrastructure": "Infraestructura",
            "web-headers": "Cabeceras HTTP",
            "web-nikto": "Nikto",
            "nse-scripts": "Scripts NSE",
            "api-owasp": "API / OWASP",
            "web-directories": "Directorios",
            "vulnerable-software": "Software vulnerable",
            "general": "General"
        }

        sev_counts = {s: 0 for s in severity_order}
        cat_counts = {}
        for v in vulnerabilities:
            s = v.get("severity", "INFO")
            if s in sev_counts:
                sev_counts[s] += 1
            c = v.get("category", "general")
            cat_counts[c] = cat_counts.get(c, 0) + 1

        total = len(vulnerabilities)

        chips_html = (
            f'<button class="filter-chip" data-sev="ALL" onclick="setSevFilter(this,\'ALL\')" '
            f'style="border-color:#94a3b8;color:#94a3b8;">'
            f'Todos <span class="chip-badge">{total}</span></button>\n'
        )
        for sev in severity_order:
            count = sev_counts[sev]
            if count == 0:
                continue
            color = severity_colors_inline[sev]
            label = severity_labels[sev]
            chips_html += (
                f'<button class="filter-chip" data-sev="{sev}" onclick="setSevFilter(this,\'{sev}\')" '
                f'style="border-color:{color};color:{color};">'
                f'{label} <span class="chip-badge">{count}</span></button>\n'
            )

        cat_options = '<option value="ALL">Todos los tipos</option>\n'
        for cat, count in sorted(cat_counts.items()):
            label = category_labels.get(cat, cat)
            cat_options += f'<option value="{cat}">{label} ({count})</option>\n'

        html += f"""
            <!-- Hallazgos de Seguridad -->
            <div class="section" id="findings-section">
                <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:16px;">
                    <h2 style="margin:0;border-bottom:none;padding:0;">🚨 Hallazgos de Seguridad</h2>
                    <span id="findings-counter" style="font-size:0.88em;color:#94a3b8;">Mostrando {total} de {total} hallazgos</span>
                </div>
                <div id="findings-filter-bar">
                    <div style="display:flex;flex-wrap:wrap;gap:6px;">
                        {chips_html}
                    </div>
                    <select id="cat-filter" onchange="applyFindingsFilter()">
                        {cat_options}
                    </select>
                </div>
                <div id="no-findings-msg">Sin hallazgos para los filtros seleccionados.</div>
"""
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "INFO")
            severity_class = severity.lower()
            severity_color = severity_colors_inline.get(severity, "#757575")
            category = vuln.get("category", "general")

            vuln_id = vuln.get('vuln_id', '')
            vuln_id_attr = f' data-vuln-id="{vuln_id}"' if vuln_id else ''
            port_info = f"Puerto {vuln.get('port', '')} ({vuln.get('service', '')})" if vuln.get('port') else ""
            cves = vuln.get('cves', [])
            cves_html = ""
            if cves:
                cves_links = " ".join(
                    f'<a href="https://nvd.nist.gov/vuln/detail/{c}" target="_blank" '
                    f'style="color:#c62828;font-size:0.8em;margin-right:6px;">{c}</a>'
                    for c in cves
                )
                cves_html = f'<div style="margin-top:6px;">{cves_links}</div>'

            recs = vuln.get('recommendations', [])
            recs_html = ""
            if recs:
                items = "".join(f'<li style="margin:4px 0;">{r}</li>' for r in recs)
                recs_html = f"""
                    <div class="recommendation">
                        <div class="recommendation-title">💡 Recomendaciones</div>
                        <ul style="margin:8px 0 0 16px;padding:0;">{items}</ul>
                    </div>
"""
            html += f"""
                <div class="finding-card finding-{severity_class}" data-severity="{severity}" data-category="{category}"{vuln_id_attr}>
                    <div class="finding-header">
                        <div class="finding-title">{vuln.get('title', 'Hallazgo sin título')}</div>
                        <div class="finding-severity" style="background:{severity_color};">{severity}</div>
                    </div>
                    {'<div style="font-size:0.82em;color:#888;margin-bottom:6px;">'+port_info+'</div>' if port_info else ''}
                    <div style="color:#555;margin:10px 0;">{vuln.get('description', 'Sin descripción disponible')}</div>
                    {cves_html}
                    {recs_html}
                </div>
"""
        html += """
            </div>
"""

    # Secciones específicas por perfil (cabeceras HTTP, OWASP, directorios, Nikto)
    html += _generate_profile_html_sections(scan_data)

    # Recomendaciones Generales
    recommendations = scan_data.get("recommendations", [])
    if recommendations:
        html += """
            <!-- Recomendaciones Generales -->
            <div class="section">
                <h2>💡 Recomendaciones</h2>
                <ul style="list-style-type: none; padding: 0;">
"""
        for rec in recommendations:
            html += f"""
                    <li style="padding: 10px; margin: 5px 0; background: #f8f9fa; border-left: 3px solid #3498db; border-radius: 4px;">
                        ✓ {rec}
                    </li>
"""
        html += """
                </ul>
            </div>
"""

    # Datos Raw (colapsable)
    html += """
            <!-- Datos Raw -->
            <button class="collapsible" onclick="this.classList.toggle('active'); this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'block' ? 'none' : 'block';">
                📋 Ver Datos Técnicos Completos (JSON)
            </button>
            <div class="collapsible-content">
                <pre style="background: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 6px; overflow-x: auto; font-size: 0.85em;">"""

    html += json.dumps(scan_data, indent=2, ensure_ascii=False)

    html += """</pre>
            </div>
        </div>

        <div class="footer">
            <p>Generado por ScanAgent v3.0 | {}</p>
            <p style="margin-top: 5px; opacity: 0.8;">Este reporte es confidencial y debe ser tratado de acuerdo con las políticas de seguridad de su organización.</p>
        </div>
    </div>

    <script>
        var _activeSev = 'ALL';
        var _activeCat = 'ALL';

        function setSevFilter(btn, sev) {{
            _activeSev = sev;
            document.querySelectorAll('.filter-chip').forEach(function(b) {{
                b.classList.remove('active');
                b.style.background = 'transparent';
                b.style.color = b.style.borderColor;
            }});
            btn.classList.add('active');
            btn.style.background = btn.style.borderColor;
            btn.style.color = 'white';
            applyFindingsFilter();
        }}

        function applyFindingsFilter() {{
            var catSel = document.getElementById('cat-filter');
            _activeCat = catSel ? catSel.value : 'ALL';
            var cards = document.querySelectorAll('.finding-card');
            var visible = 0;
            cards.forEach(function(card) {{
                var sev = card.getAttribute('data-severity');
                var cat = card.getAttribute('data-category');
                var showSev = (_activeSev === 'ALL' || sev === _activeSev);
                var showCat = (_activeCat === 'ALL' || cat === _activeCat);
                card.style.display = (showSev && showCat) ? '' : 'none';
                if (showSev && showCat) visible++;
            }});
            var counter = document.getElementById('findings-counter');
            if (counter) counter.textContent = 'Mostrando ' + visible + ' de ' + cards.length + ' hallazgos';
            var msg = document.getElementById('no-findings-msg');
            if (msg) msg.style.display = visible === 0 ? 'block' : 'none';
        }}

        function applyHashFilters() {{
            var hash = window.location.hash.slice(1);
            if (!hash) return;
            var params = {{}};
            hash.split('&').forEach(function(p) {{
                var kv = p.split('=');
                if (kv.length === 2) params[decodeURIComponent(kv[0])] = decodeURIComponent(kv[1]);
            }});
            if (params.severity) {{
                var chip = document.querySelector('.filter-chip[data-sev="' + params.severity + '"]');
                if (chip) setSevFilter(chip, params.severity);
            }}
            if (params.category) {{
                var sel = document.getElementById('cat-filter');
                if (sel) {{ sel.value = params.category; applyFindingsFilter(); }}
            }}
        }}

        document.addEventListener('DOMContentLoaded', function() {{
            // Auto-colapsar datos técnicos
            var collapsibles = document.getElementsByClassName('collapsible-content');
            for (var i = 0; i < collapsibles.length; i++) {{
                collapsibles[i].style.display = 'none';
            }}
            // Activar chip "Todos" por defecto
            var allChip = document.querySelector('.filter-chip[data-sev="ALL"]');
            if (allChip) setSevFilter(allChip, 'ALL');
            // Aplicar filtros desde hash de URL si existen
            applyHashFilters();
        }});
    </script>
</body>
</html>
""".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    return html


def generate_professional_txt_report(scan_data: dict) -> str:
    """Genera un reporte TXT profesional."""
    scan_id = scan_data.get("scan_id", "Unknown")
    target = scan_data.get("target", "Unknown")
    profile = scan_data.get("profile", "Unknown")
    timestamp = scan_data.get("timestamp", "")
    risk_level = scan_data.get("risk_level", "Unknown")
    risk_score = scan_data.get("risk_score", 0)
    summary = scan_data.get("summary", {})

    profile_lbl, _, profile_desc = _profile_label(profile)

    txt = f"""
{'='*80}
REPORTE DE SEGURIDAD - SCANAGENT v3.0
{'='*80}

RESUMEN EJECUTIVO
{'-'*80}
Nivel de Riesgo:        {risk_level}
Puntuación de Riesgo:   {risk_score}/100

Hallazgos Críticos:     {summary.get('critical_findings', 0)}
Hallazgos Altos:        {summary.get('high_findings', 0)}
Hallazgos Medios:       {summary.get('medium_findings', 0)}
Hallazgos Bajos:        {summary.get('low_findings', 0)}
Hallazgos Informativos: {summary.get('info_findings', 0)}

INFORMACIÓN DEL ESCANEO
{'-'*80}
Scan ID:                {scan_id}
Objetivo:               {target}
Perfil:                 {profile_lbl} ({profile})
Descripción:            {profile_desc}
Fecha:                  {timestamp[:19].replace('T', ' ')}

Puertos Totales:        {summary.get('total_ports', 0)}
Puertos Abiertos:       {summary.get('open_ports', 0)}

"""

    # Información del Host
    host_info = scan_data.get("host_info", {})
    if host_info:
        txt += f"""
INFORMACIÓN DEL HOST
{'-'*80}
Estado:                 {host_info.get('status', 'N/A')}
Latencia:               {host_info.get('latency', 'N/A')}
Sistema Operativo:      {host_info.get('os', 'N/A')}
"""

    # Puertos y Servicios
    ports = scan_data.get("ports", [])
    if ports:
        txt += f"""
PUERTOS Y SERVICIOS DETECTADOS
{'-'*80}
{'Puerto':<10} {'Estado':<10} {'Servicio':<20} {'Versión':<30}
{'-'*80}
"""
        for port in ports:
            txt += f"{str(port.get('port', 'N/A')):<10} {port.get('state', 'N/A'):<10} {port.get('service', 'N/A'):<20} {port.get('version', 'N/A'):<30}\n"

    # Sección específica: cabeceras de seguridad HTTP (web, api-owasp, compliance)
    profile_lower = profile.lower() if profile else "web"
    if profile_lower in ("web", "api-owasp", "compliance"):
        headers = scan_data.get("http_headers", {})
        if headers:
            required = list(VulnerabilityAnalyzer.SECURITY_HEADERS.keys())
            headers_lower = {k.lower(): v for k, v in headers.items()}
            txt += f"""
ANÁLISIS DE CABECERAS DE SEGURIDAD HTTP
{'-'*80}
{'Cabecera':<45} {'Estado':<15}
{'-'*80}
"""
            for h in required:
                estado = "PRESENTE" if h.lower() in headers_lower else "AUSENTE ⚠"
                txt += f"{h:<45} {estado}\n"

        # Hallazgos Nikto
        nikto = scan_data.get("nikto_findings", [])
        if nikto:
            txt += f"""
HALLAZGOS DEL ESCÁNER WEB (NIKTO)
{'-'*80}
"""
            for i, f in enumerate(nikto[:30], 1):
                txt += f"{i:>3}. {f[:160]}\n"

        # Directorios sensibles encontrados
        directories = scan_data.get("directories", [])
        if directories:
            txt += f"""
DIRECTORIOS Y RECURSOS ENCONTRADOS
{'-'*80}
"""
            for i, d in enumerate(directories[:50], 1):
                txt += f"{i:>3}. {d[:160]}\n"

    # Hallazgos de Seguridad (agrupados por categoría)
    vulnerabilities = scan_data.get("vulnerabilities", [])
    if vulnerabilities:
        cats_order = ["infrastructure", "vulnerable-software", "web-headers",
                      "web-nikto", "web-directories", "nse-scripts", "api-owasp", "general"]
        cats_labels = {
            "infrastructure": "INFRAESTRUCTURA (PUERTOS Y SERVICIOS)",
            "vulnerable-software": "SOFTWARE VULNERABLE (CVE)",
            "web-headers": "CABECERAS DE SEGURIDAD HTTP",
            "web-nikto": "HALLAZGOS WEB (NIKTO)",
            "web-directories": "RECURSOS SENSIBLES (DIRECTORIOS)",
            "nse-scripts": "SCRIPTS NSE DE NMAP",
            "api-owasp": "OWASP API SECURITY TOP 10",
            "general": "OTROS HALLAZGOS"
        }
        grouped = {}
        for v in vulnerabilities:
            cat = v.get("category", "general")
            if cat not in grouped:
                grouped[cat] = []
            grouped[cat].append(v)

        for cat in cats_order:
            if cat not in grouped:
                continue
            cat_vulns = grouped[cat]
            txt += f"""
{cats_labels.get(cat, cat.upper())}
{'-'*80}
"""
            for i, vuln in enumerate(cat_vulns, 1):
                vuln_id = vuln.get('vuln_id', '')
                id_line = f"    ID:          {vuln_id}\n" if vuln_id else ""
                cves = vuln.get('cves', [])
                cves_line = f"    CVEs:        {', '.join(cves)}\n" if cves else ""
                txt += f"""
[{i}] {vuln.get('title', 'Hallazgo sin título')}
    Severidad:   {vuln.get('severity', 'INFO')}
{id_line}{cves_line}    Descripción: {vuln.get('description', 'Sin descripción')[:200]}
"""
                recs = vuln.get('recommendations', [])
                if recs:
                    txt += "    Remediación:\n"
                    for j, r in enumerate(recs, 1):
                        txt += f"      {j}. {r[:160]}\n"
                txt += "\n"

    # Recomendaciones
    recommendations = scan_data.get("recommendations", [])
    if recommendations:
        txt += f"""
RECOMENDACIONES GENERALES
{'-'*80}
"""
        for i, rec in enumerate(recommendations, 1):
            txt += f"{i}. {rec}\n"

    txt += f"""
{'='*80}
Generado por ScanAgent v3.0 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*80}
"""

    return txt


def generate_professional_md_report(scan_data: dict) -> str:
    """Genera un reporte Markdown profesional."""
    scan_id = scan_data.get("scan_id", "Unknown")
    target = scan_data.get("target", "Unknown")
    profile = scan_data.get("profile", "Unknown")
    timestamp = scan_data.get("timestamp", "")
    risk_level = scan_data.get("risk_level", "Unknown")
    risk_score = scan_data.get("risk_score", 0)
    summary = scan_data.get("summary", {})

    # Emoji según nivel de riesgo
    risk_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "INFO": "🔵",
        "Unknown": "⚪"
    }
    emoji = risk_emoji.get(risk_level, "⚪")

    md = f"""# 🔍 Reporte de Seguridad

## 📊 Resumen Ejecutivo

**Nivel de Riesgo:** {emoji} **{risk_level}**
**Puntuación de Riesgo:** {risk_score}/100

| Severidad | Cantidad |
|-----------|----------|
| 🔴 Críticos | {summary.get('critical_findings', 0)} |
| 🟠 Altos | {summary.get('high_findings', 0)} |
| 🟡 Medios | {summary.get('medium_findings', 0)} |
| 🟢 Bajos | {summary.get('low_findings', 0)} |
| 🔵 Informativos | {summary.get('info_findings', 0)} |

## ℹ️ Información del Escaneo

| Campo | Valor |
|-------|-------|
| **Scan ID** | `{scan_id}` |
| **Objetivo** | `{target}` |
| **Perfil** | `{profile}` |
| **Fecha** | {timestamp[:19].replace('T', ' ')} |
| **Puertos Totales** | {summary.get('total_ports', 0)} |
| **Puertos Abiertos** | {summary.get('open_ports', 0)} |

"""

    # Información del Host
    host_info = scan_data.get("host_info", {})
    if host_info:
        md += """## 🖥️ Información del Host

| Campo | Valor |
|-------|-------|
"""
        if host_info.get("status"):
            md += f"| **Estado** | {host_info['status']} |\n"
        if host_info.get("latency"):
            md += f"| **Latencia** | {host_info['latency']} |\n"
        if host_info.get("os"):
            md += f"| **Sistema Operativo** | {host_info['os']} |\n"
        md += "\n"

    # Puertos y Servicios
    ports = scan_data.get("ports", [])
    if ports:
        md += """## 🔌 Puertos y Servicios Detectados

| Puerto | Estado | Servicio | Versión |
|--------|--------|----------|---------|
"""
        for port in ports:
            md += f"| **{port.get('port', 'N/A')}** | {port.get('state', 'N/A')} | {port.get('service', 'N/A')} | {port.get('version', 'N/A')} |\n"
        md += "\n"

    # Hallazgos de Seguridad
    vulnerabilities = scan_data.get("vulnerabilities", [])
    if vulnerabilities:
        md += """## 🚨 Hallazgos de Seguridad

"""
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get("severity", "INFO")
            severity_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
                "INFO": "🔵"
            }
            emoji_sev = severity_emoji.get(severity, "⚪")

            md += f"""### {emoji_sev} [{i}] {vuln.get('title', 'Hallazgo sin título')}

**Severidad:** {severity}

**Descripción:** {vuln.get('description', 'Sin descripción disponible')}

"""
            if vuln.get('recommendation'):
                md += f"""**💡 Recomendación:** {vuln.get('recommendation')}

"""
            md += "---\n\n"

    # Recomendaciones
    recommendations = scan_data.get("recommendations", [])
    if recommendations:
        md += """## 💡 Recomendaciones Generales

"""
        for rec in recommendations:
            md += f"- ✅ {rec}\n"
        md += "\n"

    md += f"""
---

*Generado por **ScanAgent v3.0** | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*

> ⚠️ Este reporte es confidencial y debe ser tratado de acuerdo con las políticas de seguridad de su organización.
"""

    return md
