"""
Scans API Router
================
Endpoints para gestionar escaneos de vulnerabilidades.
"""

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import asyncio
import uuid
import sys
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Importar módulos de scanagent
src_path = Path(__file__).parent.parent.parent / "src"
sys.path.insert(0, str(src_path))

from scanagent.agent import ScanAgent
from scanagent.database import DatabaseManager
from scanagent.scanner import VulnerabilityScanner

# Importar gestor de archivos
from webapp.utils.file_manager import FileRetentionManager
from webapp.utils.report_parser import ScanResultParser, VulnerabilityAnalyzer
from webapp.utils.catalog_loader import catalog_loader

router = APIRouter()
db = DatabaseManager()
file_manager = FileRetentionManager()

# Estado de escaneos activos
active_scans = {}

# Referencia a los scanners activos (para poder matar el proceso nmap al cancelar)
_active_scanners: dict = {}

# Pool de hilos para ejecutar escaneos sin bloquear el event loop
_scan_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="scan-worker")


class ScanRequest(BaseModel):
    """Modelo de petición para iniciar un escaneo"""
    target: str = Field(..., description="IP o dominio objetivo", min_length=1)
    profile: str = Field(..., description="Perfil de escaneo: quick, standard, full, web, api, api-owasp, lab, zap-passive, zap-active, stealth, network, compliance")
    description: Optional[str] = Field(default=None, description="Descripción opcional del escaneo")
    output_formats: List[str] = Field(
        default=["json", "html"],
        description="Formatos de reporte: json, html, txt, md"
    )
    save_to_db: bool = Field(default=True, description="Guardar en base de datos")


class ScanStatus(BaseModel):
    """Estado actual de un escaneo"""
    scan_id: str
    target: str
    profile: str
    description: Optional[str] = None
    status: str  # pending, running, completed, failed
    progress: int  # 0-100
    message: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScanResult(BaseModel):
    """Resultado de un escaneo completado"""
    scan_id: str
    target: str
    profile: str
    status: str
    vulnerabilities_count: int
    reports: List[str]
    started_at: datetime
    completed_at: datetime
    duration_seconds: float


@router.post("/start", response_model=ScanStatus)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Inicia un nuevo escaneo de vulnerabilidades.
    
    El escaneo se ejecuta en background y se puede monitorear su progreso
    mediante el endpoint /status/{scan_id} o via WebSocket.
    """
    # Normalizar y validar target
    try:
        VulnerabilityScanner.validate_target(request.target)
        # Normalizar: quitar protocolo, conservar host:port si hay puerto no estándar
        _hostname, _port = VulnerabilityScanner.normalize_target(request.target)
        request = request.model_copy(
            update={"target": f"{_hostname}:{_port}" if _port else _hostname}
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Validar perfil contra los perfiles reales del scanner
    valid_profiles = list(VulnerabilityScanner.PROFILES.keys())
    if request.profile not in valid_profiles:
        raise HTTPException(
            status_code=400,
            detail=f"Perfil inválido. Opciones: {', '.join(valid_profiles)}"
        )
    
    # Generar ID único para el escaneo
    scan_id = str(uuid.uuid4())[:8]
    
    # Crear estado inicial
    scan_status = {
        "scan_id": scan_id,
        "target": request.target,
        "profile": request.profile,
        "description": request.description,
        "status": "pending",
        "progress": 0,
        "message": "Escaneo en cola",
        "started_at": datetime.now(),
        "completed_at": None,
        "output_formats": request.output_formats,
        "save_to_db": request.save_to_db
    }
    
    active_scans[scan_id] = scan_status
    
    # Ejecutar escaneo en background
    background_tasks.add_task(execute_scan, scan_id, request)
    
    return ScanStatus(**scan_status)


@router.get("/status/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """
    Obtiene el estado actual de un escaneo.
    """
    if scan_id in active_scans:
        return ScanStatus(**active_scans[scan_id])
    
    # Si no está activo, buscar en metadata
    metadata = file_manager.load_scan_metadata(scan_id)
    if metadata:
        return ScanStatus(
            scan_id=scan_id,
            target=metadata.get('target', 'Unknown'),
            profile=metadata.get('profile', 'Unknown'),
            status="completed",
            progress=100,
            message="Escaneo completado",
            started_at=metadata.get('created_at'),
            completed_at=metadata.get('completed_at')
        )
    
    raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    return ScanStatus(**active_scans[scan_id])


@router.get("/list", response_model=List[ScanStatus])
async def list_scans(limit: int = 20, status: Optional[str] = None):
    """
    Lista todos los escaneos recientes.
    
    Parámetros:
    - limit: Número máximo de resultados (default: 20)
    - status: Filtrar por estado (pending, running, completed, failed)
    """
    # Obtener escaneos activos
    scans = list(active_scans.values())
    
    # Obtener escaneos completados de la BD
    try:
        db_scans = db.get_all_scans(limit=limit)
        for db_scan in db_scans:
            if db_scan['id'] not in active_scans:
                scans.append({
                    "scan_id": str(db_scan['id']),  # Convertir a string
                    "target": db_scan.get('target', 'Unknown'),
                    "profile": db_scan.get('profile', 'Unknown'),
                    "status": "completed",
                    "progress": 100,
                    "message": "Completado",
                    "started_at": db_scan.get('start_time'),
                    "completed_at": db_scan.get('end_time')
                })
    except:
        pass
    
    # Filtrar por estado si se especifica
    if status:
        scans = [s for s in scans if s.get("status") == status]
    
    # Ordenar por fecha de inicio (más recientes primero)
    # Manejar None values en started_at
    scans.sort(
        key=lambda x: x.get("started_at") or datetime.min, 
        reverse=True
    )
    
    return [ScanStatus(**s) for s in scans[:limit]]


@router.get("/{scan_id}/hosts")
async def get_discovered_hosts(scan_id: str):
    """
    Devuelve los hosts activos descubiertos en un escaneo de red (CIDR).
    Útil para escaneos de red que cubren rangos de IPs.
    """
    # Buscar en escaneos activos/recientes
    if scan_id in active_scans:
        hosts = active_scans[scan_id].get("active_hosts", [])
        return {"scan_id": scan_id, "hosts": hosts, "count": len(hosts)}

    # Buscar en el reporte JSON persistido
    json_report = Path("./reports") / f"scan_{scan_id}.json"
    if json_report.exists():
        try:
            with open(json_report, "r", encoding="utf-8") as f:
                data = json.load(f)
            hosts = data.get("active_hosts", [])
            return {"scan_id": scan_id, "hosts": hosts, "count": len(hosts)}
        except Exception:
            pass

    raise HTTPException(status_code=404, detail="Escaneo no encontrado")


@router.delete("/{scan_id}")
async def cancel_scan(scan_id: str):
    """
    Cancela un escaneo en ejecución matando el proceso subyacente.
    """
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")

    if active_scans[scan_id]["status"] in ("completed", "cancelled"):
        raise HTTPException(status_code=400, detail="El escaneo ya está completado o cancelado")

    # Matar el proceso subprocess activo (nmap, nikto, etc.)
    scanner = _active_scanners.get(scan_id)
    if scanner and scanner._current_process:
        try:
            scanner._current_process.kill()
        except Exception:
            pass

    _active_scanners.pop(scan_id, None)

    active_scans[scan_id]["status"] = "cancelled"
    active_scans[scan_id]["message"] = "Escaneo cancelado por el usuario"
    active_scans[scan_id]["completed_at"] = datetime.now()

    return {"message": "Escaneo cancelado", "scan_id": scan_id}


async def execute_scan(scan_id: str, request: ScanRequest):
    """Ejecuta el escaneo en background sin bloquear el event loop."""
    try:
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["progress"] = 5
        active_scans[scan_id]["message"] = "Iniciando escaneo..."

        Path("./outputs").mkdir(parents=True, exist_ok=True)
        Path("./reports").mkdir(parents=True, exist_ok=True)

        output_dir = f"./outputs/scan_{scan_id}"
        agent = ScanAgent(verbose=True, use_database=request.save_to_db)
        # Registrar el scanner para poder cancelarlo desde el endpoint DELETE
        _active_scanners[scan_id] = agent.scanner
        loop = asyncio.get_event_loop()

        # Obtener total de pasos del perfil para calcular porcentaje
        profile_obj = VulnerabilityScanner.PROFILES.get(request.profile)
        total_steps = len(profile_obj.commands) if profile_obj else 6

        def step_callback(step: int, total: int, tool: str, ok: bool):
            # No actualizar si el escaneo ya fue cancelado
            if active_scans[scan_id].get("status") == "cancelled":
                return
            pct = int(10 + (step / total) * 55)
            active_scans[scan_id]["progress"] = pct
            estado = "completado" if ok else "falló"
            active_scans[scan_id]["message"] = (
                f"Paso {step}/{total} — {tool} {estado}"
            )

        active_scans[scan_id]["progress"] = 10
        active_scans[scan_id]["message"] = f"Escaneando {request.target}..."

        # Ejecutar herramientas de red en hilo separado (no bloquea el event loop)
        success = await loop.run_in_executor(
            _scan_executor,
            lambda: agent.execute_scan(
                target=request.target,
                profile=request.profile,
                outputs_dir=output_dir,
                step_callback=step_callback,
            ),
        )

        if not success:
            raise Exception("El escaneo de red falló o fue interrumpido")

        active_scans[scan_id]["progress"] = 70
        active_scans[scan_id]["message"] = "Procesando y analizando resultados..."

        # Parsing y generación de reportes también en hilo
        processing_success = False
        try:
            processing_success = await loop.run_in_executor(
                _scan_executor,
                lambda: agent.run(
                    target_ip=request.target,
                    output_format="all",
                    outputs_dir=output_dir,
                    profile_used=request.profile,
                ),
            )
        except Exception as run_error:
            print(f"⚠️  Error en agent.run(): {run_error}")
            import traceback; traceback.print_exc()

        active_scans[scan_id]["progress"] = 85
        active_scans[scan_id]["message"] = "Recopilando reportes generados..."

        reports = []
        report_dir = Path("./reports")

        for fmt in request.output_formats:
            report_file = report_dir / f"informe_tecnico.{fmt}"
            if report_file.exists():
                new_name = report_dir / f"scan_{scan_id}.{fmt}"
                report_file.rename(new_name)
                reports.append(str(new_name))

        if not reports:
            active_scans[scan_id]["message"] = "Generando reportes de análisis..."
            try:
                basic_reports = await loop.run_in_executor(
                    _scan_executor,
                    lambda: generate_basic_reports(
                        scan_id=scan_id,
                        target=request.target,
                        profile=request.profile,
                        output_dir=output_dir,
                        formats=request.output_formats,
                    ),
                )
                reports.extend(basic_reports)
            except Exception as e:
                print(f"❌ Error generando reportes básicos: {e}")
                import traceback; traceback.print_exc()

        vuln_count = 0
        json_report = report_dir / f"scan_{scan_id}.json"
        if json_report.exists():
            try:
                with open(json_report, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        vuln_count = len(data.get("vulnerabilities", []))
            except Exception:
                pass

        # Extraer hosts activos solo para escaneos CIDR (targets con "/")
        # En scans de host único el parser llena active_hosts con el propio host,
        # lo que confunde al usuario y muestra el panel de hosts innecesariamente.
        active_hosts = []
        is_cidr = "/" in request.target
        if is_cidr and json_report.exists():
            try:
                with open(json_report, "r", encoding="utf-8") as _f:
                    _jdata = json.load(_f)
                    active_hosts = _jdata.get("active_hosts", [])
            except Exception:
                pass

        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["progress"] = 100
        active_scans[scan_id]["message"] = (
            f"Escaneo completado — {vuln_count} hallazgos encontrados"
        )
        active_scans[scan_id]["completed_at"] = datetime.now()
        active_scans[scan_id]["reports"] = reports
        active_scans[scan_id]["vulnerabilities_count"] = vuln_count
        active_scans[scan_id]["active_hosts"] = active_hosts
        _active_scanners.pop(scan_id, None)

        # Persistir hosts descubiertos para el endpoint /api/lab/discovered-hosts
        if is_cidr and active_hosts:
            try:
                Path("./data").mkdir(parents=True, exist_ok=True)
                store = {
                    "scan_id": scan_id,
                    "target": request.target,
                    "scanned_at": active_scans[scan_id]["completed_at"].isoformat(),
                    "hosts": active_hosts,
                    "count": len(active_hosts)
                }
                with open("./data/last_discovered_hosts.json", "w", encoding="utf-8") as _sf:
                    json.dump(store, _sf, ensure_ascii=False, indent=2)
            except Exception as _e:
                print(f"⚠️  No se pudo guardar discovered hosts: {_e}")

        scan_metadata = {
            "scan_id": scan_id,
            "target": request.target,
            "profile": request.profile,
            "created_at": active_scans[scan_id]["started_at"].isoformat(),
            "completed_at": active_scans[scan_id]["completed_at"].isoformat(),
            "status": "active",
            "tier": 1,
            "vulnerabilities_count": vuln_count,
            "reports": reports,
            "size_bytes": sum(Path(r).stat().st_size for r in reports if Path(r).exists()),
            "retention_priority": "high" if vuln_count > 10 else "normal",
        }
        file_manager.save_scan_metadata(scan_id, scan_metadata)

    except Exception as e:
        import traceback
        print(f"❌ Error en execute_scan ({scan_id}):\n{traceback.format_exc()}")
        # No sobreescribir si ya fue cancelado por el usuario
        if active_scans[scan_id].get("status") != "cancelled":
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["progress"] = 0
            active_scans[scan_id]["message"] = f"Error: {str(e)}"
            active_scans[scan_id]["completed_at"] = datetime.now()
            active_scans[scan_id]["reports"] = []
            active_scans[scan_id]["vulnerabilities_count"] = 0
        _active_scanners.pop(scan_id, None)


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


def _html_severity_badge(severity: str) -> str:
    colors = {"CRITICAL": "#d32f2f", "HIGH": "#f57c00", "MEDIUM": "#fbc02d", "LOW": "#689f38", "INFO": "#1976d2"}
    color = colors.get(severity.upper(), "#757575")
    return f'<span style="background:{color};color:white;padding:2px 10px;border-radius:10px;font-size:0.8em;font-weight:bold;">{severity}</span>'


def _generate_headers_table_html(headers: dict) -> str:
    """Genera tabla de cabeceras de seguridad HTTP presente/ausente."""
    from webapp.utils.report_parser import VulnerabilityAnalyzer
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
    nikto = scan_data.get("nikto_findings", [])
    vulnerabilities = scan_data.get("vulnerabilities", [])

    html = ""

    # Sección de cabeceras de seguridad HTTP para web, api-owasp, compliance
    if profile in ("web", "api-owasp", "compliance") and headers:
        html += _generate_headers_table_html(headers)

    # Tabla OWASP API Top 10 para api-owasp
    if profile == "api-owasp":
        html += _generate_owasp_api_table_html(vulnerabilities)

    # Hallazgos Nikto para web y api-owasp
    if profile in ("web", "api-owasp") and nikto:
        html += _generate_nikto_html(nikto)

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
        @media print {{
            body {{ background: white; padding: 0; }}
            .container {{ box-shadow: none; }}
            .collapsible-content {{ display: block !important; }}
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
        html += """
            <!-- Hallazgos de Seguridad -->
            <div class="section">
                <h2>🚨 Hallazgos de Seguridad</h2>
"""
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "INFO")
            severity_class = severity.lower()
            severity_colors_inline = {
                "CRITICAL": "#d32f2f",
                "HIGH": "#f57c00",
                "MEDIUM": "#fbc02d",
                "LOW": "#689f38",
                "INFO": "#1976d2"
            }
            severity_color = severity_colors_inline.get(severity, "#757575")
            
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
                items = "".join(
                    f'<li style="margin:4px 0;">{r}</li>' for r in recs
                )
                recs_html = f"""
                    <div class="recommendation">
                        <div class="recommendation-title">💡 Recomendaciones</div>
                        <ul style="margin:8px 0 0 16px;padding:0;">{items}</ul>
                    </div>
"""

            html += f"""
                <div class="finding-card finding-{severity_class}"{vuln_id_attr}>
                    <div class="finding-header">
                        <div class="finding-title">{vuln.get('title', 'Hallazgo sin título')}</div>
                        <div class="finding-severity" style="background: {severity_color};">{severity}</div>
                    </div>
                    {'<div style="font-size:0.82em;color:#888;margin-bottom:6px;">'+port_info+'</div>' if port_info else ''}
                    <div style="color: #555; margin: 10px 0;">
                        {vuln.get('description', 'Sin descripción disponible')}
                    </div>
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
        // Auto-colapsar datos técnicos por defecto
        document.addEventListener('DOMContentLoaded', function() {{
            const collapsibles = document.getElementsByClassName('collapsible-content');
            for (let i = 0; i < collapsibles.length; i++) {{
                collapsibles[i].style.display = 'none';
            }}
        }});
    </script>
</body>
</html>
""".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    return html


def generate_professional_txt_report(scan_data: dict) -> str:
    """
    Genera un reporte TXT profesional.
    """
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
            from webapp.utils.report_parser import VulnerabilityAnalyzer
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
        # Agrupar por categoría
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
    """
    Genera un reporte Markdown profesional.
    """
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


