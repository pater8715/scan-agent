"""
Scans API Router
================
Endpoints para gestionar escaneos de vulnerabilidades.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import asyncio
import uuid
import sys
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from webapp.utils.rate_limit import check_scan_start_rate_limit

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
from webapp.utils.report_builder import generate_basic_reports

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
    selected_steps: Optional[List[int]] = Field(
        default=None,
        description="Índices (0-based) de las fases a ejecutar. None = todas las del perfil."
    )


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
    vulnerabilities_count: Optional[int] = None  # Fase 13: incluido en list
    steps: Optional[list] = None  # Lista de etapas con su estado


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


@router.post("/start", response_model=ScanStatus, dependencies=[Depends(check_scan_start_rate_limit)])
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

    # Validar selected_steps si se especificaron
    if request.selected_steps is not None:
        profile_obj = VulnerabilityScanner.PROFILES.get(request.profile)
        max_idx = len(profile_obj.commands) - 1 if profile_obj else 0
        if len(request.selected_steps) == 0:
            raise HTTPException(status_code=400, detail="selected_steps no puede estar vacío. Selecciona al menos una fase.")
        invalid = [i for i in request.selected_steps if i < 0 or i > max_idx]
        if invalid:
            raise HTTPException(
                status_code=400,
                detail=f"Índices de fase fuera de rango [0-{max_idx}]: {invalid}"
            )
    
    # Generar ID único para el escaneo
    scan_id = str(uuid.uuid4())[:8]
    
    # Construir lista de etapas para seguimiento visual
    profile_obj_for_steps = VulnerabilityScanner.PROFILES.get(request.profile)
    steps_list = []
    if profile_obj_for_steps:
        filtered_set = (
            set(request.selected_steps)
            if request.selected_steps is not None
            else None
        )
        run_order = 0
        for idx, cmd in enumerate(profile_obj_for_steps.commands):
            is_selected = filtered_set is None or idx in filtered_set
            if is_selected:
                run_order += 1
            steps_list.append({
                "run_index": run_order if is_selected else None,
                "orig_index": idx,
                "tool": cmd["tool"],
                "status": "pending" if is_selected else "skipped",
            })

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
        "save_to_db": request.save_to_db,
        "selected_steps": request.selected_steps,
        "steps": steps_list,
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
    scans: list = []
    seen_ids: set = set()

    # 1. Escaneos activos en memoria (running / pending / recién completados)
    for scan in active_scans.values():
        scans.append(dict(scan))
        seen_ids.add(scan["scan_id"])

    # 2. Escaneos completados desde archivos de metadata en disco.
    #    Persisten entre reinicios del contenedor y sus IDs coinciden
    #    exactamente con los reportes JSON/HTML generados.
    try:
        for meta in file_manager.get_all_metadata():
            sid = meta.get("scan_id")
            if not sid or sid in seen_ids:
                continue
            seen_ids.add(sid)
            vuln_count = meta.get("vulnerabilities_count")
            scans.append({
                "scan_id": sid,
                "target": meta.get("target", "unknown"),
                "profile": meta.get("profile", "unknown"),
                "description": None,
                "status": "completed",
                "progress": 100,
                "message": (
                    f"Completado — {vuln_count} hallazgos"
                    if vuln_count is not None else "Completado"
                ),
                "started_at": meta.get("created_at"),
                "completed_at": meta.get("completed_at"),
                "vulnerabilities_count": vuln_count,
                "steps": None,
            })
    except Exception as e:
        print(f"⚠️ Error leyendo metadata de escaneos: {e}")

    # Filtrar por estado si se especifica
    if status:
        scans = [s for s in scans if s.get("status") == status]

    # Ordenar por fecha de inicio (más recientes primero).
    # Soporta tanto objetos datetime como strings ISO 8601.
    def _sort_key(s):
        val = s.get("started_at")
        if val is None:
            return datetime.min
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val)
            except Exception:
                return datetime.min
        return val

    scans.sort(key=_sort_key, reverse=True)

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

        def step_callback(step: int, total: int, tool: str, ok, retry_msg: str = None):
            # No actualizar si el escaneo ya fue cancelado
            if active_scans[scan_id].get("status") == "cancelled":
                return

            # Actualizar estado de la etapa en la lista de steps
            steps = active_scans[scan_id].get("steps", [])
            for s in steps:
                if s.get("run_index") == step:
                    if retry_msg == "running":
                        s["status"] = "running"
                    elif retry_msg:          # "reintentando X/Y…"
                        s["status"] = "retrying"
                    else:
                        s["status"] = "completed" if ok else "failed"

            # Calcular porcentaje:
            # - pre-step (running): mostrar progreso del paso anterior
            # - post-step: mostrar progreso del paso completado
            if retry_msg == "running":
                pct = int(10 + ((step - 1) / total) * 55)
            else:
                pct = int(10 + (step / total) * 55)

            active_scans[scan_id]["progress"] = pct

            if retry_msg == "running":
                active_scans[scan_id]["message"] = (
                    f"Paso {step}/{total} — ejecutando {tool}..."
                )
            elif retry_msg:
                # Fix B-02: mensaje intermedio durante reintento (ok=None en este caso)
                active_scans[scan_id]["message"] = (
                    f"Paso {step}/{total} — {tool} {retry_msg}"
                )
            else:
                estado = "completado" if ok else "falló"
                active_scans[scan_id]["message"] = (
                    f"Paso {step}/{total} — {tool} {estado}"
                )

        active_scans[scan_id]["progress"] = 10
        active_scans[scan_id]["message"] = f"Escaneando {request.target}..."

        # Ejecutar herramientas de red en hilo separado (no bloquea el event loop)
        _steps = request.selected_steps  # capturar en variable local para la lambda
        success = await loop.run_in_executor(
            _scan_executor,
            lambda: agent.execute_scan(
                target=request.target,
                profile=request.profile,
                outputs_dir=output_dir,
                step_callback=step_callback,
                steps_filter=_steps,
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

        # Marcar pasos que nunca llegaron a ejecutarse (quedaron en "pending")
        # Ocurre cuando un paso required=True falla y el scanner aborta el resto
        for s in active_scans[scan_id].get("steps", []):
            if s.get("status") == "pending":
                s["status"] = "aborted"

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

        # Recopilar pasos omitidos del scanner (si hubo selección parcial)
        skipped_steps = agent.scanner.results.get("skipped_steps", [])
        is_custom = request.selected_steps is not None

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
            "custom_steps": request.selected_steps,
            "skipped_steps": skipped_steps,
            "is_custom_profile": is_custom,
        }
        file_manager.save_scan_metadata(scan_id, scan_metadata)

        # Añadir scan_config al JSON de reporte si existe
        if json_report.exists() and is_custom:
            try:
                with open(json_report, "r", encoding="utf-8") as _jf:
                    _jdata = json.load(_jf)
                _jdata["scan_config"] = {
                    "profile": request.profile,
                    "custom_steps": request.selected_steps,
                    "skipped": [s["tool"] for s in skipped_steps],
                    "is_custom_profile": True,
                }
                with open(json_report, "w", encoding="utf-8") as _jf:
                    json.dump(_jdata, _jf, ensure_ascii=False, indent=2)
            except Exception:
                pass

    except Exception as e:
        import traceback
        print(f"❌ Error en execute_scan ({scan_id}):\n{traceback.format_exc()}")
        # No sobreescribir si ya fue cancelado por el usuario
        if active_scans[scan_id].get("status") != "cancelled":
            for s in active_scans[scan_id].get("steps", []):
                if s.get("status") == "pending":
                    s["status"] = "aborted"
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["progress"] = 0
            active_scans[scan_id]["message"] = f"Error: {str(e)}"
            active_scans[scan_id]["completed_at"] = datetime.now()
            active_scans[scan_id]["reports"] = []
            active_scans[scan_id]["vulnerabilities_count"] = 0
        _active_scanners.pop(scan_id, None)

@router.get("/stats")
async def get_scan_stats():
    """
    Fase 13 — Métricas agregadas de todos los escaneos disponibles.

    Lee los reportes JSON persistidos en ./reports/ y computa:
    - Totales: scans, vulnerabilidades
    - Distribución por severidad
    - Distribución por perfil usado
    - Top-10 vulnerabilidades más frecuentes
    - 5 escaneos más recientes
    """
    reports_dir = Path("./reports")

    total_scans = 0
    total_vulnerabilities = 0
    by_severity: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_profile: dict = {}
    vuln_counter: dict = {}
    recent_scans: list = []

    if reports_dir.exists():
        json_files = sorted(
            reports_dir.glob("scan_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for json_file in json_files:
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue

            scan_id = json_file.stem.replace("scan_", "")
            target = data.get("target", "unknown")
            profile = data.get("profile_used", data.get("profile", "unknown"))
            vulns = data.get("vulnerabilities", [])

            total_scans += 1
            total_vulnerabilities += len(vulns)

            for v in vulns:
                sev = v.get("severity", "info").lower()
                if sev not in by_severity:
                    sev = "info"
                by_severity[sev] += 1

                name = v.get("title", v.get("type", "Desconocida"))
                if len(name) > 65:
                    name = name[:62] + "..."
                vuln_counter[name] = vuln_counter.get(name, 0) + 1

            by_profile[profile] = by_profile.get(profile, 0) + 1

            if len(recent_scans) < 5:
                meta = data.get("metadata", {})
                recent_scans.append({
                    "scan_id": scan_id,
                    "target": target,
                    "profile": profile,
                    "vuln_count": len(vulns),
                    "completed_at": meta.get("scan_date", ""),
                })

    top_vulns = sorted(vuln_counter.items(), key=lambda x: x[1], reverse=True)[:10]
    most_used_profile = max(by_profile, key=lambda k: by_profile[k]) if by_profile else "—"

    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulnerabilities,
        "by_severity": by_severity,
        "by_profile": by_profile,
        "most_used_profile": most_used_profile,
        "top_vulnerabilities": [{"name": n, "count": c} for n, c in top_vulns],
        "recent_scans": recent_scans,
    }


# Las funciones generate_basic_reports, generate_professional_html_report,
# generate_professional_txt_report y generate_professional_md_report han sido
# extraídas a webapp/utils/report_builder.py (SRP — Clean Code Fase 12).
# Se importan al inicio del archivo con:
#   from webapp.utils.report_builder import generate_basic_reports
#
# Las funciones helper (_html_severity_badge, _generate_headers_table_html,
# _generate_directories_html, _generate_owasp_api_table_html, _generate_nikto_html,
# _generate_profile_html_sections, _profile_label) también viven en report_builder.py.

