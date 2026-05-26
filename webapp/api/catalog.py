"""
Catalog API Router
==================
Endpoints para gestionar el catálogo de recomendaciones de vulnerabilidades.

GET  /api/catalog/version         — hash actual, fecha, nº entradas
POST /api/catalog/reload          — recarga manual sin reiniciar el servicio
GET  /api/catalog/entries         — lista todas las entradas del catálogo
GET  /api/catalog/entries/{id}    — detalle de una entrada
PUT  /api/catalog/entries/{id}    — editar recomendaciones de una entrada
GET  /api/catalog/sync-log        — historial de sincronizaciones
POST /api/catalog/sync            — lanzar sincronización on-demand
POST /api/reports/{scan_id}/refresh — regenerar reporte con catálogo actual
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from webapp.utils.catalog_loader import catalog_loader
from webapp.utils.catalog_sync import run_sync, get_sync_log

router = APIRouter()

_REPORTS_DIR = Path("./reports")
_OUTPUTS_DIR = Path("./outputs")


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

class EntryUpdate(BaseModel):
    recommendations: List[str]
    description: Optional[str] = None


class RefreshResult(BaseModel):
    scan_id: str
    status: str
    message: str
    reports_regenerated: List[str]


# ---------------------------------------------------------------------------
# Endpoints de versión y recarga
# ---------------------------------------------------------------------------

@router.get("/version")
async def get_catalog_version():
    """Hash SHA-256 actual, fecha de última modificación y número de entradas."""
    return catalog_loader.version_info()


@router.post("/reload")
async def reload_catalog():
    """Fuerza recarga del catálogo desde disco sin reiniciar el servicio."""
    changed = catalog_loader.force_reload()
    info = catalog_loader.version_info()
    return {
        "changed": changed,
        "message": "Catálogo recargado con cambios" if changed else "Catálogo ya estaba actualizado",
        **info,
    }


# ---------------------------------------------------------------------------
# Endpoints de entradas
# ---------------------------------------------------------------------------

@router.get("/entries")
async def list_catalog_entries():
    """Lista todas las entradas del catálogo agrupadas por sección."""
    catalog = catalog_loader.get()
    if not catalog:
        raise HTTPException(status_code=503, detail="Catálogo no disponible")

    entries = []

    for port_id, data in catalog.get("ports", {}).items():
        entries.append({
            "id": f"port_{port_id}",
            "section": "ports",
            "key": port_id,
            "risk_level": data.get("risk_level", ""),
            "description": data.get("description", ""),
            "recommendations": data.get("recommendations", []),
            "cves": data.get("cves", []),
            "source": data.get("source", "manual"),
            "last_updated": data.get("last_updated"),
        })

    for header, data in catalog.get("security_headers", {}).items():
        entries.append({
            "id": f"header_{header.lower().replace('-', '_')}",
            "section": "security_headers",
            "key": header,
            "risk_level": data.get("severity", ""),
            "description": data.get("description", ""),
            "recommendations": data.get("recommendations", []),
            "cves": [],
            "source": data.get("source", "manual"),
            "last_updated": data.get("last_updated"),
        })

    for path, data in catalog.get("sensitive_paths", {}).items():
        entries.append({
            "id": f"path_{path.replace('/', '_').replace('.', '').strip('_')}",
            "section": "sensitive_paths",
            "key": path,
            "risk_level": data.get("severity", "") if isinstance(data, dict) else data,
            "description": data.get("description", "") if isinstance(data, dict) else "",
            "recommendations": data.get("recommendations", []) if isinstance(data, dict) else [],
            "cves": [],
            "source": "manual",
            "last_updated": None,
        })

    kev = catalog.get("known_exploited_cves", {})
    return {
        "entries": entries,
        "total": len(entries),
        "kev_count": len(kev),
        "version": catalog.get("version"),
        "last_updated": catalog.get("last_updated"),
    }


@router.get("/entries/{entry_id}")
async def get_catalog_entry(entry_id: str):
    """Detalle de una entrada del catálogo por su ID."""
    catalog = catalog_loader.get()
    if not catalog:
        raise HTTPException(status_code=503, detail="Catálogo no disponible")

    # Buscar en puertos
    if entry_id.startswith("port_"):
        port = entry_id[5:]
        data = catalog.get("ports", {}).get(port)
        if data:
            return {"id": entry_id, "section": "ports", "key": port, **data}

    # Buscar en cabeceras
    elif entry_id.startswith("header_"):
        key = entry_id[7:].replace("_", "-").title()
        for header, data in catalog.get("security_headers", {}).items():
            if header.lower().replace("-", "_") == entry_id[7:]:
                return {"id": entry_id, "section": "security_headers", "key": header, **data}

    # Buscar en paths sensibles
    elif entry_id.startswith("path_"):
        raw_key = "/" + entry_id[5:].replace("_", "/").replace("//", "/")
        for path, data in catalog.get("sensitive_paths", {}).items():
            path_id = f"path_{path.replace('/', '_').replace('.', '').strip('_')}"
            if path_id == entry_id:
                if isinstance(data, dict):
                    return {"id": entry_id, "section": "sensitive_paths", "key": path, **data}
                else:
                    return {"id": entry_id, "section": "sensitive_paths", "key": path, "severity": data}

    raise HTTPException(status_code=404, detail=f"Entrada '{entry_id}' no encontrada")


@router.put("/entries/{entry_id}")
async def update_catalog_entry(entry_id: str, update: EntryUpdate):
    """Edita las recomendaciones de una entrada. Actualiza el archivo JSON en disco."""
    catalog = catalog_loader.get()
    if not catalog:
        raise HTTPException(status_code=503, detail="Catálogo no disponible")

    # Trabajar sobre una copia para no mutar el singleton en memoria
    import copy
    catalog_copy = copy.deepcopy(catalog)
    updated = False

    if entry_id.startswith("port_"):
        port = entry_id[5:]
        if port in catalog_copy.get("ports", {}):
            catalog_copy["ports"][port]["recommendations"] = update.recommendations
            if update.description:
                catalog_copy["ports"][port]["description"] = update.description
            catalog_copy["ports"][port]["source"] = "manual"
            catalog_copy["ports"][port]["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d")
            updated = True

    elif entry_id.startswith("header_"):
        for header, data in catalog_copy.get("security_headers", {}).items():
            if header.lower().replace("-", "_") == entry_id[7:]:
                catalog_copy["security_headers"][header]["recommendations"] = update.recommendations
                if update.description:
                    catalog_copy["security_headers"][header]["description"] = update.description
                catalog_copy["security_headers"][header]["source"] = "manual"
                catalog_copy["security_headers"][header]["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d")
                updated = True
                break

    if not updated:
        raise HTTPException(status_code=404, detail=f"Entrada '{entry_id}' no encontrada o no editable")

    # Persistir al disco
    catalog_copy["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d")
    catalog_path = Path(__file__).parent.parent.parent / "data" / "recommendations_catalog.json"
    try:
        with open(catalog_path, "w", encoding="utf-8") as f:
            json.dump(catalog_copy, f, ensure_ascii=False, indent=2)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error guardando catálogo: {exc}")

    # Forzar recarga del loader
    catalog_loader.force_reload()
    return {"status": "updated", "entry_id": entry_id, "sha256": catalog_loader.sha256()}


# ---------------------------------------------------------------------------
# Endpoints de sincronización
# ---------------------------------------------------------------------------

@router.get("/sync-log")
async def get_catalog_sync_log(limit: int = 50):
    """Historial de sincronizaciones con NVD/CISA KEV."""
    return {"log": get_sync_log(limit=limit)}


@router.post("/sync")
async def trigger_catalog_sync(background_tasks: BackgroundTasks):
    """Lanza una sincronización on-demand con NVD/CISA KEV en background."""
    background_tasks.add_task(_run_sync_task)
    return {"status": "started", "message": "Sincronización iniciada en background"}


async def _run_sync_task():
    import asyncio
    loop = asyncio.get_event_loop()
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=1) as ex:
        await loop.run_in_executor(ex, run_sync)
    catalog_loader.force_reload()


# ---------------------------------------------------------------------------
# Endpoint de refresco de reportes
# ---------------------------------------------------------------------------

@router.post("/reports/{scan_id}/refresh", response_model=RefreshResult)
async def refresh_report(scan_id: str, background_tasks: BackgroundTasks):
    """
    Regenera todos los reportes de un escaneo usando el catálogo actual.
    Lee los outputs crudos en ./outputs/scan_{id}/ y re-ejecuta el análisis.
    """
    output_dir = _OUTPUTS_DIR / f"scan_{scan_id}"
    if not output_dir.exists():
        raise HTTPException(
            status_code=404,
            detail=f"No se encontraron outputs para el escaneo {scan_id}. "
                   "Solo es posible refrescar escaneos que conserven sus archivos raw."
        )

    background_tasks.add_task(_regenerate_reports, scan_id, output_dir)
    return RefreshResult(
        scan_id=scan_id,
        status="queued",
        message="Regeneración de reportes iniciada en background",
        reports_regenerated=[],
    )


async def _regenerate_reports(scan_id: str, output_dir: Path):
    """Re-ejecuta el análisis y sobreescribe los reportes existentes."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=1) as ex:
        await loop.run_in_executor(ex, _do_regenerate, scan_id, output_dir)


def _do_regenerate(scan_id: str, output_dir: Path):
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

    from webapp.utils.report_parser import ScanResultParser, VulnerabilityAnalyzer

    # Leer metadata para recuperar target y profile
    meta_path = Path(f"./data/scans/{scan_id}.json")
    target = scan_id
    profile = "web"
    try:
        if meta_path.exists():
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            target = meta.get("target", scan_id)
            profile = meta.get("profile", "web")
    except Exception:
        pass

    # Intentar recuperar target/profile del JSON de reporte existente
    json_report = _REPORTS_DIR / f"scan_{scan_id}.json"
    if json_report.exists():
        try:
            with open(json_report, "r", encoding="utf-8") as f:
                old = json.load(f)
            target = old.get("target", target)
            profile = old.get("profile", profile)
        except Exception:
            pass

    # Parsear outputs crudos con el catálogo actual
    catalog = catalog_loader.get()
    parser = ScanResultParser()
    parsed = parser.parse_all_files(output_dir, target)

    analyzer = VulnerabilityAnalyzer(parsed, profile=profile, catalog=catalog)
    analysis = analyzer.analyze()

    scan_data = {
        "scan_id": scan_id,
        "target": target,
        "profile": profile,
        "timestamp": datetime.utcnow().isoformat(),
        "refreshed_at": datetime.utcnow().isoformat(),
        "catalog_sha256": catalog_loader.sha256(),
        "host_info": {
            "status": "activo" if parsed.get("host_up") else "desconocido",
            "latency": f"{parsed['latency_ms']} ms" if parsed.get("latency_ms") else "N/A",
            "os": parsed.get("os", "Unknown"),
            "os_cpe": parsed.get("os_cpe", ""),
        },
        "ports": parsed.get("ports", []),
        "active_hosts": parsed.get("active_hosts", []),
        "http_headers": parsed.get("headers", {}),
        "nikto_findings": parsed.get("nikto_findings", []),
        "directories": parsed.get("directories", []),
        "nse_findings": parsed.get("nse_findings", []),
        "whatweb_findings": parsed.get("whatweb_findings", []),
        "waf_info": parsed.get("waf_info", {}),
        "ssl_info": parsed.get("ssl_info", {}),
        "vulnerabilities": analysis.get("findings", []),
        "risk_score": analysis.get("risk_score", 0),
        "risk_level": analysis.get("risk_level", "Unknown"),
        "recommendations": analysis.get("recommendations", []),
        "summary": analysis.get("summary", {}),
    }

    # Sobreescribir JSON
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(json_report, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, ensure_ascii=False, indent=2)

    print(f"✅ Reporte {scan_id} regenerado con catálogo {catalog_loader.sha256()[:8]}...")
