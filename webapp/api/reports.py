"""
Reports API Router
==================
Endpoints para gestionar y descargar reportes de escaneos.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
from pathlib import Path
import json

router = APIRouter()


class ReportInfo(BaseModel):
    """Información de un reporte"""
    scan_id: str
    format: str
    filename: str
    size_bytes: int
    created_at: str


@router.get("/{scan_id}", response_model=List[ReportInfo])
async def get_scan_reports(scan_id: str):
    """
    Lista todos los reportes disponibles para un escaneo específico.
    """
    reports_dir = Path("./reports")
    reports = []
    
    if not reports_dir.exists():
        return []
    
    # Buscar archivos que coincidan con el scan_id
    for report_file in reports_dir.glob(f"scan_{scan_id}.*"):
        if report_file.is_file():
            stat = report_file.stat()
            reports.append(ReportInfo(
                scan_id=scan_id,
                format=report_file.suffix[1:],  # Quitar el punto
                filename=report_file.name,
                size_bytes=stat.st_size,
                created_at=str(stat.st_mtime)
            ))
    
    return reports


@router.get("/{scan_id}/download/{format}")
async def download_report(scan_id: str, format: str):
    """
    Descarga un reporte en el formato especificado.
    
    Formatos soportados: json, html, txt, md
    """
    valid_formats = ['json', 'html', 'txt', 'md']
    if format not in valid_formats:
        raise HTTPException(
            status_code=400,
            detail=f"Formato inválido. Opciones: {', '.join(valid_formats)}"
        )
    
    report_path = Path(f"./reports/scan_{scan_id}.{format}")
    
    if not report_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Reporte no encontrado: {report_path.name}"
        )
    
    # Determinar media type
    media_types = {
        'json': 'application/json',
        'html': 'text/html',
        'txt': 'text/plain',
        'md': 'text/markdown'
    }
    
    return FileResponse(
        path=str(report_path),
        media_type=media_types.get(format, 'application/octet-stream'),
        filename=f"scan_report_{scan_id}.{format}"
    )


@router.get("/{scan_id}/preview")
async def preview_report(scan_id: str):
    """
    Obtiene una vista previa del reporte en formato JSON.
    """
    report_path = Path(f"./reports/scan_{scan_id}.json")
    
    if not report_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Reporte no encontrado"
        )
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error leyendo reporte: {str(e)}"
        )
