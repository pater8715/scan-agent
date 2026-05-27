#!/usr/bin/env python3
"""
Scan Agent Web - Main Application
==================================
FastAPI application para interfaz web de Scan Agent.

Características:
- API REST para ejecutar escaneos
- WebSocket para progreso en tiempo real
- Gestión de historial de escaneos
- Exportación de reportes

Autor: Scan Agent Team
Versión: 1.0.0
"""

import asyncio
import sys
import os
import logging
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Añadir src/ al path para importar scanagent
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

# Importar routers de la API
from webapp.api.scans import router as scans_router
from webapp.api.reports import router as reports_router
from webapp.api.profiles import router as profiles_router
from webapp.api.lab import router as lab_router
from webapp.api.catalog import router as catalog_router

# Importar utilidades de catálogo (Fase 9)
from webapp.utils.catalog_loader import catalog_loader
from webapp.utils.catalog_watcher import CatalogWatcher
from webapp.utils.catalog_sync import CatalogSyncWorker

# Cola asyncio para eventos de cambio de catálogo → WebSocket broadcast
_catalog_event_queue: asyncio.Queue = asyncio.Queue()

# Inicializar logging estructurado
try:
    from scanagent.logging_config import setup_logging
    setup_logging(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        json_output=os.environ.get("JSON_LOGGING", "true").lower() != "false",
    )
except ImportError:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("scan_agent.web")

# ---------------------------------------------------------------------------
# Autenticación por API Key (opcional — se activa con SCAN_AGENT_API_KEY)
# ---------------------------------------------------------------------------
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(API_KEY_HEADER)):
    configured_key = os.environ.get("SCAN_AGENT_API_KEY", "").strip()
    if not configured_key:
        return  # Auth desactivada en modo desarrollo
    if api_key != configured_key:
        logger.warning("Intento de acceso con API key inválida")
        raise HTTPException(status_code=403, detail="API key inválida o ausente")


# ---------------------------------------------------------------------------
# Rate limiter en memoria (sin dependencias externas)
# 30 peticiones / 60 s por IP para endpoints de escaneo
# ---------------------------------------------------------------------------
class _InMemoryRateLimiter:
    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = timedelta(seconds=window_seconds)
        self._log: dict[str, list[datetime]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        now = datetime.now()
        cutoff = now - self.window
        bucket = self._log[client_ip]
        # eliminar entradas viejas
        self._log[client_ip] = [t for t in bucket if t > cutoff]
        if len(self._log[client_ip]) >= self.max_requests:
            return False
        self._log[client_ip].append(now)
        return True


_rate_limiter = _InMemoryRateLimiter()


async def check_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_limiter.is_allowed(client_ip):
        logger.warning("Rate limit excedido para IP %s", client_ip)
        raise HTTPException(status_code=429, detail="Demasiadas peticiones. Espera un momento.")


# Crear aplicación FastAPI
app = FastAPI(
    title="Scan Agent Web",
    description="Interfaz web para ejecutar y gestionar escaneos de vulnerabilidades",
    version="3.3.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Montar archivos estáticos y templates
webapp_path = Path(__file__).parent
app.mount("/static", StaticFiles(directory=str(webapp_path / "static")), name="static")
templates = Jinja2Templates(directory=str(webapp_path / "templates"))

# Incluir routers de la API
# Los endpoints de escaneo llevan autenticación + rate limit
# Los de perfiles y reportes solo autenticación
_scan_deps = [Depends(verify_api_key), Depends(check_rate_limit)]
_auth_deps = [Depends(verify_api_key)]

app.include_router(scans_router, prefix="/api/scans", tags=["Scans"], dependencies=_scan_deps)
app.include_router(reports_router, prefix="/api/reports", tags=["Reports"], dependencies=_auth_deps)
app.include_router(profiles_router, prefix="/api/profiles", tags=["Profiles"])
app.include_router(lab_router, prefix="/api/lab", tags=["Lab"])
app.include_router(catalog_router, prefix="/api/catalog", tags=["Catalog"], dependencies=_auth_deps)


# ---------------------------------------------------------------------------
# Eventos de ciclo de vida: arrancar/parar watcher y sync worker
# ---------------------------------------------------------------------------

_catalog_watcher: CatalogWatcher = None
_catalog_sync_worker: CatalogSyncWorker = None


@app.on_event("startup")
async def _startup():
    global _catalog_watcher, _catalog_sync_worker

    # Warm-up del CatalogLoader
    catalog_loader.get()
    logger.info("CatalogLoader inicializado — SHA-256: %s", catalog_loader.sha256())

    # Loop de broadcast de eventos de catálogo
    asyncio.create_task(_catalog_broadcast_loop())

    # CatalogWatcher — detecta cambios en el JSON y los emite al WS
    loop = asyncio.get_event_loop()
    _catalog_watcher = CatalogWatcher(event_queue=_catalog_event_queue, loop=loop, interval=60)
    _catalog_watcher.start()
    logger.info("CatalogWatcher iniciado (polling cada 60 s)")

    # CatalogSyncWorker — sincroniza NVD/CISA KEV cada 24h
    _catalog_sync_worker = CatalogSyncWorker()
    _catalog_sync_worker.start()
    logger.info("CatalogSyncWorker iniciado (ciclo cada 24h)")


@app.on_event("shutdown")
async def _shutdown():
    if _catalog_watcher:
        _catalog_watcher.stop()
    if _catalog_sync_worker:
        _catalog_sync_worker.stop()


# WebSocket Manager para progreso en tiempo real
class ConnectionManager:
    """Gestiona conexiones WebSocket para actualizar progreso en tiempo real"""

    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[scan_id] = websocket

    def disconnect(self, scan_id: str):
        if scan_id in self.active_connections:
            del self.active_connections[scan_id]

    async def send_progress(self, scan_id: str, message: dict):
        if scan_id in self.active_connections:
            try:
                await self.active_connections[scan_id].send_json(message)
            except Exception:
                self.disconnect(scan_id)

    async def broadcast(self, message: dict):
        """Envía un mensaje a TODOS los clientes WebSocket conectados."""
        dead = []
        for sid, ws in list(self.active_connections.items()):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(sid)
        for sid in dead:
            self.disconnect(sid)


manager = ConnectionManager()


async def _catalog_broadcast_loop():
    """Consume eventos de la cola de catálogo y los difunde por WebSocket."""
    while True:
        try:
            event = await _catalog_event_queue.get()
            await manager.broadcast(event)
        except Exception as exc:
            logger.warning("Error en catalog broadcast loop: %s", exc)


@app.get("/", response_class=HTMLResponse)
async def index():
    """Página principal de la aplicación web"""
    with open(webapp_path / "templates" / "index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/manual")
async def get_manual():
    """Devuelve el Manual de Usuario como HTML y secciones para el TOC."""
    docs_paths = [
        Path(__file__).parent.parent / "docs" / "MANUAL_USUARIO.md",
        Path(__file__).parent.parent / "README.md",
    ]
    md_file = next((p for p in docs_paths if p.exists()), None)
    if md_file is None:
        return JSONResponse({"html": "<p>Manual no disponible.</p>", "toc": []})

    raw = md_file.read_text(encoding="utf-8")

    # Renderizar Markdown → HTML (con extensiones de tablas, código, y IDs en headings)
    try:
        import markdown as _md
        html = _md.markdown(
            raw,
            extensions=["tables", "fenced_code", "toc", "attr_list"],
            extension_configs={"toc": {"anchorlink": True}},
        )
    except ImportError:
        # Fallback sin librería markdown: envuelve en <pre>
        import html as _html_mod
        html = f"<pre>{_html_mod.escape(raw)}</pre>"

    # Extraer secciones de nivel 1 y 2 para el TOC lateral
    # Ignorar líneas dentro de bloques de código (``` ... ```)
    import re
    toc = []
    in_code_block = False
    for line in raw.splitlines():
        if line.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            continue
        m = re.match(r'^(#{1,2})\s+(.+)$', line)
        if m:
            level = len(m.group(1))
            title = m.group(2).strip()
            anchor = re.sub(r'[^\w\s-]', '', title.lower())
            anchor = re.sub(r'[\s_-]+', '-', anchor).strip('-')
            toc.append({"level": level, "title": title, "anchor": anchor})

    return JSONResponse({"html": html, "toc": toc})


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """WebSocket para recibir actualizaciones de progreso del escaneo"""
    await manager.connect(scan_id, websocket)
    try:
        while True:
            # Mantener la conexión abierta
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id)


@app.get("/health")
async def health_check():
    """Endpoint de health check"""
    return {"status": "healthy", "version": "3.3.0"}


if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                   SCAN AGENT WEB v3.3.0                      ║
    ║              Interfaz Web de Escaneo de Seguridad            ║
    ╚══════════════════════════════════════════════════════════════╝

    🌐 Servidor iniciando en: http://localhost:8000
    📚 Documentación API: http://localhost:8000/api/docs

    Presiona Ctrl+C para detener el servidor
    """)
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
