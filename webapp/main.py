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

import sys
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Añadir src/ al path para importar scanagent
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

# Importar routers de la API
from webapp.api.scans import router as scans_router
from webapp.api.reports import router as reports_router
from webapp.api.profiles import router as profiles_router

# Crear aplicación FastAPI
app = FastAPI(
    title="Scan Agent Web",
    description="Interfaz web para ejecutar y gestionar escaneos de vulnerabilidades",
    version="1.0.0",
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
app.include_router(scans_router, prefix="/api/scans", tags=["Scans"])
app.include_router(reports_router, prefix="/api/reports", tags=["Reports"])
app.include_router(profiles_router, prefix="/api/profiles", tags=["Profiles"])


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
            except:
                self.disconnect(scan_id)


manager = ConnectionManager()


@app.get("/", response_class=HTMLResponse)
async def index():
    """Página principal de la aplicación web"""
    with open(webapp_path / "templates" / "index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


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
    return {"status": "healthy", "version": "1.0.0"}


if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    SCAN AGENT WEB v1.0                       ║
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
