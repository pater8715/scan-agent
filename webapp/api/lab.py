"""
Lab Targets API
===============
Lista los objetivos de laboratorio disponibles dentro de la red Docker,
con sus IPs fijas, puertos y perfil de escaneo recomendado.
"""

import socket
import json
import os
from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

# Definición estática de los servicios del laboratorio
LAB_TARGETS = [
    {
        "id": "juice-shop",
        "name": "OWASP Juice Shop",
        "hostname": "juice-shop",
        "ip": "172.20.0.3",
        "port": 3000,
        "url": "http://juice-shop:3000",
        "profile": "web",
        "profiles": ["web", "api-owasp"],
        "description": "Aplicación web vulnerable deliberadamente (OWASP). Ideal para pruebas de XSS, SQLi, IDOR y más.",
        "category": "webapp",
        "icon": "🧃",
        "external_url": "http://localhost:3000",
    },
    {
        "id": "dvwa",
        "name": "DVWA",
        "hostname": "dvwa",
        "ip": "172.20.0.4",
        "port": 80,
        "url": "http://dvwa:80",
        "profile": "web",
        "profiles": ["web", "compliance"],
        "description": "Damn Vulnerable Web Application. Niveles de seguridad configurables (Low/Medium/High).",
        "category": "webapp",
        "icon": "🎯",
        "external_url": "http://localhost:8081",
        "credentials": {"user": "admin", "password": "password"},
    },
    {
        "id": "dvwa-db",
        "name": "DVWA Database (MariaDB)",
        "hostname": "dvwa-db",
        "ip": "172.20.0.6",
        "port": 3306,
        "url": "dvwa-db:3306",
        "profile": "network",
        "profiles": ["network"],
        "description": "Base de datos MariaDB de DVWA. Útil para escaneos de infraestructura de BD.",
        "category": "database",
        "icon": "🗄️",
        "external_url": None,
    },
    {
        "id": "zap",
        "name": "OWASP ZAP",
        "hostname": "zap",
        "ip": "172.20.0.5",
        "port": 8090,
        "url": "http://zap:8090",
        "profile": "web",
        "profiles": ["web", "api-owasp"],
        "description": "OWASP Zed Attack Proxy en modo daemon. API disponible para integración.",
        "category": "tool",
        "icon": "🔬",
        "external_url": "http://localhost:8090",
    },
    {
        "id": "scan-agent-web",
        "name": "Scan Agent Web UI (self)",
        "hostname": "scan-agent-web",
        "ip": "172.20.0.2",
        "port": 8080,
        "url": "http://scan-agent-web:8080",
        "profile": "web",
        "profiles": ["web", "api-owasp", "compliance"],
        "description": "La propia aplicación Scan Agent. Útil para escanear y auditar la plataforma.",
        "category": "self",
        "icon": "🛡️",
        "external_url": "http://localhost:8080",
    },
    {
        "id": "host-machine",
        "name": "Host Docker (máquina real)",
        "hostname": "host.docker.internal",
        "ip": None,          # Dinámica — se resuelve en tiempo real
        "port": 80,
        "url": "http://host.docker.internal",
        "profile": "network",
        "profiles": ["network", "web", "compliance"],
        "description": "La máquina host que ejecuta Docker. Permite escanear servicios del host desde el contenedor.",
        "category": "host",
        "icon": "🖥️",
        "external_url": None,
    },
]


def _check_reachable(hostname: str, port: int, timeout: float = 1.0) -> bool:
    """Intenta conectar al host:puerto para verificar si está activo."""
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


@router.get("/targets")
async def list_lab_targets():
    """
    Lista los objetivos de laboratorio disponibles en la red Docker,
    con estado de conectividad en tiempo real.
    """
    # Resolver IP del host Docker
    host_ip = None
    try:
        host_ip = socket.gethostbyname("host.docker.internal")
    except Exception:
        pass

    result = []
    for t in LAB_TARGETS:
        entry = dict(t)
        # Rellenar IP dinámica del host
        if t["id"] == "host-machine":
            entry["ip"] = host_ip
            if host_ip:
                entry["reachable"] = _check_reachable("host.docker.internal", t["port"])
            else:
                entry["reachable"] = False
        else:
            entry["reachable"] = _check_reachable(t["hostname"], t["port"])
        result.append(entry)
    return result


@router.get("/discovered-hosts")
async def get_discovered_hosts():
    """
    Retorna la lista de hosts activos descubiertos en el último escaneo de red (CIDR).
    Se actualiza cada vez que un escaneo de perfil 'network' sobre un rango CIDR completa.
    """
    store_path = Path("./data/last_discovered_hosts.json")
    if not store_path.exists():
        return {"hosts": [], "count": 0, "scan_id": None, "target": None, "scanned_at": None}
    try:
        with open(store_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception:
        return {"hosts": [], "count": 0, "scan_id": None, "target": None, "scanned_at": None}


@router.get("/network-info")
async def network_info():
    """
    Información de la red del contenedor scan-agent:
    nombre de host, IP local, red Docker y host externo.
    """
    try:
        local_hostname = socket.gethostname()
        local_ip = socket.gethostbyname(local_hostname)
    except Exception:
        local_hostname = "unknown"
        local_ip = "unknown"

    # IP del host Docker (si está disponible via extra_hosts)
    host_ip = None
    try:
        host_ip = socket.gethostbyname("host.docker.internal")
    except Exception:
        pass

    return {
        "container_hostname": local_hostname,
        "container_ip": local_ip,
        "docker_network": "scan-agent-network",
        "subnet": "172.20.0.0/16",
        "host_docker_internal": host_ip,
        "note": "Usar hostname del servicio (ej: juice-shop:3000) para escanear contenedores de la red."
    }
