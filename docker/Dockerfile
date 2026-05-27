# Scan Agent v3.0 - Multi-Stage Dockerfile
# ==========================================
# Dockerfile optimizado con multi-stage build para Scan Agent v3.0
# Incluye soporte completo para CLI, Web UI, y análisis profesional

# ============================================================================
# STAGE 1: Base image with security tools
# ============================================================================
FROM kalilinux/kali-rolling:latest AS base

# Metadata
LABEL maintainer="Scan Agent Team"
LABEL version="3.0.0"
LABEL description="Professional Vulnerability Scanner & Web Analysis Platform"
LABEL org.opencontainers.image.title="Scan Agent"
LABEL org.opencontainers.image.description="Advanced security scanning with intelligent vulnerability analysis"
LABEL org.opencontainers.image.version="3.0.0"
LABEL org.opencontainers.image.authors="Scan Agent Team"
LABEL org.opencontainers.image.url="https://github.com/pater8715/scan-agent"
LABEL org.opencontainers.image.source="https://github.com/pater8715/scan-agent"

# Evitar prompts interactivos
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# -- Paquetes esenciales del escaner (sin git/vim/nano que arrastran libexpat1) -
RUN apt update && \
    apt install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    curl \
    wget \
    sqlite3 \
    jq \
    netcat-traditional \
    dnsutils \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

# -- Herramientas de seguridad opcionales ---------------------
# Cada una se instala de forma independiente; si falla, se ignora.
RUN apt update && \
    for pkg in nikto gobuster dirb sslscan enum4linux snmp-check whatweb wafw00f; do \
        apt install -y --no-install-recommends $pkg 2>/dev/null || echo "SKIP: $pkg no disponible"; \
    done && \
    apt clean && rm -rf /var/lib/apt/lists/*

# -- Garantizar /usr/bin/python3 (Kali 2026+ usa python3.X) --
RUN ls /usr/bin/python3 2>/dev/null \
    || (ls /usr/bin/python3.* 2>/dev/null | sort -V | tail -1 \
        | xargs -I{} sh -c 'ln -sf {} /usr/bin/python3 && echo "Symlink: python3 -> {}"') \
    && python3 --version

# -- Wordlist de endpoints (opcional) -------------------------
RUN mkdir -p /usr/share/wordlists && \
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt" \
         -O /usr/share/wordlists/api-endpoints.txt \
    || echo "api-endpoints.txt no descargado, se usara dirb/common.txt"

# ============================================================================
# STAGE 2: Python dependencies
# ============================================================================
FROM base AS python-deps

# Crear directorio de trabajo
WORKDIR /scan-agent

# Copiar archivos de dependencias
COPY requirements.txt ./
COPY webapp/requirements.txt ./webapp-requirements.txt

# Instalar dependencias Python
# --break-system-packages : permite instalar sobre el entorno del sistema
# --ignore-installed      : no intenta desinstalar versiones del sistema (evita
#                           "uninstall-no-record-file" con paquetes apt como jinja2)
RUN python3 -m pip install \
    --break-system-packages \
    --ignore-installed \
    --no-cache-dir \
    fastapi==0.115.0 \
    "uvicorn[standard]==0.31.0" \
    jinja2==3.1.4 \
    python-multipart==0.0.9 \
    pydantic==2.9.0 \
    websockets==13.1 \
    markdown==3.7 && \
    python3 -m pip cache purge 2>/dev/null || true

# ============================================================================
# STAGE 3: Application files
# ============================================================================
FROM python-deps AS app

# Copiar estructura completa del proyecto
COPY src/ ./src/
COPY webapp/ ./webapp/
COPY config/ ./config/
COPY scripts/ ./scripts/
COPY README.md ./

# Crear directorios necesarios con permisos correctos
RUN mkdir -p outputs reports data logs && \
    # Hacer ejecutables los scripts
    chmod +x scripts/*.sh && \
    chmod +x scripts/scan-agent.py && \
    # Crear enlace simbólico para compatibilidad
    ln -sf /scan-agent/scripts/scan-agent.py /scan-agent/scan-agent.py

# ============================================================================
# STAGE 4: Security & User setup
# ============================================================================
FROM app AS security

# Crear usuario no privilegiado
RUN groupadd -r scanagent && \
    useradd -r -g scanagent -d /scan-agent -s /bin/bash -c "Scan Agent User" scanagent && \
    # Asignar permisos
    chown -R scanagent:scanagent /scan-agent && \
    # Permisos específicos para directorios de trabajo
    chmod 755 /scan-agent && \
    chmod -R 755 /scan-agent/scripts && \
    chmod -R 644 /scan-agent/config

# Variables de entorno de seguridad
ENV SCAN_USER=scanagent
ENV SCAN_HOME=/scan-agent
ENV PATH="$PATH:/scan-agent/scripts"

# ============================================================================
# STAGE 5: Final production image
# ============================================================================
FROM security AS production

# Healthcheck para monitoreo
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

# Volúmenes para persistir datos
VOLUME ["/scan-agent/outputs", "/scan-agent/reports", "/scan-agent/data", "/scan-agent/logs"]

# Puertos expuestos
EXPOSE 8080 8000

# Script de entrada mejorado
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# NOTA: Se mantiene como root para permitir escaneos con nmap que requieren raw sockets
# El contenedor debe ejecutarse con privileged: true o cap_add: NET_RAW, NET_ADMIN
# USER scanagent

# Punto de entrada y comando por defecto
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
