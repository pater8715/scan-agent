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

# Actualizar sistema e instalar herramientas de pentesting + dependencias web
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # Python y herramientas básicas
    python3 \
    python3-pip \
    python3-venv \
    # Herramientas de seguridad
    nmap \
    nikto \
    gobuster \
    dirb \
    whatweb \
    # Utilidades de red
    curl \
    wget \
    netcat-traditional \
    dnsutils \
    # Herramientas del sistema
    git \
    vim \
    nano \
    sqlite3 \
    jq \
    # Limpieza
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# ============================================================================
# STAGE 2: Python dependencies
# ============================================================================
FROM base AS python-deps

# Crear directorio de trabajo
WORKDIR /scan-agent

# Copiar archivos de dependencias
COPY requirements.txt ./
COPY webapp/requirements.txt ./webapp-requirements.txt

# Instalar dependencias Python (manejando entorno gestionado externamente)
RUN pip3 install --break-system-packages --no-cache-dir \
    fastapi==0.115.0 \
    uvicorn[standard]==0.31.0 \
    jinja2==3.1.4 \
    python-multipart==0.0.9 \
    pydantic==2.9.0 \
    websockets==13.1 && \
    # Limpiar cache de pip
    pip3 cache purge || true

# ============================================================================
# STAGE 3: Application files
# ============================================================================
FROM python-deps AS app

# Copiar estructura completa del proyecto
COPY src/ ./src/
COPY webapp/ ./webapp/
COPY config/ ./config/
COPY scripts/ ./scripts/
COPY scan-agent.py ./
COPY README.md ./
COPY VERSION.md ./

# Crear directorios necesarios con permisos correctos
RUN mkdir -p outputs reports data logs && \
    # Hacer ejecutables los scripts
    chmod +x scripts/*.sh && \
    chmod +x scan-agent.py

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

# Cambiar a usuario no privilegiado por defecto
USER scanagent

# Punto de entrada y comando por defecto
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
