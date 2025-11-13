# Scan Agent v2.0 - Dockerfile
# =============================
# Imagen Docker para ejecutar Scan Agent con todas las herramientas de pentesting

FROM kalilinux/kali-rolling:latest

# Metadata
LABEL maintainer="Scan Agent Team"
LABEL version="2.1.0"
LABEL description="Agente de análisis de vulnerabilidades web - Estructura reorganizada siguiendo mejores prácticas Python"

# Evitar prompts interactivos durante la instalación
ENV DEBIAN_FRONTEND=noninteractive

# Actualizar sistema e instalar herramientas de pentesting
RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    nikto \
    gobuster \
    curl \
    wget \
    git \
    vim \
    sqlite3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /scan-agent

# Copiar estructura del proyecto
COPY src/ ./src/
COPY config/ ./config/
COPY scan-agent.py ./
COPY scripts/docker-entrypoint.sh /usr/local/bin/
COPY requirements.txt .
COPY README.md .

# Crear directorios necesarios
RUN mkdir -p outputs reports data

# Dar permisos de ejecución
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Crear usuario no privilegiado para escaneos que no requieran sudo
RUN useradd -m -s /bin/bash scanagent && \
    chown -R scanagent:scanagent /scan-agent

# Volúmenes para persistir resultados y BD
VOLUME ["/scan-agent/outputs", "/scan-agent/reports", "/scan-agent/data"]

# Puerto expuesto (por si se agrega interfaz web en el futuro)
EXPOSE 8080

# Script de entrada
COPY scripts/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--help"]
