# Scan Agent v3.0 - Docker Makefile
# ===================================
# Comandos para gestionar contenedores Docker
#
# NOTA: En Windows usar start.ps1 para el menu interactivo de perfiles:
#   .\start.ps1                          -> menu interactivo
#   .\start.ps1 -Perfil lab -Accion iniciar
#   .\start.ps1 -Perfil web -Accion reconstruir

# Variables
IMAGE_NAME  = scan-agent
VERSION     = 3.0.0
REGISTRY    = ghcr.io/pater8715
FULL_IMAGE  = $(REGISTRY)/$(IMAGE_NAME):$(VERSION)
LATEST_IMAGE = $(REGISTRY)/$(IMAGE_NAME):latest
COMPOSE     = docker compose -f docker/docker-compose.yml

# Colores para output
RED    = \033[0;31m
GREEN  = \033[0;32m
YELLOW = \033[1;33m
BLUE   = \033[0;34m
NC     = \033[0m

.PHONY: help build build-dev build-no-cache push pull \
        up up-web up-lab up-cli up-dev up-analyzer up-zap \
        down restart logs logs-web status \
        run-help run-web run-cli run-analyzer shell \
        clean clean-all test test-unit test-unit-docker test-scan \
        lab-start lab-stop lab-status lab-scan-juice lab-scan-dvwa \
        zap-start zap-stop zap-status zap-scan-juice zap-scan-dvwa zap-active-juice \
        dep-scan ctf-list ctf-scoreboard ctf-start sarif-report info size

# Comando por defecto
help: ## Mostrar esta ayuda
	@echo -e "$(BLUE)Scan Agent v3.0 - Docker Management$(NC)"
	@echo -e "$(BLUE)===================================$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-22s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo -e "$(YELLOW)Ejemplos:$(NC)"
	@echo "  make build                          # Construir imagen"
	@echo "  make up-web                         # Levantar interfaz web"
	@echo "  make up-lab                         # Levantar laboratorio completo"
	@echo "  make run-cli TARGET=scanme.nmap.org # Escaneo CLI"
	@echo "  make shell                          # Acceso interactivo"
	@echo ""
	@echo -e "$(YELLOW)Windows (menu interactivo):$(NC)"
	@echo "  .\\start.ps1"

# ============================================================================
# CONSTRUCCION
# ============================================================================

build: ## Construir imagen Docker (usa cache de capas)
	@echo -e "$(BLUE)[BUILD]$(NC) Construyendo $(IMAGE_NAME):$(VERSION)..."
	$(COMPOSE) build
	@echo -e "$(GREEN)[OK]$(NC) Imagen construida exitosamente"

build-dev: ## Construir imagen de desarrollo
	@echo -e "$(BLUE)[BUILD]$(NC) Construyendo imagen de desarrollo..."
	docker build --target app -t $(IMAGE_NAME):$(VERSION)-dev -f docker/Dockerfile .
	@echo -e "$(GREEN)[OK]$(NC) Imagen de desarrollo construida"

build-no-cache: ## Construir imagen sin cache (puede fallar por mirrors de Kali rolling)
	@echo -e "$(BLUE)[BUILD]$(NC) Construyendo sin cache — puede tardar varios minutos..."
	@echo -e "$(YELLOW)[AVISO]$(NC) Si falla por mirrors de Kali, usar: make build"
	$(COMPOSE) build --no-cache
	@echo -e "$(GREEN)[OK]$(NC) Imagen construida sin cache"

# ============================================================================
# PUBLICACION
# ============================================================================

push: ## Subir imagen al registry
	@echo -e "$(BLUE)[PUSH]$(NC) Subiendo imagen al registry..."
	docker tag $(IMAGE_NAME):$(VERSION) $(FULL_IMAGE)
	docker tag $(IMAGE_NAME):$(VERSION) $(LATEST_IMAGE)
	docker push $(FULL_IMAGE)
	docker push $(LATEST_IMAGE)
	@echo -e "$(GREEN)[OK]$(NC) Imagen subida al registry"

pull: ## Descargar imagen del registry
	@echo -e "$(BLUE)[PULL]$(NC) Descargando imagen del registry..."
	docker pull $(FULL_IMAGE)
	docker tag $(FULL_IMAGE) $(IMAGE_NAME):$(VERSION)
	@echo -e "$(GREEN)[OK]$(NC) Imagen descargada"

# ============================================================================
# EJECUCION — DOCKER COMPOSE (por perfil)
# ============================================================================

up: ## Iniciar todos los servicios (perfil all)
	@echo -e "$(BLUE)[UP]$(NC) Iniciando todos los servicios..."
	$(COMPOSE) --profile all up -d
	@echo -e "$(GREEN)[OK]$(NC) Servicios iniciados"

up-web: ## Iniciar Web UI + Analyzer (perfil web)
	@echo -e "$(BLUE)[UP]$(NC) Iniciando interfaz web..."
	$(COMPOSE) --profile web up -d
	@echo -e "$(GREEN)[OK]$(NC) Web UI en http://localhost:8080 | API en http://localhost:8000"

up-lab: ## Iniciar laboratorio completo — Web + Juice Shop + DVWA + ZAP (perfil lab)
	@echo -e "$(BLUE)[LAB]$(NC) Iniciando entorno de laboratorio..."
	$(COMPOSE) --profile lab up -d
	@echo ""
	@echo -e "$(GREEN)[LAB LISTO]$(NC) Accesos:"
	@echo -e "  $(GREEN)>>$(NC) Scan Agent  : http://localhost:8080"
	@echo -e "  $(GREEN)>>$(NC) Juice Shop  : http://localhost:3000"
	@echo -e "  $(GREEN)>>$(NC) DVWA        : http://localhost:8081  (admin / password)"
	@echo -e "  $(GREEN)>>$(NC) ZAP API     : http://localhost:8090"
	@echo ""
	@echo -e "$(YELLOW)[DVWA]$(NC) Primera vez: http://localhost:8081/setup.php -> Create / Reset Database"

up-cli: ## Iniciar solo servicio CLI (perfil cli)
	@echo -e "$(BLUE)[UP]$(NC) Iniciando servicio CLI..."
	$(COMPOSE) --profile cli up -d
	@echo -e "$(GREEN)[OK]$(NC) CLI listo"

up-analyzer: ## Iniciar solo el analyzer (perfil analyzer)
	@echo -e "$(BLUE)[UP]$(NC) Iniciando analyzer..."
	$(COMPOSE) --profile analyzer up -d

up-zap: ## Iniciar solo OWASP ZAP (perfil zap)
	@echo -e "$(BLUE)[UP]$(NC) Iniciando OWASP ZAP..."
	$(COMPOSE) --profile zap up -d
	@echo -e "$(GREEN)[OK]$(NC) ZAP API en http://localhost:8090 (tarda ~30s)"

up-dev: ## Iniciar modo desarrollo con hot reload (perfil dev)
	@echo -e "$(BLUE)[UP]$(NC) Iniciando modo desarrollo..."
	$(COMPOSE) --profile dev up -d
	@echo -e "$(GREEN)[OK]$(NC) Entorno de desarrollo listo"

down: ## Detener todos los servicios
	@echo -e "$(BLUE)[DOWN]$(NC) Deteniendo servicios..."
	$(COMPOSE) --profile all down
	@echo -e "$(GREEN)[OK]$(NC) Servicios detenidos"

restart: down up-web ## Reiniciar servicios web

# ============================================================================
# EJECUCION — DOCKER RUN
# ============================================================================

run-help: ## Mostrar ayuda del scan-agent
	docker run --rm $(IMAGE_NAME):$(VERSION) --help

run-version: ## Mostrar version del scan-agent
	docker run --rm $(IMAGE_NAME):$(VERSION) --version

run-web: ## Ejecutar interfaz web standalone (sin compose)
	@echo -e "$(BLUE)[RUN]$(NC) Iniciando web standalone en http://localhost:8080"
	docker run --rm -p 8080:8080 -p 8000:8000 \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		-v $$(pwd)/data:/scan-agent/data \
		-v $$(pwd)/logs:/scan-agent/logs \
		$(IMAGE_NAME):$(VERSION) --web

run-cli: ## Ejecutar escaneo CLI (usar TARGET=ip)
ifndef TARGET
	@echo -e "$(RED)[ERROR]$(NC) Especifica TARGET=<ip|domain>"
	@echo "Ejemplo: make run-cli TARGET=scanme.nmap.org"
	@exit 1
endif
	@echo -e "$(BLUE)[RUN]$(NC) Escaneando $(TARGET)..."
	docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		$(IMAGE_NAME):$(VERSION) --scan --target $(TARGET) --profile quick

run-analyzer: ## Ejecutar analisis de resultados existentes
	@echo -e "$(BLUE)[RUN]$(NC) Analizando resultados en ./outputs/..."
	docker run --rm \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		$(IMAGE_NAME):$(VERSION) --outputs-dir /scan-agent/outputs --format html

shell: ## Acceso interactivo al contenedor
	@echo -e "$(BLUE)[SHELL]$(NC) Abriendo shell interactivo..."
	docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		-v $$(pwd)/data:/scan-agent/data \
		-v $$(pwd)/logs:/scan-agent/logs \
		$(IMAGE_NAME):$(VERSION) /bin/bash

# ============================================================================
# GESTION Y MANTENIMIENTO
# ============================================================================

logs: ## Ver logs de todos los servicios activos
	$(COMPOSE) --profile all logs -f

logs-web: ## Ver logs del servicio web
	$(COMPOSE) --profile web logs -f scan-agent-web

status: ## Ver estado de todos los contenedores
	@echo -e "$(BLUE)[STATUS]$(NC) Contenedores Scan Agent:"
	@docker ps -a --filter "name=scan-agent" --filter "name=juice-shop" \
		--filter "name=dvwa" --filter "name=zap" \
		--format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

clean: ## Limpiar contenedores e imagenes huerfanas
	@echo -e "$(BLUE)[CLEAN]$(NC) Limpiando recursos no utilizados..."
	docker container prune -f
	docker image prune -f
	@echo -e "$(GREEN)[OK]$(NC) Limpieza completada"

clean-all: ## Limpiar todo — contenedores, imagenes y volumenes (con confirmacion)
	@echo -e "$(YELLOW)[WARNING]$(NC) Esto eliminara TODOS los contenedores, imagenes y volumenes"
	@read -p "Continuar? [y/N]: " confirm && [ "$$confirm" = "y" ]
	$(COMPOSE) --profile all down -v --remove-orphans
	$(COMPOSE) --profile all down --rmi all 2>/dev/null || true
	docker builder prune -f
	@echo -e "$(GREEN)[OK]$(NC) Limpieza completa terminada"

# ============================================================================
# TESTING
# ============================================================================

test: ## Tests basicos de la imagen (version + perfiles)
	@echo -e "$(BLUE)[TEST]$(NC) Tests basicos..."
	docker run --rm $(IMAGE_NAME):$(VERSION) --version
	docker run --rm $(IMAGE_NAME):$(VERSION) --list-profiles
	@echo -e "$(GREEN)[OK]$(NC) Tests basicos completados"

test-unit: ## Suite pytest en local (requiere: pip install pytest)
	python3 -m pytest tests/ -v --tb=short

test-unit-docker: ## Suite pytest dentro del contenedor
	docker run --rm \
		-v $$(pwd)/tests:/scan-agent/tests:ro \
		-v $$(pwd)/pytest.ini:/scan-agent/pytest.ini:ro \
		--entrypoint python3 $(IMAGE_NAME):$(VERSION) \
		-m pytest /scan-agent/tests/ -v --tb=short

test-scan: ## Test de escaneo contra TARGET
ifndef TARGET
	@echo -e "$(RED)[ERROR]$(NC) Especifica TARGET=<ip|domain>"
	@exit 1
endif
	docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		$(IMAGE_NAME):$(VERSION) --scan --target $(TARGET) --profile quick --debug

# ============================================================================
# LABORATORIO — Juice Shop + DVWA + ZAP
# ============================================================================

lab-start: up-lab ## Alias para iniciar el laboratorio completo

lab-stop: ## Detener laboratorio
	@echo -e "$(BLUE)[LAB]$(NC) Deteniendo laboratorio..."
	$(COMPOSE) --profile lab down
	@echo -e "$(GREEN)[OK]$(NC) Laboratorio detenido"

lab-status: ## Ver estado del laboratorio
	@echo -e "$(BLUE)[LAB]$(NC) Estado:"
	@docker ps -a --filter "name=juice-shop" --filter "name=dvwa" \
		--filter "name=scan-agent-web" --filter "name=zap" \
		--format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

lab-scan-juice: ## Escanear OWASP Juice Shop
	@echo -e "$(BLUE)[LAB]$(NC) Escaneando Juice Shop..."
	docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
		--network scan-agent-network \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		$(IMAGE_NAME):$(VERSION) --scan --target juice-shop:3000 --profile lab
	@echo -e "$(GREEN)[OK]$(NC) Reporte en ./reports/"

lab-scan-dvwa: ## Escanear DVWA
	@echo -e "$(BLUE)[LAB]$(NC) Escaneando DVWA..."
	docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
		--network scan-agent-network \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		$(IMAGE_NAME):$(VERSION) --scan --target dvwa:80 --profile lab
	@echo -e "$(GREEN)[OK]$(NC) Reporte en ./reports/"

zap-start: up-lab ## Alias para levantar lab con ZAP incluido

zap-stop: lab-stop ## Alias para detener lab con ZAP

zap-status: ## Ver estado de ZAP
	@echo -e "$(BLUE)[ZAP]$(NC) Estado:"
	@docker ps -a --filter "name=zap" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	@echo ""
	@echo -e "$(BLUE)[ZAP]$(NC) Verificando API..."
	@curl -s "http://localhost:8090/JSON/core/view/version/?apikey=zap-scan-agent-lab" 2>/dev/null \
		| python3 -c "import sys,json; d=json.load(sys.stdin); print('  ZAP version:', d['version'])" \
		|| echo -e "  $(YELLOW)ZAP aun iniciando o no disponible$(NC)"

zap-scan-juice: ## Escaneo PASIVO ZAP sobre Juice Shop
	docker run --rm --network scan-agent-network \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		-e ZAP_HOST=zap -e ZAP_PORT=8090 \
		$(IMAGE_NAME):$(VERSION) --scan --target juice-shop:3000 --profile zap-passive

zap-scan-dvwa: ## Escaneo PASIVO ZAP sobre DVWA
	docker run --rm --network scan-agent-network \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		-e ZAP_HOST=zap -e ZAP_PORT=8090 \
		$(IMAGE_NAME):$(VERSION) --scan --target dvwa:80 --profile zap-passive

zap-active-juice: ## Escaneo ACTIVO ZAP sobre Juice Shop (30-60 min)
	@echo -e "$(YELLOW)[ZAP ACTIVO]$(NC) Puede tardar 30-60 minutos..."
	docker run --rm --network scan-agent-network \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		-e ZAP_HOST=zap -e ZAP_PORT=8090 \
		$(IMAGE_NAME):$(VERSION) --scan --target juice-shop:3000 --profile zap-active

# ============================================================================
# FUNCIONALIDADES AVANZADAS (Fase 7)
# ============================================================================

dep-scan: ## Escanear dependencias del proyecto buscando CVEs
	docker run --rm \
		-v $$(pwd):/scan-agent/project:ro \
		$(IMAGE_NAME):$(VERSION) --dep-scan /scan-agent/project

ctf-list: ## Listar desafios CTF disponibles
	docker run --rm \
		-v $$(pwd)/data:/scan-agent/data \
		-v $$(pwd)/config:/scan-agent/config:ro \
		$(IMAGE_NAME):$(VERSION) --ctf list

ctf-scoreboard: ## Ver ranking CTF
	docker run --rm \
		-v $$(pwd)/data:/scan-agent/data \
		-v $$(pwd)/config:/scan-agent/config:ro \
		$(IMAGE_NAME):$(VERSION) --ctf scoreboard

ctf-start: ## Iniciar desafio CTF (requiere CHALLENGE_ID=CTF-XX)
ifndef CHALLENGE_ID
	@echo -e "$(RED)[ERROR]$(NC) Especifica CHALLENGE_ID=CTF-01 (y opcionalmente STUDENT_ID=nombre)"
	@exit 1
endif
	docker run --rm \
		-v $$(pwd)/data:/scan-agent/data \
		-v $$(pwd)/config:/scan-agent/config:ro \
		-e STUDENT_ID=$${STUDENT_ID:-anonymous} \
		$(IMAGE_NAME):$(VERSION) --ctf start --challenge-id $(CHALLENGE_ID)

sarif-report: ## Generar reporte SARIF para GitHub Advanced Security
	docker run --rm \
		-v $$(pwd)/outputs:/scan-agent/outputs:ro \
		-v $$(pwd)/reports:/scan-agent/reports \
		$(IMAGE_NAME):$(VERSION) --format sarif
	@echo -e "$(GREEN)[OK]$(NC) SARIF generado en ./reports/"

# ============================================================================
# INFORMACION
# ============================================================================

info: ## Mostrar informacion del entorno Docker
	@echo -e "$(BLUE)[INFO]$(NC) Docker:"
	@docker --version
	@docker compose version
	@echo ""
	@echo -e "$(BLUE)[INFO]$(NC) Imagen: $(IMAGE_NAME):$(VERSION)"
	@echo -e "$(BLUE)[INFO]$(NC) Registry: $(REGISTRY)"
	@echo ""
	@echo -e "$(BLUE)[INFO]$(NC) Contenedores activos:"
	@docker ps --filter "name=scan-agent" --filter "name=juice-shop" \
		--filter "name=dvwa" --filter "name=zap" \
		--format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "  Ninguno"

size: ## Mostrar tamano de la imagen
	@docker images $(IMAGE_NAME):$(VERSION) \
		--format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" 2>/dev/null \
		|| echo "Imagen no encontrada localmente"

# ============================================================================
# ATAJOS
# ============================================================================

quick-scan: ## Escaneo rapido + analisis (requiere TARGET=ip)
ifndef TARGET
	@echo -e "$(RED)[ERROR]$(NC) Uso: make quick-scan TARGET=<ip|domain>"
	@exit 1
endif
	@make run-cli TARGET=$(TARGET)
	@make run-analyzer

web-ui:  up-web  ## Alias para iniciar la interfaz web
stop:    down    ## Alias para detener servicios
dev-setup: up-dev ## Alias para iniciar entorno de desarrollo
