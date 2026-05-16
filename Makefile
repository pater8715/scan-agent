# Scan Agent v3.0 - Docker Makefile
# ===================================
# Comandos útiles para gestionar contenedores Docker

# Variables
IMAGE_NAME = scan-agent
VERSION = 3.0.0
REGISTRY = ghcr.io/pater8715
FULL_IMAGE = $(REGISTRY)/$(IMAGE_NAME):$(VERSION)
LATEST_IMAGE = $(REGISTRY)/$(IMAGE_NAME):latest

# Colores para output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

.PHONY: help build build-dev push pull run-cli run-web run-analyzer clean logs shell test lab-start lab-stop lab-status lab-scan-juice lab-scan-dvwa

# Comando por defecto
help: ## Mostrar esta ayuda
	@echo -e "$(BLUE)Scan Agent v3.0 - Docker Management$(NC)"
	@echo -e "$(BLUE)===================================$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo -e "$(YELLOW)Ejemplos:$(NC)"
	@echo "  make build                 # Construir imagen"
	@echo "  make run-web              # Ejecutar interfaz web"
	@echo "  make run-cli TARGET=scanme.nmap.org  # Escaneo CLI"
	@echo "  make shell                # Acceso interactivo"

# ============================================================================
# CONSTRUCCIÓN
# ============================================================================

build: ## Construir imagen Docker
	@echo -e "$(BLUE)[BUILD]$(NC) Construyendo imagen $(IMAGE_NAME):$(VERSION)..."
	docker build -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest -f docker/Dockerfile .
	@echo -e "$(GREEN)[OK]$(NC) Imagen construida exitosamente"

build-dev: ## Construir imagen de desarrollo
	@echo -e "$(BLUE)[BUILD]$(NC) Construyendo imagen de desarrollo..."
	docker build --target app -t $(IMAGE_NAME):$(VERSION)-dev -f docker/Dockerfile .
	@echo -e "$(GREEN)[OK]$(NC) Imagen de desarrollo construida"

build-no-cache: ## Construir imagen sin cache
	@echo -e "$(BLUE)[BUILD]$(NC) Construyendo imagen sin cache..."
	docker build --no-cache -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest -f docker/Dockerfile .
	@echo -e "$(GREEN)[OK]$(NC) Imagen construida sin cache"

# ============================================================================
# PUBLICACIÓN
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
# EJECUCIÓN - DOCKER COMPOSE
# ============================================================================

up: ## Iniciar todos los servicios
	@echo -e "$(BLUE)[UP]$(NC) Iniciando servicios con docker-compose..."
	cd docker && docker-compose --profile all up -d
	@echo -e "$(GREEN)[OK]$(NC) Servicios iniciados"

up-web: ## Iniciar solo interfaz web
	@echo -e "$(BLUE)[UP]$(NC) Iniciando interfaz web..."
	cd docker && docker-compose --profile web up -d
	@echo -e "$(GREEN)[OK]$(NC) Interfaz web disponible en http://localhost:8080"

up-dev: ## Iniciar servicios en modo desarrollo
	@echo -e "$(BLUE)[UP]$(NC) Iniciando servicios en modo desarrollo..."
	cd docker && docker-compose --profile dev up -d
	@echo -e "$(GREEN)[OK]$(NC) Servicios de desarrollo iniciados"

down: ## Detener todos los servicios
	@echo -e "$(BLUE)[DOWN]$(NC) Deteniendo servicios..."
	cd docker && docker-compose down
	@echo -e "$(GREEN)[OK]$(NC) Servicios detenidos"

restart: down up ## Reiniciar servicios

# ============================================================================
# EJECUCIÓN - DOCKER RUN
# ============================================================================

run-help: ## Mostrar ayuda del scan-agent
	@echo -e "$(BLUE)[RUN]$(NC) Mostrando ayuda de Scan Agent..."
	docker run --rm $(IMAGE_NAME):$(VERSION) --help

run-version: ## Mostrar versión
	@echo -e "$(BLUE)[RUN]$(NC) Mostrando versión..."
	docker run --rm $(IMAGE_NAME):$(VERSION) --version

run-web: ## Ejecutar interfaz web
	@echo -e "$(BLUE)[RUN]$(NC) Iniciando interfaz web..."
	@echo -e "$(YELLOW)[INFO]$(NC) Acceso: http://localhost:8080"
	docker run --rm -p 8080:8080 \
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
	@echo -e "$(BLUE)[RUN]$(NC) Ejecutando escaneo CLI contra $(TARGET)..."
	docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		$(IMAGE_NAME):$(VERSION) --scan --target $(TARGET) --profile quick

run-analyzer: ## Ejecutar análisis de resultados existentes
	@echo -e "$(BLUE)[RUN]$(NC) Ejecutando análisis de resultados..."
	docker run --rm \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		$(IMAGE_NAME):$(VERSION) --outputs-dir /scan-agent/outputs --format html

shell: ## Acceso interactivo al contenedor
	@echo -e "$(BLUE)[SHELL]$(NC) Accediendo al contenedor..."
	docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		-v $$(pwd)/data:/scan-agent/data \
		-v $$(pwd)/logs:/scan-agent/logs \
		$(IMAGE_NAME):$(VERSION) /bin/bash

# ============================================================================
# GESTIÓN Y MANTENIMIENTO
# ============================================================================

logs: ## Ver logs de los servicios
	@echo -e "$(BLUE)[LOGS]$(NC) Mostrando logs..."
	cd docker && docker-compose logs -f

logs-web: ## Ver logs del servicio web
	@echo -e "$(BLUE)[LOGS]$(NC) Logs del servicio web..."
	cd docker && docker-compose logs -f scan-agent-web

status: ## Ver estado de los contenedores
	@echo -e "$(BLUE)[STATUS]$(NC) Estado de contenedores Scan Agent:"
	@docker ps -a --filter "name=scan-agent" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

clean: ## Limpiar contenedores e imágenes
	@echo -e "$(BLUE)[CLEAN]$(NC) Limpiando contenedores detenidos..."
	docker container prune -f
	@echo -e "$(BLUE)[CLEAN]$(NC) Limpiando imágenes no utilizadas..."
	docker image prune -f
	@echo -e "$(GREEN)[OK]$(NC) Limpieza completada"

clean-all: ## Limpiar todo (contenedores, imágenes, volúmenes)
	@echo -e "$(YELLOW)[WARNING]$(NC) Esto eliminará TODOS los contenedores, imágenes y volúmenes"
	@read -p "¿Continuar? [y/N]: " confirm && [ "$$confirm" = "y" ]
	@echo -e "$(BLUE)[CLEAN]$(NC) Limpieza completa..."
	cd docker && docker-compose down -v --remove-orphans
	docker system prune -af --volumes
	@echo -e "$(GREEN)[OK]$(NC) Limpieza completa terminada"

# ============================================================================
# DESARROLLO Y TESTING
# ============================================================================

test: ## Ejecutar tests básicos
	@echo -e "$(BLUE)[TEST]$(NC) Ejecutando tests básicos..."
	docker run --rm $(IMAGE_NAME):$(VERSION) --version
	docker run --rm $(IMAGE_NAME):$(VERSION) --list-profiles
	@echo -e "$(GREEN)[OK]$(NC) Tests básicos completados"

test-scan: ## Test de escaneo (requiere TARGET)
ifndef TARGET
	@echo -e "$(RED)[ERROR]$(NC) Especifica TARGET=<ip|domain>"
	@exit 1
endif
	@echo -e "$(BLUE)[TEST]$(NC) Test de escaneo contra $(TARGET)..."
	docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		$(IMAGE_NAME):$(VERSION) --scan --target $(TARGET) --profile quick --debug

dev-setup: ## Configurar entorno de desarrollo
	@echo -e "$(BLUE)[DEV]$(NC) Configurando entorno de desarrollo..."
	mkdir -p outputs reports data logs
	cd docker && docker-compose --profile dev up -d
	@echo -e "$(GREEN)[OK]$(NC) Entorno de desarrollo configurado"

# ============================================================================
# INFORMACIÓN
# ============================================================================

info: ## Mostrar información del sistema
	@echo -e "$(BLUE)[INFO]$(NC) Información del sistema Docker:"
	@echo "Docker version: $$(docker --version)"
	@echo "Docker Compose version: $$(docker-compose --version)"
	@echo "Imagen: $(IMAGE_NAME):$(VERSION)"
	@echo "Registry: $(REGISTRY)"
	@echo ""
	@echo -e "$(BLUE)[INFO]$(NC) Imágenes locales:"
	@docker images | grep $(IMAGE_NAME) || echo "No hay imágenes locales"
	@echo ""
	@echo -e "$(BLUE)[INFO]$(NC) Contenedores relacionados:"
	@docker ps -a --filter "name=scan-agent" || echo "No hay contenedores"

size: ## Mostrar tamaño de la imagen
	@echo -e "$(BLUE)[SIZE]$(NC) Tamaño de la imagen:"
	@docker images $(IMAGE_NAME):$(VERSION) --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

# ============================================================================
# ATAJOS ÚTILES
# ============================================================================

quick-scan: ## Escaneo rápido (usar TARGET=ip)
ifndef TARGET
	@echo -e "$(RED)[ERROR]$(NC) Uso: make quick-scan TARGET=<ip|domain>"
	@exit 1
endif
	@make run-cli TARGET=$(TARGET)
	@make run-analyzer

web-ui: up-web ## Alias para iniciar interfaz web

stop: down ## Alias para detener servicios

# ============================================================================
# ENTORNO DE LABORATORIO (FASE 4) - Juice Shop + DVWA + Web UI
# ============================================================================

lab-start: ## Iniciar entorno de práctica completo (Juice Shop + DVWA + Web UI)
	@echo -e "$(BLUE)[LAB]$(NC) Iniciando entorno de laboratorio..."
	@echo -e "$(YELLOW)[INFO]$(NC) Descargando imágenes si es necesario (primera vez puede tardar)..."
	cd docker && docker-compose --profile lab up -d
	@echo ""
	@echo -e "$(GREEN)[LAB LISTO]$(NC) Entorno de práctica disponible:"
	@echo -e "  $(GREEN)►$(NC) Scan Agent Web UI : http://localhost:8080"
	@echo -e "  $(GREEN)►$(NC) OWASP Juice Shop   : http://localhost:3000"
	@echo -e "  $(GREEN)►$(NC) DVWA               : http://localhost:8081"
	@echo -e "  $(YELLOW)  DVWA credenciales  : admin / password$(NC)"
	@echo ""
	@echo -e "$(YELLOW)[DVWA]$(NC) Primera vez: ingresa a http://localhost:8081/setup.php y haz clic en 'Create / Reset Database'"

lab-stop: ## Detener entorno de práctica
	@echo -e "$(BLUE)[LAB]$(NC) Deteniendo entorno de laboratorio..."
	cd docker && docker-compose --profile lab down
	@echo -e "$(GREEN)[OK]$(NC) Entorno de laboratorio detenido"

lab-status: ## Ver estado del entorno de práctica
	@echo -e "$(BLUE)[LAB]$(NC) Estado del entorno de laboratorio:"
	@docker ps -a --filter "name=juice-shop" --filter "name=dvwa" --filter "name=scan-agent-web" \
		--format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

lab-scan-juice: ## Escanear OWASP Juice Shop con perfil lab
	@echo -e "$(BLUE)[LAB]$(NC) Escaneando OWASP Juice Shop (localhost:3000)..."
	docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
		--network scan-agent-network \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		$(IMAGE_NAME):$(VERSION) --scan --target juice-shop:3000 --profile lab
	@echo -e "$(GREEN)[OK]$(NC) Reporte disponible en ./reports/"

lab-scan-dvwa: ## Escanear DVWA con perfil lab
	@echo -e "$(BLUE)[LAB]$(NC) Escaneando DVWA (localhost:8081)..."
	docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
		--network scan-agent-network \
		-v $$(pwd)/outputs:/scan-agent/outputs \
		-v $$(pwd)/reports:/scan-agent/reports \
		$(IMAGE_NAME):$(VERSION) --scan --target dvwa:80 --profile lab
	@echo -e "$(GREEN)[OK]$(NC) Reporte disponible en ./reports/"