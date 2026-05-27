# ============================================================
#  Scan Agent - Lanzador de perfiles Docker Compose
#  Uso:  .\start.ps1                  (menu interactivo)
#        .\start.ps1 -Perfil lab      (perfil directo)
#        .\start.ps1 -Accion detener  (detener todo)
#        .\start.ps1 -Accion estado   (ver estado)
# ============================================================
param(
    [ValidateSet("cli","web","lab","analyzer","zap","dev","all","")]
    [string]$Perfil = "",

    [ValidateSet("iniciar","detener","reiniciar","estado","logs","reconstruir","limpiar","")]
    [string]$Accion = ""
)

# -- Colores --------------------------------------------------
$ESC = [char]27
function Write-Color([string]$Texto, [string]$Color = "White", [switch]$NoNewLine) {
    $codes = @{ Cyan="36"; Yellow="33"; Green="32"; Red="31"; Magenta="35"; White="37"; Gray="90"; Blue="34" }
    $c = $codes[$Color]
    if ($NoNewLine) { Write-Host "${ESC}[${c}m${Texto}${ESC}[0m" -NoNewline }
    else            { Write-Host "${ESC}[${c}m${Texto}${ESC}[0m" }
}

function Write-Banner {
    Clear-Host
    Write-Color ""
    Write-Color "  +------------------------------------------------------+" Cyan
    Write-Color "  |       SCAN AGENT  -  Lanzador de Perfiles            |" Cyan
    Write-Color "  |              Docker Compose v3.0                     |" Cyan
    Write-Color "  +------------------------------------------------------+" Cyan
    Write-Color ""
}

# -- Definicion de perfiles -----------------------------------
$Perfiles = [ordered]@{
    "1" = @{
        Key         = "cli"
        Nombre      = "CLI        - Escaneo desde linea de comandos"
        Descripcion = "Lanza scan-agent-cli. Ideal para escaneos rapidos en terminal."
        Icono       = "[>_]"
        Color       = "Cyan"
    }
    "2" = @{
        Key         = "web"
        Nombre      = "Web        - Interfaz web + Analyzer"
        Descripcion = "Web UI en :8080, API en :8000, analizador de resultados."
        Icono       = "[WEB]"
        Color       = "Blue"
    }
    "3" = @{
        Key         = "lab"
        Nombre      = "Lab        - Laboratorio completo"
        Descripcion = "Web UI + Juice Shop (:3000) + DVWA (:8081) + ZAP (:8090)."
        Icono       = "[LAB]"
        Color       = "Magenta"
    }
    "4" = @{
        Key         = "analyzer"
        Nombre      = "Analyzer   - Solo analisis de resultados"
        Descripcion = "Procesa outputs existentes y genera reportes. Sin escaneo activo."
        Icono       = "[ANA]"
        Color       = "Yellow"
    }
    "5" = @{
        Key         = "zap"
        Nombre      = "ZAP        - Solo OWASP ZAP"
        Descripcion = "Arranca unicamente OWASP ZAP en modo daemon (:8090)."
        Icono       = "[ZAP]"
        Color       = "Red"
    }
    "6" = @{
        Key         = "dev"
        Nombre      = "Dev        - Modo desarrollo (hot reload)"
        Descripcion = "Monta codigo fuente, DEBUG activo, shell interactivo."
        Icono       = "[DEV]"
        Color       = "Green"
    }
    "7" = @{
        Key         = "all"
        Nombre      = "All        - Todos los servicios"
        Descripcion = "Levanta absolutamente todo. Requiere bastantes recursos."
        Icono       = "[ALL]"
        Color       = "White"
    }
}

# -- Verificar Docker -----------------------------------------
function Test-Docker {
    $null = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Color "  [X] Docker no esta corriendo. Inicialo antes de continuar." Red
        exit 1
    }
}

# -- Menu de perfiles -----------------------------------------
function Show-MenuPerfiles {
    Write-Color "  Selecciona el perfil a iniciar:" White
    Write-Color ""
    foreach ($num in $Perfiles.Keys) {
        $p = $Perfiles[$num]
        Write-Color "  $num) " Gray -NoNewLine
        Write-Color "$($p.Icono) " $p.Color -NoNewLine
        Write-Color "$($p.Nombre)" White
        Write-Color "       $($p.Descripcion)" Gray
        Write-Color ""
    }
    Write-Color "  q) Salir" Gray
    Write-Color ""
}

# -- Menu de acciones -----------------------------------------
function Show-MenuAcciones([string]$perfilKey) {
    Write-Color ""
    Write-Color "  Accion para el perfil " White -NoNewLine
    Write-Color "[$perfilKey]" Yellow -NoNewLine
    Write-Color ":" White
    Write-Color ""
    Write-Color "  1) Iniciar        (docker compose up -d)" Green
    Write-Color "  2) Detener        (docker compose down)" Red
    Write-Color "  3) Reiniciar      (down + up)" Yellow
    Write-Color "  4) Ver estado     (docker compose ps)" Cyan
    Write-Color "  5) Ver logs       (docker compose logs -f)" Magenta
    Write-Color "  6) Reconstruir    (build --no-cache + up)" Yellow
    Write-Color "  7) Limpiar todo   (down -v + rmi + prune)" Red
    Write-Color "  b) Volver al menu de perfiles" Gray
    Write-Color ""
}

# -- Ejecutar accion Docker Compose ---------------------------
$ComposeFile = Join-Path $PSScriptRoot "docker\docker-compose.yml"

function Invoke-ComposeAction([string]$perfilKey, [string]$accion) {
    $base = "docker compose -f `"$ComposeFile`" --profile $perfilKey"

    switch ($accion) {
        "iniciar" {
            Write-Color ""
            Write-Color "  [>>] Iniciando perfil [$perfilKey]..." Green
            Write-Color ""
            Invoke-Expression "$base up -d"
            if ($LASTEXITCODE -eq 0) {
                Write-Color ""
                Write-Color "  [OK] Contenedores iniciados correctamente." Green
                Show-PortInfo $perfilKey
            } else {
                Write-Color "  [X]  Error al iniciar. Revisa los logs con: docker compose logs" Red
            }
        }
        "detener" {
            Write-Color ""
            Write-Color "  [..] Deteniendo perfil [$perfilKey]..." Red
            Write-Color ""
            Invoke-Expression "$base down"
            if ($LASTEXITCODE -eq 0) {
                Write-Color "  [OK] Contenedores detenidos." Green
            }
        }
        "reiniciar" {
            Write-Color ""
            Write-Color "  [~~] Reiniciando perfil [$perfilKey]..." Yellow
            Write-Color ""
            Invoke-Expression "$base down"
            Start-Sleep -Seconds 2
            Invoke-Expression "$base up -d"
            if ($LASTEXITCODE -eq 0) {
                Write-Color ""
                Write-Color "  [OK] Contenedores reiniciados." Green
                Show-PortInfo $perfilKey
            }
        }
        "estado" {
            Write-Color ""
            Invoke-Expression "$base ps"
        }
        "logs" {
            Write-Color ""
            Write-Color "  (Ctrl+C para salir de los logs)" Gray
            Write-Color ""
            Invoke-Expression "$base logs -f"
        }
        "reconstruir" {
            Write-Color ""
            Write-Color "  [BUILD] Reconstruyendo imagen para perfil [$perfilKey]..." Yellow
            Write-Color "  (reusa cache de paquetes del SO, solo actualiza capas de codigo)" Gray
            Write-Color ""
            Invoke-Expression "$base build"
            if ($LASTEXITCODE -eq 0) {
                Write-Color ""
                Write-Color "  [OK] Build completado. Iniciando contenedores..." Green
                Write-Color ""
                Invoke-Expression "$base up -d"
                if ($LASTEXITCODE -eq 0) {
                    Write-Color ""
                    Write-Color "  [OK] Contenedores iniciados con imagen actualizada." Green
                    Show-PortInfo $perfilKey
                }
            } else {
                Write-Color "  [X]  Error durante el build. Revisa el output." Red
            }
        }
        "limpiar" {
            Write-Color ""
            Write-Color "  [!] Esta accion eliminara:" Red
            Write-Color "      - Contenedores del perfil [$perfilKey]" Gray
            Write-Color "      - Volumenes asociados" Gray
            Write-Color "      - Imagenes del perfil" Gray
            Write-Color "      - Cache de build de Docker" Gray
            Write-Color ""
            Write-Color "  Confirmar? (s/N): " Yellow -NoNewLine
            $conf = Read-Host
            if ($conf -ne "s" -and $conf -ne "S") {
                Write-Color "  Cancelado." Gray
            } else {
                Write-Color ""
                Write-Color "  [..] Deteniendo y eliminando contenedores + volumenes..." Red
                Invoke-Expression "$base down -v --remove-orphans"
                Write-Color ""
                Write-Color "  [..] Eliminando imagenes del perfil..." Red
                Invoke-Expression "$base down --rmi all" 2>&1 | Out-Null
                Write-Color ""
                Write-Color "  [..] Limpiando cache de build..." Red
                docker builder prune -f 2>&1 | Out-Null
                Write-Color ""
                Write-Color "  [OK] Limpieza completada." Green
                Write-Color "       Usa 'Reconstruir' o 'Iniciar' para volver a levantar." Cyan
            }
        }
    }
    Write-Color ""
}

# -- Info de puertos segun perfil -----------------------------
function Show-PortInfo([string]$perfilKey) {
    $info = @{
        cli      = @()
        web      = @("  -> Web UI : http://localhost:8080",
                     "  -> API    : http://localhost:8000")
        lab      = @("  -> Web UI    : http://localhost:8080",
                     "  -> Juice Shop: http://localhost:3000",
                     "  -> DVWA      : http://localhost:8081  (admin / password)",
                     "  -> ZAP API   : http://localhost:8090")
        analyzer = @()
        zap      = @("  -> ZAP API: http://localhost:8090")
        dev      = @()
        all      = @("  -> Web UI    : http://localhost:8080",
                     "  -> Juice Shop: http://localhost:3000",
                     "  -> DVWA      : http://localhost:8081  (admin / password)",
                     "  -> ZAP API   : http://localhost:8090")
    }
    if ($info.ContainsKey($perfilKey) -and $info[$perfilKey].Count -gt 0) {
        Write-Color "  Accesos disponibles:" Cyan
        foreach ($linea in $info[$perfilKey]) {
            Write-Color $linea Yellow
        }
    }
}

# -- Resolver perfil desde clave o numero ---------------------
function Resolve-Perfil([string]$entrada) {
    if ($Perfiles.Contains($entrada)) { return $Perfiles[$entrada].Key }
    foreach ($p in $Perfiles.Values) {
        if ($p.Key -eq $entrada) { return $p.Key }
    }
    return $null
}

# -- Flujo principal ------------------------------------------
Test-Docker
Write-Banner

# Ejecucion directa si se pasaron ambos parametros
if ($Perfil -ne "" -and $Accion -ne "") {
    Invoke-ComposeAction $Perfil $Accion
    exit 0
}

# Si solo se paso -Perfil, resolver
$perfilSeleccionado = ""
if ($Perfil -ne "") {
    $perfilSeleccionado = Resolve-Perfil $Perfil
}

# Bucle principal
while ($true) {

    # Seleccion de perfil
    if ($perfilSeleccionado -eq "") {
        Write-Banner
        Show-MenuPerfiles
        Write-Color "  Opcion: " White -NoNewLine
        $entrada = Read-Host

        if ($entrada -eq "q" -or $entrada -eq "") {
            Write-Color "  Saliendo..." Gray
            exit 0
        }

        $perfilSeleccionado = Resolve-Perfil $entrada
        if ($null -eq $perfilSeleccionado) {
            Write-Color "  [X] Opcion no valida." Red
            Start-Sleep -Seconds 1
            continue
        }
    }

    # Menu de acciones
    Write-Banner
    Show-MenuAcciones $perfilSeleccionado
    Write-Color "  Opcion: " White -NoNewLine
    $accionEntrada = Read-Host

    $accionMap = @{
        "1" = "iniciar"
        "2" = "detener"
        "3" = "reiniciar"
        "4" = "estado"
        "5" = "logs"
        "6" = "reconstruir"
        "7" = "limpiar"
    }

    if ($accionEntrada -eq "b") {
        $perfilSeleccionado = ""
        continue
    }

    if (-not $accionMap.ContainsKey($accionEntrada)) {
        Write-Color "  [X] Opcion no valida." Red
        Start-Sleep -Seconds 1
        continue
    }

    Invoke-ComposeAction $perfilSeleccionado $accionMap[$accionEntrada]

    Write-Color "  Presiona Enter para continuar..." Gray
    Read-Host | Out-Null
}
