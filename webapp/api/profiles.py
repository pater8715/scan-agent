"""
Profiles API Router
===================
Endpoints para obtener información sobre perfiles de escaneo disponibles.
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Dict
import sys
from pathlib import Path

# Importar módulos de scanagent
src_path = Path(__file__).parent.parent.parent / "src"
sys.path.insert(0, str(src_path))

from scanagent.scanner import VulnerabilityScanner

router = APIRouter()


class ScanProfileInfo(BaseModel):
    """Información de un perfil de escaneo"""
    id: str
    name: str
    description: str
    estimated_time: str
    tools: List[str]
    requires_sudo: bool


class ProfileParameter(BaseModel):
    """Parámetro configurable de un perfil"""
    name: str
    type: str  # text, number, boolean
    label: str
    description: str
    required: bool
    default: str = ""


@router.get("/", response_model=List[ScanProfileInfo])
async def get_profiles():
    """
    Obtiene la lista de todos los perfiles de escaneo disponibles.
    """
    scanner = VulnerabilityScanner()
    profiles_info = []
    
    for profile_id, profile in scanner.PROFILES.items():
        # Extraer herramientas únicas
        tools = list(set([cmd['tool'] for cmd in profile.commands]))
        
        # Estimar tiempo
        time_estimates = {
            'quick': '5-10 minutos',
            'standard': '15-20 minutos',
            'full': '30-60 minutos',
            'web-full': '20-30 minutos'
        }
        
        profiles_info.append(ScanProfileInfo(
            id=profile_id,
            name=profile.name,
            description=profile.description,
            estimated_time=time_estimates.get(profile_id, 'Variable'),
            tools=tools,
            requires_sudo=profile.requires_sudo
        ))
    
    return profiles_info


@router.get("/{profile_id}", response_model=ScanProfileInfo)
async def get_profile(profile_id: str):
    """
    Obtiene información detallada de un perfil específico.
    """
    scanner = VulnerabilityScanner()
    
    if profile_id not in scanner.PROFILES:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Perfil no encontrado")
    
    profile = scanner.PROFILES[profile_id]
    tools = list(set([cmd['tool'] for cmd in profile.commands]))
    
    time_estimates = {
        'quick': '5-10 minutos',
        'standard': '15-20 minutos',
        'full': '30-60 minutos',
        'web-full': '20-30 minutos'
    }
    
    return ScanProfileInfo(
        id=profile_id,
        name=profile.name,
        description=profile.description,
        estimated_time=time_estimates.get(profile_id, 'Variable'),
        tools=tools,
        requires_sudo=profile.requires_sudo
    )


@router.get("/{profile_id}/parameters", response_model=List[ProfileParameter])
async def get_profile_parameters(profile_id: str):
    """
    Obtiene los parámetros configurables de un perfil.
    
    Por ahora, todos los perfiles usan el mismo conjunto básico de parámetros.
    """
    # Parámetros comunes para todos los perfiles
    parameters = [
        ProfileParameter(
            name="target",
            type="text",
            label="Objetivo",
            description="Dirección IP o dominio a escanear",
            required=True,
            default=""
        ),
        ProfileParameter(
            name="output_formats",
            type="multiselect",
            label="Formatos de Reporte",
            description="Selecciona los formatos en los que deseas el reporte",
            required=False,
            default="json,html"
        ),
        ProfileParameter(
            name="save_to_db",
            type="boolean",
            label="Guardar en Base de Datos",
            description="Almacenar resultados en la base de datos local",
            required=False,
            default="true"
        )
    ]
    
    # Parámetros específicos según el perfil
    if profile_id == "web-full":
        parameters.append(
            ProfileParameter(
                name="wordlist",
                type="text",
                label="Wordlist (opcional)",
                description="Ruta a wordlist personalizada para gobuster",
                required=False,
                default=""
            )
        )
    
    return parameters
