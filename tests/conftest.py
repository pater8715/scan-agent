"""
Configuración global de pytest para Scan Agent.
"""

import sys
from pathlib import Path

# Asegurar que src/ y el proyecto raíz estén en el path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))