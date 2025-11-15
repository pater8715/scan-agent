#!/usr/bin/env python3
"""
Scan Agent - Entry Point
========================
Wrapper para ejecutar scan agent con los imports correctos.
"""

import sys
from pathlib import Path

# Añadir src/ al path de Python
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# Importar y ejecutar el agente
from scanagent.agent import main

if __name__ == "__main__":
    sys.exit(main())
