"""
Tests para el módulo de logging estructurado.
Verifica que setup_logging configure el logger raíz correctamente
y que el formato JSON produzca salida parseable.
"""

import json
import logging
import sys
from io import StringIO
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def _fresh_root_logger():
    """Devuelve el logger raíz sin handlers para aislar cada test."""
    root = logging.getLogger()
    for h in root.handlers[:]:
        root.removeHandler(h)
    return root


def test_setup_logging_adds_handler():
    _fresh_root_logger()
    from importlib import reload
    import scanagent.logging_config as lc
    reload(lc)
    lc.setup_logging(level="INFO", json_output=True)
    root = logging.getLogger()
    assert len(root.handlers) == 1


def test_json_formatter_produces_valid_json():
    _fresh_root_logger()
    from importlib import reload
    import scanagent.logging_config as lc
    reload(lc)

    buf = StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(lc._JSONFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.DEBUG)

    logging.getLogger("test").info("mensaje de prueba")

    output = buf.getvalue().strip()
    parsed = json.loads(output)
    assert parsed["level"] == "INFO"
    assert parsed["msg"] == "mensaje de prueba"
    assert "ts" in parsed


def test_setup_logging_idempotent():
    """Llamar setup_logging dos veces no duplica handlers."""
    _fresh_root_logger()
    from importlib import reload
    import scanagent.logging_config as lc
    reload(lc)

    lc.setup_logging(level="INFO", json_output=False)
    lc.setup_logging(level="INFO", json_output=False)
    root = logging.getLogger()
    assert len(root.handlers) == 1