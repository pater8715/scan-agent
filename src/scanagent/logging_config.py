#!/usr/bin/env python3
"""
Logging centralizado para Scan Agent.
Formato JSON estructurado para auditoría y análisis.

Uso:
    from scanagent.logging_config import setup_logging
    setup_logging(level="INFO")   # llamar una vez al inicio
"""

import logging
import json
import sys
import os
from datetime import datetime, timezone


class _JSONFormatter(logging.Formatter):
    """Formateador que emite cada registro como una línea JSON."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        # Campos extra opcionales que el llamador puede pasar via extra={}
        for field in ("target", "scan_id", "profile", "client_ip", "tool"):
            if hasattr(record, field):
                entry[field] = getattr(record, field)
        return json.dumps(entry, ensure_ascii=False)


def setup_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Configura el logging global de la aplicación.

    Args:
        level: Nivel de logging (DEBUG, INFO, WARNING, ERROR).
        json_output: Si True, emite JSON por stderr; si False, formato legible.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Evitar duplicar handlers si se llama más de una vez
    if root.handlers:
        return

    handler = logging.StreamHandler(sys.stderr)

    if json_output:
        handler.setFormatter(_JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )

    root.addHandler(handler)

    # Silenciar loggers ruidosos de librerías externas
    for noisy in ("uvicorn.access", "urllib3", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)