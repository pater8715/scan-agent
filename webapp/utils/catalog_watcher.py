"""
CatalogWatcher
==============
Hilo background que monitorea recommendations_catalog.json con polling SHA-256
cada 60 s. Cuando detecta un cambio:
  1. Registra la nueva versión en la tabla catalog_versions (DB).
  2. Pone un evento en el asyncio.Queue para que el WebSocket lo difunda.
"""

import asyncio
import threading
import time
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from .catalog_loader import catalog_loader

_DB_PATH = Path(__file__).parent.parent.parent / "data" / "scan_agent.db"


class CatalogWatcher(threading.Thread):
    """Demonio que observa el catálogo y notifica cambios."""

    def __init__(self, event_queue: asyncio.Queue, loop: asyncio.AbstractEventLoop,
                 interval: int = 60):
        super().__init__(daemon=True, name="CatalogWatcher")
        self._queue = event_queue
        self._loop = loop
        self._interval = interval
        self._last_hash: Optional[str] = None
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        # Inicializar con hash actual sin disparar evento
        self._last_hash = catalog_loader.sha256()

        while not self._stop_event.is_set():
            time.sleep(self._interval)
            try:
                current_hash = catalog_loader.sha256()
                catalog = catalog_loader.get()
                new_hash = catalog_loader.sha256()

                if new_hash and new_hash != self._last_hash:
                    self._last_hash = new_hash
                    count = catalog_loader.entry_count()
                    self._persist_version(new_hash, count)
                    self._emit_event(new_hash, count)
            except Exception as exc:
                print(f"⚠️  CatalogWatcher error: {exc}")

    def _persist_version(self, sha256: str, count: int):
        try:
            conn = sqlite3.connect(str(_DB_PATH))
            conn.execute(
                "INSERT INTO catalog_versions (catalog_file, sha256_hash, entry_count, detected_at) "
                "VALUES (?, ?, ?, ?)",
                ("recommendations_catalog.json", sha256, count, datetime.utcnow().isoformat())
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            print(f"⚠️  CatalogWatcher: no pudo guardar versión en DB: {exc}")

    def _emit_event(self, sha256: str, count: int):
        event = {
            "event": "catalog_updated",
            "sha256": sha256,
            "entry_count": count,
            "detected_at": datetime.utcnow().isoformat(),
        }
        try:
            asyncio.run_coroutine_threadsafe(
                self._queue.put(event), self._loop
            )
        except Exception as exc:
            print(f"⚠️  CatalogWatcher: no pudo emitir evento WS: {exc}")
