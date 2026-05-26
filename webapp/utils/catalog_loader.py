"""
CatalogLoader
=============
Caché en memoria del catálogo de recomendaciones con invalidación automática
por SHA-256. Singleton thread-safe: todas las solicitudes de render usan la
misma instancia para evitar lecturas redundantes al disco.
"""

import hashlib
import json
import threading
from pathlib import Path
from typing import Dict, Optional


_CATALOG_PATH = Path(__file__).parent.parent.parent / "data" / "recommendations_catalog.json"


class CatalogLoader:
    """Singleton que mantiene el catálogo en memoria y lo recarga si el SHA-256 cambia."""

    _instance: Optional["CatalogLoader"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "CatalogLoader":
        with cls._lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._catalog: Optional[Dict] = None
                inst._sha256: Optional[str] = None
                inst._rlock = threading.RLock()
                inst._path = _CATALOG_PATH
                cls._instance = inst
        return cls._instance

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self) -> Optional[Dict]:
        """Devuelve el catálogo actual. Recarga desde disco si el hash cambió."""
        with self._rlock:
            current_hash = self._hash_file()
            if current_hash and current_hash != self._sha256:
                self._reload()
            return self._catalog

    def sha256(self) -> Optional[str]:
        with self._rlock:
            return self._sha256

    def entry_count(self) -> int:
        catalog = self.get()
        if not catalog:
            return 0
        return (
            len(catalog.get("ports", {}))
            + len(catalog.get("security_headers", {}))
            + len(catalog.get("sensitive_paths", {}))
        )

    def version_info(self) -> Dict:
        catalog = self.get() or {}
        return {
            "version": catalog.get("version", "unknown"),
            "last_updated": catalog.get("last_updated"),
            "sha256": self._sha256,
            "entry_count": self.entry_count(),
            "path": str(self._path),
        }

    def force_reload(self) -> bool:
        """Fuerza recarga desde disco. Retorna True si hubo cambios."""
        with self._rlock:
            old = self._sha256
            self._reload()
            return self._sha256 != old

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _hash_file(self) -> Optional[str]:
        try:
            data = self._path.read_bytes()
            return hashlib.sha256(data).hexdigest()
        except Exception:
            return None

    def _reload(self) -> None:
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                self._catalog = json.load(f)
            self._sha256 = self._hash_file()
        except Exception as exc:
            print(f"⚠️  CatalogLoader: error recargando catálogo: {exc}")
            if self._catalog is None:
                self._catalog = {}


# Instancia global
catalog_loader = CatalogLoader()
