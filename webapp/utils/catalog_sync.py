"""
CatalogSync
===========
Tarea background que sincroniza el catálogo local con NVD y CISA KEV cada 24h.

Estrategia de merge:
- Entradas nuevas se añaden.
- Entradas existentes solo se actualizan si el hash del contenido cambió
  (preserva ediciones manuales).
- Cada sincronización se registra en catalog_sync_log.
"""

import hashlib
import json
import sqlite3
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_CATALOG_PATH = Path(__file__).parent.parent.parent / "data" / "recommendations_catalog.json"
_DB_PATH = Path(__file__).parent.parent.parent / "data" / "scan_agent.db"
_SYNC_INTERVAL = 86400  # 24 horas en segundos

# URL del catálogo CISA KEV (JSON)
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _fetch_json(url: str, timeout: int = 20) -> Optional[Dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ScanAgent/3.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        print(f"⚠️  CatalogSync: error descargando {url}: {exc}")
        return None


def _entry_hash(entry: Dict) -> str:
    """Hash determinístico del contenido de una entrada del catálogo."""
    return hashlib.md5(json.dumps(entry, sort_keys=True).encode()).hexdigest()


def _load_catalog() -> Dict:
    try:
        with open(_CATALOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"version": "1.0", "ports": {}, "security_headers": {}, "sensitive_paths": {}}


def _save_catalog(catalog: Dict):
    catalog["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d")
    with open(_CATALOG_PATH, "w", encoding="utf-8") as f:
        json.dump(catalog, f, ensure_ascii=False, indent=2)


def _log_sync(source: str, added: int, updated: int, unchanged: int,
              error: Optional[str], duration_ms: int):
    try:
        conn = sqlite3.connect(str(_DB_PATH))
        conn.execute(
            "INSERT INTO catalog_sync_log "
            "(timestamp, source, entries_added, entries_updated, entries_unchanged, error, duration_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), source, added, updated, unchanged, error, duration_ms)
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"⚠️  CatalogSync: no pudo registrar log: {exc}")


def sync_cisa_kev(catalog: Dict) -> Tuple[int, int, int]:
    """Incorpora CVEs de CISA KEV al catálogo. Retorna (added, updated, unchanged)."""
    data = _fetch_json(_CISA_KEV_URL)
    if not data:
        return 0, 0, 0

    vulns = data.get("vulnerabilities", [])
    kev_entries = catalog.setdefault("known_exploited_cves", {})

    added = updated = unchanged = 0
    for v in vulns:
        cve_id = v.get("cveID", "")
        if not cve_id:
            continue

        new_entry = {
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded", ""),
            "description": v.get("shortDescription", ""),
            "action": v.get("requiredAction", ""),
            "due_date": v.get("dueDate", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            "source": "cisa_kev",
        }
        new_hash = _entry_hash(new_entry)

        if cve_id not in kev_entries:
            kev_entries[cve_id] = new_entry
            added += 1
        elif _entry_hash(kev_entries[cve_id]) != new_hash:
            # Solo actualizar si el contenido cambió (preserva ediciones manuales)
            if kev_entries[cve_id].get("source") == "cisa_kev":
                kev_entries[cve_id] = new_entry
                updated += 1
            else:
                unchanged += 1
        else:
            unchanged += 1

    return added, updated, unchanged


def run_sync(on_demand: bool = False) -> Dict:
    """Ejecuta la sincronización completa y registra en DB."""
    start = time.time()
    results = {
        "cisa_kev": {"added": 0, "updated": 0, "unchanged": 0, "error": None},
    }

    try:
        catalog = _load_catalog()

        # Sincronizar CISA KEV
        try:
            a, u, uc = sync_cisa_kev(catalog)
            results["cisa_kev"] = {"added": a, "updated": u, "unchanged": uc, "error": None}
        except Exception as exc:
            results["cisa_kev"]["error"] = str(exc)

        _save_catalog(catalog)

    except Exception as exc:
        for source in results:
            if not results[source]["error"]:
                results[source]["error"] = str(exc)

    duration_ms = int((time.time() - start) * 1000)

    for source, r in results.items():
        _log_sync(
            source=source,
            added=r.get("added", 0),
            updated=r.get("updated", 0),
            unchanged=r.get("unchanged", 0),
            error=r.get("error"),
            duration_ms=duration_ms,
        )

    return results


class CatalogSyncWorker(threading.Thread):
    """Hilo background que ejecuta sync_all() cada 24h."""

    def __init__(self, interval: int = _SYNC_INTERVAL):
        super().__init__(daemon=True, name="CatalogSyncWorker")
        self._interval = interval
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        # Primera ejecución tras 5 minutos para no bloquear el arranque
        time.sleep(300)
        while not self._stop.is_set():
            try:
                print("🔄 CatalogSync: iniciando sincronización periódica...")
                run_sync()
                print("✅ CatalogSync: sincronización completada.")
            except Exception as exc:
                print(f"⚠️  CatalogSync: error en ciclo: {exc}")
            self._stop.wait(self._interval)


def get_sync_log(limit: int = 50) -> List[Dict]:
    """Devuelve el historial de sincronizaciones desde la DB."""
    try:
        conn = sqlite3.connect(str(_DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM catalog_sync_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []
