#!/usr/bin/env python3
"""
VulnDB - Base de Conocimiento de Vulnerabilidades
===================================================
Módulo que reemplaza el knowledge base hardcodeado con fuentes actualizadas:

  - NVD API 2.0  (NIST)    — detalles de CVE, CVSS, CWE
  - CISA KEV               — CVEs conocidos y explotados activamente
  - OSV (osv.dev)          — vulnerabilidades en librerías (PyPI, npm, Go…)

Todas las consultas se cachean en SQLite con TTL configurable.
Solo usa stdlib: urllib, sqlite3, json, datetime.

Uso:
    db = VulnDB()
    info = db.lookup_cve("CVE-2021-44228")   # Log4Shell
    kev  = db.is_in_kev("CVE-2021-44228")    # True — activamente explotado
    db.update_all()                            # Refrescar todos los feeds

Autor: Scan Agent Team
Versión: 1.0.0
"""

import json
import sqlite3
import time
import urllib.request
import urllib.parse
import urllib.error
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any


class VulnDB:
    """
    Base de conocimiento de vulnerabilidades con caché SQLite y TTL.
    Las consultas a NVD, CISA KEV y OSV se realizan solo cuando el caché expira.
    """

    NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    OSV_API_URL  = "https://api.osv.dev/v1/query"

    CVE_TTL_HOURS = 24
    KEV_TTL_HOURS = 12
    OSV_TTL_HOURS = 24

    # Severidades NVD → nuestro sistema interno
    CVSS_SEVERITY_MAP = {
        "CRITICAL": "critica",
        "HIGH":     "alta",
        "MEDIUM":   "media",
        "LOW":      "baja",
        "NONE":     "baja",
    }

    def __init__(self, db_path: Optional[str] = None, api_key: Optional[str] = None,
                 timeout: int = 10, verbose: bool = False):
        """
        Args:
            db_path:  Ruta al archivo SQLite de caché (default: ./data/vuln_cache.db)
            api_key:  API key de NVD — opcional, aumenta el rate limit de 5 a 50 req/30s
            timeout:  Timeout en segundos para peticiones HTTP
            verbose:  Modo detallado
        """
        self.db_path = Path(db_path or "./data/vuln_cache.db")
        self.api_key = api_key
        self.timeout = timeout
        self.verbose = verbose
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # =========================================================================
    # Inicialización de la base de datos
    # =========================================================================

    def _init_db(self) -> None:
        """Crea las tablas de caché si no existen."""
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id          TEXT PRIMARY KEY,
                    source          TEXT NOT NULL DEFAULT 'nvd',
                    cvss_score      REAL,
                    cvss_vector     TEXT,
                    cvss_version    TEXT,
                    severity        TEXT,
                    description     TEXT,
                    published       TEXT,
                    modified        TEXT,
                    cwe_ids         TEXT,   -- JSON array
                    references_     TEXT,   -- JSON array of URLs
                    affected_cpe    TEXT,   -- JSON array
                    raw_json        TEXT,   -- JSON completo de NVD
                    cached_at       TEXT    NOT NULL,
                    expires_at      TEXT    NOT NULL
                );

                CREATE TABLE IF NOT EXISTS kev_catalog (
                    cve_id              TEXT PRIMARY KEY,
                    vendor_project      TEXT,
                    product             TEXT,
                    vulnerability_name  TEXT,
                    date_added          TEXT,
                    short_description   TEXT,
                    required_action     TEXT,
                    due_date            TEXT,
                    known_ransomware    TEXT,
                    cached_at           TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS osv_cache (
                    cache_key       TEXT PRIMARY KEY,  -- package:ecosystem
                    package         TEXT NOT NULL,
                    ecosystem       TEXT NOT NULL,
                    vulns_json      TEXT NOT NULL,     -- JSON array de vulns
                    cached_at       TEXT NOT NULL,
                    expires_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vuln_db_meta (
                    key     TEXT PRIMARY KEY,
                    value   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cve_expires ON cve_cache(expires_at);
                CREATE INDEX IF NOT EXISTS idx_kev_cached  ON kev_catalog(cached_at);
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    # =========================================================================
    # NVD API 2.0 — Lookup de CVE
    # =========================================================================

    def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Devuelve información detallada de un CVE.
        Usa caché local; consulta NVD solo si el caché expiró o no existe.

        Returns:
            Dict con cvss_score, severity, description, cwe_ids, is_in_kev, etc.
            None si el CVE no se encuentra en ninguna fuente.
        """
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith("CVE-"):
            return None

        # 1. Intentar desde caché
        cached = self._get_cached_cve(cve_id)
        if cached:
            cached["is_in_kev"] = self.is_in_kev(cve_id)
            return cached

        # 2. Consultar NVD
        raw = self._fetch_nvd_cve(cve_id)
        if raw:
            parsed = self._parse_nvd_cve(raw)
            self._cache_cve(cve_id, parsed, raw)
            parsed["is_in_kev"] = self.is_in_kev(cve_id)
            return parsed

        return None

    def _get_cached_cve(self, cve_id: str) -> Optional[Dict]:
        """Devuelve CVE desde caché si no ha expirado."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM cve_cache WHERE cve_id = ? AND expires_at > ?",
                (cve_id, datetime.utcnow().isoformat())
            ).fetchone()
        if not row:
            return None
        return self._row_to_cve_dict(row)

    def _row_to_cve_dict(self, row: sqlite3.Row) -> Dict:
        return {
            "cve_id":      row["cve_id"],
            "source":      row["source"],
            "cvss_score":  row["cvss_score"],
            "cvss_vector": row["cvss_vector"],
            "cvss_version":row["cvss_version"],
            "severity":    row["severity"],
            "description": row["description"],
            "published":   row["published"],
            "modified":    row["modified"],
            "cwe_ids":     json.loads(row["cwe_ids"] or "[]"),
            "references":  json.loads(row["references_"] or "[]"),
            "affected_cpe":json.loads(row["affected_cpe"] or "[]"),
            "cached_at":   row["cached_at"],
        }

    def _fetch_nvd_cve(self, cve_id: str) -> Optional[Dict]:
        """Consulta NVD API 2.0 para un CVE específico."""
        url = f"{self.NVD_API_URL}?cveId={cve_id}"
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve", {})
            return None
        except Exception as e:
            if self.verbose:
                print(f"  [VulnDB] NVD lookup failed for {cve_id}: {e}")
            return None
        finally:
            # Respetar rate limit de NVD: sin API key → 5 req / 30s
            time.sleep(0.7 if self.api_key else 6.5)

    def _parse_nvd_cve(self, cve_data: Dict) -> Dict:
        """Extrae los campos relevantes de la respuesta de NVD."""
        cve_id = cve_data.get("id", "")

        # Descripción en inglés
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )

        # CVSS — preferir v3.1 > v3.0 > v2
        metrics = cve_data.get("metrics", {})
        cvss_score, cvss_vector, cvss_severity, cvss_version = None, None, "MEDIUM", "N/A"
        for ver_key, ver_label in [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")]:
            entries = metrics.get(ver_key, [])
            if entries:
                data_v = entries[0].get("cvssData", {})
                cvss_score   = data_v.get("baseScore")
                cvss_vector  = data_v.get("vectorString")
                cvss_severity = (data_v.get("baseSeverity") or
                                 entries[0].get("baseSeverity", "MEDIUM")).upper()
                cvss_version = ver_label
                break

        # CWEs
        weaknesses = cve_data.get("weaknesses", [])
        cwe_ids = list({
            d["value"] for w in weaknesses
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        })

        # References (primeras 5)
        refs = [r.get("url", "") for r in cve_data.get("references", [])[:5]]

        # CPE afectados (primeros 10)
        configs = cve_data.get("configurations", [])
        cpe_list = []
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_list.append(match.get("criteria", ""))
                    if len(cpe_list) >= 10:
                        break

        return {
            "cve_id":      cve_id,
            "source":      "nvd",
            "cvss_score":  cvss_score,
            "cvss_vector": cvss_vector,
            "cvss_version":cvss_version,
            "severity":    self.CVSS_SEVERITY_MAP.get(cvss_severity, "media"),
            "description": description[:2000],
            "published":   cve_data.get("published", ""),
            "modified":    cve_data.get("lastModified", ""),
            "cwe_ids":     cwe_ids,
            "references":  refs,
            "affected_cpe":cpe_list,
        }

    def _cache_cve(self, cve_id: str, parsed: Dict, raw: Dict) -> None:
        """Guarda CVE en caché con TTL."""
        now = datetime.utcnow()
        expires = (now + timedelta(hours=self.CVE_TTL_HOURS)).isoformat()
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO cve_cache
                (cve_id, source, cvss_score, cvss_vector, cvss_version, severity,
                 description, published, modified, cwe_ids, references_, affected_cpe,
                 raw_json, cached_at, expires_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                cve_id,
                parsed["source"],
                parsed["cvss_score"],
                parsed["cvss_vector"],
                parsed["cvss_version"],
                parsed["severity"],
                parsed["description"],
                parsed["published"],
                parsed["modified"],
                json.dumps(parsed["cwe_ids"]),
                json.dumps(parsed["references"]),
                json.dumps(parsed["affected_cpe"]),
                json.dumps(raw),
                now.isoformat(),
                expires,
            ))

    # =========================================================================
    # CISA KEV — Known Exploited Vulnerabilities
    # =========================================================================

    def is_in_kev(self, cve_id: str) -> bool:
        """
        Comprueba si un CVE está en el catálogo CISA KEV.
        Descarga el catálogo automáticamente si no está en caché o expiró.
        """
        cve_id = cve_id.upper().strip()
        self._ensure_kev_loaded()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT cve_id FROM kev_catalog WHERE cve_id = ?", (cve_id,)
            ).fetchone()
        return row is not None

    def get_kev_entry(self, cve_id: str) -> Optional[Dict]:
        """Devuelve la entrada completa de KEV para un CVE."""
        cve_id = cve_id.upper().strip()
        self._ensure_kev_loaded()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM kev_catalog WHERE cve_id = ?", (cve_id,)
            ).fetchone()
        if not row:
            return None
        return {
            "cve_id":           row["cve_id"],
            "vendor_project":   row["vendor_project"],
            "product":          row["product"],
            "vulnerability_name": row["vulnerability_name"],
            "date_added":       row["date_added"],
            "short_description":row["short_description"],
            "required_action":  row["required_action"],
            "due_date":         row["due_date"],
            "known_ransomware": row["known_ransomware"],
        }

    def _ensure_kev_loaded(self) -> None:
        """Descarga el catálogo KEV si no está en caché o expiró."""
        with self._conn() as conn:
            meta = conn.execute(
                "SELECT value FROM vuln_db_meta WHERE key = 'kev_last_update'"
            ).fetchone()

        if meta:
            last_update = datetime.fromisoformat(meta["value"])
            if datetime.utcnow() - last_update < timedelta(hours=self.KEV_TTL_HOURS):
                return  # Caché válido

        self.update_kev()

    def update_kev(self) -> int:
        """
        Descarga el catálogo completo CISA KEV y actualiza el caché.

        Returns:
            Número de entradas cargadas.
        """
        if self.verbose:
            print(f"  [VulnDB] Descargando CISA KEV desde {self.CISA_KEV_URL}...")
        try:
            req = urllib.request.Request(
                self.CISA_KEV_URL,
                headers={"Accept": "application/json",
                         "User-Agent": "ScanAgent/3.0 (Security Research)"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            vulns = data.get("vulnerabilities", [])
            now = datetime.utcnow().isoformat()

            with self._conn() as conn:
                conn.execute("DELETE FROM kev_catalog")
                conn.executemany("""
                    INSERT OR REPLACE INTO kev_catalog
                    (cve_id, vendor_project, product, vulnerability_name, date_added,
                     short_description, required_action, due_date, known_ransomware, cached_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                """, [
                    (
                        v.get("cveID", ""),
                        v.get("vendorProject", ""),
                        v.get("product", ""),
                        v.get("vulnerabilityName", ""),
                        v.get("dateAdded", ""),
                        v.get("shortDescription", "")[:500],
                        v.get("requiredAction", ""),
                        v.get("dueDate", ""),
                        v.get("knownRansomwareCampaignUse", "Unknown"),
                        now,
                    )
                    for v in vulns if v.get("cveID")
                ])
                conn.execute("""
                    INSERT OR REPLACE INTO vuln_db_meta (key, value)
                    VALUES ('kev_last_update', ?)
                """, (now,))

            if self.verbose:
                print(f"  [VulnDB] KEV actualizado: {len(vulns)} entradas")
            return len(vulns)

        except Exception as e:
            if self.verbose:
                print(f"  [VulnDB] Error actualizando KEV: {e}")
            return 0

    # =========================================================================
    # OSV — Open Source Vulnerabilities
    # =========================================================================

    def search_osv(self, package: str, ecosystem: str = "PyPI",
                   version: Optional[str] = None) -> List[Dict]:
        """
        Busca vulnerabilidades de una librería en OSV (osv.dev).

        Args:
            package:   Nombre del paquete (e.g. "requests", "express")
            ecosystem: Ecosistema (PyPI, npm, Go, Maven, RubyGems, crates.io…)
            version:   Versión específica (opcional)

        Returns:
            Lista de vulnerabilidades encontradas.
        """
        cache_key = f"{package.lower()}:{ecosystem.lower()}"
        if version:
            cache_key += f":{version}"

        cached = self._get_cached_osv(cache_key)
        if cached is not None:
            return cached

        vulns = self._fetch_osv(package, ecosystem, version)
        self._cache_osv(cache_key, package, ecosystem, vulns)
        return vulns

    def _get_cached_osv(self, cache_key: str) -> Optional[List]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT vulns_json FROM osv_cache WHERE cache_key = ? AND expires_at > ?",
                (cache_key, datetime.utcnow().isoformat())
            ).fetchone()
        if not row:
            return None
        return json.loads(row["vulns_json"])

    def _fetch_osv(self, package: str, ecosystem: str,
                   version: Optional[str]) -> List[Dict]:
        """Consulta la API de OSV."""
        payload: Dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
        if version:
            payload["version"] = version

        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.OSV_API_URL,
                data=body,
                headers={"Content-Type": "application/json",
                         "Accept": "application/json",
                         "User-Agent": "ScanAgent/3.0"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            results = []
            for vuln in data.get("vulns", []):
                results.append({
                    "id":          vuln.get("id", ""),
                    "summary":     vuln.get("summary", "")[:300],
                    "severity":    self._osv_severity(vuln),
                    "cvss_score":  self._osv_cvss(vuln),
                    "published":   vuln.get("published", ""),
                    "modified":    vuln.get("modified", ""),
                    "aliases":     vuln.get("aliases", []),
                    "references":  [r.get("url", "") for r in vuln.get("references", [])[:3]],
                })
            return results

        except Exception as e:
            if self.verbose:
                print(f"  [VulnDB] OSV lookup failed for {package}/{ecosystem}: {e}")
            return []

    def _osv_severity(self, vuln: Dict) -> str:
        """Extrae severidad de respuesta OSV."""
        for sev in vuln.get("severity", []):
            score = sev.get("score", "")
            if "CVSS:3" in score:
                try:
                    base = float(score.split("/")[0].split(":")[-1])
                    if base >= 9.0:
                        return "critica"
                    if base >= 7.0:
                        return "alta"
                    if base >= 4.0:
                        return "media"
                    return "baja"
                except Exception:
                    pass
        return "media"

    def _osv_cvss(self, vuln: Dict) -> Optional[float]:
        """Extrae CVSS score de respuesta OSV."""
        for sev in vuln.get("severity", []):
            score = sev.get("score", "")
            if "CVSS:3" in score:
                try:
                    return float(score.split("/")[0].split(":")[-1])
                except Exception:
                    pass
        return None

    def _cache_osv(self, cache_key: str, package: str,
                   ecosystem: str, vulns: List) -> None:
        now = datetime.utcnow()
        expires = (now + timedelta(hours=self.OSV_TTL_HOURS)).isoformat()
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO osv_cache
                (cache_key, package, ecosystem, vulns_json, cached_at, expires_at)
                VALUES (?,?,?,?,?,?)
            """, (cache_key, package, ecosystem,
                  json.dumps(vulns), now.isoformat(), expires))

    # =========================================================================
    # Enriquecimiento de hallazgos
    # =========================================================================

    def enrich_finding(self, finding: Dict) -> Dict:
        """
        Enriquece un hallazgo de vulnerabilidad con datos actualizados de CVE.

        Agrega al finding:
          - cvss_score real del NVD (si el hallazgo tiene cve_id)
          - is_in_kev: True si está en CISA KEV (explotado activamente)
          - kev_info: detalles del KEV entry
          - nvd_description: descripción oficial del NVD
          - cwe_ids: CWEs del NVD

        Returns:
            Finding enriquecido (modifica in-place y también retorna).
        """
        cve_id = finding.get("cve_id") or self._extract_cve_from_text(
            finding.get("descripcion", "") + " " + finding.get("titulo", "")
        )

        if not cve_id:
            finding["is_in_kev"] = False
            return finding

        finding["cve_id"] = cve_id

        # Consultar NVD (con caché)
        cve_info = self.lookup_cve(cve_id)
        if cve_info:
            # Actualizar CVSS con datos reales de NVD si son más precisos
            if cve_info.get("cvss_score") and not finding.get("cvss_score"):
                finding["cvss_score"] = cve_info["cvss_score"]
            if cve_info.get("cvss_vector"):
                finding["cvss_vector"] = cve_info["cvss_vector"]
            if cve_info.get("cwe_ids"):
                finding["cwe_ids"] = cve_info["cwe_ids"]

            finding["nvd_description"] = cve_info.get("description", "")
            finding["nvd_published"]   = cve_info.get("published", "")
            finding["is_in_kev"]       = cve_info.get("is_in_kev", False)

            # Info KEV — escala la severidad a CRÍTICA si está siendo explotado
            if finding["is_in_kev"]:
                kev = self.get_kev_entry(cve_id)
                if kev:
                    finding["kev_info"] = kev
                    finding["severidad"] = "critica"
                    if self.verbose:
                        print(f"  [VulnDB] {cve_id} en CISA KEV — escalado a CRITICA")
        else:
            finding["is_in_kev"] = False

        return finding

    def _extract_cve_from_text(self, text: str) -> Optional[str]:
        """Extrae el primer CVE-XXXX-XXXXX encontrado en un texto."""
        import re
        match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
        return match.group(0).upper() if match else None

    # =========================================================================
    # Mantenimiento y utilidades
    # =========================================================================

    def update_all(self, verbose_override: bool = True) -> Dict[str, Any]:
        """
        Actualiza todos los feeds (KEV, limpia expirados).

        Returns:
            Resumen de la actualización.
        """
        prev_verbose = self.verbose
        self.verbose = verbose_override
        results: Dict[str, Any] = {}

        print("\n[VulnDB] Actualizando base de conocimiento de vulnerabilidades...")
        print("-" * 60)

        # 1. CISA KEV
        print("[1/2] Actualizando CISA KEV...")
        kev_count = self.update_kev()
        results["kev_count"] = kev_count
        print(f"      {kev_count} vulnerabilidades conocidas y explotadas cargadas")

        # 2. Limpiar caché expirado
        print("[2/2] Limpiando registros expirados del caché...")
        removed = self._purge_expired()
        results["expired_removed"] = removed
        print(f"      {removed} registros expirados eliminados")

        # Estadísticas finales
        stats = self.get_stats()
        results["stats"] = stats
        print("-" * 60)
        print(f"[VulnDB] Actualizacion completada:")
        print(f"  CVEs en cache : {stats['cve_count']}")
        print(f"  KEV entries   : {stats['kev_count']}")
        print(f"  OSV entries   : {stats['osv_count']}")
        print(f"  DB size       : {stats['db_size_kb']:.1f} KB")

        self.verbose = prev_verbose
        return results

    def _purge_expired(self) -> int:
        """Elimina registros de caché con TTL vencido."""
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            c1 = conn.execute("DELETE FROM cve_cache WHERE expires_at < ?", (now,)).rowcount
            c2 = conn.execute("DELETE FROM osv_cache  WHERE expires_at < ?", (now,)).rowcount
        return c1 + c2

    def get_stats(self) -> Dict[str, Any]:
        """Estadísticas del caché local."""
        with self._conn() as conn:
            cve_count = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
            kev_count = conn.execute("SELECT COUNT(*) FROM kev_catalog").fetchone()[0]
            osv_count = conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()[0]
            kev_meta  = conn.execute(
                "SELECT value FROM vuln_db_meta WHERE key='kev_last_update'"
            ).fetchone()
        db_size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "cve_count":      cve_count,
            "kev_count":      kev_count,
            "osv_count":      osv_count,
            "kev_last_update":kev_meta["value"] if kev_meta else "nunca",
            "db_path":        str(self.db_path),
            "db_size_kb":     db_size_bytes / 1024,
        }

    def check_connectivity(self) -> Dict[str, bool]:
        """Verifica conectividad con los servicios externos."""
        results = {}
        for name, host in [("NVD", "services.nvd.nist.gov"),
                            ("CISA", "www.cisa.gov"),
                            ("OSV", "api.osv.dev")]:
            try:
                socket.create_connection((host, 443), timeout=5).close()
                results[name] = True
            except Exception:
                results[name] = False
        return results


# =============================================================================
# Función de conveniencia para el interpreter
# =============================================================================

_default_db: Optional[VulnDB] = None


def get_default_db(db_path: Optional[str] = None) -> Optional[VulnDB]:
    """
    Devuelve una instancia singleton de VulnDB.
    Retorna None si la DB no puede inicializarse (sin permisos, etc.).
    """
    global _default_db
    if _default_db is None:
        try:
            _default_db = VulnDB(db_path=db_path)
        except Exception:
            return None
    return _default_db


if __name__ == "__main__":
    import argparse

    cli = argparse.ArgumentParser(description="VulnDB — Base de conocimiento de vulnerabilidades")
    cli.add_argument("--update",    action="store_true", help="Actualizar todos los feeds (KEV, limpiar cache)")
    cli.add_argument("--lookup",    metavar="CVE_ID",    help="Buscar un CVE específico")
    cli.add_argument("--kev-check", metavar="CVE_ID",    help="Verificar si CVE está en CISA KEV")
    cli.add_argument("--osv",       metavar="PKG",       help="Buscar vulnerabilidades de una librería")
    cli.add_argument("--ecosystem", default="PyPI",      help="Ecosistema para OSV (default: PyPI)")
    cli.add_argument("--stats",     action="store_true", help="Mostrar estadísticas del cache")
    cli.add_argument("--db-path",   default=None,        help="Ruta al archivo SQLite de cache")
    cli.add_argument("--api-key",   default=None,        help="NVD API key (opcional)")
    cli.add_argument("--verbose",   action="store_true")
    args = cli.parse_args()

    db = VulnDB(db_path=args.db_path, api_key=args.api_key, verbose=args.verbose)

    if args.stats:
        stats = db.get_stats()
        print("\n=== VulnDB Stats ===")
        for k, v in stats.items():
            print(f"  {k:20}: {v}")

    elif args.update:
        db.update_all()

    elif args.lookup:
        info = db.lookup_cve(args.lookup)
        if info:
            print(f"\n=== {info['cve_id']} ===")
            print(f"  CVSS     : {info['cvss_score']} ({info['severity']})")
            print(f"  Publicado: {info['published'][:10]}")
            print(f"  CWEs     : {', '.join(info['cwe_ids']) or 'N/A'}")
            print(f"  KEV      : {'SI - EXPLOTADO ACTIVAMENTE' if info['is_in_kev'] else 'No'}")
            print(f"  Desc     : {info['description'][:200]}...")
        else:
            print(f"CVE {args.lookup} no encontrado")

    elif args.kev_check:
        in_kev = db.is_in_kev(args.kev_check)
        print(f"\n{args.kev_check}: {'EN KEV - EXPLOTADO ACTIVAMENTE' if in_kev else 'No está en KEV'}")
        if in_kev:
            entry = db.get_kev_entry(args.kev_check)
            if entry:
                print(f"  Producto : {entry['vendor_project']} {entry['product']}")
                print(f"  Agregado : {entry['date_added']}")
                print(f"  Accion   : {entry['required_action'][:150]}")

    elif args.osv:
        vulns = db.search_osv(args.osv, args.ecosystem)
        print(f"\n=== OSV: {args.osv} ({args.ecosystem}) — {len(vulns)} vulnerabilidades ===")
        for v in vulns[:10]:
            print(f"  {v['id']:20} CVSS={v['cvss_score'] or 'N/A':5}  {v['summary'][:60]}")
