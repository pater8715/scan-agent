#!/usr/bin/env python3
"""
ZAP Integration - Scan Agent
==============================
Wrapper de la API REST de OWASP ZAP para escaneos pasivos y activos.

Requiere que el servicio ZAP esté corriendo como daemon (ver docker-compose.yml).
Usa solo stdlib — sin dependencias externas.

Autor: Scan Agent Team
Versión: 1.0.0
"""

import json
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime


ZAP_DEFAULT_HOST = "zap"       # nombre del servicio en la red Docker
ZAP_DEFAULT_PORT = 8090
ZAP_API_KEY      = "zap-scan-agent-lab"

# Esperas máximas (segundos)
SPIDER_TIMEOUT   = 300
PASSIVE_TIMEOUT  = 180
ACTIVE_TIMEOUT   = 1800


class ZAPIntegration:
    """
    Wrapper sobre la API REST de OWASP ZAP daemon.

    Flujo estándar:
        1. Verificar que ZAP esté accesible
        2. Nueva sesión limpia
        3. Spider (rastreo de URLs)
        4. Esperar escaneo pasivo automático
        5. Escaneo activo (opcional, perfil zap-active)
        6. Recoger alertas y guardar JSON
    """

    def __init__(
        self,
        host: str = ZAP_DEFAULT_HOST,
        port: int = ZAP_DEFAULT_PORT,
        api_key: str = ZAP_API_KEY,
        verbose: bool = False,
    ):
        self.base_url = f"http://{host}:{port}"
        self.api_key  = api_key
        self.verbose  = verbose

    # ------------------------------------------------------------------
    # Helpers de transporte
    # ------------------------------------------------------------------

    def _get(self, path: str, params: Optional[Dict] = None) -> Any:
        """Hace GET a la ZAP API y retorna el JSON parseado."""
        params = params or {}
        params["apikey"] = self.api_key
        qs  = urllib.parse.urlencode(params)
        url = f"{self.base_url}{path}?{qs}"
        if self.verbose:
            print(f"  [ZAP] GET {url}")
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.URLError as e:
            raise ConnectionError(f"ZAP no accesible en {self.base_url}: {e}")

    def _post(self, path: str, data: Optional[Dict] = None) -> Any:
        """Hace POST a la ZAP API y retorna el JSON parseado."""
        data = data or {}
        data["apikey"] = self.api_key
        encoded = urllib.parse.urlencode(data).encode()
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, data=encoded, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.URLError as e:
            raise ConnectionError(f"ZAP POST error en {url}: {e}")

    # ------------------------------------------------------------------
    # Operaciones de la API ZAP
    # ------------------------------------------------------------------

    def is_alive(self) -> bool:
        """Verifica que el daemon ZAP responde."""
        try:
            self._get("/JSON/core/view/version/")
            return True
        except Exception:
            return False

    def get_version(self) -> str:
        r = self._get("/JSON/core/view/version/")
        return r.get("version", "unknown")

    def new_session(self, name: str = "scan-agent-session") -> None:
        self._get("/JSON/core/action/newSession/", {"name": name, "overwrite": "true"})
        if self.verbose:
            print("  [ZAP] Nueva sesión creada")

    def access_url(self, url: str) -> None:
        """Visita la URL para que ZAP la registre en el árbol de sitios."""
        self._get("/JSON/core/action/accessUrl/", {"url": url})

    # --- Spider ---

    def start_spider(self, target_url: str, max_children: int = 0) -> str:
        r = self._get("/JSON/spider/action/scan/", {
            "url": target_url,
            "maxChildren": str(max_children),
            "recurse": "true",
        })
        scan_id = r.get("scan", "0")
        if self.verbose:
            print(f"  [ZAP] Spider iniciado (id={scan_id}) → {target_url}")
        return scan_id

    def get_spider_status(self, scan_id: str) -> int:
        r = self._get("/JSON/spider/view/status/", {"scanId": scan_id})
        return int(r.get("status", 0))

    def wait_spider(self, scan_id: str, timeout: int = SPIDER_TIMEOUT) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            pct = self.get_spider_status(scan_id)
            if self.verbose:
                print(f"  [ZAP] Spider: {pct}%", end="\r")
            if pct >= 100:
                if self.verbose:
                    print()
                return True
            time.sleep(3)
        print(f"\n  [ZAP] Spider timeout ({timeout}s)")
        return False

    # --- Passive scan ---

    def get_passive_records_left(self) -> int:
        r = self._get("/JSON/pscan/view/recordsToScan/")
        return int(r.get("recordsToScan", 0))

    def wait_passive_scan(self, timeout: int = PASSIVE_TIMEOUT) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            left = self.get_passive_records_left()
            if self.verbose:
                print(f"  [ZAP] Escaneo pasivo: {left} registros pendientes", end="\r")
            if left == 0:
                if self.verbose:
                    print()
                return True
            time.sleep(3)
        print(f"\n  [ZAP] Passive scan timeout ({timeout}s)")
        return False

    # --- Active scan ---

    def start_active_scan(self, target_url: str, policy: str = "Default Policy") -> str:
        r = self._get("/JSON/ascan/action/scan/", {
            "url":      target_url,
            "recurse":  "true",
            "scanPolicyName": policy,
        })
        scan_id = r.get("scan", "0")
        if self.verbose:
            print(f"  [ZAP] Active scan iniciado (id={scan_id})")
        return scan_id

    def get_active_scan_status(self, scan_id: str) -> int:
        r = self._get("/JSON/ascan/view/status/", {"scanId": scan_id})
        return int(r.get("status", 0))

    def wait_active_scan(self, scan_id: str, timeout: int = ACTIVE_TIMEOUT) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            pct = self.get_active_scan_status(scan_id)
            if self.verbose:
                print(f"  [ZAP] Active scan: {pct}%", end="\r")
            if pct >= 100:
                if self.verbose:
                    print()
                return True
            time.sleep(5)
        print(f"\n  [ZAP] Active scan timeout ({timeout}s)")
        return False

    # --- Alertas ---

    def get_alerts(self, base_url: str = "", risk_id: int = -1) -> List[Dict]:
        """
        Retorna todas las alertas. risk_id: 0=Info, 1=Low, 2=Medium, 3=High, -1=All.
        """
        params: Dict = {}
        if base_url:
            params["baseurl"] = base_url
        if risk_id >= 0:
            params["riskId"] = str(risk_id)
        r = self._get("/JSON/core/view/alerts/", params)
        return r.get("alerts", [])

    def get_alerts_summary(self) -> Dict[str, int]:
        r = self._get("/JSON/core/view/alertsSummary/")
        return r.get("alertsSummary", {})

    # ------------------------------------------------------------------
    # Flujos de escaneo de alto nivel
    # ------------------------------------------------------------------

    def run_passive_scan(self, target_url: str, outputs_dir: str, target_name: str) -> Dict:
        """
        Ejecuta spider + escaneo pasivo ZAP contra target_url.
        Guarda resultados en outputs_dir/zap_passive_{target_name}.json.
        """
        print(f"\n[ZAP] Iniciando escaneo pasivo → {target_url}")
        start_ts = datetime.now()

        self.new_session(f"passive-{target_name}")
        self.access_url(target_url)

        spider_id = self.start_spider(target_url)
        spider_ok = self.wait_spider(spider_id)
        if not spider_ok:
            print("[ZAP] Spider no completó en tiempo esperado, continuando...")

        passive_ok = self.wait_passive_scan()
        if not passive_ok:
            print("[ZAP] Passive scan no completó en tiempo esperado, recogiendo alertas...")

        alerts    = self.get_alerts(base_url=target_url)
        summary   = self.get_alerts_summary()
        duration  = (datetime.now() - start_ts).total_seconds()

        result = self._build_result(
            target_url, "passive", alerts, summary, duration, spider_ok, active_ok=None
        )
        out_path = self._save_results(result, outputs_dir, f"zap_passive_{target_name}")
        print(f"[ZAP] Resultados guardados: {out_path}")
        print(f"[ZAP] Alertas: {len(alerts)} total | "
              f"High={summary.get('High', 0)} "
              f"Medium={summary.get('Medium', 0)} "
              f"Low={summary.get('Low', 0)} "
              f"Informational={summary.get('Informational', 0)}")
        return result

    def run_active_scan(self, target_url: str, outputs_dir: str, target_name: str) -> Dict:
        """
        Ejecuta spider + escaneo pasivo + escaneo activo ZAP.
        Guarda resultados en outputs_dir/zap_active_{target_name}.json.
        """
        print(f"\n[ZAP] Iniciando escaneo activo → {target_url}")
        start_ts = datetime.now()

        self.new_session(f"active-{target_name}")
        self.access_url(target_url)

        spider_id = self.start_spider(target_url)
        spider_ok = self.wait_spider(spider_id)

        passive_ok = self.wait_passive_scan()
        if not passive_ok:
            print("[ZAP] Passive scan timeout, iniciando active scan de todos modos...")

        ascan_id = self.start_active_scan(target_url)
        active_ok = self.wait_active_scan(ascan_id)
        if not active_ok:
            print("[ZAP] Active scan no completó en tiempo máximo, recogiendo alertas...")

        alerts   = self.get_alerts(base_url=target_url)
        summary  = self.get_alerts_summary()
        duration = (datetime.now() - start_ts).total_seconds()

        result = self._build_result(
            target_url, "active", alerts, summary, duration, spider_ok, active_ok
        )
        out_path = self._save_results(result, outputs_dir, f"zap_active_{target_name}")
        print(f"[ZAP] Resultados guardados: {out_path}")
        print(f"[ZAP] Alertas: {len(alerts)} total | "
              f"High={summary.get('High', 0)} "
              f"Medium={summary.get('Medium', 0)} "
              f"Low={summary.get('Low', 0)} "
              f"Informational={summary.get('Informational', 0)}")
        return result

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------

    def _build_result(
        self,
        target_url: str,
        scan_type: str,
        alerts: List[Dict],
        summary: Dict,
        duration: float,
        spider_ok: bool,
        active_ok: Optional[bool],
    ) -> Dict:
        """Estructura el resultado en el formato esperado por parser.py."""
        structured = []
        for a in alerts:
            structured.append({
                "id":          a.get("alertRef", a.get("pluginId", "")),
                "nombre":      a.get("name", ""),
                "descripcion": a.get("description", ""),
                "url":         a.get("url", ""),
                "metodo":      a.get("method", "GET"),
                "evidencia":   a.get("evidence", ""),
                "solucion":    a.get("solution", ""),
                "referencia":  a.get("reference", ""),
                "risk":        a.get("risk", "Informational"),   # High/Medium/Low/Informational
                "confidence":  a.get("confidence", "Low"),
                "cweid":       a.get("cweid", ""),
                "wascid":      a.get("wascid", ""),
                "tags":        a.get("tags", {}),
                "owasp_category": self._map_risk_to_owasp(a),
                "severidad":   self._risk_to_severidad(a.get("risk", "Informational")),
                "cvss_score":  self._risk_to_cvss(a.get("risk", "Informational")),
            })
        return {
            "scan_type":        scan_type,
            "target_url":       target_url,
            "timestamp":        datetime.now().isoformat(),
            "duration_seconds": duration,
            "spider_completed": spider_ok,
            "active_completed": active_ok,
            "summary": {
                "total":         len(alerts),
                "high":          summary.get("High", 0),
                "medium":        summary.get("Medium", 0),
                "low":           summary.get("Low", 0),
                "informational": summary.get("Informational", 0),
            },
            "alerts": structured,
        }

    @staticmethod
    def _save_results(result: Dict, outputs_dir: str, filename: str) -> str:
        out_path = Path(outputs_dir) / f"{filename}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        return str(out_path)

    @staticmethod
    def _risk_to_severidad(risk: str) -> str:
        return {
            "High":          "alta",
            "Medium":        "media",
            "Low":           "baja",
            "Informational": "info",
        }.get(risk, "baja")

    @staticmethod
    def _risk_to_cvss(risk: str) -> float:
        return {
            "High":          7.5,
            "Medium":        5.0,
            "Low":           2.5,
            "Informational": 0.0,
        }.get(risk, 2.5)

    @staticmethod
    def _map_risk_to_owasp(alert: Dict) -> str:
        """Mapea tags OWASP de la alerta ZAP a la categoría OWASP Web Top 10 2021."""
        tags = alert.get("tags", {})
        # ZAP 2.13+ incluye tags tipo {"OWASP_2021_A03": "https://..."}
        for key in tags:
            if key.startswith("OWASP_2021_"):
                code = key.replace("OWASP_2021_", "")
                labels = {
                    "A01": "A01:2021 - Broken Access Control",
                    "A02": "A02:2021 - Cryptographic Failures",
                    "A03": "A03:2021 - Injection",
                    "A04": "A04:2021 - Insecure Design",
                    "A05": "A05:2021 - Security Misconfiguration",
                    "A06": "A06:2021 - Vulnerable and Outdated Components",
                    "A07": "A07:2021 - Identification and Authentication Failures",
                    "A08": "A08:2021 - Software and Data Integrity Failures",
                    "A09": "A09:2021 - Security Logging and Monitoring Failures",
                    "A10": "A10:2021 - Server-Side Request Forgery",
                }
                return labels.get(code, f"OWASP 2021 {code}")
        # Fallback por nombre
        name = alert.get("name", "").lower()
        if any(k in name for k in ["sql", "injection", "xss", "command", "ldap", "xpath"]):
            return "A03:2021 - Injection"
        if any(k in name for k in ["csrf", "access control", "idor", "authorization"]):
            return "A01:2021 - Broken Access Control"
        if any(k in name for k in ["header", "misconfigur", "cors", "csp", "hsts", "cookie"]):
            return "A05:2021 - Security Misconfiguration"
        if any(k in name for k in ["ssl", "tls", "cipher", "crypt"]):
            return "A02:2021 - Cryptographic Failures"
        if any(k in name for k in ["auth", "session", "password", "brute"]):
            return "A07:2021 - Identification and Authentication Failures"
        if any(k in name for k in ["ssrf", "request forgery"]):
            return "A10:2021 - Server-Side Request Forgery"
        return "A05:2021 - Security Misconfiguration"


# ------------------------------------------------------------------
# CLI standalone
# ------------------------------------------------------------------

def main():
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        description="ZAP Integration — Scan Agent. Requiere ZAP daemon corriendo."
    )
    ap.add_argument("--target", required=True,
                    help="URL objetivo, ej: http://juice-shop:3000")
    ap.add_argument("--mode", choices=["passive", "active"], default="passive",
                    help="Tipo de escaneo ZAP (default: passive)")
    ap.add_argument("--output-dir", default="./outputs",
                    help="Directorio de salida (default: ./outputs)")
    ap.add_argument("--target-name", default=None,
                    help="Nombre para el archivo de salida (default: slug del host)")
    ap.add_argument("--zap-host", default=ZAP_DEFAULT_HOST,
                    help=f"Host de ZAP daemon (default: {ZAP_DEFAULT_HOST})")
    ap.add_argument("--zap-port", type=int, default=ZAP_DEFAULT_PORT,
                    help=f"Puerto de ZAP daemon (default: {ZAP_DEFAULT_PORT})")
    ap.add_argument("--api-key", default=ZAP_API_KEY,
                    help="API key de ZAP")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if not args.target_name:
        host_slug = args.target.replace("http://", "").replace("https://", "")
        host_slug = host_slug.replace(":", "_").replace("/", "_").rstrip("_")
        args.target_name = host_slug

    zap = ZAPIntegration(
        host=args.zap_host,
        port=args.zap_port,
        api_key=args.api_key,
        verbose=args.verbose,
    )

    print(f"[ZAP] Verificando daemon en {zap.base_url}...")
    if not zap.is_alive():
        print(f"[ERROR] ZAP daemon no accesible en {zap.base_url}")
        print("  Asegúrate de que el servicio zap esté corriendo:")
        print("  docker compose -f docker/docker-compose.yml --profile lab up -d zap")
        sys.exit(1)

    print(f"[ZAP] Daemon activo — versión {zap.get_version()}")

    if args.mode == "active":
        zap.run_active_scan(args.target, args.output_dir, args.target_name)
    else:
        zap.run_passive_scan(args.target, args.output_dir, args.target_name)


if __name__ == "__main__":
    main()
