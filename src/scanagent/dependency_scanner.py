#!/usr/bin/env python3
"""
Dependency Scanner — Scan Agent Fase 7.1
==========================================
Analiza dependencias Python (pip) y Node.js (npm audit) buscando
paquetes con vulnerabilidades conocidas.

Mapea a OWASP A06:2021 — Vulnerable and Outdated Components.
Solo usa stdlib + subprocess; no requiere instalar `safety`.
"""

import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


class DependencyScanner:
    """Escanea dependencias de un proyecto buscando CVEs conocidos."""

    OWASP_CATEGORY = "A06:2021 — Vulnerable and Outdated Components"
    CWE = "CWE-1104 — Use of Unmaintained Third Party Components"
    OSV_API = "https://api.osv.dev/v1/query"

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: List[Dict] = []

    # ------------------------------------------------------------------
    # Punto de entrada principal
    # ------------------------------------------------------------------

    def scan_project(self, project_dir: str = ".") -> List[Dict]:
        """Escanea el directorio de proyecto y devuelve lista de vulnerabilidades."""
        self.findings = []
        project_path = Path(project_dir)

        req_files = list(project_path.rglob("requirements*.txt"))
        pkg_files = list(project_path.rglob("package.json"))

        # Filtrar node_modules
        pkg_files = [p for p in pkg_files if "node_modules" not in str(p)]

        if req_files:
            for req_file in req_files:
                self._scan_pip_requirements(req_file)
        else:
            self._scan_pip_installed()

        for pkg_file in pkg_files:
            self._scan_npm(pkg_file.parent)

        return self.findings

    # ------------------------------------------------------------------
    # Python — requirements.txt
    # ------------------------------------------------------------------

    def _scan_pip_requirements(self, req_file: Path) -> None:
        if self.verbose:
            print(f"[DependencyScanner] Escaneando {req_file}")
        packages = self._parse_requirements(req_file)
        for name, version in packages:
            self._check_osv(name, version, "PyPI")

    def _scan_pip_installed(self) -> None:
        """Fallback: usa `pip list --format=json` para obtener paquetes instalados."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--format=json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return
            packages = json.loads(result.stdout)
            for pkg in packages[:50]:  # limitar para no saturar la API
                self._check_osv(pkg["name"], pkg["version"], "PyPI")
        except Exception:
            pass

    def _parse_requirements(self, req_file: Path) -> List[tuple]:
        packages = []
        for line in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # pkg==1.2.3  pkg>=1.2.3  pkg~=1.2.3
            m = re.match(r"^([A-Za-z0-9_\-\.]+)[=~!<>]=?([0-9][^\s;#]*)?", line)
            if m:
                name = m.group(1)
                version = (m.group(2) or "").strip() or None
                packages.append((name, version))
        return packages

    # ------------------------------------------------------------------
    # Node.js — npm audit
    # ------------------------------------------------------------------

    def _scan_npm(self, pkg_dir: Path) -> None:
        if self.verbose:
            print(f"[DependencyScanner] npm audit en {pkg_dir}")
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True, text=True, timeout=120,
                cwd=str(pkg_dir)
            )
            # npm audit devuelve exit code != 0 cuando hay vulnerabilidades
            if not result.stdout:
                return
            audit = json.loads(result.stdout)
            self._parse_npm_audit(audit, pkg_dir)
        except FileNotFoundError:
            if self.verbose:
                print("[DependencyScanner] npm no disponible, omitiendo Node.js")
        except Exception:
            pass

    def _parse_npm_audit(self, audit: dict, pkg_dir: Path) -> None:
        # npm audit JSON v2 format
        vulns = audit.get("vulnerabilities", {})
        for pkg_name, info in vulns.items():
            severity = info.get("severity", "unknown")
            via = info.get("via", [])
            cves = []
            advisory_title = f"Vulnerabilidad en {pkg_name}"
            for v in via:
                if isinstance(v, dict):
                    cves.extend(v.get("cve", []))
                    if v.get("title"):
                        advisory_title = v["title"]
            self.findings.append(self._make_finding(
                package=pkg_name,
                ecosystem="npm",
                version=info.get("range", "desconocida"),
                severity=severity,
                title=advisory_title,
                cves=cves,
                source=str(pkg_dir / "package.json"),
            ))

    # ------------------------------------------------------------------
    # OSV API — comprobación de CVEs
    # ------------------------------------------------------------------

    def _check_osv(self, name: str, version: Optional[str], ecosystem: str) -> None:
        payload: Dict = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            payload["version"] = version
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                self.OSV_API,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
        except Exception:
            return

        for vuln in result.get("vulns", []):
            aliases = vuln.get("aliases", [])
            cves = [a for a in aliases if a.startswith("CVE-")]
            severity_raw = "unknown"
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score = float(sev.get("score", "0.0").replace("CVSS:3.1/", "0").split("/")[0] or 0)
                    severity_raw = self._cvss_to_level(score)
                    break
            self.findings.append(self._make_finding(
                package=name,
                ecosystem=ecosystem,
                version=version or "instalada",
                severity=severity_raw,
                title=vuln.get("summary", f"Vulnerabilidad en {name}"),
                cves=cves,
                source="requirements.txt / pip",
            ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _cvss_to_level(self, score: float) -> str:
        if score >= 9.0:
            return "critica"
        if score >= 7.0:
            return "alta"
        if score >= 4.0:
            return "media"
        return "baja"

    def _make_finding(self, package: str, ecosystem: str, version: str,
                      severity: str, title: str, cves: List[str],
                      source: str) -> Dict:
        sev_map = {"critical": "critica", "high": "alta", "moderate": "media",
                   "low": "baja", "info": "informativa", "unknown": "media"}
        sev_norm = sev_map.get(severity.lower(), severity.lower())
        return {
            "tipo": "dependencia_vulnerable",
            "descripcion": f"{package} ({ecosystem}) {version}: {title}",
            "severidad": sev_norm,
            "owasp_category": self.OWASP_CATEGORY,
            "cwe": self.CWE,
            "cves": cves,
            "package": package,
            "ecosystem": ecosystem,
            "version_afectada": version,
            "fuente": f"dependency_scanner:{source}",
            "por_que_peligroso": (
                "Usar componentes con vulnerabilidades conocidas permite a un atacante "
                "explotar fallos ya documentados con exploits públicos disponibles."
            ),
            "como_remediarlo": (
                f"Actualiza {package} a la última versión estable: "
                f"`pip install --upgrade {package}` o revisa el CHANGELOG del proyecto."
            ),
            "cheat_sheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }
