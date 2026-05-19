#!/usr/bin/env python3
"""
SARIF Exporter — Scan Agent Fase 7.2
======================================
Exporta resultados al formato SARIF 2.1.0 (Static Analysis Results
Interchange Format), compatible con GitHub Advanced Security, VS Code
SARIF Viewer, y herramientas como CodeQL / Semgrep.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional


_SEVERITY_LEVEL = {
    "critica": "error",
    "alta": "error",
    "media": "warning",
    "baja": "note",
    "informativa": "none",
}

_SEVERITY_RANK = {
    "critica": 9.5,
    "alta": 7.5,
    "media": 4.5,
    "baja": 2.0,
    "informativa": 0.0,
}


class SARIFExporter:
    """Convierte la lista de vulnerabilidades de Scan Agent a SARIF 2.1.0."""

    TOOL_NAME = "Scan Agent"
    TOOL_VERSION = "3.0.0"
    TOOL_URI = "https://github.com/pater8715/scan-agent"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def __init__(self, vulnerabilities: List[Dict], target: str = ""):
        self.vulnerabilities = vulnerabilities
        self.target = target

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export(self, output_file: str) -> str:
        sarif = self._build_sarif()
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)
        return output_file

    def to_dict(self) -> Dict:
        return self._build_sarif()

    # ------------------------------------------------------------------
    # Builder
    # ------------------------------------------------------------------

    def _build_sarif(self) -> Dict:
        rules = self._collect_rules()
        results = [self._vuln_to_result(v) for v in self.vulnerabilities]

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "informationUri": self.TOOL_URI,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    "properties": {
                        "target": self.target,
                        "scanAgent": {"version": self.TOOL_VERSION},
                    },
                }
            ],
        }

    # ------------------------------------------------------------------
    # Rules deduplicadas
    # ------------------------------------------------------------------

    def _collect_rules(self) -> Dict[str, Dict]:
        rules: Dict[str, Dict] = {}
        for v in self.vulnerabilities:
            rule_id = self._rule_id(v)
            if rule_id not in rules:
                rules[rule_id] = self._make_rule(rule_id, v)
        return rules

    def _rule_id(self, v: Dict) -> str:
        """Genera un ruleId estable a partir de tipo + categoría OWASP."""
        tipo = re.sub(r"[^A-Za-z0-9_\-]", "_", v.get("tipo", "unknown"))
        owasp = v.get("owasp_api_category") or v.get("owasp_category", "")
        owasp_slug = re.sub(r"[^A-Za-z0-9]", "", owasp)[:12]
        return f"SA-{tipo[:30]}-{owasp_slug}" if owasp_slug else f"SA-{tipo[:40]}"

    def _make_rule(self, rule_id: str, v: Dict) -> Dict:
        sev = v.get("severidad", "media")
        owasp = v.get("owasp_api_category") or v.get("owasp_category", "")
        cwe = v.get("cwe", "")
        cheat = v.get("cheat_sheet_url", "")

        rule: Dict = {
            "id": rule_id,
            "name": self._rule_name(v),
            "shortDescription": {"text": v.get("tipo", rule_id).replace("_", " ").title()},
            "fullDescription": {"text": v.get("por_que_peligroso", v.get("descripcion", ""))},
            "defaultConfiguration": {
                "level": _SEVERITY_LEVEL.get(sev, "warning"),
                "rank": _SEVERITY_RANK.get(sev, 4.5),
            },
            "properties": {
                "tags": [t for t in [owasp, cwe] if t],
                "security-severity": str(_SEVERITY_RANK.get(sev, 4.5)),
            },
        }
        if cheat:
            rule["helpUri"] = cheat
            rule["help"] = {
                "text": v.get("como_remediarlo", "Ver OWASP Cheat Sheet."),
                "markdown": (
                    f"{v.get('como_remediarlo', '')}\n\n"
                    f"[OWASP Cheat Sheet]({cheat})"
                ),
            }
        return rule

    def _rule_name(self, v: Dict) -> str:
        tipo = v.get("tipo", "finding")
        return "".join(w.capitalize() for w in tipo.split("_"))

    # ------------------------------------------------------------------
    # Result
    # ------------------------------------------------------------------

    def _vuln_to_result(self, v: Dict) -> Dict:
        sev = v.get("severidad", "media")
        mensaje = v.get("descripcion", v.get("tipo", "Vulnerabilidad detectada"))
        cves = v.get("cves", [])
        if isinstance(cves, str):
            cves = [cves]

        result: Dict = {
            "ruleId": self._rule_id(v),
            "level": _SEVERITY_LEVEL.get(sev, "warning"),
            "message": {
                "text": mensaje,
                "markdown": self._result_markdown(v),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": self.target or "target://unknown",
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                }
            ],
            "properties": {
                "severity": sev,
                "owaspCategory": v.get("owasp_api_category") or v.get("owasp_category", ""),
                "cwe": v.get("cwe", ""),
            },
        }

        if cves:
            result["relatedLocations"] = []
            result["properties"]["cveIds"] = cves

        payload = v.get("ejemplo_payload", "")
        if payload:
            result["properties"]["examplePayload"] = payload

        return result

    def _result_markdown(self, v: Dict) -> str:
        lines = [f"**{v.get('tipo', 'finding')}** — {v.get('descripcion', '')}"]
        if v.get("por_que_peligroso"):
            lines.append(f"\n**¿Por qué es peligroso?** {v['por_que_peligroso']}")
        if v.get("como_remediarlo"):
            lines.append(f"\n**Remediación:** {v['como_remediarlo']}")
        if v.get("cheat_sheet_url"):
            lines.append(f"\n[OWASP Cheat Sheet]({v['cheat_sheet_url']})")
        return "\n".join(lines)
