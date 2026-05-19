"""
Tests para los datos educativos y mappings OWASP en VulnerabilityInterpreter.
Verifica que EDUCATIONAL_DATA, OWASP_WEB_CWE y _enrich_educational funcionen
correctamente para el contexto pedagógico.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanagent.interpreter import VulnerabilityInterpreter


# ── Estructura de EDUCATIONAL_DATA ────────────────────────────────────────────

def test_educational_data_exists():
    assert hasattr(VulnerabilityInterpreter, "EDUCATIONAL_DATA")
    assert len(VulnerabilityInterpreter.EDUCATIONAL_DATA) >= 10


def test_educational_data_required_fields():
    required = {"por_que_peligroso", "ejemplo_payload", "como_remediarlo", "cheat_sheet_url"}
    for key, entry in VulnerabilityInterpreter.EDUCATIONAL_DATA.items():
        missing = required - entry.keys()
        assert not missing, f"Entrada '{key}' le faltan campos: {missing}"


def test_educational_data_cheat_sheet_urls_are_https():
    for key, entry in VulnerabilityInterpreter.EDUCATIONAL_DATA.items():
        url = entry.get("cheat_sheet_url", "")
        assert url.startswith("https://"), f"'{key}' tiene URL no HTTPS: {url}"


# ── OWASP_WEB_CWE ─────────────────────────────────────────────────────────────

def test_owasp_web_cwe_covers_all_ten():
    cwe_map = VulnerabilityInterpreter.OWASP_WEB_CWE
    for i in range(1, 11):
        key = f"A{i:02d}:2021"
        assert key in cwe_map, f"Falta entrada CWE para {key}"


def test_owasp_web_cwe_values_contain_cwe_number():
    for key, value in VulnerabilityInterpreter.OWASP_WEB_CWE.items():
        assert "CWE-" in value, f"Valor de {key} no contiene 'CWE-': {value}"


# ── _enrich_educational ────────────────────────────────────────────────────────

def _make_interpreter(vulns):
    interp = VulnerabilityInterpreter.__new__(VulnerabilityInterpreter)
    interp.vulnerabilities = vulns
    interp.risk_summary = {}
    return interp


def test_enrich_by_tipo():
    vuln = {"tipo": "missing_security_headers", "severidad": "media"}
    interp = _make_interpreter([vuln])
    interp._enrich_educational()
    assert "por_que_peligroso" in vuln
    assert "ejemplo_payload" in vuln
    assert "como_remediarlo" in vuln


def test_enrich_by_owasp_api_category():
    vuln = {"tipo": "idor", "owasp_api_category": "API1:2023", "severidad": "alta"}
    interp = _make_interpreter([vuln])
    interp._enrich_educational()
    assert "por_que_peligroso" in vuln


def test_enrich_by_owasp_web_category():
    vuln = {"tipo": "sqli_detectado", "owasp_category": "A03:2021 — Injection", "severidad": "critica"}
    interp = _make_interpreter([vuln])
    interp._enrich_educational()
    assert "por_que_peligroso" in vuln


def test_enrich_does_not_overwrite_existing():
    original = "Razón personalizada del profesor"
    vuln = {
        "tipo": "missing_security_headers",
        "por_que_peligroso": original,
    }
    interp = _make_interpreter([vuln])
    interp._enrich_educational()
    assert vuln["por_que_peligroso"] == original  # setdefault no debe sobrescribir


def test_enrich_cwe_fallback_from_owasp_web():
    vuln = {"tipo": "unknown_type", "owasp_category": "A07:2021 — Identification and Authentication Failures"}
    interp = _make_interpreter([vuln])
    interp._enrich_educational()
    # Debe asignar CWE desde OWASP_WEB_CWE aunque no haya entrada en EDUCATIONAL_DATA
    assert "cwe" in vuln
    assert "CWE-" in vuln["cwe"]