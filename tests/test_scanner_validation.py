"""
Tests para la validación de targets en VulnerabilityScanner.
Verifica que IPs privadas/locales se acepten y públicas se rechacen
cuando ALLOW_PUBLIC_TARGETS no está habilitado.
"""

import pytest
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanagent.scanner import VulnerabilityScanner


# ── IPs/hostnames que DEBEN aceptarse ─────────────────────────────────────────

@pytest.mark.parametrize("target", [
    "127.0.0.1",
    "localhost",
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "192.168.100.200",
    "app.local",
    "dvwa.internal",
    "juice-shop.corp",
])
def test_accepts_private_targets(target, monkeypatch):
    monkeypatch.delenv("ALLOW_PUBLIC_TARGETS", raising=False)
    VulnerabilityScanner.validate_target(target)  # no debe lanzar


# ── IPs públicas que DEBEN rechazarse (sin flag) ───────────────────────────────

@pytest.mark.parametrize("target", [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "google.com",
    "example.com",
])
def test_rejects_public_targets_by_default(target, monkeypatch):
    monkeypatch.delenv("ALLOW_PUBLIC_TARGETS", raising=False)
    with pytest.raises(ValueError, match="ALLOW_PUBLIC_TARGETS"):
        VulnerabilityScanner.validate_target(target)


# ── Con ALLOW_PUBLIC_TARGETS=true se aceptan IPs públicas ─────────────────────

@pytest.mark.parametrize("target", [
    "8.8.8.8",
    "1.1.1.1",
    "example.com",
])
def test_accepts_public_when_flag_enabled(target, monkeypatch):
    monkeypatch.setenv("ALLOW_PUBLIC_TARGETS", "true")
    VulnerabilityScanner.validate_target(target)  # no debe lanzar


# ── Targets maliciosos/malformados que deben rechazarse ───────────────────────

@pytest.mark.parametrize("target", [
    "",
    "192.168.1.1; rm -rf /",
    "192.168.1.1 && whoami",
    "$(reboot)",
    "127.0.0.1\n",
    "a" * 254,
    "not_a_hostname_!!",
])
def test_rejects_malformed_targets(target, monkeypatch):
    monkeypatch.delenv("ALLOW_PUBLIC_TARGETS", raising=False)
    with pytest.raises(ValueError):
        VulnerabilityScanner.validate_target(target)
