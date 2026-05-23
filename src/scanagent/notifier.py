#!/usr/bin/env python3
"""
Webhook Notifier — Scan Agent Fase 7.3
========================================
Envía notificaciones a webhooks externos cuando se detectan vulnerabilidades
críticas o altas. Soporta webhooks genéricos y Slack.

Configuración (variables de entorno):
  WEBHOOK_URL       URL del webhook (requerido para activar notificaciones)
  WEBHOOK_SECRET    Secreto HMAC-SHA256 para firmar el payload (opcional)
  WEBHOOK_FORMAT    "slack" | "generic" (default: generic)
  WEBHOOK_MIN_SEV   Severidad mínima para notificar: critica|alta|media|baja
                    (default: alta)

Solo usa stdlib — sin dependencias externas.
"""

import hashlib
import hmac
import json
import logging
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("scan_agent.notifier")

_SEV_ORDER = ["informativa", "baja", "media", "alta", "critica"]


class WebhookNotifier:
    """Envía notificaciones de vulnerabilidades a webhooks externos."""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        secret: Optional[str] = None,
        fmt: str = "generic",
        min_severity: str = "alta",
    ):
        self.webhook_url = webhook_url or os.environ.get("WEBHOOK_URL", "").strip()
        self.secret = secret or os.environ.get("WEBHOOK_SECRET", "").strip()
        self.fmt = fmt or os.environ.get("WEBHOOK_FORMAT", "generic").lower()
        min_env = os.environ.get("WEBHOOK_MIN_SEV", "alta").lower()
        self.min_severity = min_severity or min_env

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def notify_scan_complete(
        self,
        target: str,
        vulnerabilities: List[Dict],
        scan_id: str = "",
        profile: str = "",
    ) -> bool:
        """Envía notificación al completar un escaneo.

        Solo notifica si hay vulnerabilidades con severidad >= min_severity.
        Devuelve True si la notificación fue enviada con éxito.
        """
        if not self.enabled:
            return False

        relevant = self._filter_by_severity(vulnerabilities)
        if not relevant:
            logger.debug("Sin vulnerabilidades relevantes — notificación omitida")
            return False

        payload = self._build_payload(target, vulnerabilities, relevant, scan_id, profile)
        return self._send(payload)

    # ------------------------------------------------------------------
    # Builders de payload
    # ------------------------------------------------------------------

    def _build_payload(
        self,
        target: str,
        all_vulns: List[Dict],
        relevant: List[Dict],
        scan_id: str,
        profile: str,
    ) -> Dict:
        if self.fmt == "slack":
            return self._slack_payload(target, all_vulns, relevant, scan_id)
        return self._generic_payload(target, all_vulns, relevant, scan_id, profile)

    def _generic_payload(
        self,
        target: str,
        all_vulns: List[Dict],
        relevant: List[Dict],
        scan_id: str,
        profile: str,
    ) -> Dict:
        counts = self._count_by_severity(all_vulns)
        top_findings = [
            {
                "tipo": v.get("tipo"),
                "severidad": v.get("severidad"),
                "descripcion": v.get("descripcion", "")[:200],
                "owasp": v.get("owasp_api_category") or v.get("owasp_category", ""),
            }
            for v in relevant[:10]
        ]
        return {
            "event": "scan_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "summary": counts,
            "top_findings": top_findings,
            "tool": "scan-agent",
            "version": "3.0.0",
        }

    def _slack_payload(
        self,
        target: str,
        all_vulns: List[Dict],
        relevant: List[Dict],
        scan_id: str,
    ) -> Dict:
        counts = self._count_by_severity(all_vulns)
        criticas = counts.get("critica", 0)
        altas = counts.get("alta", 0)
        color = "#ff0000" if criticas else "#ff8800" if altas else "#ffcc00"
        fields = [
            {"title": "Target", "value": target, "short": True},
            {"title": "Scan ID", "value": scan_id or "—", "short": True},
            {"title": "Críticas", "value": str(criticas), "short": True},
            {"title": "Altas", "value": str(altas), "short": True},
            {"title": "Medias", "value": str(counts.get("media", 0)), "short": True},
            {"title": "Total", "value": str(len(all_vulns)), "short": True},
        ]
        top = "\n".join(
            f"• [{v.get('severidad','?').upper()}] {v.get('tipo','?')}: {v.get('descripcion','')[:80]}"
            for v in relevant[:5]
        )
        return {
            "attachments": [
                {
                    "fallback": f"Scan Agent: {len(relevant)} vulnerabilidades relevantes en {target}",
                    "color": color,
                    "title": f"Scan Agent — Escaneo completado: {target}",
                    "text": top or "Sin hallazgos destacados.",
                    "fields": fields,
                    "footer": "Scan Agent v3.0",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ]
        }

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _send(self, payload: Dict) -> bool:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.secret:
            sig = hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-Scan-Agent-Signature"] = f"sha256={sig}"

        try:
            req = urllib.request.Request(
                self.webhook_url, data=body, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.getcode()
                logger.info("Webhook enviado a %s → HTTP %s", self.webhook_url, status)
                return 200 <= status < 300
        except urllib.error.HTTPError as exc:
            logger.warning("Webhook HTTP %s: %s", exc.code, exc.reason)
        except Exception as exc:
            logger.warning("Error enviando webhook: %s", exc)
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _filter_by_severity(self, vulns: List[Dict]) -> List[Dict]:
        min_idx = _SEV_ORDER.index(self.min_severity) if self.min_severity in _SEV_ORDER else 3
        return [
            v for v in vulns
            if _SEV_ORDER.index(v.get("severidad", "baja")) >= min_idx
            if v.get("severidad", "baja") in _SEV_ORDER
        ]

    def _count_by_severity(self, vulns: List[Dict]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for v in vulns:
            sev = v.get("severidad", "desconocida")
            counts[sev] = counts.get(sev, 0) + 1
        return counts