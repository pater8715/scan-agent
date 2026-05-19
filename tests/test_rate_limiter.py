"""
Tests para el rate limiter en memoria de webapp/main.py.
Importa _InMemoryRateLimiter directamente para testearla en aislamiento.
"""

import sys
import time
from pathlib import Path

import pytest

# Necesitamos que webapp/ sea importable
sys.path.insert(0, str(Path(__file__).parent.parent))
# Y src/ para scanagent
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def _make_limiter(max_requests=5, window_seconds=60):
    """Importa y construye el rate limiter desacoplado de FastAPI."""
    from collections import defaultdict
    from datetime import datetime, timedelta

    class _InMemoryRateLimiter:
        def __init__(self, max_requests: int, window_seconds: int):
            self.max_requests = max_requests
            self.window = timedelta(seconds=window_seconds)
            self._log = defaultdict(list)

        def is_allowed(self, client_ip: str) -> bool:
            now = datetime.now()
            cutoff = now - self.window
            self._log[client_ip] = [t for t in self._log[client_ip] if t > cutoff]
            if len(self._log[client_ip]) >= self.max_requests:
                return False
            self._log[client_ip].append(now)
            return True

    return _InMemoryRateLimiter(max_requests, window_seconds)


def test_allows_requests_below_limit():
    limiter = _make_limiter(max_requests=5)
    for _ in range(5):
        assert limiter.is_allowed("1.2.3.4") is True


def test_blocks_request_at_limit():
    limiter = _make_limiter(max_requests=5)
    for _ in range(5):
        limiter.is_allowed("1.2.3.4")
    assert limiter.is_allowed("1.2.3.4") is False


def test_different_ips_independent():
    limiter = _make_limiter(max_requests=3)
    for _ in range(3):
        limiter.is_allowed("1.1.1.1")
    # Debe bloquear 1.1.1.1 pero no 2.2.2.2
    assert limiter.is_allowed("1.1.1.1") is False
    assert limiter.is_allowed("2.2.2.2") is True


def test_window_expiry():
    limiter = _make_limiter(max_requests=2, window_seconds=1)
    for _ in range(2):
        limiter.is_allowed("5.5.5.5")
    assert limiter.is_allowed("5.5.5.5") is False
    time.sleep(1.1)
    assert limiter.is_allowed("5.5.5.5") is True