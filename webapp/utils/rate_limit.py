"""Rate limiter en memoria para proteger endpoints de creación de recursos."""

from collections import defaultdict
from datetime import datetime, timedelta
from fastapi import HTTPException, Request


class _InMemoryRateLimiter:
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = timedelta(seconds=window_seconds)
        self._log: dict[str, list[datetime]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        now = datetime.now()
        cutoff = now - self.window
        self._log[client_ip] = [t for t in self._log[client_ip] if t > cutoff]
        if len(self._log[client_ip]) >= self.max_requests:
            return False
        self._log[client_ip].append(now)
        return True


# 10 escaneos nuevos por minuto por IP es suficiente para uso educativo
_scan_start_limiter = _InMemoryRateLimiter(max_requests=10, window_seconds=60)


async def check_scan_start_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not _scan_start_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Demasiadas peticiones. Espera un momento antes de iniciar otro escaneo."
        )