"""Rate limiting en memoria, por ventana deslizante.

**Limite conocido y documentado:** los contadores viven en el proceso. Con el
unico worker del Compose normal es correcto; con varios workers o replicas cada
proceso contaria por su cuenta y el limite efectivo se multiplicaria.

Esto NO es una defensa contra IDOR ni una frontera de aislamiento entre
clientes: la autorizacion por objeto se comprueba aparte, en cada endpoint.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass


@dataclass(slots=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int
    limit: int
    remaining: int


class SlidingWindowLimiter:
    """Ventana deslizante de 60 s por clave."""

    def __init__(self, *, window_seconds: int = 60, max_keys: int = 5000) -> None:
        self._window = window_seconds
        self._max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str, limit: int) -> RateLimitDecision:
        now = time.monotonic()
        cutoff = now - self._window

        async with self._lock:
            if len(self._hits) > self._max_keys:
                self._evict_locked(cutoff)

            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= limit:
                oldest = bucket[0]
                retry_after = max(1, int(self._window - (now - oldest)) + 1)
                return RateLimitDecision(False, retry_after, limit, 0)

            bucket.append(now)
            return RateLimitDecision(True, 0, limit, limit - len(bucket))

    def _evict_locked(self, cutoff: float) -> None:
        for key, bucket in list(self._hits.items()):
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if not bucket:
                self._hits.pop(key, None)

    async def reset(self) -> None:
        async with self._lock:
            self._hits.clear()
