"""Rate budget + WAF detection shared across active checks."""

from __future__ import annotations

import asyncio
import random
import time


class WAFBlocked(Exception):
    pass


class RateBudget:
    """Very simple rate limiter: min gap between any two requests, plus jitter."""

    def __init__(self, min_interval: float = 0.2, jitter: float = 0.15):
        self._min = min_interval
        self._jitter = jitter
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._last + self._min - now
            if wait > 0:
                await asyncio.sleep(wait + random.random() * self._jitter)
            self._last = time.monotonic()


class WAFDetector:
    """Tracks suspicious responses; raises WAFBlocked after a threshold."""

    def __init__(self, threshold: int = 3):
        self._threshold = threshold
        self._hits = 0

    def observe(self, status: int, body: str = "") -> None:
        body_lower = body[:2000].lower() if body else ""
        suspicious = (
            status in (403, 429)
            or "cloudflare" in body_lower
            or "access denied" in body_lower
            or "request blocked" in body_lower
            or "akamai" in body_lower
        )
        if suspicious:
            self._hits += 1
            if self._hits >= self._threshold:
                raise WAFBlocked(
                    f"WAF zablokował skan po {self._hits} podejrzanych odpowiedziach"
                )
        else:
            # reset streak on a clean response
            self._hits = max(0, self._hits - 1)
