"""A simple async token-bucket rate limiter.

Used to throttle outgoing Telegram API calls (joins, sends) so the
application stays comfortably under Telegram's flood-wait thresholds.
"""

from __future__ import annotations

import asyncio
import time


class TokenBucketRateLimiter:
    """Async token-bucket limiter: allows `rate` operations per `per_seconds`."""

    def __init__(self, rate: int, per_seconds: float = 60.0) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self._rate = rate
        self._per_seconds = per_seconds
        self._tokens = float(rate)
        self._updated_at = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a token is available, then consume it."""
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated_at
                refill = elapsed * (self._rate / self._per_seconds)
                if refill > 0:
                    self._tokens = min(self._rate, self._tokens + refill)
                    self._updated_at = now

                if self._tokens >= 1:
                    self._tokens -= 1
                    return

                deficit = 1 - self._tokens
                wait_time = deficit / (self._rate / self._per_seconds)

            await asyncio.sleep(wait_time)

    async def __aenter__(self) -> "TokenBucketRateLimiter":
        await self.acquire()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None
