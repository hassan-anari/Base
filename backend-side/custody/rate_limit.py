"""
Rate limiting guard (stub).

Guard points where rate limiting MUST be applied:
  - API endpoints (per-user / per-IP) -> see api.py decorators
  - Signing requests (per actor + policy) -> see mpc_signer.enforce_rate_limit

This skeleton provides an in-memory token-bucket. In production, back it with
Redis (shared across workers) so limits are global, not per-process.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Tuple


class RateLimitExceeded(Exception):
    pass


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


class RateLimiter:
    """In-memory token bucket. Replace with Redis in production."""

    def __init__(self) -> None:
        self._buckets: Dict[Tuple[str, int], _Bucket] = {}
        self._lock: Dict[str, float] = {}  # stub-only lock; in prod use Redis

    def consume(self, key: str, limit: int, window_seconds: int) -> None:
        now = time.time()
        b = self._buckets.get((key, limit))
        refill = limit / window_seconds
        if b is None:
            b = _Bucket(tokens=limit - 1, updated_at=now)
            self._buckets[(key, limit)] = b
            return
        elapsed = now - b.updated_at
        b.tokens = min(limit, b.tokens + elapsed * refill)
        b.updated_at = now
        if b.tokens < 1:
            raise RateLimitExceeded(f"rate limit exceeded for {key}")
        b.tokens -= 1

    # Optional distributed lock (e.g., Redis SET NX) for sweep idempotency.
    def acquire_lock(self, key: str, ttl: int = 60) -> bool:
        # Stub: in prod use redis.set(key, "1", nx=True, ex=ttl)
        token = self._lock.get(key)
        if token and time.time() < token:
            return False
        self._lock[key] = time.time() + ttl
        return True

    def release_lock(self, key: str) -> None:
        self._lock.pop(key, None)


rate_limiter = RateLimiter()