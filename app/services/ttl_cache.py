"""
4.1.0 P7 — Tiny in-process TTL cache for hot read-only computations.

Plan §1.4 + §7: Heatmap-matrix builds and dashboard-metric rollups are
the two heaviest single-tenant requests (each issues 5–15 DuckDB
queries plus pandas dataframes and reads validation JSON). Both are
strictly read-only with respect to the request and tolerate a few
seconds of staleness — perfect candidates for a short-TTL cache.

This module is deliberately minimal:

  * **Per-tenant keying** — every cache entry's key starts with the
    ``client_id``, so a stale entry from one tenant can never serve
    another tenant. `client_id=None` (super-admin "all clients" view)
    is a separate keyspace from any specific tenant.
  * **TTL only, no LRU** — the cache holds at most ``maxsize`` entries
    (FIFO eviction when full); the dominant axis here is *time*, not
    memory. A heatmap matrix dict for one tenant is a few KB.
  * **No background sweep** — entries expire lazily on read so we don't
    need a dedicated thread (which the §2 isolation contract would have
    to plumb tenant context into).
  * **Process-local** — single-container deploy means there's no
    coherence problem to solve.

NOT used for anything that depends on per-user state (e.g. quest tray)
— those calls bypass the cache because the per-tenant keying is too
coarse.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Hashable, Optional, Tuple


class TTLCache:
    """Thread-safe TTL cache with FIFO overflow eviction.

    Usage::

        cache = TTLCache(ttl_seconds=30, maxsize=64)
        value = cache.get_or_compute(key, lambda: expensive())
    """

    __slots__ = ("_ttl", "_maxsize", "_data", "_lock")

    def __init__(self, ttl_seconds: float = 30.0, maxsize: int = 64):
        self._ttl = float(ttl_seconds)
        self._maxsize = int(maxsize)
        # key -> (expires_at, value). Insertion order = eviction order.
        self._data: dict = {}
        self._lock = threading.Lock()

    def get(self, key: Hashable) -> Tuple[bool, Any]:
        """Return (hit, value). hit=False means caller should compute."""
        now = time.monotonic()
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return False, None
            expires_at, value = entry
            if expires_at < now:
                # Lazily evict expired entry so memory doesn't creep.
                self._data.pop(key, None)
                return False, None
            return True, value

    def set(self, key: Hashable, value: Any) -> None:
        with self._lock:
            # FIFO overflow: drop oldest until under cap.
            while len(self._data) >= self._maxsize and key not in self._data:
                # Pop oldest (insertion order in CPython 3.7+).
                self._data.pop(next(iter(self._data)))
            self._data[key] = (time.monotonic() + self._ttl, value)

    def get_or_compute(self, key: Hashable, compute: Callable[[], Any]) -> Any:
        hit, value = self.get(key)
        if hit:
            return value
        value = compute()
        self.set(key, value)
        return value

    def invalidate(self, key: Optional[Hashable] = None) -> None:
        """Drop one key, or all entries if key is None. Sync write
        endpoints call this so users see their changes immediately
        rather than waiting out the TTL."""
        with self._lock:
            if key is None:
                self._data.clear()
            else:
                self._data.pop(key, None)

    def invalidate_prefix(self, prefix_match: Callable[[Hashable], bool]) -> int:
        """Drop every key for which *prefix_match(key)* is true. Used
        by tenant-scoped invalidation (e.g. drop all heatmap entries
        for client X after a baseline change). Returns the number of
        entries dropped."""
        with self._lock:
            doomed = [k for k in self._data if prefix_match(k)]
            for k in doomed:
                self._data.pop(k, None)
            return len(doomed)

    def stats(self) -> dict:
        with self._lock:
            return {"size": len(self._data), "maxsize": self._maxsize, "ttl": self._ttl}


# ── Module-level instances ─────────────────────────────────────────
# Heatmap matrix: 30-second TTL is a deliberate trade-off — short
# enough that "I just added a rule, refresh" feels live; long enough
# to absorb the dashboard-then-heatmap navigation pattern users do
# constantly. 64 entries handles ~8 tenants × 8 distinct actor-set
# permutations cached at once.
heatmap_matrix_cache = TTLCache(ttl_seconds=30.0, maxsize=64)

# Dashboard rollup: longer TTL because it's an aggregate of aggregates
# and changes much less frequently than per-rule edits surface.
dashboard_cache = TTLCache(ttl_seconds=60.0, maxsize=16)
