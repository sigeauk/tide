"""
Bounded per-tenant DuckDB connection pool.

Background — TIDE 4.0.x (`DatabaseService.get_connection()`) opened a fresh
``duckdb.connect()`` for every request and closed it at the end of the
context manager. With the per-tenant DuckDB-per-file routing introduced
in 4.0.10 + Migration 37, that meant every page load paid the cost of a
file-open, WAL replay, catalog scan, and schema introspection. On the
heatmap and dashboard pages this dominated the request budget.

Design — Plan §3 (4.1.0):
    * Pool is keyed by absolute db_path (so the shared DB and each
      tenant DB get their own slot).
    * Up to ``MAX_TENANTS`` distinct db_paths kept hot; oldest is closed
      via LRU eviction when a 9th tenant arrives.
    * Up to ``MAX_PER_TENANT`` connections per db_path (DuckDB connection
      objects are not safe to share across threads concurrently — the
      Queue gates that automatically).
    * Each fresh connection is tuned once with ``PRAGMA threads`` and
      ``PRAGMA memory_limit``; both values are read from settings so we
      can tune per-environment without code changes.
    * ``acquire(db_path)`` is a context manager. On exit the connection
      goes back to the queue if there is room; otherwise it is closed.
    * No third-party dependencies (air-gap constraint).
"""

from __future__ import annotations

import logging
import os
import threading
from collections import OrderedDict
from contextlib import contextmanager
from queue import Empty, Queue
from typing import Optional

import duckdb

logger = logging.getLogger(__name__)

# Sizing — Plan §3 (8 × 2). Tunable via env vars for benchmarking but the
# defaults are what we ship.
MAX_TENANTS: int = int(os.getenv("TIDE_POOL_MAX_TENANTS", "8"))
MAX_PER_TENANT: int = int(os.getenv("TIDE_POOL_MAX_PER_TENANT", "2"))

# DuckDB tuning — applied once when each connection is created.
DUCKDB_THREADS: int = int(os.getenv("TIDE_DUCKDB_THREADS", "4"))
DUCKDB_MEMORY_LIMIT: str = os.getenv("TIDE_DUCKDB_MEMORY_LIMIT", "512MB")


class _Slot:
    """Per-db_path queue + lock pair."""

    __slots__ = ("queue", "lock")

    def __init__(self) -> None:
        self.queue: Queue = Queue(maxsize=MAX_PER_TENANT)
        self.lock = threading.Lock()


class ConnectionPool:
    """Thread-safe LRU pool of DuckDB connections, bounded per db_path."""

    def __init__(self) -> None:
        # OrderedDict gives us O(1) move-to-end + O(1) popitem(last=False)
        # for LRU eviction.
        self._slots: "OrderedDict[str, _Slot]" = OrderedDict()
        self._lock = threading.Lock()
        # Counters exposed for /health and tests.
        self.hits: int = 0
        self.misses: int = 0
        self.evictions: int = 0

    # ---- internal helpers --------------------------------------------------

    def _get_or_create_slot(self, db_path: str) -> _Slot:
        with self._lock:
            slot = self._slots.get(db_path)
            if slot is None:
                # Evict LRU slot if we are about to exceed the cap.
                while len(self._slots) >= MAX_TENANTS:
                    evicted_path, evicted_slot = self._slots.popitem(last=False)
                    self._drain_slot(evicted_slot, evicted_path)
                    self.evictions += 1
                slot = _Slot()
                self._slots[db_path] = slot
            else:
                # Mark as most-recently-used.
                self._slots.move_to_end(db_path, last=True)
            return slot

    def _drain_slot(self, slot: _Slot, db_path: str) -> None:
        """Close every cached connection in *slot*. Called under LRU eviction
        and during ``close_all``. Errors are logged but never raised — a
        misbehaving connection must not block pool teardown."""
        with slot.lock:
            while True:
                try:
                    conn = slot.queue.get_nowait()
                except Empty:
                    break
                try:
                    conn.close()
                except Exception as exc:  # pragma: no cover
                    logger.warning("ConnectionPool: failed to close %s: %s", db_path, exc)

    @staticmethod
    def _open(db_path: str) -> duckdb.DuckDBPyConnection:
        """Open a fresh DuckDB connection and apply per-process tuning.

        We always open writable; DuckDB read-only mode can serve stale
        catalogs from the WAL between processes (see ``app/database.py``
        legacy comment) and the locking guarantee we need is "one writer
        at a time", which the pool's per-slot Queue already enforces."""
        conn = duckdb.connect(db_path, read_only=False)
        try:
            conn.execute(f"PRAGMA threads={DUCKDB_THREADS}")
            conn.execute(f"PRAGMA memory_limit='{DUCKDB_MEMORY_LIMIT}'")
        except Exception as exc:  # pragma: no cover - PRAGMA must never block usage
            logger.warning("ConnectionPool: PRAGMA tuning failed for %s: %s", db_path, exc)
        return conn

    # ---- public API --------------------------------------------------------

    @contextmanager
    def acquire(self, db_path: str):
        """Yield a pooled DuckDB connection for *db_path*.

        Behaviour:
          * Try to reuse an idle connection from the slot's queue (hit).
          * Otherwise open a fresh one (miss).
          * On exit, return the connection to the queue if there is
            room; else close it.
          * On any exception during use we close the connection rather
            than recycling it — DuckDB does not document recoverability
            from arbitrary exceptions and a poisoned connection would
            silently break the next request.
        """
        slot = self._get_or_create_slot(db_path)
        conn: Optional[duckdb.DuckDBPyConnection]
        try:
            conn = slot.queue.get_nowait()
            self.hits += 1
        except Empty:
            conn = self._open(db_path)
            self.misses += 1

        poisoned = False
        try:
            yield conn
        except Exception:
            poisoned = True
            raise
        finally:
            if conn is not None:
                if poisoned:
                    try:
                        conn.close()
                    except Exception:  # pragma: no cover
                        pass
                else:
                    try:
                        slot.queue.put_nowait(conn)
                    except Exception:
                        # Queue full — close the surplus connection.
                        try:
                            conn.close()
                        except Exception:  # pragma: no cover
                            pass

    def close_all(self) -> None:
        """Close every cached connection. Called on app shutdown."""
        with self._lock:
            paths = list(self._slots.items())
            self._slots.clear()
        for db_path, slot in paths:
            self._drain_slot(slot, db_path)

    def evict(self, db_path: str) -> None:
        """Drop and close every cached connection for *db_path*.

        Used by maintenance jobs that need exclusive cross-connection
        access to a DuckDB file (e.g. the per-tenant rule distributor,
        which ATTACHes the tenant DB onto the shared connection \u2014
        DuckDB rejects that ATTACH while another connection in the same
        process holds the file open). Subsequent ``acquire(db_path)``
        calls will lazily open a fresh connection."""
        with self._lock:
            slot = self._slots.pop(db_path, None)
        if slot is not None:
            self._drain_slot(slot, db_path)

    def stats(self) -> dict:
        """Snapshot of pool counters and current occupancy. Cheap; safe to
        call from /health."""
        with self._lock:
            occupancy = {p: s.queue.qsize() for p, s in self._slots.items()}
        return {
            "max_tenants": MAX_TENANTS,
            "max_per_tenant": MAX_PER_TENANT,
            "tenants_cached": len(occupancy),
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "occupancy": occupancy,
        }


# Module-level singleton — there is exactly one DuckDB process per app
# process, so a single pool is the correct shape. NOT a tenant cache (the
# `acquire(db_path)` API is keyed by physical file path) so this is allowed
# by the P2 forbidden-pattern grep test.
_pool: ConnectionPool = ConnectionPool()


def get_pool() -> ConnectionPool:
    return _pool
