"""Background scheduler for CTI connector auto-sync.

This is the **only** sanctioned background ticker in TIDE
(AGENTS.md §2 carve-out, added 5.0.x with the connector-interval
feature). Every other surface remains operator-triggered. The
scheduler exists because CTI feeds are inherently delta-streamed —
operators want the per-tenant CTI database to reflect upstream
without remembering to click a button every hour.

Design notes
------------
* Single asyncio task started in the FastAPI lifespan handler in
  :mod:`app.main`. ``start()`` is idempotent; ``stop()`` cancels and
  joins cleanly on shutdown.
* Wakes on a fixed cadence (:data:`_TICK_SECONDS`) and asks the
  database which connectors are due. Due means
  ``is_active=TRUE``, a non-null ``sync_interval_minutes`` and
  ``COALESCE(last_sync_started_at, '1970-01-01') + interval``
  is in the past.
* Runs the actual sync through :mod:`app.services.cti_jobs` (same
  path the operator's click uses), so concurrent operator-triggered
  syncs and scheduler-triggered syncs go through the same job
  registry, status badge and connector-row update logic.
* No retry-with-backoff loop here. If a connector fails, the job
  registry records the failure and the next tick re-evaluates it
  exactly like any other due connector — same cadence, same
  rate-limit. Operators looking for a failed connector see the
  status pill on the connector card.
* No persistent claim. TIDE runs a single uvicorn worker; the in-
  process job registry already coalesces concurrent submits via the
  per-tenant write lock in the connection pool. A multi-worker
  deployment would need a database-backed claim row but that's out
  of scope until horizontal scaling is on the roadmap.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


# Tick cadence — how often the scheduler wakes to re-evaluate which
# connectors are due. 60 s keeps the math simple (intervals are
# specified in minutes) and means a connector configured for "every
# 15 minutes" fires within 60 s of its true due time.
_TICK_SECONDS = 60

_task: Optional[asyncio.Task] = None
_stop_event: Optional[asyncio.Event] = None


def start() -> None:
    """Start the scheduler task. Idempotent — safe to call repeatedly."""
    global _task, _stop_event
    if _task is not None and not _task.done():
        return
    _stop_event = asyncio.Event()
    _task = asyncio.create_task(_loop(_stop_event), name="cti-scheduler")
    logger.info("CTI connector auto-sync scheduler started (tick=%ds)",
                _TICK_SECONDS)


async def stop() -> None:
    """Signal the scheduler to stop and wait for it to exit cleanly."""
    global _task, _stop_event
    if _stop_event is not None:
        _stop_event.set()
    if _task is not None:
        try:
            await asyncio.wait_for(_task, timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("CTI scheduler did not exit within 5s; cancelling")
            _task.cancel()
            try:
                await _task
            except (asyncio.CancelledError, Exception):
                pass
    _task = None
    _stop_event = None


async def _loop(stop_event: asyncio.Event) -> None:
    """Main tick loop. Exits cleanly when ``stop_event`` is set."""
    # Stagger the first tick by a few seconds so the scheduler doesn't
    # fire while migrations are still bedding in. The lifespan handler
    # awaits them before starting us, but a few seconds of grace makes
    # local dev startup logs cleaner.
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=5.0)
        return  # stop requested during grace period
    except asyncio.TimeoutError:
        pass

    while not stop_event.is_set():
        try:
            await asyncio.to_thread(_tick_once)
        except Exception:
            # Never let a bad tick kill the scheduler — log and try
            # again next cycle. The job registry has its own per-job
            # error handling.
            logger.exception("CTI scheduler tick raised")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=_TICK_SECONDS)
        except asyncio.TimeoutError:
            continue


def _tick_once() -> None:
    """Single scheduler tick — find due connectors and submit jobs.

    Pure-sync function so it can run inside ``asyncio.to_thread``;
    the database calls and the job submit are both blocking.
    """
    from app.services.database import get_database_service
    from app.services.cti_connectors import get as get_vendor
    from app.services import cti_jobs
    from datetime import datetime as _dt

    db = get_database_service()
    try:
        connectors = db.list_cti_connectors(only_active=True) or []
    except Exception:
        logger.exception("CTI scheduler: list_cti_connectors failed")
        return

    now = _dt.utcnow()
    due: list[dict] = []
    for c in connectors:
        interval = c.get("sync_interval_minutes")
        if not interval or int(interval) <= 0:
            continue
        last = c.get("last_sync_started_at") or c.get("last_run_at")
        if last is None:
            due.append(c)
            continue
        try:
            next_due = last + timedelta(minutes=int(interval))
        except Exception:
            # last is some weird type the DuckDB driver returned —
            # treat as due so the scheduler self-heals.
            due.append(c)
            continue
        if next_due <= now:
            due.append(c)

    if not due:
        return

    logger.info("CTI scheduler: %d connector(s) due for auto-sync", len(due))

    for connector in due:
        connector_id = connector.get("id")
        if not connector_id:
            continue
        vendor = get_vendor(connector.get("vendor") or "")
        if vendor is None or vendor.fetcher is None:
            logger.warning(
                "CTI scheduler: skipping %s — vendor %r not registered",
                connector_id, connector.get("vendor"),
            )
            continue
        linked = db.get_cti_connector_clients(connector_id) or []
        if not linked:
            # No linked tenants; nothing to ingest into. Bump the
            # started timestamp so we don't re-evaluate this same
            # connector every tick.
            try:
                db.update_cti_connector(
                    connector_id, last_sync_started_at=now,
                )
            except Exception:
                pass
            continue

        # Stamp the started timestamp *before* submit so two ticks in
        # quick succession (e.g. on shutdown / restart races) don't
        # both consider this connector due.
        try:
            db.update_cti_connector(
                connector_id, last_sync_started_at=now,
            )
        except Exception:
            logger.warning(
                "CTI scheduler: could not stamp last_sync_started_at for %s",
                connector_id,
            )

        def _runner(_c=connector, _l=linked):
            return vendor.fetcher(_c, _l)

        def _on_success(result, _cid=connector_id):
            summary = (
                result.as_dict() if hasattr(result, "as_dict")
                else (result or {})
            )
            errors = summary.get("errors") or []
            tenants = summary.get("tenants", 0)
            new = summary.get("indicators_new", 0)
            merged = summary.get("indicators_merged", 0)
            badge_msg = (
                f"auto · {tenants} tenant(s) · "
                f"+{new} new / ~{merged} merged"
            )
            try:
                db.update_cti_connector(
                    _cid,
                    last_status="pass" if not errors else "fail",
                    last_message=badge_msg[:500],
                    last_run_at=_dt.utcnow(),
                )
            except Exception:
                logger.warning(
                    "CTI scheduler: could not persist auto-sync status for %s",
                    _cid,
                )

        cti_jobs.submit(
            kind="connector-auto",
            runner=_runner,
            label=connector.get("label") or connector.get("vendor") or connector_id,
            on_success=_on_success,
        )


__all__ = ["start", "stop"]
