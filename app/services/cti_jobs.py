"""In-process async job registry for CTI sync triggers.

The pre-5.0.x ``POST /cti/{kind}/sync`` and
``POST /api/management/connectors/{id}/sync`` endpoints ran the vendor
fetcher synchronously inside the request handler. For a populous
OpenCTI tenant that meant the HTMX click held the worker thread for
minutes and the nginx upstream timeout would fire long before the
sync finished — operators saw a 502, the request thread kept running
to completion in the background, and there was no way to tell whether
the data had actually landed without refreshing the page and counting
rows. This module gives every sync trigger a job id, runs the work on
a background thread, and lets the HTMX badge poll
``GET /cti/sync/jobs/{job_id}`` for the terminal state.

Design notes
------------
* Pure in-process. TIDE runs a single uvicorn worker so a process-local
  dict is sufficient; a multi-worker deployment would need to swap
  this for a shared store (Redis, a DuckDB table) but that's out of
  scope until horizontal scaling is on the roadmap.
* Threading, not asyncio. The CTI sync endpoints are plain
  ``def`` handlers (FastAPI runs them in its thread pool) and the
  vendor fetchers themselves are synchronous, so a daemon
  :class:`threading.Thread` keeps the call-graph straight and avoids
  wrapping every fetcher in ``asyncio.to_thread``.
* The per-tenant CTI DuckDB connection pool already serialises writers
  per file, so two operator clicks that race against the same tenant
  queue cleanly instead of corrupting the database. Concurrent jobs
  against *different* tenants run in parallel.
* Retention. We keep the most recent :data:`_MAX_JOBS` jobs (default
  100) and evict the oldest terminal jobs first. Running jobs are
  never evicted.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections import OrderedDict
from datetime import datetime
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ── Public job status surface ────────────────────────────────────────

JOB_STATUS_PENDING = "pending"
JOB_STATUS_RUNNING = "running"
JOB_STATUS_SUCCESS = "success"
JOB_STATUS_FAILED = "failed"

_TERMINAL_STATES = {JOB_STATUS_SUCCESS, JOB_STATUS_FAILED}

_MAX_JOBS = 100

_LOCK = threading.Lock()
_JOBS: "OrderedDict[str, dict[str, Any]]" = OrderedDict()


def _now() -> datetime:
    # Naive UTC — matches every other timestamp in TIDE so comparisons
    # against ``cti_connectors.last_run_at`` etc. don't have to juggle
    # tz-aware values.
    return datetime.utcnow()


def submit(
    kind: str,
    runner: Callable[[], Any],
    *,
    label: str = "",
    client_id: Optional[str] = None,
    on_success: Optional[Callable[[Any], None]] = None,
) -> str:
    """Register and start a background CTI sync job.

    Parameters
    ----------
    kind:
        Short tag used by the status template to choose how to render
        the terminal badge (``"indicators"``, ``"actors"``,
        ``"reports"``, ``"connector"``).
    runner:
        Zero-arg callable that performs the work and returns the
        summary dict (or any object whose ``__repr__`` is reasonable —
        callers downcast in their own renderer).
    label:
        Human-facing identifier for the job (e.g. the connector label
        or tenant name) so the status fragment can name what's running.
    client_id:
        Optional. Lets a future ``/cti/sync/jobs?client=`` filter scope
        jobs to the active tenant.
    on_success:
        Optional callback invoked with the runner's return value when
        the job finishes without raising. Errors raised by the callback
        are swallowed and logged — they must not flip the job to
        ``failed`` because the work itself succeeded.

    Returns
    -------
    str
        The job id, suitable for ``/cti/sync/jobs/{id}``.
    """
    job_id = uuid.uuid4().hex
    job: dict[str, Any] = {
        "id": job_id,
        "kind": kind,
        "label": label,
        "client_id": client_id,
        "status": JOB_STATUS_PENDING,
        "created_at": _now(),
        "started_at": None,
        "finished_at": None,
        "summary": None,
        "error": None,
    }
    with _LOCK:
        _JOBS[job_id] = job
        _evict_locked()

    thread = threading.Thread(
        target=_run,
        args=(job_id, runner, on_success),
        name=f"cti-sync-{kind}-{job_id[:8]}",
        daemon=True,
    )
    thread.start()
    return job_id


def get(job_id: str) -> Optional[dict[str, Any]]:
    """Return a shallow copy of the job record, or ``None`` if unknown."""
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return None
        return dict(job)


def list_jobs(
    *,
    client_id: Optional[str] = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Return recent jobs, newest first. Optional ``client_id`` filter."""
    with _LOCK:
        out: list[dict[str, Any]] = []
        for job in reversed(_JOBS.values()):
            if client_id is not None and job.get("client_id") != client_id:
                continue
            out.append(dict(job))
            if len(out) >= limit:
                break
    return out


# ── Internals ────────────────────────────────────────────────────────


def _run(
    job_id: str,
    runner: Callable[[], Any],
    on_success: Optional[Callable[[Any], None]],
) -> None:
    """Background-thread entry point. Updates the registry in place."""
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return
        job["status"] = JOB_STATUS_RUNNING
        job["started_at"] = _now()

    try:
        result = runner()
    except Exception as exc:
        logger.exception("CTI sync job %s failed", job_id)
        with _LOCK:
            job = _JOBS.get(job_id)
            if job is not None:
                job["status"] = JOB_STATUS_FAILED
                job["error"] = str(exc)[:500]
                job["finished_at"] = _now()
        return

    with _LOCK:
        job = _JOBS.get(job_id)
        if job is not None:
            job["status"] = JOB_STATUS_SUCCESS
            job["summary"] = result
            job["finished_at"] = _now()

    if on_success is not None:
        try:
            on_success(result)
        except Exception:
            # Callback failure must not flip the job to ``failed`` —
            # the sync itself succeeded. Surface as a warning so the
            # operator can spot it in the logs.
            logger.warning(
                "CTI sync job %s on_success callback failed", job_id,
                exc_info=True,
            )


def _evict_locked() -> None:
    """Trim the registry to the last :data:`_MAX_JOBS`, never dropping
    a still-running job. Caller must hold :data:`_LOCK`.
    """
    if len(_JOBS) <= _MAX_JOBS:
        return
    # Walk oldest-first; drop terminal-state jobs until we're back in
    # bounds. Running jobs are kept regardless of age.
    for jid in list(_JOBS.keys()):
        if len(_JOBS) <= _MAX_JOBS:
            return
        if _JOBS[jid]["status"] in _TERMINAL_STATES:
            _JOBS.pop(jid, None)


def is_terminal(status: str) -> bool:
    return status in _TERMINAL_STATES


__all__ = [
    "submit",
    "get",
    "list_jobs",
    "is_terminal",
    "JOB_STATUS_PENDING",
    "JOB_STATUS_RUNNING",
    "JOB_STATUS_SUCCESS",
    "JOB_STATUS_FAILED",
]
