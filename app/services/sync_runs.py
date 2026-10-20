"""The record of every sync: when it ran, for which client, what it covered, and how it ended.

Rule syncs (main._start_sync_job / scheduled_sync) and CTI syncs (cti_jobs) both write here, to
``sync_history`` in the shared database (migrations 42 and 83), once when a run starts and once when
it ends. Live progress messages stay in memory with each tracker, so polling writes nothing.

States: running, success, partial (some destinations didn't answer), failed, and interrupted (still
running when TIDE stopped; marked once at startup by :func:`mark_interrupted`). Finished runs older
than :data:`RETENTION_DAYS` are removed whenever a run finishes; there is no timer.

Writes are best-effort: a sync never fails because its record couldn't be written.

Every start and end is also one structured log line (``event`` sync_run_start / sync_run_end) with
the run's id, client, kind, trigger, retry_of, status, count and error, the same error text the UI
shows, so a run on screen can be found in the log and the other way round.

A rule sync's steps after the rules are saved (history, clean-ups, rule origins, Rule Monitoring)
don't fail the sync, but each failure is noted (:func:`step_failed`) and kept on the run as
``detail.steps_failed``: Diagnostics → Sync activity shows it, and Rule Monitoring raises it (#85).
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

RETENTION_DAYS = 90
INTERRUPTED = "TIDE restarted while this sync was running. Nothing after the restart was synced."
FINISHED = ("success", "partial", "failed", "interrupted")

KIND_LABELS = {
    "rules": "Rule sync",
    "indicators": "CTI indicators",
    "actors": "CTI threat actors",
    "reports": "CTI reports",
    "connector": "CTI connector",
    "connector-auto": "CTI connector (scheduled)",
    "threat-sync": "Threat Landscape",
    "mitre": "Threat Landscape",
}

_COLUMNS = ("id", "sync_kind", "status", "started_at", "finished_at", "duration_ms", "total_count", "error",
            "client_id", "trigger", "actor", "label", "scope_json", "retry_of", "detail_json")

_steps_failed: Dict[str, List[Dict[str, str]]] = {}     # run id -> its failed steps, until it finishes
_steps_lock = threading.Lock()


def step_failed(step: str, error: Any) -> None:
    """Note that ``step`` (named as the user reads it) failed during the sync running in this
    context. The sync carries on; :func:`finish` keeps the note on the run. Outside a run, nothing
    is kept (the caller has logged it)."""
    from app.services.log_context import get_context
    run_id = (get_context() or {}).get("run_id")
    if not run_id or run_id == "-":
        return
    text = str(error).strip().splitlines()[0][:300] if str(error).strip() else type(error).__name__
    with _steps_lock:
        _steps_failed.setdefault(run_id, []).append({"step": step, "error": text})


def _pop_steps_failed(run_id: str) -> List[Dict[str, str]]:
    with _steps_lock:
        return _steps_failed.pop(run_id, [])


def _db():
    from app.services.database import get_database_service
    return get_database_service()


def start(kind: str, *, run_id: Optional[str] = None, client_id: Optional[str] = None, trigger: str = "manual",
          actor: Optional[str] = None, label: str = "", scope: Optional[Dict[str, Any]] = None,
          retry_of: Optional[str] = None) -> str:
    """Record a run that has just started. Returns its id (``run_id`` when given, so a tracker's job
    id and its record are the same id)."""
    run_id = run_id or uuid.uuid4().hex
    try:
        with _db().get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO sync_history (id, sync_kind, status, started_at, client_id, trigger, actor, label, "
                "scope_json, retry_of) VALUES (?, ?, 'running', now(), ?, ?, ?, ?, ?, ?)",
                [run_id, kind, client_id, trigger, actor, label or KIND_LABELS.get(kind, kind),
                 json.dumps(scope or {}, default=str), retry_of],
            )
    except Exception as exc:  # noqa: BLE001 - the record must never stop the sync
        logger.warning("Could not record the start of %s sync %s: %s", kind, run_id, exc)
    logger.info("Sync run %s started: %s", run_id, label or KIND_LABELS.get(kind, kind), extra={
        "event": "sync_run_start", "run_id": run_id, "client_id": client_id or "-", "sync_kind": kind,
        "trigger": trigger, "actor": actor, "retry_of": retry_of, "scope": scope or {}})
    return run_id


def _log_end(run_id: str, status: str, total: int = 0, error: Optional[str] = None) -> None:
    logger.log(logging.INFO if status == "success" else logging.WARNING,
               "Sync run %s ended: %s%s", run_id, status, f" ({error})" if error else "",
               extra={"event": "sync_run_end", "run_id": run_id, "sync_status": status, "total": int(total or 0),
                      "error": error})


def finish(run_id: str, status: str, *, total: int = 0, error: Optional[str] = None,
           detail: Optional[Dict[str, Any]] = None) -> None:
    """Record how a run ended, with any steps that failed during it, then drop finished runs older
    than the retention period."""
    if status not in FINISHED:
        status = "failed"
    failed = _pop_steps_failed(run_id)
    if failed:
        detail = {**(detail or {}), "steps_failed": failed}
    try:
        with _db().get_shared_connection() as conn:
            conn.execute(
                "UPDATE sync_history SET status = ?, finished_at = now(), "
                "duration_ms = CAST(date_diff('millisecond', started_at, now()) AS INTEGER), total_count = ?, "
                "error = ?, detail_json = ? WHERE id = ?",
                [status, int(total or 0), (str(error)[:2000] if error else None),
                 json.dumps(detail or {}, default=str)[:8000], run_id],
            )
            conn.execute(
                f"DELETE FROM sync_history WHERE status <> 'running' "
                f"AND started_at < now() - INTERVAL {int(RETENTION_DAYS)} DAY"
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not record the end of sync %s: %s", run_id, exc)
    _log_end(run_id, status, total, error)


def mark_interrupted() -> int:
    """At startup: a run still 'running' was cut off when TIDE stopped. Returns how many."""
    try:
        with _db().get_shared_connection() as conn:
            ids = [r[0] for r in conn.execute("SELECT id FROM sync_history WHERE status = 'running'").fetchall()]
            if ids:
                conn.execute(
                    "UPDATE sync_history SET status = 'interrupted', finished_at = now(), "
                    f"error = '{INTERRUPTED}' WHERE status = 'running'"
                )
                logger.warning("Marked %d sync run(s) interrupted: TIDE restarted while they ran", len(ids))
        for run_id in ids:
            _log_end(run_id, "interrupted", 0, INTERRUPTED)
        return len(ids)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not check for interrupted sync runs: %s", exc)
        return 0


def _row(r) -> Dict[str, Any]:
    d = dict(zip(_COLUMNS, r))
    for key in ("scope_json", "detail_json"):
        try:
            d[key[:-5]] = json.loads(d.pop(key) or "{}")
        except ValueError:
            d[key[:-5]] = {}
    d["kind_label"] = KIND_LABELS.get(d["sync_kind"], d["sync_kind"])
    d["retryable"] = d["sync_kind"] == "rules" and (d["status"] in ("failed", "partial", "interrupted")
                                                    or (d["status"] == "success" and bool(d["detail"].get("steps_failed"))))
    return d


def get(run_id: str) -> Optional[Dict[str, Any]]:
    with _db().get_shared_connection() as conn:
        r = conn.execute(f"SELECT {', '.join(_COLUMNS)} FROM sync_history WHERE id = ?", [run_id]).fetchone()
    return _row(r) if r else None


def recent(client_ids: Optional[List[str]] = None, *, kind: Optional[str] = None, limit: int = 50,
           include_unscoped: bool = False) -> List[Dict[str, Any]]:
    """Newest first. ``client_ids`` limits to those clients' runs (None: every run);
    ``include_unscoped`` adds runs with no client (a scheduled connector sync spans clients)."""
    where, params = [], []
    if client_ids is not None:
        if not client_ids and not include_unscoped:
            return []
        part = f"client_id IN ({', '.join('?' for _ in client_ids)})" if client_ids else "FALSE"
        where.append(f"({part}{' OR client_id IS NULL' if include_unscoped else ''})")
        params += list(client_ids)
    if kind:
        where.append("sync_kind = ?")
        params.append(kind)
    sql = (f"SELECT {', '.join(_COLUMNS)} FROM sync_history"
           f"{' WHERE ' + ' AND '.join(where) if where else ''} ORDER BY started_at DESC LIMIT ?")
    with _db().get_shared_connection() as conn:
        return [_row(r) for r in conn.execute(sql, params + [int(limit)]).fetchall()]


def last_rule_sync(client_id: str) -> Optional[Dict[str, Any]]:
    """The client's most recent rule sync, running or finished."""
    rows = recent([client_id], kind="rules", limit=1)
    return rows[0] if rows else None


def last_finished_rule_sync(client_id: str) -> Optional[Dict[str, Any]]:
    """The client's most recent rule sync that has finished, however it ended."""
    return next((r for r in recent([client_id], kind="rules", limit=10) if r["status"] != "running"), None)
