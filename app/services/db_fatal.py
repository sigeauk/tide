"""What TIDE does after a DuckDB fatal error (#84).

DuckDB answers some failures (an index missing rows, a commit it can't undo) with a FATAL or
INTERNAL error, and then invalidates that database for the rest of the process: every later query
on the file fails with "database has been invalidated ... must be restarted". Left alone, every
request for that client fails until someone restarts TIDE.

So TIDE restarts itself. The error is recorded in data/last_fatal.json and the process ends; Docker
(``restart: unless-stopped``) starts it again, and startup rebuilds the rule history indexes, the
cause found so far (DatabaseService.rebuild_history_indexes). Syncs that were running are marked
interrupted, as after any restart.

A second fatal error on the same file within GUARD of a restart for it doesn't restart TIDE again,
since a loop would only take every client down with it: that file is left unavailable (its client's
pages fail, saying why), the other clients keep working, and Diagnostics shows it.

Only the app server restarts: app.main calls ``enable_restart`` at startup. A script or test that
meets a fatal error on its own database just gets the error.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

import duckdb

logger = logging.getLogger(__name__)

GUARD = timedelta(minutes=10)
HARD_EXIT_AFTER = 30        # seconds a graceful stop may take before the process is ended outright
RECORD = "last_fatal.json"

_lock = threading.Lock()
_restart_enabled = False
_restarting = False
_unavailable: Dict[str, Dict[str, Any]] = {}     # db path -> its record: files left unavailable


class DatabaseUnavailable(RuntimeError):
    """A database stopped after a DuckDB fatal error, and TIDE had already restarted once for it."""


def enable_restart() -> None:
    """Let a fatal error restart TIDE (the app server only; see the module docstring)."""
    global _restart_enabled
    _restart_enabled = True


def is_fatal(exc: BaseException) -> bool:
    return (isinstance(exc, (duckdb.FatalException, duckdb.InternalException))
            or "database has been invalidated" in str(exc))


def _record_path() -> Path:
    from app.config import get_settings
    return Path(get_settings().data_dir) / RECORD


def last() -> Optional[Dict[str, Any]]:
    """The last fatal error recorded: ``{at, db, error, restarted}``, or None."""
    try:
        return json.loads(_record_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def unavailable() -> Dict[str, Dict[str, Any]]:
    """The database files left unavailable in this process, with their records."""
    return dict(_unavailable)


def check_available(db_path: str) -> None:
    """Refuse a database left unavailable, saying why, rather than failing on DuckDB's own error."""
    record = _unavailable.get(db_path)
    if record:
        raise DatabaseUnavailable(
            f"{os.path.basename(db_path)} stopped after a DuckDB fatal error at {record['at']}, and TIDE had "
            f"already restarted for it {int(GUARD.total_seconds() // 60)} minutes before, so it isn't "
            f"restarting again. Restart TIDE; Settings → Diagnostics shows the error.")


def _summary(exc: BaseException) -> str:
    text = str(exc).strip()
    marker = '"exception_message":"'
    if marker in text:          # DuckDB's JSON form: keep the message, not the stack trace
        text = text.split(marker, 1)[1].split("\\n", 1)[0]
    return (text.splitlines()[0] if text else type(exc).__name__)[:500]


def _recent(at: Optional[str], now: datetime, span: timedelta = GUARD) -> bool:
    try:
        return now - datetime.fromisoformat(at or "") < span
    except ValueError:
        return False


def handle(db_path: str, exc: BaseException) -> None:
    """Called where a query on ``db_path`` raised ``exc``. Does nothing unless it is a fatal error
    and this is the app server; then restarts TIDE, or leaves the file unavailable (see above)."""
    global _restarting
    if not _restart_enabled or not is_fatal(exc):
        return
    with _lock:
        if _restarting or db_path in _unavailable:
            return
        now = datetime.now()
        previous = last()
        looping = bool(previous and previous.get("db") == db_path and previous.get("restarted")
                       and _recent(previous.get("at"), now))
        record = {"at": now.isoformat(timespec="seconds"), "db": db_path, "error": _summary(exc),
                  "restarted": not looping}
        try:
            _record_path().write_text(json.dumps(record, indent=2), encoding="utf-8")
        except OSError:
            logger.warning("Could not record the DuckDB fatal error in %s", _record_path(), exc_info=True)
        if looping:
            _unavailable[db_path] = record
        else:
            _restarting = True
    from app.services.log_context import error_log
    if looping:
        error_log(f"DuckDB fatal error on {db_path} again within {GUARD} of a restart for it: not restarting; "
                  f"the file is unavailable until TIDE restarts", exc=exc, event="db_fatal", db=db_path)
        return
    error_log(f"DuckDB fatal error on {db_path}: restarting TIDE so the database is opened afresh",
              exc=exc, event="db_fatal", db=db_path)
    _restart()


def _restart() -> None:
    """End TIDE so Docker starts it again: a graceful stop first (SIGTERM to the server, process 1 in
    TIDE's container: uvicorn, or its reloader in development), then a hard exit if that hasn't
    finished within HARD_EXIT_AFTER seconds (a sync's worker thread would otherwise hold it open)."""
    def hard_exit():
        time.sleep(HARD_EXIT_AFTER)
        os._exit(70)
    threading.Thread(target=hard_exit, name="tide-fatal-exit", daemon=True).start()
    try:
        os.kill(1 if _server_is_pid1() else os.getpid(), signal.SIGTERM)
    except OSError:
        os._exit(70)


def _server_is_pid1() -> bool:
    try:
        return b"uvicorn" in Path("/proc/1/cmdline").read_bytes()
    except OSError:
        return False


def note_startup() -> None:
    """At startup: say so when the last start followed a fatal error (within the hour)."""
    record = last()
    if record and record.get("restarted") and _recent(record.get("at"), datetime.now(), timedelta(hours=1)):
        logger.warning("TIDE restarted after a DuckDB fatal error on %s at %s: %s",
                       record.get("db"), record.get("at"), record.get("error"))
