"""The out-of-hours maintenance window (#82): Settings & Administration -> Management -> Maintenance
window. Opt-in (off by default), for super admins: on the days and at the time chosen, it runs, in
order and one client at a time:

  1. Sync: each client's destinations, as the Sync button does (skipping a client whose sync is
     already running). Each is a run in Diagnostics -> Sync activity, by "maintenance window".
  2. Back up: the backup Management -> Backups makes (it replaces the daily backup schedule while
     the window is on and runs this step).
  3. Reclaim space: a database file with RECLAIM_PCT of it or more empty (and at least
     RECLAIM_MIN_FILE big) is compacted. That needs the files closed, so the window announces a
     restart RESTART_NOTICE ahead: every signed-in page shows "TIDE will restart for scheduled
     maintenance" with Delay (DELAY each, up to MAX_DELAY in all; then Postpone to the next
     window). At the restart TIDE ends and Docker starts it again; at startup, before any
     database is opened, each file is compacted (app.scripts.compact_duckdb: copied, checked table
     by table, swapped in, the original kept beside it as <file>.pre-compact-<time>). A file whose
     copy doesn't check out is left as it was.

Decided 2026-10-20 (CLAUDE.md Hard Stop 6 (c)): the only scheduled sync is this opt-in window.
The schedule, the pending restart and the last run are JSON files in data/, so they can be read
whatever state the databases are in (as backups.py keeps its schedule).
"""
from __future__ import annotations

import contextlib
import glob
import io
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
DAY_NAMES = dict(zip(DAYS, ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")))
STEPS = (("sync", "Sync every client"), ("backup", "Back up"), ("reclaim", "Reclaim space"))
DEFAULT_SCHEDULE = {"enabled": False, "days": list(DAYS), "time": "02:00",
                    "steps": {"sync": True, "backup": True, "reclaim": True}}
RECLAIM_PCT = 30                          # a file this much empty space or more is compacted...
RECLAIM_MIN_FILE = 200 * 1024 * 1024      # ...when it is at least this big
RESTART_NOTICE = timedelta(minutes=15)    # how long signed-in pages are told before the restart
DELAY = timedelta(minutes=30)             # what Delay adds
MAX_DELAY = timedelta(hours=2)            # in all; after that, Postpone to the next window
STALE_RESTART = timedelta(hours=1)        # a restart TIDE missed by more than this is dropped
_TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")

_lock = threading.Lock()                  # one window at a time
_state_lock = threading.Lock()            # the pending restart's file


def _data_dir() -> Path:
    return Path(get_settings().data_dir)


def _read(name: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads((_data_dir() / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write(name: str, value: Optional[Dict[str, Any]]) -> None:
    path = _data_dir() / name
    if value is None:
        with contextlib.suppress(OSError):
            path.unlink()
        return
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


# ── the schedule ─────────────────────────────────────────────────────────────

def get_schedule() -> Dict[str, Any]:
    raw = _read("maintenance_schedule.json") or {}
    out = json.loads(json.dumps(DEFAULT_SCHEDULE))
    if isinstance(raw.get("enabled"), bool):
        out["enabled"] = raw["enabled"]
    if isinstance(raw.get("days"), list):
        out["days"] = [d for d in DAYS if d in raw["days"]]
    if isinstance(raw.get("time"), str) and _TIME.match(raw["time"]):
        out["time"] = raw["time"]
    if isinstance(raw.get("steps"), dict):
        out["steps"] = {k: bool(raw["steps"].get(k, v)) for k, v in out["steps"].items()}
    return out


def save_schedule(enabled: bool, days: List[str], time_of_day: str, steps: Dict[str, bool]) -> Dict[str, Any]:
    """Save the window; raises ValueError with a message for the form."""
    if not _TIME.match(time_of_day or ""):
        raise ValueError("Enter the start time as HH:MM, for example 02:00.")
    days = [d for d in DAYS if d in (days or [])]
    if enabled and not days:
        raise ValueError("Choose at least one day.")
    steps = {k: bool((steps or {}).get(k)) for k, _label in STEPS}
    if enabled and not any(steps.values()):
        raise ValueError("Choose at least one step.")
    schedule = {"enabled": bool(enabled), "days": days, "time": time_of_day, "steps": steps}
    _write("maintenance_schedule.json", schedule)
    return schedule


def takes_backup() -> bool:
    """Whether the window runs the backup, which then replaces the daily backup schedule."""
    s = get_schedule()
    return s["enabled"] and s["steps"]["backup"]


def summary(schedule: Optional[Dict[str, Any]] = None) -> str:
    """The window in words: "Every day at 02:00", "Saturday and Sunday at 03:30"."""
    s = schedule or get_schedule()
    days = s["days"]
    when = "Every day" if len(days) == 7 else ("Weekdays" if days == list(DAYS[:5]) else
                                               " and ".join(", ".join(DAY_NAMES[d] for d in days).rsplit(", ", 1)))
    return f"{when} at {s['time']}"


# ── what to reclaim ──────────────────────────────────────────────────────────

def measure(path: str, conn) -> Dict[str, Any]:
    """How much of a database file is empty space, from its open connection: ``{name, path, size,
    reclaim, pct}``, as Diagnostics works it out."""
    block, used, free = conn.execute(
        "SELECT block_size, used_blocks, free_blocks FROM pragma_database_size() "
        "WHERE database_name = current_database()").fetchone()
    size = os.path.getsize(path)
    reclaim = max(0, min(free * block, size - used * block))
    return {"name": os.path.basename(path), "path": str(path), "size": size, "reclaim": reclaim,
            "pct": reclaim * 100 // size if size else 0}


def worth_compacting(m: Dict[str, Any]) -> bool:
    return m["size"] >= RECLAIM_MIN_FILE and m["pct"] >= RECLAIM_PCT


# ── the pending restart (the notice every signed-in page shows) ─────────────

def pending() -> Optional[Dict[str, Any]]:
    """The announced restart: ``{files, restart_at, announced_at, delays: [{by, at}], requested}``."""
    state = _read("maintenance_restart.json")
    if not state:
        return None
    for key in ("restart_at", "announced_at"):
        state[key] = datetime.fromisoformat(state[key])
    return state


def announce(files: List[Dict[str, Any]], now: Optional[datetime] = None) -> Dict[str, Any]:
    """Announce the restart that compacts ``files`` (``measure``'s), RESTART_NOTICE from now."""
    now = now or datetime.now()
    state = {"files": files, "announced_at": now.isoformat(), "restart_at": (now + RESTART_NOTICE).isoformat(),
             "delays": [], "requested": False}
    with _state_lock:
        _write("maintenance_restart.json", state)
    return pending()


def notice(now: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
    """What the banner says while a restart is announced: ``{restart_at, minutes, can_delay}``."""
    state = pending()
    if not state or state.get("requested"):
        return None
    now = now or datetime.now()
    delayed = len(state["delays"]) * DELAY
    return {"restart_at": state["restart_at"], "minutes": max(0, int((state["restart_at"] - now).total_seconds() // 60)),
            "can_delay": delayed + DELAY <= MAX_DELAY, "delays": state["delays"]}


def delay(by: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Delay the restart by DELAY, up to MAX_DELAY in all; past that, postpone the reclaim to the
    next window. ``{"ok", "message", "restart_at"}``; the caller reschedules the restart."""
    now = now or datetime.now()
    with _state_lock:
        state = pending()
        if not state or state.get("requested"):
            return {"ok": False, "message": "No restart is waiting."}
        if (len(state["delays"]) + 1) * DELAY > MAX_DELAY:
            _write("maintenance_restart.json", None)
            _record_reclaim("postponed", f"Postponed to the next window by {by}.")
            return {"ok": True, "message": "Postponed to the next maintenance window.", "restart_at": None}
        state["delays"].append({"by": by, "at": now.isoformat()})
        state["restart_at"] = state["restart_at"] + DELAY
        _write("maintenance_restart.json", {**state, "restart_at": state["restart_at"].isoformat(),
                                            "announced_at": state["announced_at"].isoformat()})
    _record_reclaim("waiting", f"Restart delayed to {state['restart_at']:%H:%M} by {by}.")
    return {"ok": True, "message": f"Restart delayed to {state['restart_at']:%H:%M}.", "restart_at": state["restart_at"]}


def postpone(by: str) -> None:
    """Drop the announced restart: the next window measures the files again."""
    with _state_lock:
        if pending():
            _write("maintenance_restart.json", None)
            _record_reclaim("postponed", f"Postponed to the next window by {by}.")


def request_restart(restart: Callable[[], None]) -> bool:
    """At the restart time: mark the restart as the maintenance window's, so startup compacts, then
    end TIDE (``restart``: Docker starts it again). False when nothing is waiting."""
    with _state_lock:
        state = pending()
        if not state:
            return False
        _write("maintenance_restart.json", {**state, "requested": True, "restart_at": state["restart_at"].isoformat(),
                                            "announced_at": state["announced_at"].isoformat()})
    _record_reclaim("restarting", "Restarting TIDE to compact the files.")
    logger.warning("Maintenance window: restarting TIDE to compact %d database file(s)", len(state["files"]))
    restart()
    return True


# ── at startup ───────────────────────────────────────────────────────────────

def reclaim_at_startup(compact: Optional[Callable[[str, bool], int]] = None, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Before any database is opened: compact the files of a restart the window requested, keeping
    each original as <file>.pre-compact-<time> (only the newest such copy of a file is kept). A file
    whose copy doesn't check out is left as it was. A restart TIDE missed by more than STALE_RESTART
    (it was restarted for something else, and not at the time) is dropped. Returns what was done."""
    state = pending()
    if not state:
        return []
    now = now or datetime.now()
    if not state.get("requested"):
        if now - state["restart_at"] > STALE_RESTART:
            _write("maintenance_restart.json", None)
            _record_reclaim("postponed", "TIDE was restarted before the maintenance restart; postponed to the next window.")
        return []
    if compact is None:
        from app.scripts.compact_duckdb import compact as compact_file
        compact = compact_file
    done = []
    for f in state["files"]:
        path = f["path"]
        before = os.path.getsize(path) if os.path.exists(path) else 0
        out = io.StringIO()
        started = time.time()
        try:
            with contextlib.redirect_stdout(out):
                code = compact(path, True)
        except Exception as exc:          # noqa: BLE001 - the file is left as it was; TIDE starts
            code, out = 1, io.StringIO(f"{type(exc).__name__}: {exc}")
        after = os.path.getsize(path) if os.path.exists(path) else 0
        ok = code == 0
        if ok:
            _keep_newest_original(path)
        done.append({"name": f["name"], "ok": ok, "before": before, "after": after if ok else before,
                     "seconds": round(time.time() - started), "note": "" if ok else out.getvalue().strip()[-300:]})
        logger.info("Maintenance window: compacted %s: %s", f["name"], "ok" if ok else out.getvalue().strip()[-300:])
    _write("maintenance_restart.json", None)
    _record_reclaim("done" if all(d["ok"] for d in done) else "failed",
                    "Compacted at the restart." if all(d["ok"] for d in done) else "A file's copy didn't check out: left as it was.",
                    files=done)
    return done


def _keep_newest_original(path: str) -> None:
    """Keep only the newest <file>.pre-compact-<time> (and its WAL) beside a file."""
    olds = sorted(p for p in glob.glob(f"{glob.escape(path)}.pre-compact-*") if not p.endswith(".wal"))
    for old in olds[:-1]:
        for p in (old, old + ".wal"):
            with contextlib.suppress(OSError):
                os.remove(p)


def stale_restart(now: Optional[datetime] = None) -> Optional[datetime]:
    """After startup: when the announced restart is due (to schedule it again), or None."""
    state = pending()
    if not state or state.get("requested"):
        return None
    return max(state["restart_at"], (now or datetime.now()) + timedelta(minutes=1))


# ── a run ────────────────────────────────────────────────────────────────────

def last_run() -> Optional[Dict[str, Any]]:
    return _read("maintenance_status.json")


def running() -> bool:
    return _lock.locked()


def _record(run: Dict[str, Any]) -> None:
    try:
        _write("maintenance_status.json", run)
    except OSError:
        logger.warning("Could not record the maintenance window's run", exc_info=True)


def _record_reclaim(status: str, note: str, files: Optional[List[Dict[str, Any]]] = None) -> None:
    """The last run's Reclaim space step, as the restart moves on."""
    run = last_run() or {"started": datetime.now().isoformat(), "steps": []}
    step = next((s for s in run["steps"] if s["step"] == "reclaim"), None)
    if step is None:
        step = {"step": "reclaim", "status": status, "detail": note, "files": []}
        run["steps"].append(step)
    step.update(status=status, detail=note, at=datetime.now().isoformat())
    if files is not None:
        step["files"] = files
    _record(run)


async def run(db, *, trigger: str, by: str,
              clients: Callable[[], List[Dict[str, Any]]],
              sync_running: Callable[[str], bool],
              sync_client: Callable[[str], Awaitable[Dict[str, Any]]],
              backup: Callable[[], Awaitable[Dict[str, Any]]],
              measure_files: Callable[[], Awaitable[List[Dict[str, Any]]]],
              schedule_restart: Callable[[datetime], None],
              steps: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
    """Run the window's steps in order (``steps``, else the schedule's): each client's sync, one
    after another (a client already syncing skipped; one failing doesn't stop the others), the
    backup, then the files worth compacting and the announced restart. Recorded step by step
    (``last_run``). Returns the run; skipped (``{"skipped": ...}``) when a window is already running."""
    if not _lock.acquire(blocking=False):
        logger.warning("Maintenance window skipped: one is already running")
        return {"skipped": "Another maintenance window was still running."}
    try:
        steps = steps or get_schedule()["steps"]
        result: Dict[str, Any] = {"started": datetime.now().isoformat(), "trigger": trigger, "by": by, "steps": []}
        _record(result)
        from app.services.log_context import audit_log
        audit_log("maintenance_window", trigger=trigger, actor_username=by, steps=[k for k, v in steps.items() if v])
        if steps.get("sync"):
            for client in clients():
                entry = {"step": "sync", "client": client["name"], "started": datetime.now().isoformat()}
                if sync_running(client["id"]):
                    entry.update(status="skipped", detail="A sync was already running.")
                else:
                    try:
                        got = await sync_client(client["id"])
                        entry.update(status=got.get("status", "success"), detail=got.get("detail", ""))
                    except Exception as exc:        # noqa: BLE001 - the next client still syncs
                        logger.warning("Maintenance window: sync of %s failed", client["name"], exc_info=True)
                        entry.update(status="failed", detail=f"{type(exc).__name__}: {exc}")
                result["steps"].append(entry)
                _record(result)
        if steps.get("backup"):
            entry = {"step": "backup", "started": datetime.now().isoformat()}
            try:
                got = await backup()
                entry.update(status="success" if got.get("ok") else "failed",
                             detail=got.get("name", "") if got.get("ok") else got.get("error", ""))
            except Exception as exc:                # noqa: BLE001
                logger.warning("Maintenance window: backup failed", exc_info=True)
                entry.update(status="failed", detail=f"{type(exc).__name__}: {exc}")
            result["steps"].append(entry)
            _record(result)
        if steps.get("reclaim"):
            entry: Dict[str, Any] = {"step": "reclaim", "started": datetime.now().isoformat(), "files": []}
            try:
                measured = await measure_files()
                worth = [m for m in measured if worth_compacting(m)]
                entry["measured"] = measured
                if not worth:
                    entry.update(status="success", detail=f"No file is {RECLAIM_PCT}% empty space or more.")
                elif pending():
                    entry.update(status="waiting", detail="A restart is already announced.")
                else:
                    state = announce(worth)
                    schedule_restart(state["restart_at"])
                    entry.update(status="waiting", files=[{"name": m["name"], "before": m["size"], "reclaim": m["reclaim"]} for m in worth],
                                 detail=f"Restart announced for {state['restart_at']:%H:%M} to compact "
                                        f"{len(worth)} file{'s' if len(worth) != 1 else ''}.")
            except Exception as exc:                # noqa: BLE001
                logger.warning("Maintenance window: could not measure the database files", exc_info=True)
                entry.update(status="failed", detail=f"{type(exc).__name__}: {exc}")
            result["steps"].append(entry)
        result["ended"] = datetime.now().isoformat()
        _record(result)
        return result
    finally:
        _lock.release()
