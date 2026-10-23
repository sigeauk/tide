"""Backups of everything TIDE keeps: Settings & Administration -> Management -> Backups.

A backup is one folder, tide-backup-<YYYYMMDD-HHMMSS>-v<version>/ (when, then the TIDE version
that made it; backups made before 6.2.3 have the version only in their manifest), in BACKUP_DIR
(the host folder BACKUP_PATH names in docker-compose.yml). It holds a fresh copy of the shared
database and of each client's database, credentials.key (without it the stored SIEM and
connector credentials can't be read), the Sigma pipelines and templates, and manifest.json (with
the TIDE version). Each database is copied with
DuckDB's COPY FROM DATABASE through TIDE's own connection, inside one transaction: a consistent
copy while TIDE is in use, holding only live data, so a backup is a fraction of data/'s size (a
database file never shrinks) and restoring one also compacts. The folder is written under a
.partial name and renamed when complete, so a listed backup is always whole.

Restoring is copying a backup's files back into data/ with TIDE stopped (restore_steps()), into the
TIDE version that made the backup or a newer one.

The schedule (on, time, how many to keep) is in data/backup_schedule.json rather than a database,
so it can be read whatever state the databases are in. app.main schedules the daily run
(_schedule_backup_job, CLAUDE.md Hard Stop 6); "Back up now" starts one in a background thread.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)

BACKUP_DIR = Path(os.environ.get("TIDE_BACKUP_DIR", "/app/backups"))
PREFIX = "tide-backup-"
DEFAULT_SCHEDULE = {"enabled": False, "time": "02:00", "keep": 7}
KEEP_RANGE = (1, 90)
_TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]*$")   # a version safe in a folder name and a shell command

_lock = threading.Lock()
_running: Dict[str, object] = {}          # {"started": datetime, "trigger": str, "by": str} while one runs


def _data_dir() -> Path:
    return Path(get_settings().data_dir)


# ── schedule ─────────────────────────────────────────────────────────────────

def _schedule_file() -> Path:
    return _data_dir() / "backup_schedule.json"


def get_schedule() -> Dict:
    try:
        raw = json.loads(_schedule_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = {}
    out = dict(DEFAULT_SCHEDULE)
    out.update({k: raw[k] for k in DEFAULT_SCHEDULE if k in raw})
    return out


def save_schedule(enabled: bool, time_of_day: str, keep: int) -> Dict:
    """Save the schedule; raises ValueError with a message for the form."""
    if not _TIME.match(time_of_day or ""):
        raise ValueError("Enter the time as HH:MM, for example 02:00.")
    if not KEEP_RANGE[0] <= keep <= KEEP_RANGE[1]:
        raise ValueError(f"Keep between {KEEP_RANGE[0]} and {KEEP_RANGE[1]} backups.")
    schedule = {"enabled": bool(enabled), "time": time_of_day, "keep": keep}
    _schedule_file().write_text(json.dumps(schedule, indent=2), encoding="utf-8")
    return schedule


# ── where backups go ─────────────────────────────────────────────────────────

def folder_is_mapped() -> bool:
    """Whether BACKUP_DIR is a mount from the host. If it isn't, backups live only inside the
    container and are lost when it is recreated. (os.path.ismount can't tell for a bind mount
    from the same host disk, so read the mount table.)"""
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as f:
            return any(line.split()[4] == str(BACKUP_DIR) for line in f if len(line.split()) > 4)
    except OSError:
        return False


def disk() -> Optional[Dict]:
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        usage = shutil.disk_usage(BACKUP_DIR)
        return {"free": usage.free, "total": usage.total}
    except OSError:
        return None


# ── what is backed up ────────────────────────────────────────────────────────

def _databases(db) -> List[Dict]:
    """The shared database and each client's database that exists: ``{name, path, client}``."""
    from app.services.tenant_manager import resolve_tenant_db_path
    data = _data_dir()
    out = [{"name": "tide.duckdb", "path": Path(get_settings().db_path), "client": None}]
    for c in sorted(db.list_clients(), key=lambda c: (c.get("name") or "").lower()):
        path = resolve_tenant_db_path(c["id"], str(data))
        if path and os.path.exists(path):
            out.append({"name": os.path.basename(path), "path": Path(path), "client": c["name"]})
    return out


def _copy_database(source: Path, target: Path) -> None:
    """A consistent copy of ``source`` into a new file ``target``, holding only live data."""
    from app.services.connection_pool import get_pool
    alias = f"tide_backup_{int(time.time() * 1000) % 10**9}"
    with get_pool().acquire(str(source)) as conn:
        name = conn.execute("SELECT current_database()").fetchone()[0]
        conn.execute(f"ATTACH '{str(target).replace(chr(39), chr(39) * 2)}' AS {alias}")
        try:
            conn.execute(f'COPY FROM DATABASE "{name}" TO {alias}')
        finally:
            conn.execute(f"DETACH {alias}")


# ── running one ──────────────────────────────────────────────────────────────

def running() -> Optional[Dict]:
    return dict(_running) if _running else None


def start(db, trigger: str, by: str) -> bool:
    """Start a backup in a background thread. False if one is already running."""
    if not _lock.acquire(blocking=False):
        return False
    _running.update(started=datetime.now(), trigger=trigger, by=by)
    threading.Thread(target=_run_locked, args=(db, trigger, by), name="tide-backup", daemon=True).start()
    return True


def run_now(db, trigger: str, by: str) -> Dict:
    """Run a backup in this thread (the scheduled job). Skipped if one is already running."""
    if not _lock.acquire(blocking=False):
        logger.warning("Backup skipped: another backup is still running")
        return {"ok": False, "error": "Another backup was still running."}
    _running.update(started=datetime.now(), trigger=trigger, by=by)
    return _run_locked(db, trigger, by)


def _run_locked(db, trigger: str, by: str) -> Dict:
    try:
        return _run(db, trigger, by)
    finally:
        _running.clear()
        _lock.release()


def backup_name(started: datetime, version: str) -> str:
    """``tide-backup-<YYYYMMDD-HHMMSS>-v<version>``: when, then the TIDE version that made it.
    Characters a folder name can't hold become '-'."""
    safe = re.sub(r"[^0-9A-Za-z._-]+", "-", version or "").strip("-.") or "unknown"
    return f"{PREFIX}{started.strftime('%Y%m%d-%H%M%S')}-v{safe}"


def _run(db, trigger: str, by: str) -> Dict:
    from app.services.log_context import audit_log
    started = datetime.now()
    name = backup_name(started, get_settings().tide_version)
    partial = BACKUP_DIR / (name + ".partial")
    result: Dict = {"name": name, "trigger": trigger, "by": by, "at": started.isoformat(timespec="seconds")}
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        need = max((b["size"] for b in list_backups()[:1]), default=0) * 2 or 512 * 1024 * 1024
        free = shutil.disk_usage(BACKUP_DIR).free
        if free < need:
            raise RuntimeError(f"Not enough free space for a backup: {_size(free)} free, "
                               f"about {_size(need)} needed. Free some space, or keep fewer backups.")
        shutil.rmtree(partial, ignore_errors=True)
        partial.mkdir(parents=True)
        files = []
        for d in _databases(db):
            t0 = time.time()
            _copy_database(d["path"], partial / d["name"])
            files.append({"file": d["name"], "client": d["client"], "size": (partial / d["name"]).stat().st_size,
                          "seconds": round(time.time() - t0, 1)})
        data = _data_dir()
        key = data / "credentials.key"
        if key.exists():
            shutil.copy2(key, partial / key.name)
            files.append({"file": key.name, "client": None, "size": key.stat().st_size})
        for folder in ("sigma_pipelines", "sigma_templates"):
            if (data / folder).is_dir():
                shutil.copytree(data / folder, partial / folder)
        settings = get_settings()
        manifest = {"tide_version": settings.tide_version, "created": result["at"], "trigger": trigger, "by": by,
                    "seconds": round((datetime.now() - started).total_seconds(), 1), "files": files}
        (partial / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        partial.rename(BACKUP_DIR / name)
        result.update(ok=True, size=_folder_size(BACKUP_DIR / name), seconds=manifest["seconds"])
        removed = prune(get_schedule()["keep"])
        logger.info("Backup %s done: %s in %.1fs (%d files); removed %d old backup(s)",
                    name, _size(result["size"]), result["seconds"], len(files), len(removed))
        audit_log("backup", actor_username=by, trigger=trigger, backup=name, size=result["size"], removed=removed)
    except Exception as exc:
        shutil.rmtree(partial, ignore_errors=True)
        result.update(ok=False, error=str(exc) or exc.__class__.__name__)
        logger.error("Backup %s failed: %s", name, result["error"], exc_info=True)
        audit_log("backup_failed", actor_username=by, trigger=trigger, error=result["error"])
    _write_status(result)
    return result


def prune(keep: int) -> List[str]:
    """Delete complete backups beyond the newest ``keep``, and any left half-written."""
    removed = []
    for b in list_backups()[keep:]:
        shutil.rmtree(BACKUP_DIR / b["name"], ignore_errors=True)
        removed.append(b["name"])
    if BACKUP_DIR.is_dir() and not running():
        for p in BACKUP_DIR.glob(PREFIX + "*.partial"):
            shutil.rmtree(p, ignore_errors=True)
    return removed


# ── what there is ────────────────────────────────────────────────────────────

def list_backups() -> List[Dict]:
    """Complete backups, newest first: ``{name, created, trigger, by, size, clients, tide_version}``."""
    out = []
    if not BACKUP_DIR.is_dir():
        return out
    for p in BACKUP_DIR.iterdir():
        if not (p.is_dir() and p.name.startswith(PREFIX) and not p.name.endswith(".partial")):
            continue
        try:
            m = json.loads((p / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append({"name": p.name, "created": datetime.fromisoformat(m["created"]), "trigger": m.get("trigger"),
                    "by": m.get("by"), "size": _folder_size(p), "tide_version": m.get("tide_version"),
                    "clients": len({f["client"] for f in m.get("files", []) if f.get("client")})})
    return sorted(out, key=lambda b: b["created"], reverse=True)


def _status_file() -> Path:
    return _data_dir() / "backup_status.json"


def _write_status(result: Dict) -> None:
    try:
        _status_file().write_text(json.dumps(result, indent=2), encoding="utf-8")
    except OSError:
        logger.warning("Could not record the backup result", exc_info=True)


def last_result() -> Optional[Dict]:
    try:
        r = json.loads(_status_file().read_text(encoding="utf-8"))
        r["at"] = datetime.fromisoformat(r["at"])
        return r
    except (OSError, ValueError, KeyError):
        return None


def host_folder() -> str:
    """The backups folder as the host sees it: BACKUP_PATH from .env, else backups/ beside
    docker-compose.yml."""
    return (os.environ.get("BACKUP_PATH") or "").rstrip("/") or "backups"


def _version_key(version: str) -> Optional[tuple]:
    """``6.2.10`` as (6, 2, 10), to compare; None for a version that isn't numbers and dots."""
    return tuple(int(p) for p in version.split(".")) if re.fullmatch(r"\d+(\.\d+)*", version or "") else None


def version_relation(version: Optional[str]) -> str:
    """How the TIDE version that made a backup compares with the one running: ``same``, ``older``,
    ``newer``, or ``unknown`` (not recorded, or not a plain version number)."""
    running = get_settings().tide_version
    if version and version == running:
        return "same"
    made, now = _version_key(version), _version_key(running)
    if made is None or now is None:
        return "unknown"
    return "older" if made < now else "newer" if made > now else "same"


def restore_steps(name: str = "<backup>", version: Optional[str] = None) -> List[str]:
    """The commands that restore backup ``name``, run on the host in TIDE's folder. The current
    databases are moved aside to a folder named for the moment, not deleted, so running them
    twice never overwrites what the first run set aside. A backup can go back into the TIDE
    version that made it (``version``, from its manifest) or a newer one, which upgrades it as it
    starts, never an older one. So for a backup made by another version there is a line setting
    TIDE_VERSION in .env to it: needed for a backup from a newer TIDE than this one, and for one
    from an older TIDE only to go back to that version. ``up -d`` then starts whichever version
    .env names."""
    relation = version_relation(version)
    steps = ["docker compose stop tide-app"]
    if version and relation != "same":
        target = version if _VERSION.match(version) else "<version>"
        line = f"sed -i 's/^TIDE_VERSION=.*/TIDE_VERSION={target}/' .env"
        if relation == "older":
            running = get_settings().tide_version
            line += (f"  # only to go back to {target}; leave this line out to stay on "
                     f"{running if _VERSION.match(running) else 'this version'}")
        steps.append(line)
    steps += [
        'old=data-before-restore-$(date +%Y%m%d-%H%M%S) && mkdir "$old" && mv data/*.duckdb* data/credentials.key "$old"/',
        f"cp -a {host_folder()}/{name}/. data/ && rm data/manifest.json",
        "docker compose up -d tide-app",
    ]
    return steps


def _folder_size(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def _size(n: float) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit in ("bytes", "KB") else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} GB"


size = _size
