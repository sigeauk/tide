"""Deleting a client and its data (#64), and database files no client owns (Diagnostics).

A client's data is its rows in TIDE's own database (``DatabaseService.CLIENT_TABLES``) and its files in
the data folder: its database ``<slug>_<id8>.duckdb`` and ``.wal``, the copy the maintenance window
keeps beside it when it compacts it (``<file>.pre-compact-<time>``, and its ``.wal``), and the copies
Diagnostics fixes take first (``diagnostics-backups/<stem>_<time>.duckdb``, and ``.wal``).

Deleting a client, by a super admin who types its name:
  1. refused for the default client, while a sync of it or the maintenance window runs, or when the
     name typed isn't the client's (nothing changes);
  2. its rows go in one transaction, so no request can reach the client from then on;
  3. its database leaves the tenant cache and its pooled connections are closed, so nothing reopens
     (and so recreates) the file;
  4. its files are deleted; one that can't be is named, and Diagnostics' check lists it;
  5. it is recorded in the audit log, with the files removed.

Diagnostics' ``orphaned_db_files`` lists the database files that belong to no client (left by a client
deleted before 6.4.0, a file that couldn't be deleted, or a CTI database from before 6.3.0), and a super
admin can delete them, typing ``delete_orphan_files``. Neither ever touches TIDE's own database, its
credentials key, or a file a client owns.
"""
from __future__ import annotations

import glob
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set

logger = logging.getLogger(__name__)

CONFIRM_ORPHANS = "delete_orphan_files"
FIX_BACKUPS = "diagnostics-backups"
# diagnostic_fixes names a backup <stem>_<UTC time to the microsecond>Z.duckdb (and .wal).
_BACKUP_TIME = r"_\d{8}T\d{12}Z\.duckdb(\.wal)?"


class DeleteRefused(Exception):
    """A deletion that must not happen (nothing was changed)."""


class ClientNotFound(Exception):
    """No client has that id (nothing was changed)."""


def _stem(db_filename: str) -> str:
    """The name diagnostic_fixes gives a database's backups (its file name, made safe)."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", db_filename.rsplit(".", 1)[0])


def files_of(data_dir: str, db_filename: str) -> List[str]:
    """Every file in the data folder that holds this database: itself, its WAL, the maintenance
    window's kept original (and its WAL), and Diagnostics fixes' backups of it. Only those that exist."""
    if not db_filename:
        return []
    base = os.path.join(data_dir, db_filename)
    found = [base, base + ".wal", *sorted(glob.glob(glob.escape(base) + ".pre-compact-*"))]
    backups = os.path.join(data_dir, FIX_BACKUPS)
    pattern = re.compile(re.escape(_stem(db_filename)) + _BACKUP_TIME + "$")
    if os.path.isdir(backups):
        found += sorted(os.path.join(backups, f) for f in os.listdir(backups) if pattern.match(f))
    return [p for p in found if os.path.isfile(p)]


def _size(paths: Iterable[str]) -> int:
    total = 0
    for p in paths:
        try:
            total += os.path.getsize(p)
        except OSError:
            pass
    return total


def size_text(n: int) -> str:
    """Bytes as people read them: 512 bytes, 12.3 MB, 1.5 GB."""
    for unit, scale in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= scale:
            return f"{n / scale:.1f} {unit}"
    return f"{n} bytes"


def _settings():
    from app.config import get_settings
    return get_settings()


def _close(path: str) -> None:
    """Close every pooled connection to a database file, so it can be deleted and isn't reopened."""
    from app.services.connection_pool import get_pool
    for p in {path, os.path.realpath(path)}:
        try:
            get_pool().evict(p)
        except Exception:
            logger.warning("Could not close the pooled connections to %s", p, exc_info=True)


def _remove(paths: Iterable[str]) -> Dict[str, List[Dict[str, Any]]]:
    removed, kept = [], []
    for p in paths:
        size = _size([p])
        try:
            os.remove(p)
            removed.append({"file": p, "size": size})
        except FileNotFoundError:
            continue
        except OSError as exc:
            kept.append({"file": p, "size": size, "error": str(exc)})
    return {"removed": removed, "kept": kept}


def preview(db, client: Dict[str, Any], data_dir: Optional[str] = None) -> Dict[str, Any]:
    """What deleting the client would remove: its files and their size, and how much else it holds."""
    data_dir = data_dir or _settings().data_dir
    files = files_of(data_dir, client.get("db_filename") or "")
    return {"client": client, "files": [os.path.relpath(p, data_dir) for p in files], "size": size_text(_size(files))}


def delete_client(db, client_id: str, confirm: str, actor, data_dir: Optional[str] = None) -> Dict[str, Any]:
    """Delete a client, its rows and its database files (see the module's docstring). ``actor`` is the
    super admin (``id``, ``username``). Raises DeleteRefused or ClientNotFound (nothing changed).
    Returns ``{client, rows, removed: [{file, size}], kept: [{file, size, error}], size}``."""
    from app.services import maintenance, tenant_manager
    from app.services.log_context import audit_log
    data_dir = data_dir or _settings().data_dir
    client = db.get_client(client_id)
    if not client:
        raise ClientNotFound(client_id)
    if client.get("is_default"):
        raise DeleteRefused("TIDE's default client can't be deleted.")
    if (confirm or "").strip() != (client.get("name") or "").strip():
        raise DeleteRefused(f"Type the client's name, {client.get('name')}, to confirm. Nothing was deleted.")
    from app.main import sync_running
    if sync_running(client_id):
        raise DeleteRefused(f"A sync of {client.get('name')} is running. Wait for it to finish, then delete it. "
                            "Nothing was deleted.")
    if maintenance.running():
        raise DeleteRefused("The maintenance window is running. Wait for it to finish, then delete the client. "
                            "Nothing was deleted.")
    db_filename = client.get("db_filename") or ""
    files = files_of(data_dir, db_filename)
    rows = db.delete_client(client_id)
    if rows is None:
        raise ClientNotFound(client_id)
    # From here the client is gone: what follows must not turn that into a failure.
    tenant_manager.forget_tenant(client_id)
    if db_filename:
        _close(os.path.join(data_dir, db_filename))
    gone = _remove(files)
    for f in gone["kept"]:
        logger.warning("Deleted client %s, but could not delete %s: %s", client_id, f["file"], f["error"])
    try:
        audit_log("client_deleted", actor_id=getattr(actor, "id", None),
                  actor_username=getattr(actor, "username", None), client=client_id, client_name=client.get("name"),
                  rows=rows, files=[{"file": os.path.relpath(f["file"], data_dir), "size": f["size"]}
                                    for f in gone["removed"]],
                  not_deleted=[os.path.relpath(f["file"], data_dir) for f in gone["kept"]])
    except Exception:
        logger.exception("Could not write the audit record of deleting client %s (%s)", client.get("name"), client_id)
    logger.info("Client %s (%s) deleted by %s: %d file(s) removed", client.get("name"), client_id,
                getattr(actor, "username", "?"), len(gone["removed"]))
    return {"client": client, "rows": rows, **gone, "size": size_text(sum(f["size"] for f in gone["removed"]))}


# ── database files no client owns (Diagnostics) ──────────────────────────

def _owned(conn, data_dir: str, shared_db: str) -> Set[str]:
    """Every database file a client (or TIDE itself) owns."""
    names = [r[0] for r in conn.execute("SELECT db_filename FROM clients WHERE db_filename IS NOT NULL").fetchall()]
    owned = {os.path.realpath(p) for name in names for p in files_of(data_dir, name)}
    owned |= {os.path.realpath(p) for p in files_of(data_dir, os.path.basename(shared_db))}
    for name in names:   # a client's file that is missing now still owns that name
        owned.add(os.path.realpath(os.path.join(data_dir, name)))
    return owned


def _database_files(data_dir: str) -> List[str]:
    """The database files in the data folder and in Diagnostics fixes' backups."""
    found = []
    for pattern in ("*.duckdb", "*.duckdb.wal", "*.duckdb.pre-compact-*"):
        found += glob.glob(os.path.join(glob.escape(data_dir), pattern))
    found += glob.glob(os.path.join(glob.escape(os.path.join(data_dir, FIX_BACKUPS)), "*.duckdb*"))
    return sorted({p for p in found if os.path.isfile(p)})


def orphans(conn, data_dir: Optional[str] = None, shared_db: Optional[str] = None) -> List[Dict[str, Any]]:
    """Database files in the data folder that belong to no client: ``[{file, size, modified}]``. Never
    TIDE's own database (``shared_db``) or a file of a client that exists."""
    settings = None if data_dir and shared_db else _settings()
    data_dir = data_dir or settings.data_dir
    shared_db = shared_db or settings.db_path
    owned = _owned(conn, data_dir, shared_db)
    out = []
    for p in _database_files(data_dir):
        if os.path.realpath(p) in owned:
            continue
        try:
            st = os.stat(p)
        except OSError:
            continue
        out.append({"file": os.path.relpath(p, data_dir), "size": st.st_size,
                    "modified": datetime.fromtimestamp(st.st_mtime)})
    return out


def delete_orphans(conn, confirm: str, actor, data_dir: Optional[str] = None,
                   shared_db: Optional[str] = None) -> Dict[str, Any]:
    """Delete the database files no client owns, as ``orphans`` finds them now (a file a client took
    since the check ran is kept). The person types ``delete_orphan_files``. Audit-logged."""
    from app.services.log_context import audit_log
    if (confirm or "").strip() != CONFIRM_ORPHANS:
        raise DeleteRefused(f"Type {CONFIRM_ORPHANS} to confirm. Nothing was deleted.")
    data_dir = data_dir or _settings().data_dir
    found = orphans(conn, data_dir, shared_db)
    if not found:
        raise DeleteRefused("No database file is without a client now. Nothing was deleted.")
    paths = [os.path.join(data_dir, f["file"]) for f in found]
    for p in paths:
        if p.endswith(".duckdb"):
            _close(p)
    gone = _remove(paths)
    audit_log("orphaned_db_files_deleted", actor_id=getattr(actor, "id", None),
              actor_username=getattr(actor, "username", None),
              files=[{"file": os.path.relpath(f["file"], data_dir), "size": f["size"]} for f in gone["removed"]],
              not_deleted=[os.path.relpath(f["file"], data_dir) for f in gone["kept"]])
    return {"removed": [os.path.relpath(f["file"], data_dir) for f in gone["removed"]],
            "kept": [{"file": os.path.relpath(f["file"], data_dir), "error": f["error"]} for f in gone["kept"]],
            "size": size_text(sum(f["size"] for f in gone["removed"]))}
