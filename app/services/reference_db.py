"""App-wide reference data in one read-only DuckDB.

MITRE ATT&CK, NIST 800-53 mappings and the Sigma rule index are identical for
every tenant, so they live in ``reference.duckdb`` (baked into the image at
build time) instead of being stored in ``tide.duckdb`` or copied into each
tenant database.

Every pooled connection attaches the file read-only as ``ref`` and puts it on
the schema search path, so ``SELECT ... FROM mitre_techniques`` resolves to it
from the shared DB and from any tenant DB. Nothing at runtime writes to it:
``ensure_reference_db()`` rebuilds it before the first connection is opened,
and only when the source files changed.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
import threading
import time
from typing import Any, Dict

import duckdb

from app.config import get_settings

logger = logging.getLogger(__name__)

# Bump when the reference schema or the way it is populated changes.
BUILD_VERSION = 1

REFERENCE_TABLES = (
    "mitre_campaign_software",
    "mitre_campaign_techniques",
    "mitre_campaign_groups",
    "mitre_software_techniques",
    "mitre_group_software",
    "mitre_group_associations",
    "mitre_technique_mitigations",
    "mitre_group_techniques",
    "mitre_technique_tactics",
    "mitre_campaigns",
    "mitre_software",
    "mitre_mitigations",
    "mitre_groups",
    "mitre_tactics",
    "mitre_techniques",
    "nist_capabilities",
    "nist_capability_groups",
    "sigma_rules_index",
)

# Tables that once tracked load state inside tide.duckdb.
_RETIRED_TABLES = ("mitre_kb_state", "nist_kb_state")

_MITRE_DIR = "/opt/repos/mitre"
_MAPPINGS_DIR = "/opt/repos/mappings"

_attach_warned = False
_cleaned_paths: set = set()
_cleaned_lock = threading.Lock()


def reference_db_path() -> str:
    return get_settings().reference_db_path


def _sigma_rules_dir() -> str:
    for base in ("/opt/repos/sigma", "/app/repos/sigma", os.path.join(os.getcwd(), "repos", "sigma")):
        rules = os.path.join(base, "rules")
        if os.path.isdir(rules):
            return rules
    return os.path.join(os.getenv("SIGMA_REPO_PATH", "/opt/repos/sigma"), "rules")


def _sigma_digest(rules_dir: str) -> str:
    h = hashlib.sha256()
    count = size = newest = 0
    for root, _dirs, files in os.walk(rules_dir):
        for name in files:
            if name.endswith((".yml", ".yaml")):
                st = os.stat(os.path.join(root, name))
                count += 1
                size += st.st_size
                newest = max(newest, st.st_mtime_ns)
    h.update(f"{count}:{size}:{newest}".encode("ascii"))
    return h.hexdigest()


def source_digest() -> str:
    """Fingerprint of every input the reference DB is built from."""
    from app.services import mitre_kb, nist_kb

    h = hashlib.sha256()
    h.update(f"v{BUILD_VERSION}".encode("ascii"))
    if os.path.isdir(_MITRE_DIR):
        h.update(mitre_kb.source_digest(_MITRE_DIR).encode("ascii"))
    if os.path.isdir(_MAPPINGS_DIR):
        h.update(nist_kb.source_digest(_MAPPINGS_DIR).encode("ascii"))
    rules_dir = _sigma_rules_dir()
    if os.path.isdir(rules_dir):
        h.update(_sigma_digest(rules_dir).encode("ascii"))
    return h.hexdigest()


def _stored_digest(path: str) -> str:
    if not os.path.exists(path):
        return ""
    try:
        conn = duckdb.connect(path, read_only=True)
        try:
            row = conn.execute(
                "SELECT value FROM reference_meta WHERE key = 'source_digest'"
            ).fetchone()
            rows = conn.execute("SELECT COUNT(*) FROM mitre_techniques").fetchone()[0]
        finally:
            conn.close()
        return row[0] if row and rows else ""
    except Exception:
        return ""


def _build(tmp_path: str, digest: str) -> Dict[str, Any]:
    """Populate a fresh reference file at *tmp_path*."""
    app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)

    import app.database as legacy
    from app.services import mitre_kb, nist_kb

    out: Dict[str, Any] = {"errors": [], "counts": {}}
    previous_path = legacy.DB_PATH
    legacy.DB_PATH = tmp_path  # the KB writers connect through this path
    try:
        if os.path.isdir(_MITRE_DIR):
            out["errors"] += mitre_kb.load(_MITRE_DIR)
        if os.path.isdir(_MAPPINGS_DIR):
            out["errors"] += nist_kb.load(_MAPPINGS_DIR)
    finally:
        legacy.DB_PATH = previous_path

    conn = duckdb.connect(tmp_path)
    try:
        rules_dir = _sigma_rules_dir()
        if os.path.isdir(rules_dir):
            from app import sigma_helper
            try:
                sigma_helper.index_sigma_rules(conn)
            except Exception as exc:
                logger.error("Sigma index build failed", exc_info=True)
                out["errors"].append(f"sigma index: {exc}")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS reference_meta "
            "(key VARCHAR PRIMARY KEY, value VARCHAR, updated_at TIMESTAMP DEFAULT now())"
        )
        if not out["errors"]:
            conn.execute(
                "INSERT INTO reference_meta (key, value) VALUES ('source_digest', ?)", [digest]
            )
        for table in REFERENCE_TABLES:
            try:
                out["counts"][table] = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            except Exception:
                out["counts"][table] = 0
        conn.execute("CHECKPOINT")
    finally:
        conn.close()
    return out


def ensure_reference_db(force: bool = False) -> Dict[str, Any]:
    """Build ``reference.duckdb`` if it is missing or its sources changed.

    Must run before any pooled connection attaches the file (attaches are
    read-only and cannot coexist with a writer).
    """
    path = reference_db_path()
    result: Dict[str, Any] = {"updated": False, "path": path, "reason": ""}
    if not (os.path.isdir(_MITRE_DIR) or os.path.isdir(_MAPPINGS_DIR) or os.path.isdir(_sigma_rules_dir())):
        result["reason"] = "No reference source files found; nothing to build."
        return result

    digest = source_digest()
    if not force and _stored_digest(path) == digest:
        result["reason"] = "Reference sources unchanged."
        return result

    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".build"
    for leftover in (tmp_path, tmp_path + ".wal"):
        if os.path.exists(leftover):
            os.remove(leftover)

    started = time.time()
    built = _build(tmp_path, digest)
    result.update(built)
    if built["errors"] and os.path.exists(path):
        os.remove(tmp_path)
        result["reason"] = "Reference build had errors; kept the existing file."
        logger.error("Reference DB build failed: %s", built["errors"])
        return result

    if os.path.exists(path + ".wal"):
        os.remove(path + ".wal")
    os.replace(tmp_path, path)
    result["updated"] = True
    result["reason"] = f"Reference DB built in {time.time() - started:.0f}s."
    logger.info("%s %s", result["reason"], built["counts"])
    return result


def attach(conn) -> None:
    """Attach the reference DB read-only and add it to the search path."""
    global _attach_warned
    path = reference_db_path()
    if not os.path.exists(path):
        if not _attach_warned:
            logger.warning("Reference DB %s not found; ATT&CK, NIST and Sigma data unavailable", path)
            _attach_warned = True
        return
    try:
        conn.execute(f"ATTACH IF NOT EXISTS '{path.replace(chr(39), chr(39) * 2)}' AS ref (READ_ONLY)")
        conn.execute("SET search_path = 'main,ref'")
    except Exception as exc:
        logger.error("Could not attach reference DB %s: %s", path, exc)


def drop_legacy_copies(conn, key: str = "") -> None:
    """Drop reference tables still stored in a shared/tenant DB.

    Copies in ``main`` would shadow the attached reference tables. Nothing is
    dropped unless the reference DB is healthy (it has ATT&CK techniques).
    """
    with _cleaned_lock:
        if key and key in _cleaned_paths:
            return
        if key:
            _cleaned_paths.add(key)
    try:
        catalog = conn.execute("SELECT current_database()").fetchone()[0]
        if catalog == "ref":
            return
        held = {
            r[0] for r in conn.execute(
                "SELECT table_name FROM duckdb_tables() WHERE database_name = 'ref'"
            ).fetchall()
        }
        if "mitre_techniques" not in held or not conn.execute(
            "SELECT COUNT(*) FROM ref.main.mitre_techniques"
        ).fetchone()[0]:
            return
        local = {
            r[0] for r in conn.execute(
                "SELECT table_name FROM duckdb_tables() "
                "WHERE database_name = ? AND schema_name = 'main'", [catalog]
            ).fetchall()
        }
        for table in REFERENCE_TABLES + _RETIRED_TABLES:
            if table not in local:
                continue
            if table in REFERENCE_TABLES and table not in held:
                continue
            conn.execute(f'DROP TABLE "{catalog}".main."{table}"')
            logger.info("Dropped legacy copy of %s from %s", table, catalog)
    except Exception as exc:
        logger.warning("Legacy reference table cleanup skipped: %s", exc)
