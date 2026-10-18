"""Hunting: Elastic's hunting queries and SigmaHQ's threat-hunting rules, both bundled in the image,
searched as one list for the Hunting page.

Elastic's are indexed by ``elastic_rules.build_index`` (``elastic_hunts_index``). SigmaHQ keeps its
hunting rules apart from its detection rules, in ``rules-threat-hunting/``: ``build_sigma_index``
reads them into ``sigma_hunts_index`` when the reference DB is built. Both are read-only here.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SOURCES = (("elastic", "Elastic"), ("sigma", "Sigma"))
SIGMA_HUNTING_DIR = "rules-threat-hunting"

SIGMA_HUNTS_DDL = """
    CREATE TABLE IF NOT EXISTS sigma_hunts_index (
        hunt_id       VARCHAR PRIMARY KEY,
        name          VARCHAR,
        description   VARCHAR,
        status        VARCHAR,
        level         VARCHAR,
        platform      VARCHAR,
        techniques    VARCHAR[],
        file_path     VARCHAR,
        raw_yaml      VARCHAR,
        content_hash  VARCHAR,
        indexed_at    TIMESTAMP
    )
"""


def sigma_hunting_dir() -> str:
    from app.config import get_settings
    return os.path.join(get_settings().sigma_repo_path, SIGMA_HUNTING_DIR)


def _yaml_files(root: str):
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if name.endswith((".yml", ".yaml")):
                yield os.path.join(dirpath, name)


def sigma_digest(root: str) -> str:
    count = size = newest = 0
    for path in _yaml_files(root):
        st = os.stat(path)
        count, size, newest = count + 1, size + st.st_size, max(newest, st.st_mtime_ns)
    return hashlib.sha256(f"{count}:{size}:{newest}".encode("ascii")).hexdigest()


def build_sigma_index(conn, root: Optional[str] = None) -> int:
    """Fill ``sigma_hunts_index`` on *conn* (the reference DB being built). A file that cannot be
    read is logged and skipped. Returns how many were indexed."""
    from app import sigma_helper

    root = root or sigma_hunting_dir()
    conn.execute(SIGMA_HUNTS_DDL)
    conn.execute("DELETE FROM sigma_hunts_index")
    if not os.path.isdir(root):
        return 0
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows = {}
    for path in _yaml_files(root):
        rule = sigma_helper.load_sigma_rule(path)
        if not rule or not rule.get("id"):
            continue
        rel = os.path.relpath(path, os.path.dirname(root)).replace(os.sep, "/")
        parts = rel.split("/")
        logsource = rule.get("logsource") or {}
        rows[str(rule["id"])] = (
            str(rule["id"]), str(rule.get("title") or ""), str(rule.get("description") or "").strip(),
            str(rule.get("status") or "").lower(), str(rule.get("level") or "").lower(),
            parts[1] if len(parts) > 2 else str(logsource.get("product") or "other"),
            sigma_helper.extract_mitre_techniques(rule) or [], rel, rule.get("_raw_yaml", ""),
            sigma_helper.rule_content_hash(rule), now,
        )
    if rows:
        conn.executemany(f"INSERT INTO sigma_hunts_index VALUES ({', '.join('?' * 11)})", list(rows.values()))
    logger.info("Sigma hunting: indexed %d threat-hunting rules", len(rows))
    return len(rows)


def indexes_ready(conn) -> Tuple[bool, bool]:
    tables = {r[0] for r in conn.execute(
        "SELECT table_name FROM duckdb_tables() WHERE table_name IN ('elastic_hunts_index', 'sigma_hunts_index')"
    ).fetchall()}
    return "elastic_hunts_index" in tables, "sigma_hunts_index" in tables


def _union(conn) -> str:
    elastic, sigma = indexes_ready(conn)
    parts = []
    if elastic:
        parts.append("SELECT 'elastic' AS source, hunt_id, name, description, platform, techniques, "
                     "array_to_string(queries, ' ') AS body FROM elastic_hunts_index")
    if sigma:
        parts.append("SELECT 'sigma' AS source, hunt_id, name, description, platform, techniques, "
                     "raw_yaml AS body FROM sigma_hunts_index")
    return " UNION ALL ".join(parts)


def search(conn, q: str = "", technique: str = "", platform: str = "", source: str = "",
           limit: int = 200, offset: int = 0) -> Tuple[List[Dict[str, Any]], int, int]:
    """Hunts matching every filter, by name: ``(rows, matching, total)``, ``limit`` of them from
    ``offset`` on."""
    from app.services.elastic_rules import rows_as_dicts, technique_clause

    union = _union(conn)
    if not union:
        return [], 0, 0
    where: List[str] = []
    params: List[Any] = []
    if q.strip():
        like = f"%{q.strip()}%"
        where.append("(name ILIKE ? OR description ILIKE ? OR hunt_id ILIKE ? OR body ILIKE ? "
                     "OR array_to_string(techniques, ' ') ILIKE ?)")
        params += [like] * 5
    if technique.strip():
        where.append(technique_clause("techniques", technique, params))
    for column, value in (("platform", platform), ("source", source)):
        if value:
            where.append(f"{column} = ?")
            params.append(value)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM ({union}) h").fetchone()[0]
    matching = conn.execute(f"SELECT COUNT(*) FROM ({union}) h {clause}", params).fetchone()[0]
    rows = rows_as_dicts(conn.execute(
        f"SELECT source, hunt_id, name, platform, techniques FROM ({union}) h {clause} "
        f"ORDER BY lower(name), hunt_id LIMIT ? OFFSET ?", params + [int(limit), max(0, int(offset))]))
    return rows, matching, total


def platforms(conn) -> List[str]:
    union = _union(conn)
    if not union:
        return []
    return [r[0] for r in conn.execute(f"SELECT DISTINCT platform FROM ({union}) h ORDER BY 1").fetchall() if r[0]]


def counts(conn) -> Dict[str, int]:
    elastic, sigma = indexes_ready(conn)
    return {
        "elastic": conn.execute("SELECT COUNT(*) FROM elastic_hunts_index").fetchone()[0] if elastic else 0,
        "sigma": conn.execute("SELECT COUNT(*) FROM sigma_hunts_index").fetchone()[0] if sigma else 0,
    }


def get_sigma(conn, hunt_id: str) -> Optional[Dict[str, Any]]:
    """One SigmaHQ hunting rule: its index row with the parsed rule as ``rule``."""
    import yaml
    from app.services.elastic_rules import rows_as_dicts

    if not indexes_ready(conn)[1]:
        return None
    rows = rows_as_dicts(conn.execute("SELECT * FROM sigma_hunts_index WHERE hunt_id = ?", [hunt_id]))
    if not rows:
        return None
    row = rows[0]
    try:
        row["rule"] = yaml.safe_load(row["raw_yaml"]) or {}
    except yaml.YAMLError:
        row["rule"] = {}
    return row
