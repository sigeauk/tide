"""
Database service for TIDE - DuckDB operations.
Ported from the original Streamlit database.py to a FastAPI-friendly singleton pattern.
"""

import duckdb
import json
import os
import shutil
import tempfile
import time
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Set
from contextlib import contextmanager
from threading import Lock

from app.config import get_settings
from app.models.rules import DetectionRule, RuleHealthMetrics, RuleFilters
from app.models.threats import ThreatActor, ThreatLandscapeMetrics

import logging

logger = logging.getLogger(__name__)

# Schema version for migrations
SCHEMA_VERSION = 54


def _scope_predicate(
    scopes: Optional[List[Tuple[str, str]]],
    table_alias: str = "",
) -> Tuple[str, list]:
    """Build a (siem_id, space) composite WHERE fragment for tenant scoping.

    Per AGENTS.md §8.2 guarantee 4 / §8.3, ANY query that filters
    ``detection_rules`` by space alone leaks rules between two SIEMs that
    share a Kibana space name. This helper is the single source of truth for
    the correct predicate shape; every reader that takes a tenant scope must
    route through it.

    Args:
        scopes: List of ``(siem_id, space)`` tuples (typically from
            :py:meth:`get_client_siem_scopes`). Spaces are matched
            case-insensitively to mirror the LOWER() normalisation used at
            insert time.
        table_alias: Optional table alias / qualifier (e.g. ``"dr"``) to
            prefix the column references when used inside a JOIN.

    Returns:
        Tuple ``(sql_fragment, params)``. ``sql_fragment`` is wrapped in
        parentheses and is safe to drop straight after ``WHERE`` /
        ``AND`` / ``OR``. ``params`` is the flat positional bind list.
        When ``scopes`` is empty/None the helper returns ``("1=0", [])``
        so the caller's query short-circuits to zero rows rather than
        unintentionally returning the whole table.
    """
    if not scopes:
        return "1=0", []
    prefix = f"{table_alias}." if table_alias else ""
    frag = " OR ".join(
        f"({prefix}siem_id = ? AND LOWER({prefix}space) = ?)" for _ in scopes
    )
    params: list = []
    for sid, sp in scopes:
        params.append(sid)
        params.append((sp or "").lower())
    return f"({frag})", params


class DatabaseService:
    """
    Singleton database service for DuckDB operations.
    Thread-safe with connection pooling and retry logic.
    """
    
    _instance: Optional["DatabaseService"] = None
    _lock: Lock = Lock()
    
    def __new__(cls) -> "DatabaseService":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.settings = get_settings()
        self.db_path = self.settings.db_path
        self.trigger_dir = self.settings.trigger_dir
        self.validation_file = self.settings.validation_file
        self._conn_lock = Lock()
        
        # Validation data cache (avoids re-reading JSON file on every metrics call)
        self._validation_cache: Optional[Dict] = None
        self._validation_cache_mtime: float = 0.0
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        os.makedirs(self.trigger_dir, exist_ok=True)
        
        # Initialize database
        self._init_db()
        self._initialized = True
        logger.info("DuckDB Service initialized")
    
    @contextmanager
    def get_connection(self, read_only: bool = False, retries: int = 5, delay: float = 0.5):
        """
        Context manager for database connections with retry logic.
        Routes to the tenant DB when a tenant context is active,
        otherwise connects to the shared DB.
        """
        from app.services.tenant_manager import get_tenant_db_path
        db_path = get_tenant_db_path() or self.db_path

        # 4.1.0 P2 — Tenant-scope guard. If we're inside a request that the
        # middleware classified as tenant-required AND no tenant context is
        # active, the caller is about to read from the *shared* DB on a route
        # that should be tenant-scoped. This is the exact class of bug that
        # caused the 4.0.13 OpenCTI leak. Emit a tide.error JSON line so the
        # incident is greppable; default mode is warn-only (logs the leak,
        # serves the request) but `TIDE_ISOLATION_STRICT=1` upgrades to a
        # hard 500 so the regression cannot ship.
        if get_tenant_db_path() is None:
            try:
                from app.services.log_context import get_context
                ctx = get_context()
                if ctx.get("tenant_required"):
                    msg = (
                        f"isolation_violation route={ctx.get('route')} "
                        f"user={ctx.get('user_id')} req={ctx.get('request_id')}"
                    )
                    logger.error(msg)
                    if os.getenv("TIDE_ISOLATION_STRICT", "0") == "1":
                        raise RuntimeError(
                            "Tenant context required for "
                            f"{ctx.get('method')} {ctx.get('route')} "
                            "(set X-Client-ID header or use ActiveClient dep)"
                        )
            except RuntimeError:
                raise
            except Exception:  # pragma: no cover - guard must never break a request
                pass

        # 4.1.0 P3 — connection pool. The pool itself handles per-path
        # mutual exclusion (Queue with maxsize=MAX_PER_TENANT) so we no
        # longer need self._conn_lock around the connect() call. We do
        # still retry on lock contention because a *different* process
        # (e.g. the sync worker) could be holding a write lock on the
        # underlying file.
        from app.services.connection_pool import get_pool
        pool = get_pool()
        attempt = 0
        while attempt < retries:
            try:
                with pool.acquire(db_path) as conn:
                    yield conn
                return
            except duckdb.IOException as e:
                if "lock" in str(e).lower():
                    attempt += 1
                    logger.warning(f"DB Locked. Retrying ({attempt}/{retries})...")
                    time.sleep(delay)
                else:
                    raise
            except Exception as e:
                logger.error(f"DB Connection failed: {e}")
                raise
        raise duckdb.IOException("Database locked by another process.")

    @contextmanager
    def get_shared_connection(self, read_only: bool = False, retries: int = 5, delay: float = 0.5):
        """
        Context manager that always connects to the shared database,
        ignoring any active tenant context.  Used for auth, RBAC,
        client management, and SIEM inventory operations.
        """
        from app.services.connection_pool import get_pool
        pool = get_pool()
        attempt = 0
        while attempt < retries:
            try:
                with pool.acquire(self.db_path) as conn:
                    yield conn
                return
            except duckdb.IOException as e:
                if "lock" in str(e).lower():
                    attempt += 1
                    logger.warning(f"Shared DB Locked. Retrying ({attempt}/{retries})...")
                    time.sleep(delay)
                else:
                    raise
            except Exception as e:
                logger.error(f"Shared DB Connection failed: {e}")
                raise
        raise duckdb.IOException("Shared database locked by another process.")
    
    def _get_schema_version(self, conn) -> int:
        """Get current schema version from database."""
        try:
            result = conn.execute("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_name = 'schema_version'
            """).fetchone()
            
            if result:
                version = conn.execute(
                    "SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1"
                ).fetchone()
                return version[0] if version else 0
            return 0
        except:
            return 0
    
    def _set_schema_version(self, conn, version: int):
        """Record schema version in database."""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP
            )
        """)
        conn.execute("""
            INSERT INTO schema_version (version, applied_at)
            VALUES (?, now())
            ON CONFLICT (version) DO UPDATE SET applied_at = now()
        """, [version])

    def _backfill_legacy_opencti_to_connectors(self, conn) -> int:
        """No-op since 5.0.0.

        The legacy OpenCTI GraphQL path has been fully retired and
        migration 50 drops the source tables (``opencti_inventory`` /
        ``client_opencti_map``) along with any ``cti_connectors`` rows
        whose vendor is the legacy ``opencti``. This method is kept as
        a stub so older callers (e.g. migration 47, which is now also
        a no-op for fresh installs since migration 50 unconditionally
        wipes its output) don't blow up when they import it.
        """
        return 0

    def _backfill_legacy_opencti_to_connectors_DISABLED(self, conn) -> int:
        """Original 4.1.20 implementation retained for archaeology only."""
        import json as _json
        backfilled = 0
        try:
            tables = {
                r[0] for r in conn.execute(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'main'"
                ).fetchall()
            }
            if "opencti_inventory" not in tables or "cti_connectors" not in tables:
                return 0
            src_rows = conn.execute(
                "SELECT id, label, url, token_enc, is_active, "
                "COALESCE(kind, 'actors'), created_at, updated_at "
                "FROM opencti_inventory"
            ).fetchall()
            for (oid, label, url, token_enc, is_active, kind,
                 created_at, updated_at) in src_rows:
                existing = conn.execute(
                    "SELECT 1 FROM cti_connectors "
                    "WHERE vendor = 'opencti' AND label = ? LIMIT 1",
                    [label],
                ).fetchone()
                if existing:
                    continue
                config = _json.dumps({
                    "url": url or "",
                    "token": token_enc or "",
                    "legacy_opencti_id": oid,
                })
                conn.execute(
                    "INSERT INTO cti_connectors "
                    "(vendor, label, is_active, kind, config_json, "
                    "created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    ["opencti", label, bool(is_active),
                     kind if kind in ("actors", "cti", "both") else "actors",
                     config,
                     created_at, updated_at],
                )
                new_id_row = conn.execute(
                    "SELECT id FROM cti_connectors "
                    "WHERE vendor = 'opencti' AND label = ? "
                    "ORDER BY created_at DESC LIMIT 1",
                    [label],
                ).fetchone()
                if new_id_row:
                    new_id = new_id_row[0]
                    try:
                        client_links = conn.execute(
                            "SELECT client_id FROM client_opencti_map "
                            "WHERE opencti_id = ?", [oid]
                        ).fetchall()
                    except Exception:
                        client_links = []
                    for (cid,) in client_links:
                        conn.execute(
                            "INSERT INTO cti_connector_clients "
                            "(connector_id, client_id) VALUES (?, ?) "
                            "ON CONFLICT DO NOTHING",
                            [new_id, cid],
                        )
                backfilled += 1
            if backfilled:
                logger.info(
                    "Legacy OpenCTI back-fill: copied %d row(s) into cti_connectors",
                    backfilled,
                )
        except Exception as exc:
            logger.warning(
                f"Legacy OpenCTI back-fill skipped: {exc!r}"
            )
        return backfilled

    def _run_migrations(self, conn):
        """Run database migrations."""
        current_version = self._get_schema_version(conn)
        
        if current_version >= SCHEMA_VERSION:
            return
        
        logger.info(f"Running migrations from v{current_version} to v{SCHEMA_VERSION}...")
        
        # Migration 1: Initial schema
        if current_version < 1:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_actors (
                    name VARCHAR PRIMARY KEY,
                    description VARCHAR,
                    ttps VARCHAR[],
                    ttp_count INTEGER,
                    aliases VARCHAR,
                    origin VARCHAR,
                    last_updated TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS detection_rules (
                    rule_id VARCHAR PRIMARY KEY,
                    name VARCHAR,
                    severity VARCHAR,
                    author VARCHAR,
                    enabled INTEGER,
                    space VARCHAR,
                    score INTEGER,
                    quality_score INTEGER,
                    meta_score INTEGER,
                    score_mapping INTEGER,
                    score_field_type INTEGER,
                    score_search_time INTEGER,
                    score_language INTEGER,
                    score_note INTEGER,
                    score_override INTEGER,
                    score_tactics INTEGER,
                    score_techniques INTEGER,
                    score_author INTEGER,
                    score_highlights INTEGER,
                    last_updated TIMESTAMP,
                    mitre_ids VARCHAR[], 
                    raw_data JSON
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mitre_techniques (
                    id VARCHAR PRIMARY KEY,
                    name VARCHAR,
                    tactic VARCHAR,
                    url VARCHAR
                )
            """)
            self._set_schema_version(conn, 1)
            logger.info("Migration 1: Initial schema created")
        
        # Migration 2: Add/fix source column to threat_actors as VARCHAR[]
        if current_version < 2:
            # Check if source column exists and has wrong type
            cols = conn.execute("DESCRIBE threat_actors").fetchall()
            source_col = next((c for c in cols if c[0] == 'source'), None)
            
            if source_col and source_col[1] == 'VARCHAR':
                # Source column exists but has wrong type - need to fix
                logger.info("Converting source column from VARCHAR to VARCHAR[]...")
                conn.execute("ALTER TABLE threat_actors ADD COLUMN source_new VARCHAR[]")
                conn.execute("""
                    UPDATE threat_actors 
                    SET source_new = CASE 
                        WHEN source IS NOT NULL AND source != '' THEN [source]
                        ELSE []
                    END
                """)
                conn.execute("ALTER TABLE threat_actors DROP COLUMN source")
                conn.execute("ALTER TABLE threat_actors RENAME COLUMN source_new TO source")
            elif source_col is None:
                conn.execute("ALTER TABLE threat_actors ADD COLUMN source VARCHAR[]")
            
            self._set_schema_version(conn, 2)
            logger.info("Migration 2: Source column fixed as VARCHAR[]")
        
        # Migration 3: Composite PK for detection_rules
        if current_version < 3:
            conn.execute("DROP TABLE IF EXISTS detection_rules")
            conn.execute("""
                CREATE TABLE detection_rules (
                    rule_id VARCHAR,
                    name VARCHAR,
                    severity VARCHAR,
                    author VARCHAR,
                    enabled INTEGER,
                    space VARCHAR,
                    score INTEGER,
                    quality_score INTEGER,
                    meta_score INTEGER,
                    score_mapping INTEGER,
                    score_field_type INTEGER,
                    score_search_time INTEGER,
                    score_language INTEGER,
                    score_note INTEGER,
                    score_override INTEGER,
                    score_tactics INTEGER,
                    score_techniques INTEGER,
                    score_author INTEGER,
                    score_highlights INTEGER,
                    last_updated TIMESTAMP,
                    mitre_ids VARCHAR[], 
                    raw_data JSON,
                    PRIMARY KEY (rule_id, space)
                )
            """)
            self._set_schema_version(conn, 3)
            logger.info("Migration 3: Composite PK for detection_rules")
        
        # Migration 4: App settings table for runtime configuration
        if current_version < 4:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS app_settings (
                    key VARCHAR PRIMARY KEY,
                    value VARCHAR,
                    updated_at TIMESTAMP DEFAULT now()
                )
            """)
            # Insert defaults
            conn.execute("""
                INSERT OR IGNORE INTO app_settings (key, value) VALUES
                    ('rule_log_enabled', 'false'),
                    ('rule_log_path', '/app/data/log/rules'),
                    ('rule_log_schedule', '00:00'),
                    ('rule_log_retention_days', '7')
            """)
            self._set_schema_version(conn, 4)
            logger.info("Migration 4: App settings table created")
        
        # Migration 5: Asset inventory — systems & software inventory
        if current_version < 5:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS systems (
                    id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    name VARCHAR NOT NULL,
                    hostname_pattern VARCHAR,
                    description VARCHAR,
                    created_at TIMESTAMP DEFAULT now(),
                    updated_at TIMESTAMP DEFAULT now()
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS software_inventory (
                    id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    system_id VARCHAR NOT NULL,
                    name VARCHAR NOT NULL,
                    version VARCHAR,
                    vendor VARCHAR,
                    cpe VARCHAR,
                    source VARCHAR DEFAULT 'manual',
                    created_at TIMESTAMP DEFAULT now()
                )
            """)
            self._set_schema_version(conn, 5)
            logger.info("Migration 5: Asset inventory tables created (systems, software_inventory)")

        # Migration 6: Enterprise model — hosts + host_id on software_inventory
        if current_version < 6:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    system_id VARCHAR NOT NULL,
                    name VARCHAR NOT NULL,
                    ip_address VARCHAR,
                    os VARCHAR,
                    hardware_vendor VARCHAR,
                    model VARCHAR,
                    source VARCHAR DEFAULT 'manual',
                    created_at TIMESTAMP DEFAULT now()
                )
            """)
            # Add host_id column to existing software_inventory (nullable for backward compat)
            try:
                conn.execute("ALTER TABLE software_inventory ADD COLUMN host_id VARCHAR")
            except Exception:
                pass  # Column may already exist if migration was partially applied
            self._set_schema_version(conn, 6)
            logger.info("Migration 6: Enterprise model — hosts table + host_id column added")

        # Migration 7: Vulnerability detection assertions
        if current_version < 7:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vuln_detections (
                    cve_id  VARCHAR PRIMARY KEY,
                    note    TEXT,
                    rule_ref VARCHAR,
                    created_at TIMESTAMP DEFAULT now()
                )
            """)
            self._set_schema_version(conn, 7)
            logger.info("Migration 7: vuln_detections table created")

        # Migration 8: Per-system detection support
        if current_version < 8:
            # Preserve existing rows (if any) then rebuild with composite PK
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vuln_detections_v8_tmp AS
                SELECT cve_id,
                       ''                AS system_id,
                       note,
                       rule_ref,
                       created_at
                FROM vuln_detections
            """)
            conn.execute("DROP TABLE IF EXISTS vuln_detections")
            conn.execute("""
                CREATE TABLE vuln_detections (
                    cve_id     VARCHAR  NOT NULL,
                    system_id  VARCHAR  NOT NULL DEFAULT '',
                    note       TEXT,
                    rule_ref   VARCHAR,
                    created_at TIMESTAMP DEFAULT now(),
                    PRIMARY KEY (cve_id, system_id)
                )
            """)
            conn.execute("INSERT INTO vuln_detections SELECT * FROM vuln_detections_v8_tmp")
            conn.execute("DROP TABLE IF EXISTS vuln_detections_v8_tmp")
            self._set_schema_version(conn, 8)
            logger.info("Migration 8: vuln_detections rebuilt with per-system PK")

        # Migration 9: Add classification column to systems
        if current_version < 9:
            try:
                conn.execute("ALTER TABLE systems ADD COLUMN classification VARCHAR")
            except Exception:
                pass  # Column may already exist
            self._set_schema_version(conn, 9)
            logger.info("Migration 9: Added classification column to systems")

        # Migration 10: Add cve_technique_overrides table for manual MITRE mappings
        if current_version < 10:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_technique_overrides (
                    cve_id      VARCHAR NOT NULL,
                    technique_id VARCHAR NOT NULL,
                    PRIMARY KEY (cve_id, technique_id)
                )
            """)
            self._set_schema_version(conn, 10)
            logger.info("Migration 10: Created cve_technique_overrides table")

        # Migration 11: Custom classifications table
        if current_version < 11:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS classifications (
                    id   VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    name VARCHAR NOT NULL UNIQUE,
                    color VARCHAR NOT NULL DEFAULT '#6b7280'
                )
            """)
            # Seed default government classifications
            for name, color in [
                ('Official',     '#22c55e'),
                ('Confidential', '#f59e0b'),
                ('Secret',       '#ef4444'),
                ('Top Secret',   '#dc2626'),
            ]:
                conn.execute(
                    "INSERT INTO classifications (name, color) VALUES (?, ?) ON CONFLICT DO NOTHING",
                    [name, color],
                )
            self._set_schema_version(conn, 11)
            logger.info("Migration 11: Created classifications table with defaults")

        # Migration 12: Restructure vuln_detections to allow multiple detections per CVE
        if current_version < 12:
            conn.execute("CREATE TABLE IF NOT EXISTS vuln_detections_v12_tmp AS SELECT * FROM vuln_detections")
            conn.execute("DROP TABLE IF EXISTS vuln_detections")
            conn.execute("""
                CREATE TABLE vuln_detections (
                    id          VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    cve_id      VARCHAR NOT NULL,
                    rule_ref    VARCHAR,
                    note        TEXT,
                    source      VARCHAR DEFAULT 'manual',
                    created_at  TIMESTAMP DEFAULT now()
                )
            """)
            # Migrate existing rows: split comma-separated rule_refs into individual rows
            old_rows = conn.execute("SELECT cve_id, rule_ref, note, created_at FROM vuln_detections_v12_tmp").fetchall()
            for row in old_rows:
                cve_id, rule_ref, note, created_at = row
                if rule_ref:
                    for ref in rule_ref.split(','):
                        ref = ref.strip()
                        if ref:
                            conn.execute(
                                "INSERT INTO vuln_detections (cve_id, rule_ref, note, source, created_at) VALUES (?, ?, ?, 'manual', ?)",
                                [cve_id, ref, note, created_at])
                else:
                    conn.execute(
                        "INSERT INTO vuln_detections (cve_id, rule_ref, note, source, created_at) VALUES (?, ?, ?, 'manual', ?)",
                        [cve_id, rule_ref, note, created_at])
            conn.execute("DROP TABLE IF EXISTS vuln_detections_v12_tmp")
            self._set_schema_version(conn, 12)
            logger.info("Migration 12: vuln_detections restructured for multi-detection per CVE")

        # Migration 13: Track which detections are applied to systems/hosts (Tier 3)
        if current_version < 13:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS applied_detections (
                    id            VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    detection_id  VARCHAR NOT NULL,
                    system_id     VARCHAR,
                    host_id       VARCHAR,
                    applied_at    TIMESTAMP DEFAULT now()
                )
            """)
            self._set_schema_version(conn, 13)
            logger.info("Migration 13: Created applied_detections table for Tier 3 coverage")

        # Migration 14: Assurance Baselines (Threat Playbooks)
        if current_version < 14:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS playbooks (
                    id            VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    name          VARCHAR NOT NULL,
                    description   VARCHAR DEFAULT '',
                    created_at    TIMESTAMP DEFAULT now(),
                    updated_at    TIMESTAMP DEFAULT now()
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS playbook_steps (
                    id            VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    playbook_id   VARCHAR NOT NULL,
                    step_number   INTEGER NOT NULL,
                    title         VARCHAR NOT NULL,
                    technique_id  VARCHAR DEFAULT '',
                    required_rule VARCHAR DEFAULT '',
                    description   VARCHAR DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS system_baselines (
                    id            VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    system_id     VARCHAR NOT NULL,
                    playbook_id   VARCHAR NOT NULL,
                    applied_at    TIMESTAMP DEFAULT now()
                )
            """)
            self._set_schema_version(conn, 14)
            logger.info("Migration 14: Created playbooks, playbook_steps, system_baselines tables")

        # Migration 15: Baseline-CVE parity — tactic field, multi-technique & multi-detection per step
        if current_version < 15:
            # Add tactic column to playbook_steps
            try:
                conn.execute("ALTER TABLE playbook_steps ADD COLUMN tactic VARCHAR DEFAULT ''")
            except Exception:
                pass  # column may already exist

            # Junction table: many techniques per step
            conn.execute("""
                CREATE TABLE IF NOT EXISTS step_techniques (
                    id            VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    step_id       VARCHAR NOT NULL,
                    technique_id  VARCHAR NOT NULL
                )
            """)

            # Junction table: many detection rules per step (mirrors vuln_detections pattern)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS step_detections (
                    id            VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    step_id       VARCHAR NOT NULL,
                    rule_ref      VARCHAR DEFAULT '',
                    note          VARCHAR DEFAULT '',
                    source        VARCHAR DEFAULT 'manual'
                )
            """)

            # Migrate existing single technique_id -> step_techniques rows
            existing_steps = conn.execute(
                "SELECT id, technique_id FROM playbook_steps WHERE technique_id IS NOT NULL AND technique_id != ''"
            ).fetchall()
            for step_id, tech_id in existing_steps:
                dup = conn.execute(
                    "SELECT 1 FROM step_techniques WHERE step_id = ? AND technique_id = ?",
                    [step_id, tech_id],
                ).fetchone()
                if not dup:
                    conn.execute(
                        "INSERT INTO step_techniques (step_id, technique_id) VALUES (?, ?)",
                        [step_id, tech_id],
                    )

            # Migrate existing single required_rule -> step_detections rows
            existing_rules = conn.execute(
                "SELECT id, required_rule FROM playbook_steps WHERE required_rule IS NOT NULL AND required_rule != ''"
            ).fetchall()
            for step_id, rule_ref in existing_rules:
                dup = conn.execute(
                    "SELECT 1 FROM step_detections WHERE step_id = ? AND rule_ref = ?",
                    [step_id, rule_ref],
                ).fetchone()
                if not dup:
                    conn.execute(
                        "INSERT INTO step_detections (step_id, rule_ref) VALUES (?, ?)",
                        [step_id, rule_ref],
                    )

            self._set_schema_version(conn, 15)
            logger.info("Migration 15: Added tactic to steps, created step_techniques & step_detections tables")

        # Migration 16: Negative Coverage / Known Blind Spots
        if current_version < 16:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blind_spots (
                    id            VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    entity_type   VARCHAR NOT NULL,
                    entity_id     VARCHAR NOT NULL,
                    system_id     VARCHAR,
                    host_id       VARCHAR,
                    reason        VARCHAR NOT NULL,
                    created_by    VARCHAR DEFAULT '',
                    created_at    TIMESTAMP DEFAULT now()
                )
            """)
            self._set_schema_version(conn, 16)
            logger.info("Migration 16: Created blind_spots table for negative coverage tracking")

        # Migration 17: Rename entity_type 'step' -> 'tactic' in blind_spots
        if current_version < 17:
            conn.execute("UPDATE blind_spots SET entity_type = 'tactic' WHERE entity_type = 'step'")
            self._set_schema_version(conn, 17)
            logger.info("Migration 17: Renamed blind_spots entity_type 'step' to 'tactic'")

        # Migration 18: Add override_type column to blind_spots for 4-tier status
        if current_version < 18:
            try:
                conn.execute("ALTER TABLE blind_spots ADD COLUMN override_type VARCHAR DEFAULT 'gap'")
            except Exception:
                pass  # Column may already exist
            self._set_schema_version(conn, 18)
            logger.info("Migration 18: Added override_type column to blind_spots (gap|na)")

        # Migration 19: Audit Snapshots — point-in-time baseline coverage
        if current_version < 19:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS system_baseline_snapshots (
                    id VARCHAR PRIMARY KEY,
                    system_id VARCHAR NOT NULL,
                    baseline_id VARCHAR NOT NULL,
                    captured_at TIMESTAMP NOT NULL,
                    captured_by VARCHAR,
                    label VARCHAR,
                    score_percentage FLOAT,
                    count_green INTEGER DEFAULT 0,
                    count_amber INTEGER DEFAULT 0,
                    count_red INTEGER DEFAULT 0,
                    count_grey INTEGER DEFAULT 0
                )
            """)
            self._set_schema_version(conn, 19)
            logger.info("Migration 19: Created system_baseline_snapshots table")

        # Migration 20: External API keys for sidecar query service
        if current_version < 20:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_hash VARCHAR PRIMARY KEY,
                    label VARCHAR NOT NULL,
                    created_at TIMESTAMP DEFAULT now(),
                    last_used_at TIMESTAMP
                )
            """)
            self._set_schema_version(conn, 20)
            logger.info("Migration 20: Created api_keys table")

        # Migration 21: Hybrid Auth & RBAC
        if current_version < 21:
            # Drop legacy users table (from _ensure_users_table) and rebuild
            conn.execute("DROP TABLE IF EXISTS users")
            conn.execute("""
                CREATE TABLE users (
                    id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    username VARCHAR UNIQUE NOT NULL,
                    email VARCHAR,
                    full_name VARCHAR,
                    password_hash VARCHAR,
                    keycloak_id VARCHAR,
                    auth_provider VARCHAR DEFAULT 'local',
                    is_active BOOLEAN DEFAULT true,
                    created_at TIMESTAMP DEFAULT now(),
                    updated_at TIMESTAMP DEFAULT now(),
                    last_login TIMESTAMP
                )
            """)
            # Roles table with seeded roles
            conn.execute("""
                CREATE TABLE IF NOT EXISTS roles (
                    id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    name VARCHAR UNIQUE NOT NULL,
                    description VARCHAR
                )
            """)
            for role_name, role_desc in [
                ('ADMIN', 'Full platform administration'),
                ('ANALYST', 'View and edit detection rules, baselines, and threats'),
                ('ENGINEER', 'Read-only access to dashboards and reports'),
            ]:
                conn.execute(
                    "INSERT INTO roles (name, description) VALUES (?, ?) ON CONFLICT DO NOTHING",
                    [role_name, role_desc],
                )
            # User-to-Role join table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_roles (
                    user_id VARCHAR NOT NULL,
                    role_id VARCHAR NOT NULL,
                    assigned_at TIMESTAMP DEFAULT now(),
                    PRIMARY KEY (user_id, role_id)
                )
            """)
            self._set_schema_version(conn, 21)
            logger.info("Migration 21: Created RBAC tables (users, roles, user_roles)")

        # Migration 22: Page / tab permissions per role
        if current_version < 22:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS role_permissions (
                    id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    role_id VARCHAR NOT NULL,
                    resource VARCHAR NOT NULL,
                    can_read BOOLEAN DEFAULT false,
                    can_write BOOLEAN DEFAULT false,
                    UNIQUE(role_id, resource)
                )
            """)
            # Seed default permissions for the three built-in roles
            role_rows = conn.execute("SELECT id, name FROM roles").fetchall()
            role_map = {name: rid for rid, name in role_rows}
            # Resource definitions: pages and settings tabs
            page_resources = [
                'page:home', 'page:dashboard', 'page:systems',
                'page:cve_overview', 'page:baselines',
                'page:rules', 'page:promotion', 'page:sigma',
                'page:threats', 'page:heatmap', 'page:settings',
            ]
            tab_resources = [
                'tab:logging', 'tab:integrations', 'tab:sigma',
                'tab:classifications', 'tab:apikeys', 'tab:users',
            ]
            all_resources = page_resources + tab_resources
            # ADMIN: full read+write on everything
            if 'ADMIN' in role_map:
                for res in all_resources:
                    conn.execute(
                        "INSERT INTO role_permissions (role_id, resource, can_read, can_write) "
                        "VALUES (?, ?, true, true) ON CONFLICT DO NOTHING",
                        [role_map['ADMIN'], res],
                    )
            # ANALYST: read+write on most pages, read on settings (except users)
            if 'ANALYST' in role_map:
                analyst_rw = {
                    'page:home', 'page:dashboard', 'page:systems',
                    'page:cve_overview', 'page:baselines',
                    'page:rules', 'page:promotion', 'page:sigma',
                    'page:threats', 'page:heatmap',
                }
                analyst_read = {
                    'page:settings',
                    'tab:logging', 'tab:integrations', 'tab:sigma',
                    'tab:classifications', 'tab:apikeys',
                }
                for res in analyst_rw:
                    conn.execute(
                        "INSERT INTO role_permissions (role_id, resource, can_read, can_write) "
                        "VALUES (?, ?, true, true) ON CONFLICT DO NOTHING",
                        [role_map['ANALYST'], res],
                    )
                for res in analyst_read:
                    conn.execute(
                        "INSERT INTO role_permissions (role_id, resource, can_read, can_write) "
                        "VALUES (?, ?, true, false) ON CONFLICT DO NOTHING",
                        [role_map['ANALYST'], res],
                    )
            # ENGINEER: read-only on dashboards and reports
            if 'ENGINEER' in role_map:
                engineer_read = {
                    'page:home', 'page:dashboard', 'page:systems',
                    'page:cve_overview', 'page:baselines',
                    'page:rules', 'page:threats', 'page:heatmap',
                    'page:settings',
                    'tab:logging', 'tab:integrations', 'tab:sigma',
                    'tab:classifications', 'tab:apikeys',
                }
                for res in engineer_read:
                    conn.execute(
                        "INSERT INTO role_permissions (role_id, resource, can_read, can_write) "
                        "VALUES (?, ?, true, false) ON CONFLICT DO NOTHING",
                        [role_map['ENGINEER'], res],
                    )
            self._set_schema_version(conn, 22)
            logger.info("Migration 22: Created role_permissions table with defaults")

        # Migration 23: Profile tab rename + local auth password reset flow support
        if current_version < 23:
            # Rename settings permission resource from legacy tab:apikeys to tab:profile
            try:
                conn.execute(
                    "UPDATE role_permissions SET resource = 'tab:profile' WHERE resource = 'tab:apikeys'"
                )
            except Exception:
                pass

            # Ensure default Profile tab access matches expected role defaults.
            for role_name in ("ANALYST", "ENGINEER"):
                role_row = conn.execute("SELECT id FROM roles WHERE name = ?", [role_name]).fetchone()
                if not role_row:
                    continue
                role_id = role_row[0]
                exists = conn.execute(
                    "SELECT 1 FROM role_permissions WHERE role_id = ? AND resource = 'tab:profile'",
                    [role_id],
                ).fetchone()
                if exists:
                    conn.execute(
                        "UPDATE role_permissions SET can_read = true, can_write = true WHERE role_id = ? AND resource = 'tab:profile'",
                        [role_id],
                    )
                else:
                    conn.execute(
                        "INSERT INTO role_permissions (role_id, resource, can_read, can_write) VALUES (?, 'tab:profile', true, true)",
                        [role_id],
                    )

            # Ensure users table supports forced password change flow
            try:
                conn.execute("ALTER TABLE users ADD COLUMN change_on_next_login BOOLEAN DEFAULT false")
            except Exception:
                pass

            self._set_schema_version(conn, 23)
            logger.info("Migration 23: Renamed tab:apikeys to tab:profile and added users.change_on_next_login")

        # Migration 24: API key ownership metadata for role-based revocation
        if current_version < 24:
            try:
                conn.execute("ALTER TABLE api_keys ADD COLUMN created_by_user_id VARCHAR")
            except Exception:
                pass

            self._set_schema_version(conn, 24)
            logger.info("Migration 24: Added api_keys.created_by_user_id for ownership-aware revocation")

        # ── Migration 25: Multi-Tenant MSSP Architecture ──────────────
        if current_version < 25:
            # Step 1.2 — clients table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    name VARCHAR UNIQUE NOT NULL,
                    slug VARCHAR UNIQUE NOT NULL,
                    description VARCHAR,
                    is_default BOOLEAN DEFAULT false,
                    created_at TIMESTAMP DEFAULT now(),
                    updated_at TIMESTAMP DEFAULT now()
                )
            """)
            # Seed default client and capture its id
            conn.execute("""
                INSERT INTO clients (id, name, slug, description, is_default)
                VALUES (uuid(), 'Primary Client', 'primary', 'Default tenant — migrated from standalone deployment', true)
                ON CONFLICT (slug) DO NOTHING
            """)
            default_client_id = conn.execute(
                "SELECT id FROM clients WHERE slug = 'primary'"
            ).fetchone()[0]

            # Step 1.3 — user-to-client mapping table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_clients (
                    user_id VARCHAR NOT NULL,
                    client_id VARCHAR NOT NULL,
                    is_default BOOLEAN DEFAULT false,
                    assigned_at TIMESTAMP DEFAULT now(),
                    PRIMARY KEY (user_id, client_id)
                )
            """)
            # Backfill: assign every existing user to Primary Client
            existing_users = conn.execute("SELECT id FROM users").fetchall()
            for (uid,) in existing_users:
                conn.execute(
                    "INSERT INTO user_clients (user_id, client_id, is_default) "
                    "VALUES (?, ?, true) ON CONFLICT DO NOTHING",
                    [uid, default_client_id],
                )

            # Step 1.4 — per-client SIEM connection configs
            conn.execute("""
                CREATE TABLE IF NOT EXISTS client_siem_configs (
                    id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    client_id VARCHAR NOT NULL,
                    siem_type VARCHAR NOT NULL,
                    label VARCHAR NOT NULL,
                    base_url VARCHAR,
                    api_token_enc VARCHAR,
                    space_list VARCHAR,
                    extra_config JSON,
                    is_active BOOLEAN DEFAULT true,
                    created_at TIMESTAMP DEFAULT now(),
                    updated_at TIMESTAMP DEFAULT now()
                )
            """)
            # Backfill: migrate current env-var Elastic config into a row
            _kibana_url = os.environ.get("KIBANA_URL", "")
            _kibana_spaces = os.environ.get("KIBANA_SPACE_LIST", "default")
            if _kibana_url:
                conn.execute(
                    "INSERT INTO client_siem_configs "
                    "(client_id, siem_type, label, base_url, space_list) "
                    "VALUES (?, 'elastic', 'Primary Elastic', ?, ?)",
                    [default_client_id, _kibana_url, _kibana_spaces],
                )

            # Step 1.5 — add client_id to tenant-scoped tables
            _tenant_tables = [
                "systems", "hosts", "software_inventory",
                "detection_rules", "playbooks", "system_baselines",
                "system_baseline_snapshots", "vuln_detections",
                "applied_detections", "cve_technique_overrides",
                "classifications", "blind_spots", "api_keys",
            ]
            for tbl in _tenant_tables:
                try:
                    conn.execute(f"ALTER TABLE {tbl} ADD COLUMN client_id VARCHAR")
                except Exception:
                    pass  # Column may already exist
                conn.execute(f"UPDATE {tbl} SET client_id = ? WHERE client_id IS NULL", [default_client_id])

            # Step 1.5b — app_settings: composite key (key, client_id)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS app_settings_new (
                    key VARCHAR NOT NULL,
                    value VARCHAR,
                    client_id VARCHAR NOT NULL,
                    updated_at TIMESTAMP DEFAULT now(),
                    PRIMARY KEY (key, client_id)
                )
            """)
            conn.execute(f"""
                INSERT INTO app_settings_new (key, value, client_id, updated_at)
                SELECT key, value, '{default_client_id}', updated_at
                FROM app_settings
            """)
            conn.execute("DROP TABLE IF EXISTS app_settings")
            conn.execute("ALTER TABLE app_settings_new RENAME TO app_settings")

            # Step 1.6 — threat_actors hybrid scoping (nullable client_id)
            try:
                conn.execute("ALTER TABLE threat_actors ADD COLUMN client_id VARCHAR")
            except Exception:
                pass  # Column may already exist
            # Leave existing threat actors as NULL (shared/global MITRE data)

            # Step 1.7 — add page:clients permission resource for built-in roles
            role_rows = conn.execute("SELECT id, name FROM roles").fetchall()
            role_map = {name: rid for rid, name in role_rows}
            if 'ADMIN' in role_map:
                conn.execute(
                    "INSERT INTO role_permissions (role_id, resource, can_read, can_write) "
                    "VALUES (?, 'page:clients', true, true) ON CONFLICT DO NOTHING",
                    [role_map['ADMIN']],
                )
            for rname in ('ANALYST', 'ENGINEER'):
                if rname in role_map:
                    conn.execute(
                        "INSERT INTO role_permissions (role_id, resource, can_read, can_write) "
                        "VALUES (?, 'page:clients', true, false) ON CONFLICT DO NOTHING",
                        [role_map[rname]],
                    )

            self._set_schema_version(conn, 25)
            logger.info(
                f"Migration 25: Multi-tenant schema — clients table, user_clients, "
                f"client_siem_configs, client_id on {len(_tenant_tables)} tables, "
                f"app_settings composite key. Default client: {default_client_id}"
            )

        # ── Migration 26: SIEM Inventory & Management Hub ─────────────
        if current_version < 26:
            # Centralized SIEM inventory — shared SIEM objects linkable to clients
            conn.execute("""
                CREATE TABLE IF NOT EXISTS siem_inventory (
                    id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    label VARCHAR NOT NULL,
                    siem_type VARCHAR NOT NULL,
                    base_url VARCHAR,
                    api_token_enc VARCHAR,
                    space_list VARCHAR,
                    extra_config JSON,
                    is_active BOOLEAN DEFAULT true,
                    created_at TIMESTAMP DEFAULT now(),
                    updated_at TIMESTAMP DEFAULT now()
                )
            """)

            # Join table: many-to-many between clients and SIEM inventory
            conn.execute("""
                CREATE TABLE IF NOT EXISTS client_siem_map (
                    client_id VARCHAR NOT NULL,
                    siem_id VARCHAR NOT NULL,
                    assigned_at TIMESTAMP DEFAULT now(),
                    PRIMARY KEY (client_id, siem_id)
                )
            """)

            # Migrate existing client_siem_configs into siem_inventory
            existing_configs = conn.execute(
                "SELECT id, label, siem_type, base_url, api_token_enc, "
                "space_list, extra_config, is_active, client_id "
                "FROM client_siem_configs"
            ).fetchall()
            for cfg in existing_configs:
                cfg_id, label, siem_type, base_url, api_token_enc, \
                    space_list, extra_config, is_active, client_id = cfg
                # Insert into inventory (reuse original id)
                conn.execute(
                    "INSERT INTO siem_inventory "
                    "(id, label, siem_type, base_url, api_token_enc, "
                    "space_list, extra_config, is_active) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                    [cfg_id, label, siem_type, base_url, api_token_enc,
                     space_list, extra_config, is_active],
                )
                # Link to the original client
                conn.execute(
                    "INSERT INTO client_siem_map (client_id, siem_id) "
                    "VALUES (?, ?) ON CONFLICT DO NOTHING",
                    [client_id, cfg_id],
                )

            # Add page:management permission for ADMIN role
            role_rows = conn.execute("SELECT id, name FROM roles").fetchall()
            role_map = {name: rid for rid, name in role_rows}
            if 'ADMIN' in role_map:
                conn.execute(
                    "INSERT INTO role_permissions (role_id, resource, can_read, can_write) "
                    "VALUES (?, 'page:management', true, true) ON CONFLICT DO NOTHING",
                    [role_map['ADMIN']],
                )

            self._set_schema_version(conn, 26)
            logger.info(
                f"Migration 26: SIEM Inventory — siem_inventory table, "
                f"client_siem_map join table, migrated {len(existing_configs)} configs"
            )

        # ── Migration 27: Advanced SIEM fields ───────────────────────
        if current_version < 27:
            # Add separate URL fields and space fields
            conn.execute("ALTER TABLE siem_inventory ADD COLUMN IF NOT EXISTS elasticsearch_url VARCHAR")
            conn.execute("ALTER TABLE siem_inventory ADD COLUMN IF NOT EXISTS kibana_url VARCHAR")
            conn.execute("ALTER TABLE siem_inventory ADD COLUMN IF NOT EXISTS production_space VARCHAR")
            conn.execute("ALTER TABLE siem_inventory ADD COLUMN IF NOT EXISTS staging_space VARCHAR")

            # Migrate: base_url → kibana_url, space_list first entry → production_space
            conn.execute("UPDATE siem_inventory SET kibana_url = base_url WHERE kibana_url IS NULL AND base_url IS NOT NULL")
            # space_list was comma-separated; split into production/staging
            rows = conn.execute("SELECT id, space_list FROM siem_inventory WHERE space_list IS NOT NULL").fetchall()
            for row_id, space_list in rows:
                parts = [s.strip() for s in space_list.split(",") if s.strip()]
                prod = parts[0] if parts else None
                stag = parts[1] if len(parts) > 1 else None
                conn.execute(
                    "UPDATE siem_inventory SET production_space = ?, staging_space = ? WHERE id = ?",
                    [prod, stag, row_id],
                )

            self._set_schema_version(conn, 27)
            logger.info("Migration 27: Advanced SIEM fields — elasticsearch_url, kibana_url, production_space, staging_space")

        # ── Migration 28: Environment-Aware SIEM Roles ───────────────
        if current_version < 28:
            # Rebuild client_siem_map with new composite PK
            # (client_id, siem_id, environment_role) and split dual-space
            # configs into separate production/staging rows.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS client_siem_map_new (
                    client_id VARCHAR NOT NULL,
                    siem_id VARCHAR NOT NULL,
                    environment_role VARCHAR NOT NULL DEFAULT 'production',
                    space VARCHAR,
                    assigned_at TIMESTAMP DEFAULT now(),
                    PRIMARY KEY (client_id, siem_id, environment_role)
                )
            """)

            # Copy existing mappings as 'production' rows, pulling
            # production_space from siem_inventory where available.
            conn.execute("""
                INSERT INTO client_siem_map_new
                    (client_id, siem_id, environment_role, space, assigned_at)
                SELECT m.client_id, m.siem_id, 'production',
                       s.production_space, m.assigned_at
                FROM client_siem_map m
                JOIN siem_inventory s ON s.id = m.siem_id
            """)

            # For SIEMs that also had a staging_space, create a second
            # 'staging' row so each space gets its own environment role.
            conn.execute("""
                INSERT INTO client_siem_map_new
                    (client_id, siem_id, environment_role, space, assigned_at)
                SELECT m.client_id, m.siem_id, 'staging',
                       s.staging_space, m.assigned_at
                FROM client_siem_map m
                JOIN siem_inventory s ON s.id = m.siem_id
                WHERE s.staging_space IS NOT NULL
                  AND s.staging_space != ''
            """)

            conn.execute("DROP TABLE client_siem_map")
            conn.execute("ALTER TABLE client_siem_map_new RENAME TO client_siem_map")

            self._set_schema_version(conn, 28)
            logger.info(
                "Migration 28: Environment-aware SIEM roles — "
                "environment_role + space on client_siem_map, "
                "split dual-space configs into separate rows"
            )

        # ── Migration 29: Database-Per-Tenant — db_filename on clients ──
        if current_version < 29:
            try:
                conn.execute(
                    "ALTER TABLE clients ADD COLUMN db_filename VARCHAR"
                )
            except Exception:
                pass  # Column may already exist
            self._set_schema_version(conn, 29)
            logger.info(
                "Migration 29: Added clients.db_filename for "
                "database-per-tenant physical isolation"
            )

        # ── Migration 30: Sigma Rules Index (shared DB only) ─────────
        if current_version < 30:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sigma_rules_index (
                    rule_id   VARCHAR PRIMARY KEY,
                    title     VARCHAR,
                    level     VARCHAR,
                    status    VARCHAR,
                    product   VARCHAR,
                    category  VARCHAR,
                    service   VARCHAR,
                    techniques VARCHAR[],
                    tactics   VARCHAR[],
                    file_path VARCHAR,
                    indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            try:
                conn.execute("CREATE INDEX idx_sigma_product  ON sigma_rules_index(product)")
                conn.execute("CREATE INDEX idx_sigma_service  ON sigma_rules_index(service)")
                conn.execute("CREATE INDEX idx_sigma_category ON sigma_rules_index(category)")
            except Exception:
                pass  # Indexes may already exist
            self._set_schema_version(conn, 30)
            logger.info(
                "Migration 30: Created sigma_rules_index table "
                "for Sigma logsource metadata indexing"
            )

        # ── Migration 31: OpenCTI and GitLab inventory tables ────────
        if current_version < 31:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS opencti_inventory (
                    id VARCHAR PRIMARY KEY DEFAULT (gen_random_uuid()::VARCHAR),
                    label VARCHAR NOT NULL,
                    url VARCHAR NOT NULL,
                    token_enc VARCHAR,
                    is_active BOOLEAN DEFAULT true,
                    created_at TIMESTAMP DEFAULT now(),
                    updated_at TIMESTAMP DEFAULT now()
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS client_opencti_map (
                    client_id VARCHAR NOT NULL,
                    opencti_id VARCHAR NOT NULL,
                    assigned_at TIMESTAMP DEFAULT now(),
                    PRIMARY KEY (client_id, opencti_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS gitlab_inventory (
                    id VARCHAR PRIMARY KEY DEFAULT (gen_random_uuid()::VARCHAR),
                    label VARCHAR NOT NULL,
                    url VARCHAR NOT NULL,
                    token_enc VARCHAR,
                    default_group VARCHAR,
                    is_active BOOLEAN DEFAULT true,
                    created_at TIMESTAMP DEFAULT now(),
                    updated_at TIMESTAMP DEFAULT now()
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS client_gitlab_map (
                    client_id VARCHAR NOT NULL,
                    gitlab_id VARCHAR NOT NULL,
                    assigned_at TIMESTAMP DEFAULT now(),
                    PRIMARY KEY (client_id, gitlab_id)
                )
            """)
            self._set_schema_version(conn, 31)
            logger.info(
                "Migration 31: Created opencti_inventory, client_opencti_map, "
                "gitlab_inventory, client_gitlab_map tables"
            )

        # ── Migration 32: Keycloak inventory table ────────────────────
        if current_version < 32:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS keycloak_inventory (
                    id VARCHAR PRIMARY KEY DEFAULT (gen_random_uuid()::VARCHAR),
                    label VARCHAR NOT NULL,
                    url VARCHAR NOT NULL,
                    realm VARCHAR NOT NULL DEFAULT 'master',
                    client_id_enc VARCHAR,
                    client_secret_enc VARCHAR,
                    is_active BOOLEAN DEFAULT true,
                    created_at TIMESTAMP DEFAULT now(),
                    updated_at TIMESTAMP DEFAULT now()
                )
            """)
            self._set_schema_version(conn, 32)
            logger.info("Migration 32: Created keycloak_inventory table")

        # ── Migration 33: Management Hub consolidation ────────────────
        # 1. Per-instance Test-Connection status persistence
        # 2. Logging-on-SIEM (rule-score export configured per SIEM)
        # 3. Sigma asset (pipeline/template) tenant assignment
        # 4. Migrate legacy app_settings.rule_log_* keys to each tenant's
        #    primary client → first production SIEM (best-effort).
        if current_version < 33:
            for tbl in ("siem_inventory", "opencti_inventory",
                        "gitlab_inventory", "keycloak_inventory"):
                conn.execute(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS last_test_status VARCHAR")
                conn.execute(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS last_test_at TIMESTAMP")
                conn.execute(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS last_test_message VARCHAR")

            conn.execute("ALTER TABLE siem_inventory ADD COLUMN IF NOT EXISTS log_enabled BOOLEAN DEFAULT FALSE")
            conn.execute("ALTER TABLE siem_inventory ADD COLUMN IF NOT EXISTS log_target_space VARCHAR")
            conn.execute("ALTER TABLE siem_inventory ADD COLUMN IF NOT EXISTS log_schedule VARCHAR DEFAULT '00:00'")
            conn.execute("ALTER TABLE siem_inventory ADD COLUMN IF NOT EXISTS log_retention_days INTEGER DEFAULT 7")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS sigma_asset_assignments (
                    asset_type VARCHAR NOT NULL,
                    filename   VARCHAR NOT NULL,
                    client_id  VARCHAR NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (asset_type, filename, client_id)
                )
            """)

            # Legacy app_settings rule_log_* migration → primary SIEM per client.
            # app_settings has composite PK (client_id, key, value).  We move the
            # global toggle/schedule/retention onto the FIRST production SIEM
            # linked to each client and drop the legacy rows.  log_target_space
            # stays NULL so the user explicitly picks production vs staging.
            try:
                migrated_clients = 0
                client_rows = conn.execute(
                    "SELECT DISTINCT client_id FROM app_settings "
                    "WHERE key IN ('rule_log_enabled','rule_log_schedule','rule_log_retention_days')"
                ).fetchall()
                for (cid,) in client_rows:
                    siem_row = conn.execute(
                        "SELECT siem_id FROM client_siem_map "
                        "WHERE client_id = ? AND environment_role = 'production' "
                        "ORDER BY assigned_at LIMIT 1",
                        [cid],
                    ).fetchone()
                    if not siem_row:
                        continue
                    siem_id = siem_row[0]
                    settings_map = dict(conn.execute(
                        "SELECT key, value FROM app_settings WHERE client_id = ? "
                        "AND key IN ('rule_log_enabled','rule_log_schedule','rule_log_retention_days')",
                        [cid],
                    ).fetchall())
                    enabled = str(settings_map.get('rule_log_enabled', 'false')).lower() == 'true'
                    schedule = settings_map.get('rule_log_schedule', '00:00') or '00:00'
                    try:
                        retention = int(settings_map.get('rule_log_retention_days', 7) or 7)
                    except (TypeError, ValueError):
                        retention = 7
                    conn.execute(
                        "UPDATE siem_inventory SET log_enabled = ?, log_schedule = ?, "
                        "log_retention_days = ? WHERE id = ?",
                        [enabled, schedule, retention, siem_id],
                    )
                    migrated_clients += 1
                conn.execute(
                    "DELETE FROM app_settings WHERE key IN "
                    "('rule_log_enabled','rule_log_schedule','rule_log_retention_days')"
                )
                logger.info(f"Migration 33: migrated logging config for {migrated_clients} client(s) to SIEM inventory")
            except Exception as exc:
                logger.warning(f"Migration 33: legacy log-settings migration skipped: {exc}")

            self._set_schema_version(conn, 33)
            logger.info(
                "Migration 33: Management Hub consolidation — last_test_* columns on "
                "all 4 inventory tables, log_enabled/log_target_space/log_schedule/"
                "log_retention_days on siem_inventory, sigma_asset_assignments table"
            )

        # ── Migration 34: Tenant-scoped roles + superadmin flag + KC group passthrough ──
        # - Adds users.is_superadmin (mapped from Keycloak `superadmin` group).
        # - Recreates user_roles with a client_id column so an ADMIN in DC is not
        #   automatically an ADMIN in Marvel. Existing global roles are expanded
        #   into one row per (user, client) the user is assigned to, preserving
        #   current effective behaviour.
        if current_version < 34:
            # 34.1 — superadmin flag on users.
            try:
                cols = {
                    r[1] for r in conn.execute("PRAGMA table_info('users')").fetchall()
                }
            except Exception:
                cols = set()
            if "is_superadmin" not in cols:
                conn.execute(
                    "ALTER TABLE users ADD COLUMN is_superadmin BOOLEAN DEFAULT false"
                )

            # 34.2 — Recreate user_roles with client_id.
            # Read existing rows, drop, recreate with the new PK, then expand each
            # existing (user_id, role_id) into one row per assigned client.
            try:
                legacy_rows = conn.execute(
                    "SELECT user_id, role_id FROM user_roles"
                ).fetchall()
            except Exception:
                legacy_rows = []

            try:
                conn.execute("DROP TABLE IF EXISTS user_roles")
            except Exception:
                pass

            conn.execute(
                """
                CREATE TABLE user_roles (
                    user_id VARCHAR NOT NULL,
                    client_id VARCHAR NOT NULL,
                    role_id VARCHAR NOT NULL,
                    assigned_at TIMESTAMP DEFAULT now(),
                    PRIMARY KEY (user_id, client_id, role_id)
                )
                """
            )

            # Backfill: each legacy global role → one row per (user, client) the
            # user is already assigned to. If the user has no client assignment,
            # fall back to the default client so they don't lose access.
            default_cid_row = conn.execute(
                "SELECT id FROM clients WHERE is_default = true LIMIT 1"
            ).fetchone()
            default_cid = default_cid_row[0] if default_cid_row else None

            backfilled = 0
            for uid, rid in legacy_rows:
                client_ids = [
                    r[0]
                    for r in conn.execute(
                        "SELECT client_id FROM user_clients WHERE user_id = ?",
                        [uid],
                    ).fetchall()
                ]
                if not client_ids and default_cid:
                    client_ids = [default_cid]
                for cid in client_ids:
                    conn.execute(
                        "INSERT INTO user_roles (user_id, client_id, role_id) "
                        "VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                        [uid, cid, rid],
                    )
                    backfilled += 1

            # 34.3 — Promote any existing 'admin' user account to superadmin so the
            # bootstrap account keeps full management access through the migration.
            try:
                conn.execute(
                    "UPDATE users SET is_superadmin = true "
                    "WHERE LOWER(username) = 'admin' AND auth_provider = 'local'"
                )
            except Exception:
                pass

            self._set_schema_version(conn, 34)
            logger.info(
                "Migration 34: Tenant-scoped roles — added users.is_superadmin, "
                "rebuilt user_roles with client_id, backfilled %d (user,client,role) "
                "rows from %d legacy global rows",
                backfilled,
                len(legacy_rows),
            )

        # ── Migration 35: Tenant-scoped role permissions ──
        # Adds `client_id` to role_permissions so the Role Templates matrix
        # is edited per-tenant from the client detail page. Existing global
        # rows (client_id IS NULL) are fanned out into one per current client
        # and then dropped, so every tenant starts with the previous defaults.
        if current_version < 35:
            try:
                conn.execute(
                    """
                    CREATE TABLE role_permissions_v35 (
                        id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                        role_id VARCHAR NOT NULL,
                        client_id VARCHAR,
                        resource VARCHAR NOT NULL,
                        can_read BOOLEAN DEFAULT false,
                        can_write BOOLEAN DEFAULT false,
                        UNIQUE(role_id, client_id, resource)
                    )
                    """
                )
                rp35_rows = 0
                client_rows = conn.execute("SELECT id FROM clients").fetchall()
                if client_rows:
                    legacy = conn.execute(
                        "SELECT role_id, resource, can_read, can_write FROM role_permissions"
                    ).fetchall()
                    for cid, in client_rows:
                        for role_id, resource, cr, cw in legacy:
                            conn.execute(
                                "INSERT INTO role_permissions_v35 "
                                "(role_id, client_id, resource, can_read, can_write) "
                                "VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                                [role_id, cid, resource, cr, cw],
                            )
                            rp35_rows += 1
                conn.execute("DROP TABLE role_permissions")
                conn.execute("ALTER TABLE role_permissions_v35 RENAME TO role_permissions")
            except Exception as exc:
                logger.error(f"Migration 35 failed: {exc}")
                raise
            self._set_schema_version(conn, 35)
            logger.info(
                "Migration 35: Tenant-scoped role permissions — fanned legacy "
                "global rows into %d per-(role,client,resource) rows.",
                rp35_rows,
            )

        # ── Migration 36: Per-SIEM rule-log destination path ──
        # Restores the operator-controlled output directory that existed pre-4.0.8
        # (when the global ``RULE_LOG_PATH`` setting drove the exporter). The new
        # column is per-SIEM so two SIEMs can write to different mounts; NULL means
        # "use the container default" (``/app/data/log/rules/<siem_label>/``).
        if current_version < 36:
            try:
                conn.execute(
                    "ALTER TABLE siem_inventory ADD COLUMN IF NOT EXISTS log_destination_path VARCHAR"
                )
            except Exception as exc:
                logger.error(f"Migration 36 failed: {exc}")
                raise
            self._set_schema_version(conn, 36)
            logger.info(
                "Migration 36: Added siem_inventory.log_destination_path "
                "(per-SIEM rule-log output directory; NULL = container default)"
            )

        # ── Migration 37: SIEM-aware detection_rules ──
        # Pre-4.0.13 the table PK was (rule_id, space) only — a global identifier
        # with no notion of which SIEM the rule came from. When a tenant has two
        # SIEMs that both expose the same Kibana space name (e.g. 'production'),
        # rules from both SIEMs collide on insert (last writer wins) and the
        # Test Rule / Promotion / coverage queries silently route to the wrong
        # Kibana — manifesting as 401s, missing rules, and incorrect counts.
        # Adds a NOT NULL ``siem_id`` column, rebuilds PK as (rule_id, siem_id),
        # and WIPES the table. The next sync rebuilds it correctly with each
        # row's true ``siem_id`` populated by the per-SIEM fetch loop in
        # ``services/sync.py``. No operator data is lost (the table is purely
        # cached SIEM state — no manual notes, overrides, or annotations live
        # here). The UI surfaces a banner asking the operator to run a sync.
        if current_version < 37:
            try:
                row_count = conn.execute(
                    "SELECT COUNT(*) FROM detection_rules"
                ).fetchone()[0]
            except Exception:
                row_count = 0

            try:
                conn.execute("DROP TABLE IF EXISTS detection_rules")
                conn.execute("""
                    CREATE TABLE detection_rules (
                        rule_id VARCHAR NOT NULL,
                        siem_id VARCHAR NOT NULL,
                        name VARCHAR,
                        severity VARCHAR,
                        author VARCHAR,
                        enabled INTEGER,
                        space VARCHAR,
                        score INTEGER,
                        quality_score INTEGER,
                        meta_score INTEGER,
                        score_mapping INTEGER,
                        score_field_type INTEGER,
                        score_search_time INTEGER,
                        score_language INTEGER,
                        score_note INTEGER,
                        score_override INTEGER,
                        score_tactics INTEGER,
                        score_techniques INTEGER,
                        score_author INTEGER,
                        score_highlights INTEGER,
                        last_updated TIMESTAMP,
                        mitre_ids VARCHAR[],
                        raw_data JSON,
                        PRIMARY KEY (rule_id, siem_id)
                    )
                """)
            except Exception as exc:
                logger.error(f"Migration 37 failed: {exc}")
                raise
            self._set_schema_version(conn, 37)
            logger.warning(
                "Migration 37: detection_rules rebuilt with PK (rule_id, siem_id) "
                "and WIPED (%d rows removed). Trigger a sync (Settings → Sync, or "
                "POST /api/admin/sync) to repopulate with siem_id correctly "
                "assigned per SIEM. The next scheduled sync will also do this "
                "automatically. See CHANGELOG [4.0.13].",
                row_count,
            )

        # ── Migration 38: Move space ownership to client_siem_map only ──
        # The 4.1.x data model: ``siem_inventory`` is a credentials holder
        # only (URL + API key). The ONLY place that decides which Kibana space
        # a tenant uses for which environment role is ``client_siem_map``
        # (one row per client × siem × role × space).
        #
        # Migration 27 added ``production_space`` and ``staging_space`` to
        # ``siem_inventory`` as a property of the SIEM itself. That broke the
        # model: a SIEM with ``production_space='one'`` and
        # ``staging_space='two'`` was synced from BOTH spaces even when no
        # tenant had linked it (sync.py fell back to those columns when
        # ``client_siem_map`` had no row), and operators couldn't have two
        # tenants use the same SIEM with different role↔space mappings.
        #
        # This migration: (1) for every existing ``siem_inventory`` row that
        # has a ``production_space`` and at least one client linked to that
        # SIEM, ensure a ``client_siem_map`` row exists for
        # ``(client, siem, 'production', production_space)`` — INSERT-only
        # with ``ON CONFLICT DO NOTHING`` so any operator-set row wins.
        # Same for staging. (2) Drop the two columns from ``siem_inventory``.
        if current_version < 38:
            try:
                # Discover every (client_id, siem_id) pair currently linked.
                pairs = conn.execute(
                    "SELECT DISTINCT client_id, siem_id FROM client_siem_map"
                ).fetchall()
                # Build {siem_id: (production_space, staging_space)}
                rows = conn.execute(
                    "SELECT id, "
                    "       NULLIF(TRIM(production_space), ''), "
                    "       NULLIF(TRIM(staging_space), '') "
                    "FROM siem_inventory"
                ).fetchall()
                siem_spaces = {r[0]: (r[1], r[2]) for r in rows}
                inserted = 0
                for client_id, siem_id in pairs:
                    prod, stage = siem_spaces.get(siem_id, (None, None))
                    if prod:
                        cur = conn.execute(
                            "INSERT INTO client_siem_map "
                            "(client_id, siem_id, environment_role, space) "
                            "VALUES (?, ?, 'production', ?) "
                            "ON CONFLICT DO NOTHING",
                            [client_id, siem_id, prod],
                        )
                        try:
                            inserted += cur.rowcount or 0
                        except Exception:
                            pass
                    if stage:
                        cur = conn.execute(
                            "INSERT INTO client_siem_map "
                            "(client_id, siem_id, environment_role, space) "
                            "VALUES (?, ?, 'staging', ?) "
                            "ON CONFLICT DO NOTHING",
                            [client_id, siem_id, stage],
                        )
                        try:
                            inserted += cur.rowcount or 0
                        except Exception:
                            pass

                # Drop the now-redundant columns. DuckDB supports
                # ``ALTER TABLE ... DROP COLUMN`` since 0.7; wrap in try so
                # an older engine doesn't brick the upgrade.
                for col in ("production_space", "staging_space"):
                    try:
                        conn.execute(
                            f"ALTER TABLE siem_inventory DROP COLUMN IF EXISTS {col}"
                        )
                    except Exception as exc:
                        logger.warning(
                            f"Migration 38: could not drop "
                            f"siem_inventory.{col}: {exc!r}. The column "
                            f"will be ignored by application code regardless."
                        )
            except Exception as exc:
                logger.error(f"Migration 38 failed: {exc}")
                raise
            self._set_schema_version(conn, 38)
            logger.info(
                "Migration 38: client_siem_map is now the sole source of "
                "(siem, role, space). Inserted %d backfilled rows from "
                "legacy siem_inventory.production_space/staging_space; "
                "those columns dropped.",
                inserted,
            )

        # ── Migration 39: NEUTERED in 4.1.8 ─────────────────────────────
        # Original 4.1.5 intent: rewrite ``client_siem_map.space`` rows
        # whose value was literally ``'production'`` / ``'staging'`` to
        # ``'default'``, on the theory that those values were always
        # operator confusion between the environment-role dropdown and the
        # Kibana-space input. That theory was wrong — Kibana permits space
        # ids with those names, and at least one standalone deployment
        # legitimately uses them. Migration 39 was destroying valid
        # mappings on every container restart, then the form-side reject
        # made it impossible to recreate them. Now a no-op: we only bump
        # ``schema_version`` so existing DBs that already ran the original
        # migration still advance to ``39`` cleanly. Any rows the original
        # migration rewrote to ``'default'`` cannot be recovered
        # automatically — operators must re-pick the correct space via the
        # link-to-tenant form (which now accepts ``production`` / ``staging``
        # iff Kibana confirms they exist).
        if current_version < 39:
            logger.info(
                "Migration 39: skipped (neutered in 4.1.8). 'production' / "
                "'staging' are now allowed as Kibana space ids when the "
                "live Kibana validator confirms they exist on the SIEM."
            )
            self._set_schema_version(conn, 39)

        # ── Migration 40: drop stale threat_actors snapshot from tenant DBs ─
        # Pre-4.1.5 tenant DBs received a full ``threat_actors`` mirror at
        # provisioning time and on every subsequent shared-data sync. That
        # mirrored EVERY tenant's OpenCTI feed into EVERY other tenant. From
        # 4.1.5 onward MITRE actors are read live from the shared DB and
        # OpenCTI is written per-tenant by the sync service, so the stale
        # snapshot must go. The next OpenCTI sync re-populates each tenant
        # with only its own intel; MITRE is unaffected because it is no
        # longer mirrored.
        if current_version < 40:
            try:
                rows = conn.execute(
                    "SELECT id, name, db_filename FROM clients "
                    "WHERE db_filename IS NOT NULL"
                ).fetchall()
            except Exception as exc:
                logger.warning(
                    f"Migration 40: could not list tenant DBs: {exc}"
                )
                rows = []
            wiped_total = 0
            tenant_count = 0
            import os as _os
            data_dir = _os.path.dirname(self.db_path)
            for cid, cname, fname in rows:
                tdb_path = _os.path.join(data_dir, fname)
                if not _os.path.exists(tdb_path):
                    logger.warning(
                        f"Migration 40: tenant DB missing for client "
                        f"{cname} ({cid[:8]}): {tdb_path} — skipping"
                    )
                    continue
                try:
                    # Use a fresh standalone connection per tenant DB so we
                    # don't fight the connection pool during boot.
                    import duckdb as _duckdb
                    tconn = _duckdb.connect(tdb_path)
                    try:
                        try:
                            cnt = tconn.execute(
                                "SELECT COUNT(*) FROM threat_actors"
                            ).fetchone()[0] or 0
                        except Exception:
                            cnt = 0
                        if cnt:
                            tconn.execute("DELETE FROM threat_actors")
                            wiped_total += cnt
                            logger.info(
                                f"Migration 40: wiped {cnt} stale "
                                f"threat_actors row(s) from tenant DB "
                                f"{fname} ({cname})"
                            )
                        tenant_count += 1
                    finally:
                        tconn.close()
                except Exception as exc:
                    logger.error(
                        f"Migration 40: failed to wipe {fname} ({cname}): "
                        f"{exc}"
                    )
            if tenant_count:
                logger.warning(
                    "Migration 40: cleared %d stale threat_actors row(s) "
                    "across %d tenant DB(s). Re-run OpenCTI sync from "
                    "Management to re-populate per-tenant intel.",
                    wiped_total, tenant_count,
                )
            else:
                logger.info(
                    "Migration 40: no tenant DBs registered — nothing to "
                    "clean up."
                )
            self._set_schema_version(conn, 40)

        # ── Migration 41: persistent Kibana spaces cache ───────────────────
        # Pre-4.1.6 the spaces dropdown on the tenant link form relied on a
        # 60-second in-memory cache populated only by Test Connection. After
        # an app restart the dropdown silently went empty until either an
        # operator hit Test, or a successful sync back-filled detection_rules.
        # Persist the spaces a Test Connection discovers so the dropdown
        # survives restarts and works without a sync-first chicken-and-egg.
        if current_version < 41:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS siem_kibana_spaces (
                    siem_id VARCHAR NOT NULL,
                    space VARCHAR NOT NULL,
                    discovered_at TIMESTAMP DEFAULT now(),
                    PRIMARY KEY (siem_id, space)
                )
            """)
            self._set_schema_version(conn, 41)

        # ── Migration 42: structured sync history (4.1.7 Phase D) ──────────
        # Both run_mitre_sync (Phase C) and run_elastic_sync now produce
        # structured per-run results that are useful for support triage and
        # for the new read-only Query tab's predefined searches. Persist a
        # bounded history so an operator can answer "did MITRE sync the last
        # time it ran, and how long did it take?" without scraping logs.
        # Idempotent: CREATE TABLE IF NOT EXISTS, no destructive operations.
        if current_version < 42:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_history (
                    id           VARCHAR PRIMARY KEY,
                    sync_kind    VARCHAR NOT NULL,
                    status       VARCHAR NOT NULL,
                    started_at   TIMESTAMP NOT NULL DEFAULT now(),
                    duration_ms  INTEGER,
                    total_count  INTEGER,
                    detail_json  VARCHAR,
                    error        VARCHAR
                )
            """)
            # Lookup index for the lookup pattern used by the Query tab
            # ("recent sync runs by kind"). DuckDB silently ignores this if
            # already present.
            try:
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_sync_history_kind_started "
                    "ON sync_history (sync_kind, started_at DESC)"
                )
            except Exception as exc:  # noqa: BLE001 — non-fatal optimisation
                logger.warning(f"Migration 42: index create skipped: {exc!r}")
            # Also add an index on siem_kibana_spaces.siem_id for the
            # persistent fallback lookup, which is now hit on every render
            # of the link-to-tenant dropdown thanks to the Phase B refactor.
            # DuckDB's primary-key index covers (siem_id, space), but a
            # standalone (siem_id) index is cheaper for the COUNT(*)/SELECT
            # pattern. Best-effort.
            try:
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_siem_kibana_spaces_siem "
                    "ON siem_kibana_spaces (siem_id)"
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"Migration 42: spaces index skipped: {exc!r}")
            self._set_schema_version(conn, 42)

        # ── Migration 43: Query templates + SIEM URL compatibility ──────────
        # Adds persistent templates for the Management Query tab so operators
        # can save/delete named SQL snippets. Also backfills legacy
        # siem_inventory.base_url from kibana_url so older diagnostics that
        # still project base_url do not show misleading NULL values.
        if current_version < 43:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS query_templates (
                    id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    name VARCHAR NOT NULL UNIQUE,
                    sql_text VARCHAR NOT NULL,
                    target_key VARCHAR NOT NULL DEFAULT 'shared',
                    created_by_user_id VARCHAR,
                    created_at TIMESTAMP DEFAULT now(),
                    updated_at TIMESTAMP DEFAULT now()
                )
            """)
            try:
                conn.execute(
                    "UPDATE siem_inventory SET base_url = kibana_url "
                    "WHERE (base_url IS NULL OR TRIM(base_url) = '') "
                    "AND kibana_url IS NOT NULL"
                )
            except Exception as exc:
                logger.warning(f"Migration 43: base_url backfill skipped: {exc!r}")
            self._set_schema_version(conn, 43)
            logger.info(
                "Migration 43: added query_templates and backfilled "
                "siem_inventory.base_url from kibana_url"
            )

        # ── Migration 44: detection_rules PK adds space ────────────────────
        # Pre-4.1.12 the PK was (rule_id, siem_id). That collides whenever a
        # single SIEM exposes the same rule_id in more than one Kibana space
        # (e.g. an operator clones the base prebuilt rule into both ``one``
        # and ``two`` so different tenants can map their staging vs production
        # routes onto the same SIEM). Sync wrote both rows into the shared
        # cache, then ``_distribute_rules_to_tenants`` blew up with
        # ``Constraint Error: Duplicate key "rule_id: ..., siem_id: ..."``
        # the moment a tenant's mapping resolved to two of those spaces.
        # Tenant DBs ended up with ZERO rows, so Rule Health and Promotion
        # showed nothing for that client.
        #
        # Fix: rebuild the table with PK ``(rule_id, siem_id, space)``. The
        # composite isolation contract from 4.1.12 is unchanged — readers
        # still filter on ``(siem_id, space)`` pairs from
        # ``client_siem_map`` — but a single rule can now legitimately exist
        # in N rows of the same SIEM (one per Kibana space). Tenant
        # ``detection_rules`` PK is bumped in lockstep by
        # ``services/sync._ensure_tenant_detection_rules_schema`` and
        # ``services/tenant_manager`` (new tenant DBs).
        #
        # Cache-only data: WIPE and let the next sync repopulate. No
        # operator state is lost (no manual notes/overrides live here).
        if current_version < 44:
            try:
                row_count = conn.execute(
                    "SELECT COUNT(*) FROM detection_rules"
                ).fetchone()[0]
            except Exception:
                row_count = 0
            try:
                conn.execute("DROP TABLE IF EXISTS detection_rules")
                conn.execute("""
                    CREATE TABLE detection_rules (
                        rule_id VARCHAR NOT NULL,
                        siem_id VARCHAR NOT NULL,
                        name VARCHAR,
                        severity VARCHAR,
                        author VARCHAR,
                        enabled INTEGER,
                        space VARCHAR NOT NULL,
                        score INTEGER,
                        quality_score INTEGER,
                        meta_score INTEGER,
                        score_mapping INTEGER,
                        score_field_type INTEGER,
                        score_search_time INTEGER,
                        score_language INTEGER,
                        score_note INTEGER,
                        score_override INTEGER,
                        score_tactics INTEGER,
                        score_techniques INTEGER,
                        score_author INTEGER,
                        score_highlights INTEGER,
                        last_updated TIMESTAMP,
                        mitre_ids VARCHAR[],
                        raw_data JSON,
                        PRIMARY KEY (rule_id, siem_id, space)
                    )
                """)
            except Exception as exc:
                logger.error(f"Migration 44 failed: {exc}")
                raise
            self._set_schema_version(conn, 44)
            logger.warning(
                "Migration 44: detection_rules rebuilt with PK "
                "(rule_id, siem_id, space) and WIPED (%d rows removed). "
                "Trigger a sync (Settings → Sync, or POST /api/admin/sync) "
                "to repopulate. Tenant DBs will be re-distributed on the "
                "same call. See CHANGELOG [4.1.12].",
                row_count,
            )

        # ── Migration 45: drop shared detection_rules ─────────────────────
        # Detection rules are per-tenant since 4.1.13. The shared cache
        # ``detection_rules`` table in ``tide.duckdb`` is no longer used —
        # ``run_elastic_sync(client_id)`` writes directly to the tenant's
        # own DuckDB file via ``tenant_context_for(client_id)`` and every
        # reader (`get_rules`, `get_rule_health_metrics`, etc.) routes to
        # the tenant DB through the contextvar in ``DatabaseService.get_connection()``.
        #
        # Cache-only data: drop the table outright. The next user-triggered
        # sync per tenant repopulates that tenant's DuckDB file. No
        # operator state is lost. See CHANGELOG [4.1.13].
        if current_version < 45:
            try:
                row_count = conn.execute(
                    "SELECT COUNT(*) FROM detection_rules"
                ).fetchone()[0]
            except Exception:
                row_count = 0
            try:
                conn.execute("DROP TABLE IF EXISTS detection_rules")
            except Exception as exc:
                logger.error(f"Migration 45 failed to drop shared detection_rules: {exc}")
                raise
            self._set_schema_version(conn, 45)
            logger.warning(
                "Migration 45: shared detection_rules dropped (%d rows removed). "
                "Detection rules are per-tenant since 4.1.13 — sync writes "
                "directly to the tenant DuckDB file. Each tenant must trigger "
                "a sync (Sync button on /rules or /promotion) to repopulate "
                "its own rules. See CHANGELOG [4.1.13].",
                row_count,
            )

        # ── Migration 46: opencti_inventory.kind column ──────────────────
        # The native CTI engine reuses ``opencti_inventory`` rows as the
        # source list for the new transitional STIX-bundle fetcher, but
        # the legacy actor-only sync (cti_helper.get_threat_landscape →
        # save_octi_threat_actors_to_active_db) must keep working
        # untouched on existing rows. ``kind`` lets a single inventory
        # row declare which fetcher(s) it participates in:
        #   * 'actors'  — legacy intrusion-set/TTP sync only (default,
        #                 matches pre-4.1.20 behaviour for existing rows)
        #   * 'cti'     — new STIX bundle pull into the per-tenant
        #                 cti_<tenant>.duckdb only
        #   * 'both'    — same instance serves both fetchers
        # The column is additive; no code path is changed by this
        # migration. The CTI fetcher introduced in a follow-up step will
        # filter ``WHERE kind IN ('cti', 'both')`` and the legacy sync
        # is unchanged.
        if current_version < 46:
            try:
                conn.execute(
                    "ALTER TABLE opencti_inventory "
                    "ADD COLUMN IF NOT EXISTS kind VARCHAR DEFAULT 'actors'"
                )
                # Backfill any pre-existing NULLs (DuckDB DEFAULT only
                # applies to subsequent INSERTs, not to rows present
                # before the column existed).
                conn.execute(
                    "UPDATE opencti_inventory SET kind = 'actors' "
                    "WHERE kind IS NULL"
                )
            except Exception as exc:
                logger.error(f"Migration 46 failed: {exc}")
                raise
            self._set_schema_version(conn, 46)
            logger.info(
                "Migration 46: added opencti_inventory.kind "
                "(default 'actors'; new CTI fetcher will opt-in via "
                "'cti' or 'both')."
            )

        # ── Migration 47: cti_connectors + cti_connector_clients ─────────
        # Generic per-vendor connector framework. Replaces the
        # OpenCTI-only ``opencti_inventory`` shape with a vendor-tagged
        # table whose vendor-specific knobs live in ``config_json``.
        # The legacy ``opencti_inventory`` / ``client_opencti_map`` tables
        # are kept for one release and back-filled into
        # ``cti_connectors(vendor='opencti')`` so the new UI shows them
        # on day one. The legacy CRUD paths and the
        # ``cti_helper.get_threat_landscape`` actor sync are untouched
        # by this migration.
        if current_version < 47:
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cti_connectors (
                        id VARCHAR PRIMARY KEY DEFAULT (gen_random_uuid()::VARCHAR),
                        vendor VARCHAR NOT NULL,
                        label VARCHAR NOT NULL,
                        is_active BOOLEAN DEFAULT true,
                        kind VARCHAR DEFAULT 'cti',
                        duration_period VARCHAR,
                        confidence_floor INTEGER,
                        marking_definition VARCHAR,
                        config_json VARCHAR,
                        last_run_at TIMESTAMP,
                        last_status VARCHAR,
                        last_message VARCHAR,
                        created_at TIMESTAMP DEFAULT now(),
                        updated_at TIMESTAMP DEFAULT now()
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cti_connector_clients (
                        connector_id VARCHAR NOT NULL,
                        client_id VARCHAR NOT NULL,
                        assigned_at TIMESTAMP DEFAULT now(),
                        PRIMARY KEY (connector_id, client_id)
                    )
                """)

                # Back-fill from opencti_inventory if it exists. Done as a
                # left-anti join on (vendor='opencti', label) so re-runs
                # are idempotent. Delegates to the shared backfill helper
                # which is also invoked at app startup so any rows added
                # after this migration ran (e.g. from a legacy import on
                # an older release) eventually land in cti_connectors.
                self._backfill_legacy_opencti_to_connectors(conn)
            except Exception as exc:
                logger.error(f"Migration 47 failed: {exc}")
                raise
            self._set_schema_version(conn, 47)
            logger.info(
                "Migration 47: created cti_connectors + "
                "cti_connector_clients (generic per-vendor connector "
                "framework; opencti_inventory back-filled, legacy tables "
                "retained for one release)."
            )

        # ── Migration 48: per-tenant rule validation thresholds ──────
        # The amber/expired week thresholds used to colour the rule
        # validation badge were a single global env var pair
        # (RULE_VALIDATION_AMBER_WEEKS / RULE_VALIDATION_EXPIRED_WEEKS).
        # Different tenants run different review cadences, so we now
        # store per-tenant overrides on the ``clients`` table; NULL
        # means "use the global default". Surfaced on the client
        # detail page in the Linked SIEMs section.
        if current_version < 48:
            try:
                cols = {
                    r[1] for r in conn.execute(
                        "PRAGMA table_info('clients')"
                    ).fetchall()
                }
                if "rule_validation_amber_weeks" not in cols:
                    conn.execute(
                        "ALTER TABLE clients "
                        "ADD COLUMN rule_validation_amber_weeks INTEGER"
                    )
                if "rule_validation_expired_weeks" not in cols:
                    conn.execute(
                        "ALTER TABLE clients "
                        "ADD COLUMN rule_validation_expired_weeks INTEGER"
                    )
            except Exception as exc:
                logger.error(f"Migration 48 failed: {exc}")
                raise
            self._set_schema_version(conn, 48)
            logger.info(
                "Migration 48: added rule_validation_amber_weeks / "
                "rule_validation_expired_weeks to clients (per-tenant "
                "override of the global validation thresholds; NULL = "
                "inherit settings default)."
            )

        # ── Migration 54: validation mode + per-criticality thresholds ─
        # The original amber/expired pair remains the master cadence.
        # Tenants can now switch to a criticality-aware mode where each
        # severity level carries its own pair.
        if current_version < 54:
            try:
                cols = {
                    r[1] for r in conn.execute(
                        "PRAGMA table_info('clients')"
                    ).fetchall()
                }
                if "rule_validation_mode" not in cols:
                    conn.execute(
                        "ALTER TABLE clients ADD COLUMN rule_validation_mode VARCHAR"
                    )
                for name in (
                    "rule_validation_low_amber_weeks",
                    "rule_validation_low_expired_weeks",
                    "rule_validation_medium_amber_weeks",
                    "rule_validation_medium_expired_weeks",
                    "rule_validation_high_amber_weeks",
                    "rule_validation_high_expired_weeks",
                    "rule_validation_critical_amber_weeks",
                    "rule_validation_critical_expired_weeks",
                ):
                    if name not in cols:
                        conn.execute(f"ALTER TABLE clients ADD COLUMN {name} INTEGER")
                conn.execute(
                    "UPDATE clients SET rule_validation_mode = COALESCE(rule_validation_mode, 'master')"
                )
            except Exception as exc:
                logger.error(f"Migration 54 failed: {exc}")
                raise
            self._set_schema_version(conn, 54)
            logger.info(
                "Migration 54: added rule_validation_mode and per-severity "
                "validation thresholds to clients (criticality mode augments "
                "the existing master cadence)."
            )

        # ── Migration 49: TAXII 2.1 cursor store ─────────────────────
        # Persistent per-(connector, api_root, collection) watermark
        # captured from the TAXII server's ``X-TAXII-Date-Added-Last``
        # response header. Read by the generic TAXII client
        # (``app.services.cti_fetchers.taxii21``) on each poll and
        # written back at the end of each successful collection pull
        # so subsequent runs are delta syncs (``added_after=...``).
        # No FK to ``cti_connectors`` — DuckDB FKs are optional and
        # this table is intentionally orphan-tolerant so a connector
        # delete doesn't blow up on the cursor row; orphans are cleaned
        # up lazily by the connector delete path.
        if current_version < 49:
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cti_taxii_cursors (
                        connector_id VARCHAR NOT NULL,
                        api_root     VARCHAR NOT NULL,
                        collection_id VARCHAR NOT NULL,
                        added_after  VARCHAR NOT NULL,
                        last_run_at  TIMESTAMP DEFAULT now(),
                        PRIMARY KEY (connector_id, api_root, collection_id)
                    )
                    """
                )
            except Exception as exc:
                logger.error(f"Migration 49 failed: {exc}")
                raise
            self._set_schema_version(conn, 49)
            logger.info(
                "Migration 49: created cti_taxii_cursors (per-collection "
                "added_after watermark for the TAXII 2.1 client)."
            )

        # ── Migration 50: retire the legacy OpenCTI GraphQL surface ──
        # The pre-5.0.0 OpenCTI GraphQL fetcher wrote ``opencti:<uuid>``
        # source IDs and was driven by two shared tables
        # (``opencti_inventory`` and ``client_opencti_map``). The new
        # TAXII 2.1 ingest path replaces both, so this migration:
        #   1. Deletes any ``cti_connectors`` row whose vendor is the
        #      legacy ``opencti`` (the back-fill mirror introduced by
        #      migration 47). These rows kept resurrecting themselves
        #      across restarts because the boot-time back-fill kept
        #      copying them out of ``opencti_inventory`` until the
        #      back-fill helper was no-op'd in 5.0.0.
        #   2. Cleans the ``cti_connector_clients`` membership and
        #      ``cti_taxii_cursors`` watermark rows for those connectors
        #      so a TAXII connector that is later created with the same
        #      id starts clean.
        #   3. Drops ``opencti_inventory`` and ``client_opencti_map``
        #      entirely so no code path can re-introduce GraphQL rows.
        # Operators on existing installs must re-create their OpenCTI
        # source using the ``opencti_taxii`` vendor under Management →
        # Connectors.
        if current_version < 50:
            try:
                # Snapshot the ids we are about to nuke so we can clean
                # up the FK-soft children (memberships, cursors).
                tables = {
                    r[0] for r in conn.execute(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'main'"
                    ).fetchall()
                }
                legacy_ids: list = []
                if "cti_connectors" in tables:
                    legacy_ids = [
                        r[0] for r in conn.execute(
                            "SELECT id FROM cti_connectors "
                            "WHERE vendor = 'opencti'"
                        ).fetchall()
                    ]
                for lid in legacy_ids:
                    if "cti_connector_clients" in tables:
                        conn.execute(
                            "DELETE FROM cti_connector_clients "
                            "WHERE connector_id = ?", [lid],
                        )
                    if "cti_taxii_cursors" in tables:
                        conn.execute(
                            "DELETE FROM cti_taxii_cursors "
                            "WHERE connector_id = ?", [lid],
                        )
                if legacy_ids:
                    conn.execute(
                        "DELETE FROM cti_connectors WHERE vendor = 'opencti'"
                    )
                    logger.info(
                        "Migration 50: removed %d legacy GraphQL OpenCTI "
                        "connector row(s)", len(legacy_ids),
                    )
                # Drop the legacy tables. ``client_opencti_map`` first
                # because it referenced opencti_inventory.id (soft).
                for tbl in ("client_opencti_map", "opencti_inventory"):
                    if tbl in tables:
                        conn.execute(f"DROP TABLE {tbl}")
                        logger.info("Migration 50: dropped %s", tbl)
            except Exception as exc:
                logger.error(f"Migration 50 failed: {exc}")
                raise
            self._set_schema_version(conn, 50)
            logger.info(
                "Migration 50: retired the legacy OpenCTI GraphQL "
                "surface (dropped opencti_inventory + client_opencti_map; "
                "removed vendor='opencti' rows from cti_connectors)."
            )

        # ── Migration 51: scrub legacy OCTI-only threat_actors rows ──
        # 5.0.0 retired the GraphQL fetcher that wrote ``source=['OCTI']``
        # into the shared ``threat_actors`` table. Those rows still
        # render on the Threat Landscape page with a CTI badge from a
        # connector that no longer exists. We only delete rows whose
        # source list is exclusively ['OCTI'] (i.e. they never matched
        # a MITRE baseline) so curated MITRE actors keep their CTI
        # enrichment when a connector merge-projects into them later.
        if current_version < 51:
            try:
                removed = 0
                row = conn.execute(
                    "SELECT COUNT(*) FROM threat_actors "
                    "WHERE source IS NOT NULL "
                    "  AND list_contains(source, 'OCTI') "
                    "  AND len(source) = 1"
                ).fetchone()
                if row and row[0]:
                    removed = int(row[0])
                    conn.execute(
                        "DELETE FROM threat_actors "
                        "WHERE source IS NOT NULL "
                        "  AND list_contains(source, 'OCTI') "
                        "  AND len(source) = 1"
                    )
                logger.info(
                    "Migration 51: removed %d OCTI-only threat_actors row(s)",
                    removed,
                )
            except Exception as exc:
                logger.error(f"Migration 51 failed: {exc}")
                raise
            self._set_schema_version(conn, 51)
            logger.info(
                "Migration 51: scrubbed legacy OCTI-only actors from "
                "the shared threat_actors table."
            )

        # ── Migration 52: add CTI connector auto-sync interval columns ──
        # The 5.0.x background-job scheduler reads these two columns
        # to decide which connectors are due for a re-pull. Existing
        # rows keep ``sync_interval_minutes IS NULL`` (auto-sync off)
        # so the migration is non-disruptive — operators opt in per
        # connector by editing the connector and choosing an interval.
        if current_version < 52:
            try:
                conn.execute(
                    "ALTER TABLE cti_connectors "
                    "ADD COLUMN IF NOT EXISTS sync_interval_minutes INTEGER"
                )
                conn.execute(
                    "ALTER TABLE cti_connectors "
                    "ADD COLUMN IF NOT EXISTS last_sync_started_at TIMESTAMP"
                )
            except Exception as exc:
                logger.error(f"Migration 52 failed: {exc}")
                raise
            self._set_schema_version(conn, 52)
            logger.info(
                "Migration 52: added sync_interval_minutes + "
                "last_sync_started_at to cti_connectors."
            )

        # ── Migration 53: rule lifecycle history audit trail ──────────
        # Tracks rule create/edit/enable/disable/validate/promote/demote
        # events with actor, timestamp, and before/after detail (JSON).
        # Per-tenant scoped via client_id for tenant isolation.
        if current_version < 53:
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS rule_lifecycle_history (
                        id VARCHAR PRIMARY KEY DEFAULT (uuid()::VARCHAR),
                        rule_id VARCHAR NOT NULL,
                        siem_id VARCHAR NOT NULL,
                        space VARCHAR NOT NULL,
                        client_id VARCHAR NOT NULL,
                        action VARCHAR NOT NULL,
                        actor_user_id VARCHAR,
                        actor_name VARCHAR,
                        detail JSON,
                        created_at TIMESTAMP DEFAULT now()
                    )
                """)
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_rule_lifecycle_rule "
                    "ON rule_lifecycle_history (rule_id, siem_id, space, client_id)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_rule_lifecycle_created "
                    "ON rule_lifecycle_history (created_at DESC)"
                )
            except Exception as exc:
                logger.error(f"Migration 53 failed: {exc}")
                raise
            self._set_schema_version(conn, 53)
            logger.info(
                "Migration 53: created rule_lifecycle_history table "
                "for audit trail tracking."
            )

        logger.info(f"Migrations complete. Schema v{SCHEMA_VERSION}")

    def _validate_legacy_tables(self, conn):
        """Validate legacy tables and align schemas non-destructively."""
        # Check for checkedRule table (legacy validation data)
        try:
            tables = conn.execute("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema = 'main'
            """).fetchall()
            table_names = {t[0] for t in tables}
            
            # If checkedRule exists, validate its schema
            if 'checkedRule' in table_names:
                cols = conn.execute("DESCRIBE checkedRule").fetchall()
                col_names = {c[0] for c in cols}
                
                # Expected columns for legacy compatibility
                expected = {'rule_name', 'last_checked_on', 'checked_by'}
                missing = expected - col_names
                
                if missing:
                    logger.warning(f"checkedRule missing columns: {missing}")
                    for col in missing:
                        try:
                            if col == 'rule_name':
                                conn.execute("ALTER TABLE checkedRule ADD COLUMN rule_name VARCHAR")
                            elif col == 'last_checked_on':
                                conn.execute("ALTER TABLE checkedRule ADD COLUMN last_checked_on TIMESTAMP")
                            elif col == 'checked_by':
                                conn.execute("ALTER TABLE checkedRule ADD COLUMN checked_by VARCHAR DEFAULT 'unknown'")
                            logger.info(f"Added missing column: {col}")
                        except Exception as e:
                            logger.warning(f"Could not add column {col}: {e}")
                else:
                    logger.info("checkedRule schema validated")
                    
        except Exception as e:
            logger.warning(f"Legacy table validation skipped: {e}")
    
    def _init_db(self):
        """Initialize database and run migrations.  Always uses the shared DB
        regardless of any active tenant context."""
        with self.get_shared_connection() as conn:
            self._run_migrations(conn)
            self._validate_legacy_tables(conn)
            self._ensure_users_table(conn)
    
    def _ensure_users_table(self, conn):
        """Bootstrap default admin user if no users exist."""
        try:
            row = conn.execute("SELECT count(*) FROM users").fetchone()
            if row and row[0] == 0:
                import bcrypt
                from app.config import get_settings
                settings = get_settings()
                bootstrap_username = settings.bootstrap_admin_username or "admin"
                bootstrap_password = (settings.bootstrap_admin_password or "admin").encode()
                default_pw = bcrypt.hashpw(bootstrap_password, bcrypt.gensalt()).decode()
                conn.execute(
                    "INSERT INTO users (username, email, full_name, password_hash, auth_provider, is_active, is_superadmin) "
                    "VALUES (?, 'admin@localhost', 'Default Admin', ?, 'local', true, true)",
                    [bootstrap_username, default_pw],
                )
                # Assign ADMIN role to the bootstrap user (in the default client only —
                # superadmin flag grants implicit access to every other tenant).
                admin_user_id = conn.execute(
                    "SELECT id FROM users WHERE username = ?", [bootstrap_username]
                ).fetchone()[0]
                admin_role_id = conn.execute(
                    "SELECT id FROM roles WHERE name = 'ADMIN'"
                ).fetchone()[0]
                default_client = conn.execute(
                    "SELECT id FROM clients WHERE is_default = true LIMIT 1"
                ).fetchone()
                if default_client:
                    conn.execute(
                        "INSERT INTO user_roles (user_id, client_id, role_id) "
                        "VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                        [admin_user_id, default_client[0], admin_role_id],
                    )
                    conn.execute(
                        "INSERT INTO user_clients (user_id, client_id, is_default) "
                        "VALUES (?, ?, true) ON CONFLICT DO NOTHING",
                        [admin_user_id, default_client[0]],
                    )
                logger.info(f"Bootstrap admin user created (username: {bootstrap_username})")
            else:
                logger.info(f"Users table has {row[0]} user(s), skipping bootstrap")
        except Exception as e:
            logger.warning(f"Could not bootstrap admin user: {e}")
    
    # --- USER / RBAC DATA ---

    _USER_COLS = [
        "id", "username", "email", "full_name", "password_hash", "keycloak_id",
        "auth_provider", "is_active", "is_superadmin", "change_on_next_login",
        "created_at", "updated_at", "last_login",
    ]
    _USER_SELECT = (
        "SELECT id, username, email, full_name, password_hash, keycloak_id, "
        "auth_provider, is_active, is_superadmin, change_on_next_login, "
        "created_at, updated_at, last_login FROM users"
    )

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        with self.get_shared_connection() as conn:
            row = conn.execute(
                self._USER_SELECT + " WHERE LOWER(username) = LOWER(?)", [username]
            ).fetchone()
            if not row:
                return None
            return dict(zip(self._USER_COLS, row))

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        with self.get_shared_connection() as conn:
            row = conn.execute(
                self._USER_SELECT + " WHERE LOWER(email) = LOWER(?)", [email]
            ).fetchone()
            if not row:
                return None
            return dict(zip(self._USER_COLS, row))

    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        with self.get_shared_connection() as conn:
            row = conn.execute(
                self._USER_SELECT + " WHERE id = ?", [user_id]
            ).fetchone()
            if not row:
                return None
            return dict(zip(self._USER_COLS, row))

    def get_user_by_keycloak_id(self, keycloak_id: str) -> Optional[Dict]:
        with self.get_shared_connection() as conn:
            row = conn.execute(
                self._USER_SELECT + " WHERE keycloak_id = ?", [keycloak_id]
            ).fetchone()
            if not row:
                return None
            return dict(zip(self._USER_COLS, row))

    def get_all_users(self) -> List[Dict]:
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT id, username, email, full_name, keycloak_id, "
                "auth_provider, is_active, is_superadmin, created_at, last_login "
                "FROM users ORDER BY username"
            ).fetchall()
            cols = ["id", "username", "email", "full_name", "keycloak_id",
                    "auth_provider", "is_active", "is_superadmin", "created_at", "last_login"]
            return [dict(zip(cols, r)) for r in rows]

    def create_user(self, username: str, email: str = None, full_name: str = None,
                    password_hash: str = None, keycloak_id: str = None,
                    auth_provider: str = "local") -> str:
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, email, full_name, password_hash, keycloak_id, auth_provider) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [username, email, full_name, password_hash, keycloak_id, auth_provider],
            )
            row = conn.execute("SELECT id FROM users WHERE username = ?", [username]).fetchone()
            return row[0]

    def update_user(self, user_id: str, **fields) -> bool:
        allowed = {
            "username", "email", "full_name", "password_hash", "is_active",
            "keycloak_id", "auth_provider", "change_on_next_login", "last_login",
            "is_superadmin",
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return False
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [user_id]
        with self.get_shared_connection() as conn:
            conn.execute(
                f"UPDATE users SET {set_clause}, updated_at = now() WHERE id = ?", values
            )
        return True

    def delete_user(self, user_id: str):
        with self.get_shared_connection() as conn:
            conn.execute("UPDATE api_keys SET created_by_user_id = NULL WHERE created_by_user_id = ?", [user_id])
            conn.execute("DELETE FROM user_clients WHERE user_id = ?", [user_id])
            conn.execute("DELETE FROM user_roles WHERE user_id = ?", [user_id])
            conn.execute("DELETE FROM users WHERE id = ?", [user_id])

    def get_user_roles(self, user_id: str, client_id: Optional[str] = None) -> List[str]:
        """Return role names for a user.

        - When `client_id` is provided, return roles assigned in that tenant only.
        - When `client_id` is None, return the DISTINCT union across all tenants
          (compatible with legacy callers that treated roles as global).
        """
        with self.get_shared_connection() as conn:
            if client_id is None:
                rows = conn.execute(
                    "SELECT DISTINCT r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id "
                    "WHERE ur.user_id = ?", [user_id]
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id "
                    "WHERE ur.user_id = ? AND ur.client_id = ?", [user_id, client_id]
                ).fetchall()
            return [r[0] for r in rows]

    def get_user_role_map(self, user_id: str) -> Dict[str, List[str]]:
        """Return {client_id: [role_name, ...]} for the user across all tenants."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT ur.client_id, r.name FROM user_roles ur "
                "JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ?",
                [user_id],
            ).fetchall()
        out: Dict[str, List[str]] = {}
        for cid, name in rows:
            out.setdefault(cid, []).append(name)
        return out

    def get_all_roles(self) -> List[Dict]:
        with self.get_shared_connection() as conn:
            rows = conn.execute("SELECT id, name, description FROM roles ORDER BY name").fetchall()
            return [dict(zip(["id", "name", "description"], r)) for r in rows]

    def set_user_roles(
        self,
        user_id: str,
        role_names: List[str],
        client_id: Optional[str] = None,
    ):
        """Set a user's roles.

        - With `client_id`: replaces only that tenant's roles.
        - Without `client_id` (legacy): replaces roles across every client the
          user is currently assigned to (or the default client when the user has
          no assignments). Falls back to the system default when neither exists.
        """
        with self.get_shared_connection() as conn:
            if client_id is not None:
                conn.execute(
                    "DELETE FROM user_roles WHERE user_id = ? AND client_id = ?",
                    [user_id, client_id],
                )
                target_clients = [client_id]
            else:
                conn.execute("DELETE FROM user_roles WHERE user_id = ?", [user_id])
                target_clients = [
                    r[0]
                    for r in conn.execute(
                        "SELECT client_id FROM user_clients WHERE user_id = ?",
                        [user_id],
                    ).fetchall()
                ]
                if not target_clients:
                    default_cid = self._get_default_client_id(conn)
                    if default_cid:
                        target_clients = [default_cid]
            for rn in role_names:
                role_row = conn.execute(
                    "SELECT id FROM roles WHERE name = ?", [rn]
                ).fetchone()
                if not role_row:
                    continue
                for cid in target_clients:
                    conn.execute(
                        "INSERT INTO user_roles (user_id, client_id, role_id) "
                        "VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                        [user_id, cid, role_row[0]],
                    )

    def set_user_superadmin(self, user_id: str, value: bool) -> None:
        """Toggle the superadmin flag — bypasses tenant role checks everywhere."""
        with self.get_shared_connection() as conn:
            conn.execute(
                "UPDATE users SET is_superadmin = ?, updated_at = now() WHERE id = ?",
                [bool(value), user_id],
            )

    def jit_provision_keycloak_user(self, keycloak_id: str, username: str,
                                     email: str = None, full_name: str = None,
                                     kc_role: Optional[str] = None,
                                     is_superadmin: Optional[bool] = None) -> Dict:
        """Provision/refresh a Keycloak-backed user record.

        - `kc_role` (one of ADMIN / ENGINEER / ANALYST) is applied to the user's
          Primary Client only. Other tenant assignments are left untouched so a
          TIDE admin can grant additional access without it being overwritten on
          every login. Pass `None` to skip role sync.
        - `is_superadmin` reflects membership of the Keycloak `superadmin` group.
          Pass `None` to leave the flag untouched.
        """
        existing = self.get_user_by_keycloak_id(keycloak_id)
        if existing:
            self.update_user(existing["id"], email=email, full_name=full_name, last_login=datetime.now())
            if is_superadmin is not None:
                self.set_user_superadmin(existing["id"], is_superadmin)
            self._sync_kc_role_to_primary(existing["id"], kc_role)
            return self.get_user_by_keycloak_id(keycloak_id)
        # Link existing account by username only if it is already SSO-capable.
        # Local-only accounts must never be auto-upgraded by SSO login.
        by_name = self.get_user_by_username(username)
        if by_name:
            provider = (by_name.get("auth_provider") or "local").lower()
            if provider in {"keycloak", "hybrid"}:
                self.update_user(
                    by_name["id"],
                    keycloak_id=keycloak_id,
                    email=email,
                    full_name=full_name,
                    last_login=datetime.now(),
                )
                return self.get_user_by_id(by_name["id"])

        # Avoid attaching SSO identities to local-only users by email match.
        by_email = self.get_user_by_email(email) if email else None
        if by_email:
            provider = (by_email.get("auth_provider") or "local").lower()
            if provider in {"keycloak", "hybrid"}:
                self.update_user(
                    by_email["id"],
                    keycloak_id=keycloak_id,
                    email=email,
                    full_name=full_name,
                    last_login=datetime.now(),
                )
                return self.get_user_by_id(by_email["id"])

        # Build a unique username for new SSO identities when conflicts exist.
        final_username = username
        if by_name and (by_name.get("auth_provider") or "local").lower() == "local":
            suffix = 1
            while self.get_user_by_username(f"{username}__sso{suffix}"):
                suffix += 1
            final_username = f"{username}__sso{suffix}"

        email_for_new = email
        if by_email and (by_email.get("auth_provider") or "local").lower() == "local":
            email_for_new = None

        uid = self.create_user(
            username=final_username, email=email_for_new, full_name=full_name,
            keycloak_id=keycloak_id, auth_provider="keycloak",
        )
        # Assign new user to default (Primary) client first, then map their role
        # there. Role sync only ever touches the Primary Client — admins assign
        # additional tenants in the management UI.
        default_cid = self.get_default_client_id()
        if default_cid:
            self.assign_user_to_client(uid, default_cid, is_default=True)
        if is_superadmin is not None:
            self.set_user_superadmin(uid, is_superadmin)
        # Default to ANALYST when no group mapping was supplied.
        self._sync_kc_role_to_primary(uid, kc_role or "ANALYST")
        return self.get_user_by_id(uid)

    def _sync_kc_role_to_primary(self, user_id: str, kc_role: Optional[str]) -> None:
        """Replace the user's roles in the Primary (default) Client with `kc_role`.

        Other tenant assignments are intentionally left alone so admins can grant
        cross-tenant access in TIDE without having it wiped on the next SSO login.
        """
        if not kc_role:
            return
        kc_role = kc_role.upper().strip()
        if kc_role not in {"ADMIN", "ENGINEER", "ANALYST"}:
            return
        primary_cid = self.get_default_client_id()
        if not primary_cid:
            return
        # Make sure the user is still a member of the Primary Client.
        with self.get_shared_connection() as conn:
            already = conn.execute(
                "SELECT 1 FROM user_clients WHERE user_id = ? AND client_id = ?",
                [user_id, primary_cid],
            ).fetchone()
        if not already:
            self.assign_user_to_client(user_id, primary_cid, is_default=False)
        self.set_user_roles(user_id, [kc_role], client_id=primary_cid)

    # --- ROLE PERMISSIONS ---

    def get_permissions_for_role(self, role_id: str) -> List[Dict]:
        """Get all permissions for a role."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT id, resource, can_read, can_write FROM role_permissions "
                "WHERE role_id = ? ORDER BY resource", [role_id]
            ).fetchall()
            return [dict(zip(["id", "resource", "can_read", "can_write"], r)) for r in rows]

    def get_permissions_matrix(self, client_id: Optional[str] = None) -> List[Dict]:
        """Get the role×resource permissions matrix.

        With ``client_id`` set the matrix is scoped to that tenant only — this
        is what the Client Detail page edits. With ``client_id=None`` the
        legacy behaviour returns every row (used by the deprecated global view).
        """
        with self.get_shared_connection() as conn:
            if client_id is not None:
                rows = conn.execute(
                    "SELECT rp.id, r.name AS role_name, r.id AS role_id, "
                    "rp.resource, rp.can_read, rp.can_write "
                    "FROM role_permissions rp "
                    "JOIN roles r ON r.id = rp.role_id "
                    "WHERE rp.client_id = ? "
                    "ORDER BY r.name, rp.resource",
                    [client_id],
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT rp.id, r.name AS role_name, r.id AS role_id, "
                    "rp.resource, rp.can_read, rp.can_write "
                    "FROM role_permissions rp "
                    "JOIN roles r ON r.id = rp.role_id "
                    "ORDER BY r.name, rp.resource"
                ).fetchall()
            cols = ["id", "role_name", "role_id", "resource", "can_read", "can_write"]
            return [dict(zip(cols, r)) for r in rows]

    def get_all_resources(self) -> List[str]:
        """Get all distinct resource names from role_permissions."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT resource FROM role_permissions ORDER BY resource"
            ).fetchall()
            return [r[0] for r in rows]

    def set_permission(self, role_id: str, resource: str, can_read: bool, can_write: bool,
                        client_id: Optional[str] = None):
        """Upsert a role×resource permission, optionally scoped to a tenant.

        ``client_id=None`` writes a legacy global row (still supported by the
        old `/api/settings/permissions` endpoint); the per-client UI on the
        Client Detail page always supplies a tenant id.
        """
        with self.get_shared_connection() as conn:
            if client_id is None:
                existing = conn.execute(
                    "SELECT id FROM role_permissions "
                    "WHERE role_id = ? AND resource = ? AND client_id IS NULL",
                    [role_id, resource],
                ).fetchone()
            else:
                existing = conn.execute(
                    "SELECT id FROM role_permissions "
                    "WHERE role_id = ? AND resource = ? AND client_id = ?",
                    [role_id, resource, client_id],
                ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE role_permissions SET can_read = ?, can_write = ? WHERE id = ?",
                    [can_read, can_write, existing[0]],
                )
            else:
                conn.execute(
                    "INSERT INTO role_permissions (role_id, client_id, resource, can_read, can_write) "
                    "VALUES (?, ?, ?, ?, ?)",
                    [role_id, client_id, resource, can_read, can_write],
                )

    def check_permission(self, role_names: List[str], resource: str) -> Dict[str, bool]:
        """Check permission for a set of roles on a resource.
        Returns {'can_read': bool, 'can_write': bool} where True if ANY role grants it."""
        if not role_names:
            return {"can_read": False, "can_write": False}
        with self.get_shared_connection() as conn:
            placeholders = ", ".join("?" for _ in role_names)
            rows = conn.execute(
                f"SELECT rp.can_read, rp.can_write FROM role_permissions rp "
                f"JOIN roles r ON r.id = rp.role_id "
                f"WHERE r.name IN ({placeholders}) AND rp.resource = ?",
                role_names + [resource],
            ).fetchall()
            can_read = any(r[0] for r in rows)
            can_write = any(r[1] for r in rows)
            return {"can_read": can_read, "can_write": can_write}

    def get_user_permissions(self, user_id: str,
                              client_id: Optional[str] = None) -> Dict[str, Dict[str, bool]]:
        """Get all permissions for a user based on their roles.

        When ``client_id`` is provided the resolution is scoped to the roles the
        user holds in that tenant only — this is what powers the sidebar /
        page-gating data flow once the user activates a tenant. When omitted the
        legacy global behaviour (merge across every tenant) is preserved so
        callers loading a fresh login session keep working.

        Returns {resource: {can_read, can_write}}."""
        roles = self.get_user_roles(user_id, client_id=client_id)
        if not roles:
            return {}
        with self.get_shared_connection() as conn:
            placeholders = ", ".join("?" for _ in roles)
            if client_id is not None:
                # Per-tenant lookup: only rows scoped to this tenant matter.
                rows = conn.execute(
                    f"SELECT rp.resource, rp.can_read, rp.can_write FROM role_permissions rp "
                    f"JOIN roles r ON r.id = rp.role_id "
                    f"WHERE r.name IN ({placeholders}) AND rp.client_id = ?",
                    roles + [client_id],
                ).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT rp.resource, rp.can_read, rp.can_write FROM role_permissions rp "
                    f"JOIN roles r ON r.id = rp.role_id "
                    f"WHERE r.name IN ({placeholders})",
                    roles,
                ).fetchall()
            perms = {}
            for resource, can_read, can_write in rows:
                if resource not in perms:
                    perms[resource] = {"can_read": False, "can_write": False}
                perms[resource]["can_read"] = perms[resource]["can_read"] or can_read
                perms[resource]["can_write"] = perms[resource]["can_write"] or can_write
            return perms

    # --- VALIDATION DATA ---

    def _read_validation_file(self) -> Dict[str, Any]:
        """
        Safely read the validation JSON file.

        Returns the parsed dict (with a ``rules`` key) or ``None`` if the file
        does not exist.  On *any* read / parse error the **backup** file is
        tried before giving up, so a single truncated write can never destroy
        all client data.
        """
        if not os.path.exists(self.validation_file):
            return None

        # Try primary file first
        for path in (self.validation_file, self.validation_file + ".bak"):
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r") as f:
                    content = f.read().strip()
                if not content:
                    logger.warning(f"Validation file is empty: {path}")
                    continue
                data = json.loads(content)
                if isinstance(data, dict) and "rules" in data and data["rules"]:
                    return data
                logger.warning(f"Validation file has no rule data: {path}")
            except (json.JSONDecodeError, OSError) as exc:
                logger.error(f"Failed to read validation file {path}: {exc}")

        # Both files unreadable / empty — return empty structure but do NOT
        # overwrite the originals (caller decides whether to write).
        logger.error("All validation files unreadable — returning empty data")
        return {"rules": {}}

    def _atomic_write_validation(self, data: Dict[str, Any]) -> None:
        """
        Atomically write *data* to the validation file.

        Strategy:
        1. Create a backup of the current file (``<file>.bak``).
        2. Write to a temporary file in the **same directory** (important so
           ``os.replace`` is a same-filesystem atomic rename).
        3. ``os.replace`` the temp file over the real file — this is atomic on
           both POSIX and modern Windows/NTFS.

        If anything goes wrong the original file (or its backup) survives.
        """
        directory = os.path.dirname(self.validation_file) or "."
        os.makedirs(directory, exist_ok=True)

        # 1. Backup current file if it exists and is non-empty
        if os.path.exists(self.validation_file):
            try:
                if os.path.getsize(self.validation_file) > 2:  # not just "{}"
                    shutil.copy2(self.validation_file, self.validation_file + ".bak")
            except OSError as exc:
                logger.warning(f"Could not create validation backup: {exc}")

        # 2. Write to temp file in the same directory
        fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp", prefix=".validation_")
        try:
            with os.fdopen(fd, "w") as tmp_f:
                json.dump(data, tmp_f, indent=4)
                tmp_f.flush()
                os.fsync(tmp_f.fileno())
            # 3. Atomic replace
            os.replace(tmp_path, self.validation_file)
        except BaseException:
            # Clean up temp file on failure — original is untouched
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _load_validation_data(self) -> Dict[str, Dict[str, str]]:
        """Load validation data from JSON file (cached by file mtime)."""
        if not os.path.exists(self.validation_file):
            return {}
        try:
            mtime = os.path.getmtime(self.validation_file)
            if self._validation_cache is not None and mtime == self._validation_cache_mtime:
                return self._validation_cache
            data = self._read_validation_file()
            rules = data.get("rules", {}) if data else {}
            self._validation_cache = rules
            self._validation_cache_mtime = mtime
            return rules
        except Exception as exc:
            logger.error(f"Failed to load validation data: {exc}")
            return {}

    def save_validation(self, rule_name: str, user_name: str):
        """Save validation record for a rule (atomic + backup)."""
        data = self._read_validation_file() or {"rules": {}}

        if "rules" not in data:
            data["rules"] = {}

        data["rules"][str(rule_name)] = {
            "last_checked_on": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "checked_by": user_name
        }

        self._atomic_write_validation(data)
        # Invalidate cache so next read picks up the change
        self._validation_cache = None
    
    # --- RULE OPERATIONS ---
    
    def get_rules(
        self,
        filters: RuleFilters,
        thresholds: Optional[Tuple[int, int]] = None,
        client_id: Optional[str] = None,
    ) -> Tuple[List[DetectionRule], int, str]:
        """
        Get paginated list of detection rules with filters.
        Returns (rules, total_count, last_sync).

        ``thresholds`` carries an optional ``(amber_weeks, expired_weeks)``
        tuple resolved by :meth:`get_client_validation_thresholds`. When
        omitted each rule's validation status uses the global defaults.
        """
        with self.get_connection() as conn:
            # Base query
            query = "SELECT * FROM detection_rules WHERE 1=1"
            params = []

            # Tenant isolation: restrict to the client's mapped
            # (siem_id, space) pairs. Composite predicate is mandatory —
            # filtering by space alone leaks rules across SIEMs that share a
            # Kibana space name (AGENTS.md \u00a78.2 g4 / \u00a78.3).
            if filters.allowed_scopes is not None:
                if not filters.allowed_scopes:
                    return [], 0, "Never"
                frag, scope_params = _scope_predicate(filters.allowed_scopes)
                query += f" AND {frag}"
                params.extend(scope_params)
            
            # Apply filters
            if filters.space:
                query += " AND space = ?"
                params.append(filters.space)
            
            if filters.enabled is not None:
                query += " AND enabled = ?"
                params.append(1 if filters.enabled else 0)
            
            if filters.severity:
                query += " AND severity = ?"
                params.append(filters.severity.value)
            
            if filters.min_score is not None:
                query += " AND score >= ?"
                params.append(filters.min_score)
            
            if filters.max_score is not None:
                query += " AND score <= ?"
                params.append(filters.max_score)
            
            # Apply search filter IN SQL (not post-fetch) so pagination works correctly
            if filters.search:
                search_term = f"%{filters.search}%"
                query += """ AND (
                    LOWER(name) LIKE LOWER(?) 
                    OR LOWER(author) LIKE LOWER(?) 
                    OR LOWER(rule_id) LIKE LOWER(?)
                    OR LOWER(array_to_string(mitre_ids, ',')) LIKE LOWER(?)
                )"""
                params.extend([search_term, search_term, search_term, search_term])
            
            # Get total count before pagination
            count_query = query.replace("SELECT *", "SELECT COUNT(*)")
            total = conn.execute(count_query, params).fetchone()[0]
            
            # Check if sorting by validation date (Python-side sort needed)
            is_validation_sort = filters.sort_by in ("validated_asc", "validated_desc")
            
            # Apply sorting (DB-side for DB columns)
            # Use COALESCE to eliminate NULL-handling edge cases across DuckDB versions
            if not is_validation_sort:
                sort_map = {
                    "score_asc": "COALESCE(score, 0) ASC, name ASC",
                    "score_desc": "COALESCE(score, 0) DESC, name ASC",
                    "name_asc": "COALESCE(name, '') ASC",
                    "name_desc": "COALESCE(name, '') DESC",
                }
                order_by = sort_map.get(filters.sort_by, "COALESCE(score, 0) ASC, name ASC")
                query += f" ORDER BY {order_by}"
            
            if is_validation_sort:
                # Fetch ALL matching rows for Python-side sort, then paginate
                df = conn.execute(query, params).df()
            else:
                # Pagination (DB-side)
                offset = (filters.page - 1) * filters.page_size
                query += f" LIMIT {filters.page_size} OFFSET {offset}"
                df = conn.execute(query, params).df()
            
            # Get last sync time
            try:
                last_sync = df['last_updated'].max().strftime("%Y-%m-%d %H:%M") if not df.empty else "Never"
            except:
                last_sync = "Never"
        
        # Convert to models (search already applied in SQL)
        validation_data = self._load_validation_data()
        rules = []

        for _, row in df.iterrows():
            try:
                rule = self._row_to_rule(
                    row.to_dict(),
                    validation_data,
                    thresholds,
                    client_id=client_id,
                )
                rules.append(rule)
            except Exception as e:
                rule_id = row.get('rule_id', '?')
                space = row.get('space', '?')
                logger.warning(f"Skipping rule {rule_id} (space={space}): {e}")
        
        # Python-side sort for validation date
        if is_validation_sort:
            reverse = filters.sort_by == "validated_desc"
            rules.sort(
                key=lambda r: r.validation_date or datetime.min,
                reverse=reverse,
            )
            # Manual pagination
            offset = (filters.page - 1) * filters.page_size
            rules = rules[offset:offset + filters.page_size]
        
        return rules, total, last_sync
    
    def get_existing_rule_keys(self) -> set:
        """Get set of (rule_id, siem_id, space) tuples for all rules in the database.
        Used for lazy mapping: skip Elasticsearch mapping checks for known rules.
        Keyed by ``(siem_id, space)`` since 4.1.12 (Migration 44) — the same Elastic
        prebuilt rule_id can legitimately exist in multiple spaces of the SAME
        SIEM (e.g. a base rule cloned to ``one`` and ``two`` for different
        promotion routes), and these now have distinct rows under the
        ``(rule_id, siem_id, space)`` PK."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT rule_id, siem_id, space FROM detection_rules"
            ).fetchall()
            return {(r[0], r[1], r[2]) for r in rows}

    def get_existing_rule_data(self) -> dict:
        """Get existing rule scores and raw_data keyed by (rule_id, siem_id, space).
        Used to preserve mapping data for rules that skip mapping during lazy sync.
        Keyed by ``(siem_id, space)`` since 4.1.12 (Migration 44)."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT rule_id, siem_id, space, score, quality_score, meta_score, "
                "score_mapping, score_field_type, score_search_time, score_language, "
                "score_note, score_override, score_tactics, score_techniques, "
                "score_author, score_highlights, raw_data "
                "FROM detection_rules"
            ).fetchall()
            columns = [desc[0] for desc in conn.description]
            result = {}
            for row in rows:
                d = dict(zip(columns, row))
                key = (d['rule_id'], d['siem_id'], d['space'])
                # Parse raw_data JSON to get results
                raw = d.get('raw_data')
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except:
                        raw = {}
                d['raw_data'] = raw
                result[key] = d
            return result

    def move_rule_space(self, rule_id: str, from_space: str, to_space: str,
                        siem_id: Optional[str] = None):
        """Move a rule from one space to another in DuckDB (for instant UI update
        after promotion). When ``siem_id`` is supplied (4.0.13+), the move is
        scoped to that SIEM only so an in-place promote within SIEM A doesn't
        accidentally rename SIEM B's identically-keyed rule."""
        with self.get_connection() as conn:
            if siem_id is None:
                # Legacy fallback: scope by space only. Logged at WARN because
                # this is ambiguous when multiple SIEMs share a space name.
                logger.warning(
                    "move_rule_space called without siem_id (rule_id=%s %s->%s) — "
                    "this is ambiguous across SIEMs; update caller to pass siem_id",
                    rule_id, from_space, to_space,
                )
                conn.execute(
                    "DELETE FROM detection_rules WHERE rule_id = ? AND space = ?",
                    [rule_id, to_space]
                )
                conn.execute(
                    "UPDATE detection_rules SET space = ? WHERE rule_id = ? AND space = ?",
                    [to_space, rule_id, from_space]
                )
            else:
                # SIEM-scoped: target row may already exist for the same SIEM
                # (e.g. a previous promotion left a duplicate). Drop it first.
                conn.execute(
                    "DELETE FROM detection_rules "
                    "WHERE rule_id = ? AND space = ? AND siem_id = ?",
                    [rule_id, to_space, siem_id]
                )
                conn.execute(
                    "UPDATE detection_rules SET space = ? "
                    "WHERE rule_id = ? AND space = ? AND siem_id = ?",
                    [to_space, rule_id, from_space, siem_id]
                )
            # CHECKPOINT is best-effort — flushes pending writes to the
            # main DB file. Will fail if a concurrent writer (e.g. a
            # post-promote sync task on the same tenant DB) holds an open
            # transaction; the move itself is already committed by the
            # `with self.get_connection()` context exit, so we just log
            # and move on instead of bubbling a 500 to the operator.
            try:
                conn.execute("CHECKPOINT")
            except Exception as _ckpt_exc:  # noqa: BLE001
                logger.debug(
                    "move_rule_space CHECKPOINT skipped (non-fatal): %s",
                    _ckpt_exc,
                )
        logger.info(
            "Moved rule %s from '%s' to '%s' in DB (siem_id=%s)",
            rule_id, from_space, to_space, siem_id or '<unscoped>',
        )

    def get_rule_by_id(self, rule_id: str, space: str = "default",
                       siem_id: Optional[str] = None,
                       thresholds: Optional[Tuple[int, int]] = None,
                       client_id: Optional[str] = None) -> Optional[DetectionRule]:
        """Get a single rule by ID and space.

        Since 4.0.13, ``siem_id`` may be supplied to scope the lookup to a
        specific SIEM. When omitted, the lookup falls back to (rule_id, space)
        and emits a debug log noting the result may be ambiguous if multiple
        SIEMs share the space name. If multiple rows match in fallback mode the
        first row is returned (matches pre-4.0.13 behaviour).
        """
        with self.get_connection() as conn:
            if siem_id is not None:
                result = conn.execute(
                    "SELECT * FROM detection_rules "
                    "WHERE rule_id = ? AND space = ? AND siem_id = ?",
                    [rule_id, space, siem_id]
                ).fetchone()
            else:
                result = conn.execute(
                    "SELECT * FROM detection_rules WHERE rule_id = ? AND space = ? "
                    "LIMIT 1",
                    [rule_id, space]
                ).fetchone()

            if result:
                columns = [desc[0] for desc in conn.description]
                row = dict(zip(columns, result))
                validation_data = self._load_validation_data()
                return self._row_to_rule(
                    row,
                    validation_data,
                    thresholds,
                    client_id=client_id,
                )

        return None
    
    @staticmethod
    def _safe_int(val, default=0):
        """Safely convert a value to int, handling NaN/None/pd.NA from DuckDB NULL columns."""
        if val is None:
            return default
        try:
            if pd.isna(val):
                return default
        except (TypeError, ValueError):
            pass
        try:
            return int(val)
        except (TypeError, ValueError, OverflowError):
            return default

    @staticmethod
    def _safe_str(val, default=''):
        """Safely convert a value to str, handling None/NaN/pd.NA from DuckDB NULL columns."""
        if val is None:
            return default
        try:
            if pd.isna(val):
                return default
        except (TypeError, ValueError):
            pass
        s = str(val)
        return s if s and s.lower() != 'nan' else default

    @staticmethod
    def _safe_dt(val):
        """Return a datetime or None, converting pandas NaT/NA to None."""
        if val is None:
            return None
        try:
            if pd.isna(val):
                return None
        except (TypeError, ValueError):
            pass
        if isinstance(val, datetime):
            return val
        return None

    def _row_to_rule(
        self,
        row: Dict[str, Any],
        validation_data: Dict,
        thresholds: Optional[Tuple[int, int]] = None,
        client_id: Optional[str] = None,
    ) -> DetectionRule:
        """Convert database row to DetectionRule model.

        ``thresholds`` is an optional ``(amber_weeks, expired_weeks)``
        pair — callers that know which tenant they're rendering for
        should pass per-tenant overrides via
        :meth:`get_client_validation_thresholds`. When omitted the
        global settings defaults are used.
        """
        _si = self._safe_int
        _ss = self._safe_str

        # Parse raw_data
        raw_data = row.get('raw_data')
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except:
                raw_data = {}
        elif raw_data is None or (not isinstance(raw_data, dict)):
            # Handle pd.NA, NaN, or unexpected types
            try:
                if pd.isna(raw_data):
                    raw_data = {}
            except (TypeError, ValueError):
                if not isinstance(raw_data, dict):
                    raw_data = {}

        # Parse mitre_ids
        mitre_ids = row.get('mitre_ids', [])
        if hasattr(mitre_ids, 'tolist'):
            mitre_ids = mitre_ids.tolist()
        elif not isinstance(mitre_ids, list):
            mitre_ids = []
        # Filter out None/empty entries that can appear from DuckDB NULL array elements
        mitre_ids = [m for m in mitre_ids if m]

        # Parse severity — NULL / unexpected values fall back to 'low'
        sev_str = _ss(row.get('severity'), 'low').lower()
        severity = sev_str if sev_str in {'low', 'medium', 'high', 'critical'} else 'low'

        if client_id:
            amber_weeks, expired_weeks = self.get_client_validation_thresholds(
                client_id,
                severity=severity,
            )
        elif thresholds is None:
            amber_weeks = int(self.settings.rule_validation_amber_weeks)
            expired_weeks = int(self.settings.rule_validation_expired_weeks)
        else:
            amber_weeks, expired_weeks = thresholds

        # Get validation info
        rule_name = _ss(row.get('name'))
        val_info = validation_data.get(str(rule_name), {})

        validation_date = None
        validated_by = None
        validation_status = "never"

        if val_info:
            val_str = val_info.get('last_checked_on', '')
            validated_by = val_info.get('checked_by')
            if val_str:
                try:
                    validation_date = datetime.strptime(val_str[:19], "%Y-%m-%dT%H:%M:%S")
                    weeks = (datetime.now() - validation_date).days / 7
                    if weeks > expired_weeks:
                        validation_status = "expired"
                    elif weeks > amber_weeks:
                        validation_status = "amber"
                    else:
                        validation_status = "valid"
                except Exception:
                    pass

        return DetectionRule(
            rule_id=_ss(row.get('rule_id')),
            siem_id=_ss(row.get('siem_id')) or None,
            name=rule_name,
            severity=severity,
            author=_ss(row.get('author'), 'Unknown'),
            enabled=bool(_si(row.get('enabled'), 0)),
            space=_ss(row.get('space'), 'default'),
            score=_si(row.get('score')),
            quality_score=_si(row.get('quality_score')),
            meta_score=_si(row.get('meta_score')),
            score_mapping=_si(row.get('score_mapping')),
            score_field_type=_si(row.get('score_field_type')),
            score_search_time=_si(row.get('score_search_time')),
            score_language=_si(row.get('score_language')),
            score_note=_si(row.get('score_note')),
            score_override=_si(row.get('score_override')),
            score_tactics=_si(row.get('score_tactics')),
            score_techniques=_si(row.get('score_techniques')),
            score_author=_si(row.get('score_author')),
            score_highlights=_si(row.get('score_highlights')),
            mitre_ids=mitre_ids,
            last_updated=self._safe_dt(row.get('last_updated')),
            raw_data=raw_data,
            validation_date=validation_date,
            validated_by=validated_by,
            validation_status=validation_status,
        )
    
    def get_rule_health_metrics(
        self,
        allowed_scopes: Optional[List[Tuple[str, str]]] = None,
        thresholds: Optional[Tuple[int, int]] = None,
        client_id: Optional[str] = None,
    ) -> RuleHealthMetrics:
        """Calculate comprehensive rule health metrics.

        Tenant scoping is by composite ``(siem_id, space)`` pairs from
        :py:meth:`get_client_siem_scopes`. Space-name-only filtering would
        leak rules between two SIEMs that share a Kibana space name
        (AGENTS.md §8.2 g4)."""
        with self.get_connection() as conn:
            if allowed_scopes is not None:
                if not allowed_scopes:
                    return RuleHealthMetrics()
                frag, params = _scope_predicate(allowed_scopes)
                df = conn.execute(
                    f"SELECT enabled, score, siem_id, space, severity, name, raw_data "
                    f"FROM detection_rules WHERE {frag}",
                    params,
                ).df()
            else:
                df = conn.execute(
                    "SELECT enabled, score, siem_id, space, severity, name, raw_data FROM detection_rules"
                ).df()
            
            if df.empty:
                return RuleHealthMetrics()
            
            # Basic counts
            total_rules = len(df)
            enabled_rules = len(df[df['enabled'] == 1])
            
            # Score stats
            avg_score = float(df['score'].mean()) if 'score' in df.columns else 0
            min_score = int(df['score'].min()) if 'score' in df.columns else 0
            max_score = int(df['score'].max()) if 'score' in df.columns else 0
            
            # Quality tiers
            low_quality_count = len(df[df['score'] < 50])
            high_quality_count = len(df[df['score'] >= 80])
            
            # Quality brackets
            quality_excellent = len(df[df['score'] >= 80])
            quality_good = len(df[(df['score'] >= 70) & (df['score'] < 80)])
            quality_fair = len(df[(df['score'] >= 50) & (df['score'] < 70)])
            quality_poor = len(df[df['score'] < 50])
            
            # Rules by space (legacy, space-only) AND by composite scope.
            # The composite map is the authoritative one — keying by space
            # alone collapses two SIEMs that share a Kibana space-name into
            # a single bucket (AGENTS.md §8.2 g4). Templates should prefer
            # ``rules_by_scope`` and use ``rules_by_space`` only for
            # single-SIEM legacy views.
            rules_by_space = {}
            rules_by_scope = {}
            if 'space' in df.columns:
                space_counts = df['space'].value_counts().to_dict()
                rules_by_space = {str(k): int(v) for k, v in space_counts.items()}
                if 'siem_id' in df.columns:
                    pair_counts = (
                        df.dropna(subset=['siem_id', 'space'])
                          .groupby(['siem_id', 'space'])
                          .size()
                          .to_dict()
                    )
                    rules_by_scope = {
                        f"{sid}|{str(sp).lower()}": int(cnt)
                        for (sid, sp), cnt in pair_counts.items()
                    }
            
            # Severity breakdown
            severity_breakdown = {}
            if 'severity' in df.columns:
                sev_counts = df['severity'].value_counts().to_dict()
                severity_breakdown = {str(k): int(v) for k, v in sev_counts.items()}
            
            # Language breakdown
            language_breakdown = {}
            if 'raw_data' in df.columns:
                try:
                    langs = df['raw_data'].apply(
                        lambda x: json.loads(x).get('language', 'unknown') if x else 'unknown'
                    )
                    lang_counts = langs.value_counts().to_dict()
                    language_breakdown = {str(k): int(v) for k, v in lang_counts.items()}
                except:
                    pass
        
        # Validation stats (from JSON file)
        validated_count = 0
        validation_expired_count = 0
        validation_data = self._load_validation_data()
        if thresholds is None:
            expired_weeks = int(self.settings.rule_validation_expired_weeks)
        else:
            _, expired_weeks = thresholds

        if validation_data:
            now = datetime.now()
            for _, row in df.iterrows():
                rule_name = str(row.get('name') or '')
                rule_v = validation_data.get(rule_name, {})
                if rule_v:
                    validated_count += 1
                    val_str = rule_v.get('last_checked_on', '')
                    if val_str:
                        try:
                            val_date = datetime.strptime(val_str[:10], "%Y-%m-%d")
                            weeks = (now - val_date).days / 7
                            severity = str(row.get('severity') or 'low').lower()
                            amber_weeks, expired_weeks = (
                                self.get_client_validation_thresholds(client_id, severity=severity)
                                if client_id
                                else thresholds or (
                                    int(self.settings.rule_validation_amber_weeks),
                                    int(self.settings.rule_validation_expired_weeks),
                                )
                            )
                            if weeks > expired_weeks:
                                validation_expired_count += 1
                        except:
                            pass
        
        return RuleHealthMetrics(
            total_rules=total_rules,
            enabled_rules=enabled_rules,
            disabled_rules=total_rules - enabled_rules,
            avg_score=round(avg_score, 1),
            min_score=min_score,
            max_score=max_score,
            validated_count=validated_count,
            validation_expired_count=validation_expired_count,
            never_validated_count=total_rules - validated_count,
            low_quality_count=low_quality_count,
            high_quality_count=high_quality_count,
            quality_excellent=quality_excellent,
            quality_good=quality_good,
            quality_fair=quality_fair,
            quality_poor=quality_poor,
            rules_by_space=rules_by_space,
            rules_by_scope=rules_by_scope,
            severity_breakdown=severity_breakdown,
            language_breakdown=language_breakdown,
        )
    
    def get_unique_spaces(self, allowed_spaces: List[str] = None) -> List[str]:
        """Get list of unique Kibana spaces.
        If allowed_spaces is provided, only return spaces in that allow-list (tenant isolation)."""
        with self.get_connection() as conn:
            if allowed_spaces is not None:
                if not allowed_spaces:
                    return []
                placeholders = ", ".join("?" for _ in allowed_spaces)
                result = conn.execute(
                    f"SELECT DISTINCT space FROM detection_rules WHERE LOWER(space) IN ({placeholders}) ORDER BY space",
                    [s.lower() for s in allowed_spaces],
                ).fetchall()
            else:
                result = conn.execute(
                    "SELECT DISTINCT space FROM detection_rules ORDER BY space"
                ).fetchall()
            return [row[0] for row in result if row[0]]
    
    def get_threat_actor_filter_options(self) -> Tuple[List[str], List[str]]:
        """Get unique origins and sources for filter dropdowns (lightweight query)."""
        with self.get_connection() as conn:
            origins = []
            sources = []
            try:
                origin_rows = conn.execute(
                    "SELECT DISTINCT origin FROM threat_actors WHERE origin IS NOT NULL ORDER BY origin"
                ).fetchall()
                origins = [row[0] for row in origin_rows if row[0]]
            except Exception:
                pass
            try:
                source_rows = conn.execute(
                    "SELECT DISTINCT unnest(source) as src FROM threat_actors ORDER BY src"
                ).fetchall()
                sources = [row[0] for row in source_rows if row[0]]
            except Exception:
                pass
            return origins, sources
    
    def get_promotion_metrics(
        self,
        staging_scopes: Optional[List[Tuple[str, str]]] = None,
        production_scopes: Optional[List[Tuple[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Get metrics specifically for staging rules ready for promotion.

        Args:
            staging_scopes:    ``(siem_id, space)`` pairs tagged
                ``environment_role='staging'`` for the active client.
            production_scopes: ``(siem_id, space)`` pairs tagged
                ``environment_role='production'`` for the active client.

        If neither is provided, falls back to filtering by the literal
        ``staging`` / ``production`` space-name strings — used only by the
        stand-alone (no-client) admin views.

        Composite ``(siem_id, space)`` predicates are mandatory whenever a
        client scope is in play. Filtering by space-name alone leaks rules
        across SIEMs that share a Kibana space name (AGENTS.md §8.2 g4).
        """
        with self.get_connection() as conn:
            # ── Build staging filter ──
            if staging_scopes is not None:
                if not staging_scopes:
                    import pandas as _pd
                    staging_df = _pd.DataFrame(
                        columns=['enabled', 'score', 'severity', 'name']
                    )
                else:
                    frag, params = _scope_predicate(staging_scopes)
                    staging_df = conn.execute(
                        f"SELECT enabled, score, severity, name "
                        f"FROM detection_rules WHERE {frag}",
                        params,
                    ).df()
            else:
                staging_df = conn.execute(
                    "SELECT enabled, score, severity, name FROM detection_rules WHERE LOWER(space) = 'staging'"
                ).df()

            # ── Build production count ──
            if production_scopes is not None:
                if not production_scopes:
                    prod_result = (0,)
                else:
                    frag, params = _scope_predicate(production_scopes)
                    prod_result = conn.execute(
                        f"SELECT COUNT(*) FROM detection_rules WHERE {frag}",
                        params,
                    ).fetchone()
            else:
                prod_result = conn.execute(
                    "SELECT COUNT(*) FROM detection_rules WHERE LOWER(space) = 'production'"
                ).fetchone()
            production_total = prod_result[0] if prod_result else 0
            
            if staging_df.empty:
                return {
                    'staging_total': 0,
                    'staging_enabled': 0,
                    'staging_avg_score': 0,
                    'staging_min_score': 0,
                    'staging_max_score': 0,
                    'staging_low_quality': 0,
                    'staging_high_quality': 0,
                    'staging_quality_excellent': 0,
                    'staging_quality_good': 0,
                    'staging_quality_fair': 0,
                    'staging_quality_poor': 0,
                    'staging_severity': {},
                    'staging_validated': 0,
                    'staging_validation_expired': 0,
                    'staging_never_validated': 0,
                    'production_total': production_total,
                }
            
            staging_total = len(staging_df)
            staging_enabled = len(staging_df[staging_df['enabled'] == 1])
            staging_avg_score = float(staging_df['score'].mean()) if 'score' in staging_df.columns else 0
            staging_min_score = int(staging_df['score'].min()) if 'score' in staging_df.columns else 0
            staging_max_score = int(staging_df['score'].max()) if 'score' in staging_df.columns else 0
            staging_low_quality = len(staging_df[staging_df['score'] < 50])
            staging_high_quality = len(staging_df[staging_df['score'] >= 80])
            
            # Quality brackets
            staging_quality_excellent = len(staging_df[staging_df['score'] >= 80])
            staging_quality_good = len(staging_df[(staging_df['score'] >= 70) & (staging_df['score'] < 80)])
            staging_quality_fair = len(staging_df[(staging_df['score'] >= 50) & (staging_df['score'] < 70)])
            staging_quality_poor = len(staging_df[staging_df['score'] < 50])
            
            staging_severity = {}
            if 'severity' in staging_df.columns:
                sev_counts = staging_df['severity'].value_counts().to_dict()
                staging_severity = {str(k).lower(): int(v) for k, v in sev_counts.items()}
            
            # Validation stats for staging rules
            staging_validated = 0
            staging_validation_expired = 0
            validation_data = self._load_validation_data()
            if validation_data:
                now = datetime.now()
                for rule_name in staging_df['name'].tolist():
                    rule_v = validation_data.get(str(rule_name), {})
                    if rule_v:
                        staging_validated += 1
                        val_str = rule_v.get('last_checked_on', '')
                        if val_str:
                            try:
                                val_date = datetime.strptime(val_str[:10], "%Y-%m-%d")
                                weeks = (now - val_date).days / 7
                                if weeks > 12:
                                    staging_validation_expired += 1
                            except:
                                pass
            
            return {
                'staging_total': staging_total,
                'staging_enabled': staging_enabled,
                'staging_avg_score': staging_avg_score,
                'staging_min_score': staging_min_score,
                'staging_max_score': staging_max_score,
                'staging_low_quality': staging_low_quality,
                'staging_high_quality': staging_high_quality,
                'staging_quality_excellent': staging_quality_excellent,
                'staging_quality_good': staging_quality_good,
                'staging_quality_fair': staging_quality_fair,
                'staging_quality_poor': staging_quality_poor,
                'staging_severity': staging_severity,
                'staging_validated': staging_validated,
                'staging_validation_expired': staging_validation_expired,
                'staging_never_validated': staging_total - staging_validated,
                'production_total': production_total,
            }
    
    # --- RULE LIFECYCLE HISTORY ---

    def _ensure_rule_lifecycle_history_table(self, conn) -> None:
        """Ensure lifecycle history table exists in the active DB connection.

        TIDE uses per-tenant DuckDB files for tenant-scoped rule data. Migrations
        run on the shared DB at startup, so this guard also creates the table in
        tenant DBs lazily when lifecycle methods are called.
        """
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rule_lifecycle_history (
                id VARCHAR PRIMARY KEY DEFAULT (uuid()::VARCHAR),
                rule_id VARCHAR NOT NULL,
                siem_id VARCHAR NOT NULL,
                space VARCHAR NOT NULL,
                client_id VARCHAR NOT NULL,
                action VARCHAR NOT NULL,
                actor_user_id VARCHAR,
                actor_name VARCHAR,
                detail JSON,
                created_at TIMESTAMP DEFAULT now()
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rule_lifecycle_rule "
            "ON rule_lifecycle_history (rule_id, siem_id, space, client_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rule_lifecycle_created "
            "ON rule_lifecycle_history (created_at DESC)"
        )
    
    def record_rule_history(
        self,
        rule_id: str,
        siem_id: str,
        space: str,
        client_id: str,
        action: str,
        actor_user_id: Optional[str] = None,
        actor_name: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
        created_at: Optional[datetime] = None,
    ) -> str:
        """Record a rule lifecycle event (create/edit/enable/disable/validate/promote).
        
        Returns the history record ID.
        """
        import json as _json
        detail_json = _json.dumps(detail or {})
        with self.get_connection() as conn:
            self._ensure_rule_lifecycle_history_table(conn)
            if created_at is None:
                conn.execute(
                    "INSERT INTO rule_lifecycle_history "
                    "(rule_id, siem_id, space, client_id, action, actor_user_id, actor_name, detail) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    [rule_id, siem_id, space, client_id, action, actor_user_id, actor_name, detail_json],
                )
            else:
                conn.execute(
                    "INSERT INTO rule_lifecycle_history "
                    "(rule_id, siem_id, space, client_id, action, actor_user_id, actor_name, detail, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [rule_id, siem_id, space, client_id, action, actor_user_id, actor_name, detail_json, created_at],
                )
            row = conn.execute(
                "SELECT id FROM rule_lifecycle_history "
                "WHERE rule_id = ? AND siem_id = ? AND space = ? AND action = ? "
                "ORDER BY created_at DESC LIMIT 1",
                [rule_id, siem_id, space, action],
            ).fetchone()
        return row[0] if row else None
    
    def get_rule_history(
        self,
        rule_id: str,
        siem_id: str,
        space: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit trail for a specific rule (scoped by siem_id + space).
        
        Returns a list of history records sorted by creation time (newest first).
        """
        import json as _json
        with self.get_connection() as conn:
            self._ensure_rule_lifecycle_history_table(conn)
            rows = conn.execute(
                "SELECT id, action, actor_user_id, actor_name, detail, created_at "
                "FROM rule_lifecycle_history "
                "WHERE rule_id = ? AND siem_id = ? AND space = ? "
                "ORDER BY created_at DESC LIMIT ?",
                [rule_id, siem_id, space, limit],
            ).fetchall()
        
        result = []
        for row in rows:
            detail = {}
            try:
                if row[4]:
                    detail = _json.loads(row[4])
            except Exception:
                pass
            result.append({
                "id": row[0],
                "action": row[1],
                "actor_user_id": row[2],
                "actor_name": row[3],
                "detail": detail,
                "created_at": row[5],
            })
        return result

    def _ensure_rule_score_history_table(self, conn) -> None:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rule_score_history (
                id UUID DEFAULT uuid(),
                rule_id VARCHAR NOT NULL,
                siem_id VARCHAR NOT NULL,
                space VARCHAR NOT NULL,
                client_id VARCHAR NOT NULL,
                score INTEGER,
                quality_score INTEGER,
                meta_score INTEGER,
                score_mapping INTEGER,
                score_field_type INTEGER,
                score_search_time INTEGER,
                score_language INTEGER,
                score_note INTEGER,
                score_override INTEGER,
                score_tactics INTEGER,
                score_techniques INTEGER,
                score_author INTEGER,
                score_highlights INTEGER,
                created_at TIMESTAMP DEFAULT now()
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rule_score_history_rule "
            "ON rule_score_history (rule_id, siem_id, space, client_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rule_score_history_created "
            "ON rule_score_history (created_at DESC)"
        )

    def record_rule_score_snapshot(
        self,
        rule_id: str,
        siem_id: str,
        space: str,
        client_id: str,
        rule_data: Dict[str, Any],
        created_at: Optional[datetime] = None,
    ) -> Optional[str]:
        """Store the score payload for one synced rule."""
        with self.get_connection() as conn:
            self._ensure_rule_score_history_table(conn)
            columns = [
                "rule_id", "siem_id", "space", "client_id", "score",
                "quality_score", "meta_score", "score_mapping",
                "score_field_type", "score_search_time", "score_language",
                "score_note", "score_override", "score_tactics",
                "score_techniques", "score_author", "score_highlights",
            ]
            values = [
                rule_id,
                siem_id,
                space,
                client_id,
                rule_data.get("score"),
                rule_data.get("quality_score"),
                rule_data.get("meta_score"),
                rule_data.get("score_mapping"),
                rule_data.get("score_field_type"),
                rule_data.get("score_search_time"),
                rule_data.get("score_language"),
                rule_data.get("score_note"),
                rule_data.get("score_override"),
                rule_data.get("score_tactics"),
                rule_data.get("score_techniques"),
                rule_data.get("score_author"),
                rule_data.get("score_highlights"),
            ]
            if created_at is None:
                conn.execute(
                    f"INSERT INTO rule_score_history ({', '.join(columns)}) VALUES ({', '.join(['?'] * len(columns))})",
                    values,
                )
            else:
                conn.execute(
                    f"INSERT INTO rule_score_history ({', '.join(columns)}, created_at) VALUES ({', '.join(['?'] * len(columns))}, ?)",
                    values + [created_at],
                )
            row = conn.execute(
                "SELECT id FROM rule_score_history WHERE rule_id = ? AND siem_id = ? AND space = ? ORDER BY created_at DESC LIMIT 1",
                [rule_id, siem_id, space],
            ).fetchone()
        return row[0] if row else None

    def get_rule_score_history(
        self,
        rule_id: str,
        siem_id: str,
        space: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Return score snapshots for one rule, newest first."""
        with self.get_connection() as conn:
            self._ensure_rule_score_history_table(conn)
            rows = conn.execute(
                "SELECT score, quality_score, meta_score, score_mapping, score_field_type, score_search_time, score_language, score_note, score_override, score_tactics, score_techniques, score_author, score_highlights, created_at "
                "FROM rule_score_history WHERE rule_id = ? AND siem_id = ? AND space = ? ORDER BY created_at DESC LIMIT ?",
                [rule_id, siem_id, space, limit],
            ).fetchall()
        return [
            {
                "score": row[0],
                "quality_score": row[1],
                "meta_score": row[2],
                "score_mapping": row[3],
                "score_field_type": row[4],
                "score_search_time": row[5],
                "score_language": row[6],
                "score_note": row[7],
                "score_override": row[8],
                "score_tactics": row[9],
                "score_techniques": row[10],
                "score_author": row[11],
                "score_highlights": row[12],
                "created_at": row[13],
            }
            for row in rows
        ]
    
    def bootstrap_rule_history_from_elastic(
        self,
        rule_data: Dict[str, Any],
        client_id: str,
    ) -> None:
        """Bootstrap lifecycle history from Elastic metadata on first sync.
        
        Extracts created_by/created_at from raw_data and records a 'created' event
        if this is the rule's first appearance in TIDE.
        """
        rule_id = rule_data.get("rule_id")
        siem_id = rule_data.get("siem_id")
        space = rule_data.get("space") or rule_data.get("space_id") or "default"
        
        if not all([rule_id, siem_id, space]):
            return
        
        raw_data = rule_data.get("raw_data", {})
        created_by = (raw_data.get("created_by") or "system").strip() or "system"
        updated_by = (raw_data.get("updated_by") or created_by or "system").strip() or "system"

        def _coerce_ts(value: Any) -> Optional[datetime]:
            if not value:
                return None
            if isinstance(value, datetime):
                return value
            try:
                return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            except Exception:
                return None

        created_at = _coerce_ts(raw_data.get("created_at")) or datetime.now()
        updated_at = _coerce_ts(raw_data.get("updated_at"))
        updated_stamp = updated_at.isoformat() if updated_at else ""

        has_created = False
        has_matching_elastic_edit = False
        with self.get_connection() as conn:
            self._ensure_rule_lifecycle_history_table(conn)
            rows = conn.execute(
                "SELECT action, detail FROM rule_lifecycle_history "
                "WHERE rule_id = ? AND siem_id = ? AND space = ?",
                [rule_id, siem_id, space],
            ).fetchall()
            for action, detail_json in rows:
                detail = {}
                try:
                    detail = json.loads(detail_json) if detail_json else {}
                except Exception:
                    detail = {}
                if action == "created":
                    has_created = True
                if (
                    action == "edited"
                    and detail.get("source") == "elastic_sync"
                    and detail.get("elastic_timestamp") == updated_stamp
                ):
                    has_matching_elastic_edit = True

        if not has_created:
            self.record_rule_history(
                rule_id=rule_id,
                siem_id=siem_id,
                space=space,
                client_id=client_id,
                action="created",
                actor_user_id=None,
                actor_name=created_by,
                detail={
                    "source": "elastic_sync",
                    "message": "Created in Kibana before initial sync.",
                    "elastic_timestamp": created_at.isoformat(),
                },
                created_at=created_at,
            )

        if updated_at and updated_at > created_at and not has_matching_elastic_edit:
            self.record_rule_history(
                rule_id=rule_id,
                siem_id=siem_id,
                space=space,
                client_id=client_id,
                action="edited",
                actor_user_id=None,
                actor_name=updated_by,
                detail={
                    "source": "elastic_sync",
                    "message": "Updated in Kibana before sync.",
                    "elastic_timestamp": updated_stamp,
                },
                created_at=updated_at,
            )
    
    # --- THREAT ACTOR OPERATIONS ---

    def _client_has_opencti(self, client_id: Optional[str]) -> bool:
        """Return True when *client_id* has at least one ACTIVE CTI connector linked.

        Post-5.0.0: the legacy ``client_opencti_map`` + ``opencti_inventory``
        tables are dropped (migration 50). Linkage now lives in
        ``cti_connector_clients`` keyed against ``cti_connectors`` (any
        vendor — OpenCTI TAXII, Mandiant, CrowdStrike, MITRE, GreyNoise).
        """
        if not client_id:
            return False
        try:
            with self.get_shared_connection() as conn:
                row = conn.execute(
                    "SELECT 1 FROM cti_connector_clients ccc "
                    "JOIN cti_connectors c ON c.id = ccc.connector_id "
                    "WHERE ccc.client_id = ? "
                    "AND COALESCE(c.is_active, TRUE) = TRUE "
                    "LIMIT 1",
                    [client_id],
                ).fetchone()
            return bool(row)
        except Exception as exc:
            logger.warning(f"_client_has_opencti({client_id}) failed: {exc}")
            return False

    # ─── MITRE-source detection (used by threat-actor isolation) ─────
    # 4.1.5 — A threat_actors row is considered "MITRE baseline" (visible to
    # every client) if its ``source`` array contains any string that begins
    # with ``"mitre"`` (case-insensitive). That covers every form
    # ``cti_helper.process_stix_bundle`` writes — ``"MITRE: enterprise"``,
    # ``"MITRE: ics"``, ``"MITRE: mobile"``, ``"MITRE: pre"`` — plus historic
    # variants like ``"mitre-enterprise"`` / ``"mitre:ics"`` and the bare
    # ``"mitre"`` token. Anything else is treated as OpenCTI-sourced and is
    # per-tenant.
    @staticmethod
    def _row_is_mitre(source_value) -> bool:
        if hasattr(source_value, "tolist"):
            source_value = source_value.tolist()
        if source_value is None:
            return False
        if not isinstance(source_value, (list, tuple, set)):
            source_value = [source_value]
        if not source_value:
            return False
        for s in source_value:
            if not s:
                continue
            tok = str(s).strip().lower()
            if tok == "mitre" or tok.startswith("mitre:") or tok.startswith("mitre-") or tok.startswith("mitre "):
                return True
        return False

    def clear_octi_threat_actors_in_active_db(self) -> int:
        """Delete OpenCTI-sourced threat_actors rows from the active DB context.

        4.1.5 isolation: keeps any MITRE-sourced rows untouched so the shared
        DB does not lose its baseline when this is invoked without a tenant
        context. In a tenant DB the table holds OpenCTI rows only, so this
        effectively wipes it.
        """
        try:
            with self.get_connection() as conn:
                # Count first (DuckDB rowcount on bulk DELETE is unreliable).
                rows = conn.execute("SELECT name, source FROM threat_actors").fetchall()
                victims = [r[0] for r in rows if not self._row_is_mitre(r[1])]
                if not victims:
                    return 0
                conn.executemany(
                    "DELETE FROM threat_actors WHERE name = ?",
                    [[v] for v in victims],
                )
                return len(victims)
        except Exception as exc:
            logger.error(f"clear_octi_threat_actors_in_active_db failed: {exc}")
            return 0

    def save_octi_threat_actors_to_active_db(self, df) -> int:
        """Upsert OpenCTI-sourced threat_actors rows into the active DB context.

        4.1.5 isolation: callers must wrap this in
        ``tenant_manager.tenant_context_for(client_id)`` so the rows land in
        the correct tenant DB.

        4.1.19 hardening: refuse to run without an active tenant context.
        Falling back to the shared DB historically caused OpenCTI-sourced
        actors from one tenant's link to bleed into every other tenant's
        landscape view (the shared ``threat_actors`` table is read by every
        tenant before its per-tenant rows are merged in). Every tenant now
        owns its own DuckDB file, so a missing context is a bug, not a
        legacy fallback path.

        Mirrors the input shape of ``app.database.save_threat_data`` but uses
        the tenant-aware connection pool. Returns the number of rows
        upserted.
        """
        if df is None or df.empty:
            return 0
        from app.services.tenant_manager import get_tenant_db_path
        if get_tenant_db_path() is None:
            logger.error(
                "save_octi_threat_actors_to_active_db refused: no tenant "
                "context active. Wrap the call in "
                "tenant_manager.tenant_context_for(client_id). Writing "
                "OpenCTI rows to the shared DB would leak them into every "
                "tenant's threat landscape."
            )
            return 0
        try:
            from datetime import datetime as _dt
            df = df.copy()
            df.columns = [c.lower().strip() for c in df.columns]
            renames = {"actor": "name", "type": "origin"}
            df.rename(columns=renames, inplace=True)
            if "ttp_count" not in df.columns and "ttps" in df.columns:
                df["ttp_count"] = df["ttps"].apply(
                    lambda x: len(x) if isinstance(x, list) else 0
                )
            if "last_updated" not in df.columns:
                df["last_updated"] = _dt.now()
            for col in ("description", "aliases", "origin"):
                if col not in df.columns:
                    df[col] = None
            if "source" not in df.columns:
                df["source"] = [["OCTI"]] * len(df)
            df["source"] = df["source"].apply(
                lambda x: x if isinstance(x, list) else (
                    [x] if x else ["OCTI"]
                )
            )
            df["ttps"] = df["ttps"].apply(
                lambda x: x if isinstance(x, list) else []
            )

            # 4.1.19: alias-aware merge. OpenCTI and MITRE often disagree
            # on the canonical name for the same actor (e.g. MITRE calls
            # them "APT28" with "Fancy Bear" in aliases, OpenCTI returns
            # "FANCY BEAR" with "APT28" in aliases). Without merging, the
            # Threat Landscape shows two rows for the same group. Build a
            # lookup of every known name+alias (case-insensitive) from the
            # shared MITRE catalog AND any rows already in the tenant DB,
            # then rewrite each incoming OCTI ``name`` to the canonical
            # name it matches. MITRE-sourced canonicals win over OCTI when
            # both match, so the user-visible name stays consistent with
            # the ATT&CK framework.
            def _split_aliases(raw):
                if not raw:
                    return []
                if isinstance(raw, list):
                    items = raw
                else:
                    items = str(raw).split(",")
                return [a.strip() for a in items if a and str(a).strip()]

            alias_to_canonical: dict = {}
            canonical_is_mitre: dict = {}

            def _register(name: str, aliases_raw, is_mitre: bool):
                if not name:
                    return
                key = name.lower()
                # MITRE canonical always wins; otherwise first writer wins.
                if key not in alias_to_canonical or (
                    is_mitre and not canonical_is_mitre.get(
                        alias_to_canonical[key], False
                    )
                ):
                    alias_to_canonical[key] = name
                    canonical_is_mitre[name] = is_mitre
                canonical = alias_to_canonical[key]
                for alias in _split_aliases(aliases_raw):
                    akey = alias.lower()
                    if akey == key:
                        continue
                    # Don't overwrite a MITRE-owned alias with an OCTI one.
                    if akey in alias_to_canonical and canonical_is_mitre.get(
                        alias_to_canonical[akey], False
                    ):
                        continue
                    alias_to_canonical[akey] = canonical

            # Seed the lookup from existing rows (shared MITRE first so it
            # claims canonical ownership, then tenant DB).
            try:
                with self.get_shared_connection() as sconn:
                    for _n, _a, _s in sconn.execute(
                        "SELECT name, aliases, source FROM threat_actors"
                    ).fetchall():
                        _register(_n, _a, self._row_is_mitre(_s))
            except Exception as _exc:
                logger.warning(
                    f"save_octi_threat_actors_to_active_db: "
                    f"failed to seed MITRE alias map: {_exc}"
                )

            saved = 0
            with self.get_connection() as conn:
                # Seed from any rows already in this tenant DB (previous OCTI
                # sync) so re-runs stay stable.
                try:
                    for _n, _a, _s in conn.execute(
                        "SELECT name, aliases, source FROM threat_actors"
                    ).fetchall():
                        _register(_n, _a, self._row_is_mitre(_s))
                except Exception:
                    pass

                for _, row in df.iterrows():
                    name = row.get("name")
                    if not name:
                        continue

                    # Resolve canonical name via alias map.
                    candidates = {name.lower()} | {
                        a.lower() for a in _split_aliases(row.get("aliases"))
                    }
                    canonical = None
                    for cand in candidates:
                        hit = alias_to_canonical.get(cand)
                        if hit:
                            # Prefer a MITRE-owned canonical if multiple hit.
                            if canonical is None or (
                                canonical_is_mitre.get(hit, False)
                                and not canonical_is_mitre.get(canonical, False)
                            ):
                                canonical = hit
                    if canonical is None:
                        canonical = name
                    # Remember for the rest of the batch so later OCTI rows
                    # whose alias list overlaps merge into the same row.
                    _register(canonical, row.get("aliases"), False)

                    # Union the aliases string with whatever the canonical
                    # row already has, so MITRE's alias list survives the
                    # OCTI update.
                    existing_aliases = ""
                    try:
                        existing_aliases = conn.execute(
                            "SELECT aliases FROM threat_actors WHERE name = ?",
                            [canonical],
                        ).fetchone()
                        existing_aliases = (
                            existing_aliases[0] if existing_aliases else ""
                        ) or ""
                    except Exception:
                        existing_aliases = ""
                    merged_aliases_set = []
                    seen_alias = set()
                    # Include the *other* canonical names of this group so
                    # the alias field always carries the OCTI display name
                    # when MITRE wins (and vice versa).
                    for src in (
                        existing_aliases,
                        row.get("aliases"),
                        name if name.lower() != canonical.lower() else "",
                    ):
                        for a in _split_aliases(src):
                            akey = a.lower()
                            if akey == canonical.lower() or akey in seen_alias:
                                continue
                            seen_alias.add(akey)
                            merged_aliases_set.append(a)
                    merged_aliases = (
                        ", ".join(merged_aliases_set)
                        if merged_aliases_set else None
                    )

                    # 4.1.19: union the source array on conflict so the
                    # MITRE-baseline marker is preserved when an OpenCTI
                    # actor name collides with a MITRE actor name (e.g.
                    # APT28, Lazarus). Previously ``SET source =
                    # EXCLUDED.source`` overwrote ``["MITRE: enterprise"]``
                    # with ``["OCTI"]``, which then caused the row to be
                    # filtered out for tenants without an OpenCTI link
                    # (``_row_is_mitre`` no longer matched).
                    conn.execute(
                        """
                        INSERT INTO threat_actors
                            (name, description, ttps, ttp_count, aliases,
                             origin, source, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (name) DO UPDATE SET
                            ttps = EXCLUDED.ttps,
                            ttp_count = EXCLUDED.ttp_count,
                            source = list_distinct(
                                list_concat(
                                    COALESCE(threat_actors.source, []),
                                    COALESCE(EXCLUDED.source, [])
                                )
                            ),
                            aliases = EXCLUDED.aliases,
                            description = COALESCE(EXCLUDED.description,
                                                   threat_actors.description),
                            origin = COALESCE(EXCLUDED.origin,
                                              threat_actors.origin),
                            last_updated = EXCLUDED.last_updated
                        """,
                        [
                            canonical,
                            row.get("description"),
                            row["ttps"],
                            int(row.get("ttp_count") or 0),
                            merged_aliases,
                            row.get("origin"),
                            row["source"],
                            row.get("last_updated"),
                        ],
                    )
                    saved += 1
            return saved
        except Exception as exc:
            logger.error(f"save_octi_threat_actors_to_active_db failed: {exc}")
            return 0

    def get_threat_actors(self, client_id: Optional[str] = None) -> List[ThreatActor]:
        """Get all threat actors ordered by TTP count.

        4.1.5 isolation rules:
        * MITRE-sourced actors live in the **shared** DB and are visible to
          every client (they were loaded at build / by the MITRE sync phase).
        * OpenCTI-sourced actors live in the **tenant** DB and are only
          returned when the request is in that tenant's context.
        * For backwards compatibility the shared DB may still contain
          OpenCTI rows for the primary/legacy client (which has no dedicated
          tenant DB); those rows are filtered out unless ``client_id``
          actually links to an OpenCTI instance.
        * ``client_id=None`` returns everything (background jobs, exports).
        """
        from app.services.tenant_manager import get_tenant_db_path
        include_opencti_shared = client_id is None or self._client_has_opencti(client_id)
        in_tenant_ctx = get_tenant_db_path() is not None

        with self.get_shared_connection() as conn:
            df = conn.execute(
                "SELECT * FROM threat_actors ORDER BY ttp_count DESC"
            ).df()

            actors = []
            for _, row in df.iterrows():
                ttps = row.get('ttps', [])
                if hasattr(ttps, 'tolist'):
                    ttps = ttps.tolist()
                
                source = row.get('source', [])
                if hasattr(source, 'tolist'):
                    source = source.tolist()
                
                # Handle NaN values for optional string fields
                import math
                origin_val = row.get('origin')
                if origin_val is None or (isinstance(origin_val, float) and math.isnan(origin_val)):
                    origin_val = None
                    
                description_val = row.get('description')
                if description_val is None or (isinstance(description_val, float) and math.isnan(description_val)):
                    description_val = None
                    
                aliases_val = row.get('aliases')
                if aliases_val is None or (isinstance(aliases_val, float) and math.isnan(aliases_val)):
                    aliases_val = None
                
                actors.append(ThreatActor(
                    name=row.get('name', ''),
                    description=description_val,
                    ttps=ttps,
                    ttp_count=row.get('ttp_count', 0),
                    aliases=aliases_val,
                    origin=origin_val,
                    source=source if isinstance(source, list) else [],
                    last_updated=row.get('last_updated'),
                ))

            if not include_opencti_shared:
                # Tenant has no OpenCTI link — keep only MITRE-baseline rows
                # from the shared DB. Anything sourced solely from another
                # tenant's OpenCTI feed (legacy data) is hidden.
                actors = [a for a in actors if self._row_is_mitre(a.source)]

        # Tenant DB OpenCTI rows (4.1.5 isolation). Only attempt this when a
        # tenant context is active AND the tenant DB is registered, so the
        # shared DB read above is not duplicated for legacy/primary clients.
        if in_tenant_ctx:
            try:
                with self.get_connection() as tconn:
                    tdf = tconn.execute(
                        "SELECT * FROM threat_actors ORDER BY ttp_count DESC"
                    ).df()
                import math as _math
                # 4.1.19: when a tenant row's name matches a shared row
                # (alias-aware merge writes OCTI updates under the MITRE
                # canonical name), union the source markers and aliases
                # into the shared row instead of dropping the tenant copy
                # silently — otherwise the OCTI badge for actors like
                # APT28 / Lazarus disappears even though OpenCTI knows
                # about them.
                by_name = {a.name: a for a in actors}
                for _, row in tdf.iterrows():
                    name = row.get("name", "")
                    if not name:
                        continue
                    ttps = row.get("ttps", [])
                    if hasattr(ttps, "tolist"):
                        ttps = ttps.tolist()
                    source = row.get("source", [])
                    if hasattr(source, "tolist"):
                        source = source.tolist()
                    origin_val = row.get("origin")
                    if origin_val is None or (isinstance(origin_val, float)
                                              and _math.isnan(origin_val)):
                        origin_val = None
                    description_val = row.get("description")
                    if description_val is None or (isinstance(description_val, float)
                                                   and _math.isnan(description_val)):
                        description_val = None
                    aliases_val = row.get("aliases")
                    if aliases_val is None or (isinstance(aliases_val, float)
                                               and _math.isnan(aliases_val)):
                        aliases_val = None

                    existing = by_name.get(name)
                    if existing is not None:
                        # Merge: union source markers, union aliases string,
                        # prefer shared description (MITRE-curated) but fall
                        # back to OCTI's if shared is empty.
                        merged_src = list(existing.source or [])
                        for s in (source or []):
                            if s and s not in merged_src:
                                merged_src.append(s)
                        existing.source = merged_src
                        if aliases_val:
                            existing_aliases = existing.aliases or ""
                            seen = {
                                a.strip().lower()
                                for a in existing_aliases.split(",")
                                if a.strip()
                            }
                            extra = []
                            for a in aliases_val.split(","):
                                ak = a.strip()
                                if ak and ak.lower() not in seen:
                                    extra.append(ak)
                                    seen.add(ak.lower())
                            if extra:
                                existing.aliases = ", ".join(
                                    ([existing_aliases] if existing_aliases else [])
                                    + extra
                                )
                        if not existing.description and description_val:
                            existing.description = description_val
                        continue

                    new_actor = ThreatActor(
                        name=name,
                        description=description_val,
                        ttps=ttps,
                        ttp_count=row.get("ttp_count", 0),
                        aliases=aliases_val,
                        origin=origin_val,
                        source=source if isinstance(source, list) else [],
                        last_updated=row.get("last_updated"),
                    )
                    actors.append(new_actor)
                    by_name[name] = new_actor
                actors.sort(key=lambda a: (a.ttp_count or 0), reverse=True)
            except Exception as exc:
                logger.warning(
                    f"get_threat_actors: tenant DB read failed for "
                    f"client_id={client_id}: {exc}"
                )

        return actors
    
    def get_covered_ttps_by_space(self, space: str = "production") -> Set[str]:
        """Get TTPs covered by enabled detection rules in a specific space."""
        with self.get_connection() as conn:
            result = conn.execute("""
                SELECT DISTINCT unnest(mitre_ids) 
                FROM detection_rules 
                WHERE enabled = 1 AND LOWER(space) = LOWER(?)
            """, [space]).fetchall()
            return {row[0].upper() for row in result if row[0]}
    
    def get_technique_rule_counts(self, space: str = "production") -> dict:
        """Get count of enabled rules per MITRE technique in a specific space."""
        with self.get_connection() as conn:
            try:
                # Use CTE to unnest first, then group
                result = conn.execute("""
                    WITH unnested AS (
                        SELECT UPPER(unnest(mitre_ids)) as technique
                        FROM detection_rules 
                        WHERE enabled = 1 AND LOWER(space) = LOWER(?)
                    )
                    SELECT technique, COUNT(*) as rule_count
                    FROM unnested
                    WHERE technique IS NOT NULL
                    GROUP BY technique
                """, [space]).fetchall()
                return {row[0]: row[1] for row in result if row[0]}
            except Exception as e:
                logger.warning(f"Failed to get technique rule counts: {e}")
                return {}
    
    def get_threat_landscape_metrics(self, client_id: str = None) -> "ThreatLandscapeMetrics":
        """Calculate comprehensive threat landscape metrics.
        If client_id provided, coverage is scoped to that client's production
        ``(siem_id, space)`` pairs. Composite scope is mandatory — a
        space-only filter would leak TTP coverage from any other SIEM that
        shares a Kibana space name (AGENTS.md §8.2 g4)."""
        from app.models.threats import ThreatLandscapeMetrics

        # Pre-fetch composite scopes outside the main connection.
        prod_scopes = None
        if client_id:
            prod_scopes = self.get_client_siem_scopes(client_id, "production")
        
        with self.get_connection() as conn:
            # Threat actors are intentionally global (MITRE ATT&CK / OpenCTI
            # reference data shared across all clients).  Only rule *coverage*
            # is scoped to the active client's production SIEM spaces below.
            # NOTE: when the tenant has NO OpenCTI link, OpenCTI-only actors
            # are filtered out post-fetch so the landscape totals match what
            # the operator actually sees on /threats and /heatmap.
            df = conn.execute(
                "SELECT name, ttp_count, ttps, origin, source FROM threat_actors"
            ).df()

            if df.empty:
                return ThreatLandscapeMetrics()

            include_opencti_only = client_id is None or self._client_has_opencti(client_id)
            if not include_opencti_only and 'source' in df.columns:
                # 4.1.5 — delegate to the central MITRE detector so any source
                # string starting with ``mitre`` (case-insensitive, any
                # separator) is preserved. Previously this used a stale
                # frozenset that didn't match the ``"MITRE: <matrix>"`` strings
                # written by ``cti_helper.process_stix_bundle``, so for
                # tenants without an OpenCTI link this filter dropped every
                # row and the landscape cards rendered as zeros.
                df = df[df['source'].apply(self._row_is_mitre)].reset_index(drop=True)
                if df.empty:
                    return ThreatLandscapeMetrics()
            
            # Get covered TTPs inline (avoid nested connection)
            if prod_scopes is not None:
                if prod_scopes:
                    frag, params = _scope_predicate(prod_scopes)
                    covered_result = conn.execute(f"""
                        SELECT DISTINCT unnest(mitre_ids)
                        FROM detection_rules
                        WHERE enabled = 1 AND {frag}
                    """, params).fetchall()
                else:
                    # Client has 0 mapped (siem,space) pairs — no covered TTPs
                    covered_result = []
            else:
                covered_result = conn.execute("""
                    SELECT DISTINCT unnest(mitre_ids) 
                    FROM detection_rules 
                    WHERE enabled = 1
                """).fetchall()
            covered_ttps = {row[0].upper() for row in covered_result if row[0]}
            
            # Basic counts
            total_actors = len(df)
            total_ttps = int(df['ttp_count'].sum()) if 'ttp_count' in df.columns else 0
            
            # Gather all unique TTPs across all actors
            all_ttps = set()
            for ttps_list in df['ttps']:
                if ttps_list is not None and hasattr(ttps_list, '__len__') and len(ttps_list) > 0:
                    for t in ttps_list:
                        all_ttps.add(str(t).strip().upper())
            
            unique_ttps = len(all_ttps)
            
            # Coverage stats
            covered_unique = all_ttps.intersection(covered_ttps)
            uncovered_unique = all_ttps - covered_ttps
            covered_count = len(covered_unique)
            uncovered_count = len(uncovered_unique)
            global_coverage_pct = round((covered_count / unique_ttps * 100), 1) if unique_ttps > 0 else 0
            
            # Actor stats
            avg_ttps = round(total_ttps / total_actors, 1) if total_actors > 0 else 0
            
            # Origin breakdown
            origin_breakdown = {}
            if 'origin' in df.columns:
                origin_counts = df['origin'].value_counts().to_dict()
                origin_breakdown = {str(k): int(v) for k, v in origin_counts.items() if k}
            
            # Source breakdown
            source_breakdown = {}
            if 'source' in df.columns:
                for source_list in df['source']:
                    if source_list is not None:
                        if hasattr(source_list, 'tolist'):
                            source_list = source_list.tolist()
                        if isinstance(source_list, list):
                            for src in source_list:
                                source_breakdown[src] = source_breakdown.get(src, 0) + 1
            
            # Actor coverage tiers
            fully_covered = 0
            partially_covered = 0
            uncovered_actors = 0
            
            for ttps_list in df['ttps']:
                if ttps_list is None or len(ttps_list) == 0:
                    uncovered_actors += 1
                    continue
                
                actor_ttps = {str(t).strip().upper() for t in ttps_list}
                actor_covered = actor_ttps.intersection(covered_ttps)
                
                if len(actor_covered) == len(actor_ttps):
                    fully_covered += 1
                elif len(actor_covered) > 0:
                    partially_covered += 1
                else:
                    uncovered_actors += 1
            
            return ThreatLandscapeMetrics(
                total_actors=total_actors,
                total_ttps=total_ttps,
                unique_ttps=unique_ttps,
                avg_ttps_per_actor=avg_ttps,
                covered_ttps=covered_count,
                uncovered_ttps=uncovered_count,
                global_coverage_pct=global_coverage_pct,
                origin_breakdown=origin_breakdown,
                source_breakdown=source_breakdown,
                fully_covered_actors=fully_covered,
                partially_covered_actors=partially_covered,
                uncovered_actors=uncovered_actors,
            )
    
    def get_dashboard_metrics(self, client_id: str = None) -> Tuple[RuleHealthMetrics, Dict[str, Any], "ThreatLandscapeMetrics"]:
        """
        Get all three metric sets for the dashboard in a single DB connection.
        Loads validation data once and reuses it across rule health + promotion.
        When client_id is provided, scopes rules to that client's production SIEM spaces.
        """
        from app.models.threats import ThreatLandscapeMetrics
        
        # Load validation data once
        validation_data = self._load_validation_data()
        now = datetime.now()
        
        # Resolve composite (siem_id, space) scopes for tenant scoping.
        # Composite key is mandatory — a space-only allow-list bleeds rules
        # between SIEMs that share a Kibana space name (AGENTS.md §8.2 g4).
        allowed_scopes: Optional[List[Tuple[str, str]]] = None
        if client_id:
            allowed_scopes = self.get_client_siem_scopes(client_id)

        with self.get_connection() as conn:
            # ── Rule Health Metrics ──
            if allowed_scopes is not None:
                if allowed_scopes:
                    frag, scope_params = _scope_predicate(allowed_scopes)
                    rules_df = conn.execute(
                        f"SELECT enabled, score, space, severity, name "
                        f"FROM detection_rules WHERE {frag}",
                        scope_params,
                    ).df()
                else:
                    # Client has 0 SIEMs — empty result
                    import pandas as pd
                    rules_df = pd.DataFrame(columns=['enabled', 'score', 'space', 'severity', 'name'])
            else:
                rules_df = conn.execute(
                    "SELECT enabled, score, space, severity, name FROM detection_rules"
                ).df()
            
            if rules_df.empty:
                rule_metrics = RuleHealthMetrics()
            else:
                total_rules = len(rules_df)
                enabled_rules = len(rules_df[rules_df['enabled'] == 1])
                avg_score = float(rules_df['score'].mean()) if 'score' in rules_df.columns else 0
                min_score = int(rules_df['score'].min()) if 'score' in rules_df.columns else 0
                max_score = int(rules_df['score'].max()) if 'score' in rules_df.columns else 0
                low_quality_count = len(rules_df[rules_df['score'] < 50])
                high_quality_count = len(rules_df[rules_df['score'] >= 80])
                quality_excellent = len(rules_df[rules_df['score'] >= 80])
                quality_good = len(rules_df[(rules_df['score'] >= 70) & (rules_df['score'] < 80)])
                quality_fair = len(rules_df[(rules_df['score'] >= 50) & (rules_df['score'] < 70)])
                quality_poor = len(rules_df[rules_df['score'] < 50])
                
                rules_by_space = {}
                if 'space' in rules_df.columns:
                    space_counts = rules_df['space'].value_counts().to_dict()
                    rules_by_space = {str(k): int(v) for k, v in space_counts.items()}
                
                severity_breakdown = {}
                if 'severity' in rules_df.columns:
                    sev_counts = rules_df['severity'].value_counts().to_dict()
                    severity_breakdown = {str(k): int(v) for k, v in sev_counts.items()}
                
                # Validation stats (reuse cached data)
                validated_count = 0
                validation_expired_count = 0
                if validation_data:
                    for rule_name in rules_df['name'].tolist():
                        rule_v = validation_data.get(str(rule_name), {})
                        if rule_v:
                            validated_count += 1
                            val_str = rule_v.get('last_checked_on', '')
                            if val_str:
                                try:
                                    val_date = datetime.strptime(val_str[:10], "%Y-%m-%d")
                                    if (now - val_date).days / 7 > 12:
                                        validation_expired_count += 1
                                except:
                                    pass
                
                rule_metrics = RuleHealthMetrics(
                    total_rules=total_rules,
                    enabled_rules=enabled_rules,
                    disabled_rules=total_rules - enabled_rules,
                    avg_score=round(avg_score, 1),
                    min_score=min_score,
                    max_score=max_score,
                    validated_count=validated_count,
                    validation_expired_count=validation_expired_count,
                    never_validated_count=total_rules - validated_count,
                    low_quality_count=low_quality_count,
                    high_quality_count=high_quality_count,
                    quality_excellent=quality_excellent,
                    quality_good=quality_good,
                    quality_fair=quality_fair,
                    quality_poor=quality_poor,
                    rules_by_space=rules_by_space,
                    severity_breakdown=severity_breakdown,
                    language_breakdown={},  # Skip expensive JSON parsing for dashboard
                )
            
            # ── Promotion Metrics ──
            if allowed_scopes is not None:
                if allowed_scopes:
                    frag, scope_params = _scope_predicate(allowed_scopes)
                    staging_df = conn.execute(
                        f"SELECT enabled, score, severity, name FROM detection_rules "
                        f"WHERE LOWER(space) = 'staging' AND {frag}",
                        scope_params,
                    ).df()
                    prod_result = conn.execute(
                        f"SELECT COUNT(*) FROM detection_rules "
                        f"WHERE LOWER(space) = 'production' AND {frag}",
                        scope_params,
                    ).fetchone()
                else:
                    # Client has 0 SIEMs — empty staging/production
                    import pandas as pd
                    staging_df = pd.DataFrame(columns=['enabled', 'score', 'severity', 'name'])
                    prod_result = (0,)
            else:
                staging_df = conn.execute(
                    "SELECT enabled, score, severity, name FROM detection_rules WHERE LOWER(space) = 'staging'"
                ).df()
                prod_result = conn.execute(
                    "SELECT COUNT(*) FROM detection_rules WHERE LOWER(space) = 'production'"
                ).fetchone()
            production_total = prod_result[0] if prod_result else 0
            
            if staging_df.empty:
                promo_metrics = {
                    'staging_total': 0, 'staging_enabled': 0,
                    'staging_avg_score': 0, 'staging_min_score': 0, 'staging_max_score': 0,
                    'staging_low_quality': 0, 'staging_high_quality': 0,
                    'staging_quality_excellent': 0, 'staging_quality_good': 0,
                    'staging_quality_fair': 0, 'staging_quality_poor': 0,
                    'staging_severity': {},
                    'staging_validated': 0, 'staging_validation_expired': 0,
                    'staging_never_validated': 0,
                    'production_total': production_total,
                }
            else:
                staging_total = len(staging_df)
                staging_enabled = len(staging_df[staging_df['enabled'] == 1])
                staging_avg_score = float(staging_df['score'].mean()) if 'score' in staging_df.columns else 0
                staging_min_score = int(staging_df['score'].min()) if 'score' in staging_df.columns else 0
                staging_max_score = int(staging_df['score'].max()) if 'score' in staging_df.columns else 0
                staging_quality_excellent = len(staging_df[staging_df['score'] >= 80])
                staging_quality_good = len(staging_df[(staging_df['score'] >= 70) & (staging_df['score'] < 80)])
                staging_quality_fair = len(staging_df[(staging_df['score'] >= 50) & (staging_df['score'] < 70)])
                staging_quality_poor = len(staging_df[staging_df['score'] < 50])
                
                staging_severity = {}
                if 'severity' in staging_df.columns:
                    sev_counts = staging_df['severity'].value_counts().to_dict()
                    staging_severity = {str(k).lower(): int(v) for k, v in sev_counts.items()}
                
                staging_validated = 0
                staging_validation_expired = 0
                if validation_data:
                    for rule_name in staging_df['name'].tolist():
                        rule_v = validation_data.get(str(rule_name), {})
                        if rule_v:
                            staging_validated += 1
                            val_str = rule_v.get('last_checked_on', '')
                            if val_str:
                                try:
                                    val_date = datetime.strptime(val_str[:10], "%Y-%m-%d")
                                    if (now - val_date).days / 7 > 12:
                                        staging_validation_expired += 1
                                except:
                                    pass
                
                promo_metrics = {
                    'staging_total': staging_total,
                    'staging_enabled': staging_enabled,
                    'staging_avg_score': staging_avg_score,
                    'staging_min_score': staging_min_score,
                    'staging_max_score': staging_max_score,
                    'staging_low_quality': staging_quality_poor,
                    'staging_high_quality': staging_quality_excellent,
                    'staging_quality_excellent': staging_quality_excellent,
                    'staging_quality_good': staging_quality_good,
                    'staging_quality_fair': staging_quality_fair,
                    'staging_quality_poor': staging_quality_poor,
                    'staging_severity': staging_severity,
                    'staging_validated': staging_validated,
                    'staging_validation_expired': staging_validation_expired,
                    'staging_never_validated': staging_total - staging_validated,
                    'production_total': production_total,
                }
            
            # ── Threat Landscape Metrics ──
            threat_df = conn.execute(
                "SELECT ttp_count, ttps, origin, source FROM threat_actors"
            ).df()
            
            # Covered TTPs (reuse same connection, scoped to client's pairs)
            if allowed_scopes is not None:
                if allowed_scopes:
                    frag, scope_params = _scope_predicate(allowed_scopes)
                    covered_result = conn.execute(f"""
                        SELECT DISTINCT unnest(mitre_ids) 
                        FROM detection_rules 
                        WHERE enabled = 1 AND {frag}
                    """, scope_params).fetchall()
                else:
                    # Client has 0 SIEMs — no covered TTPs
                    covered_result = []
            else:
                covered_result = conn.execute("""
                    SELECT DISTINCT unnest(mitre_ids) 
                    FROM detection_rules 
                    WHERE enabled = 1 AND LOWER(space) = LOWER('production')
                """).fetchall()
            covered_ttps = {row[0].upper() for row in covered_result if row[0]}
            
            if threat_df.empty:
                threat_metrics = ThreatLandscapeMetrics()
            else:
                total_actors = len(threat_df)
                total_ttps = int(threat_df['ttp_count'].sum()) if 'ttp_count' in threat_df.columns else 0
                
                all_ttps = set()
                for ttps_list in threat_df['ttps']:
                    if ttps_list is not None and hasattr(ttps_list, '__len__') and len(ttps_list) > 0:
                        for t in ttps_list:
                            all_ttps.add(str(t).strip().upper())
                
                unique_ttps = len(all_ttps)
                covered_unique = all_ttps.intersection(covered_ttps)
                uncovered_unique = all_ttps - covered_ttps
                covered_count = len(covered_unique)
                uncovered_count = len(uncovered_unique)
                global_coverage_pct = round((covered_count / unique_ttps * 100), 1) if unique_ttps > 0 else 0
                avg_ttps = round(total_ttps / total_actors, 1) if total_actors > 0 else 0
                
                origin_breakdown = {}
                if 'origin' in threat_df.columns:
                    origin_counts = threat_df['origin'].value_counts().to_dict()
                    origin_breakdown = {str(k): int(v) for k, v in origin_counts.items() if k}
                
                source_breakdown = {}
                if 'source' in threat_df.columns:
                    for source_list in threat_df['source']:
                        if source_list is not None:
                            if hasattr(source_list, 'tolist'):
                                source_list = source_list.tolist()
                            if isinstance(source_list, list):
                                for src in source_list:
                                    source_breakdown[src] = source_breakdown.get(src, 0) + 1
                
                fully_covered = 0
                partially_covered = 0
                uncovered_actors = 0
                for ttps_list in threat_df['ttps']:
                    if ttps_list is None or len(ttps_list) == 0:
                        uncovered_actors += 1
                        continue
                    actor_ttps = {str(t).strip().upper() for t in ttps_list}
                    actor_covered = actor_ttps.intersection(covered_ttps)
                    if len(actor_covered) == len(actor_ttps):
                        fully_covered += 1
                    elif len(actor_covered) > 0:
                        partially_covered += 1
                    else:
                        uncovered_actors += 1
                
                threat_metrics = ThreatLandscapeMetrics(
                    total_actors=total_actors,
                    total_ttps=total_ttps,
                    unique_ttps=unique_ttps,
                    avg_ttps_per_actor=avg_ttps,
                    covered_ttps=covered_count,
                    uncovered_ttps=uncovered_count,
                    global_coverage_pct=global_coverage_pct,
                    origin_breakdown=origin_breakdown,
                    source_breakdown=source_breakdown,
                    fully_covered_actors=fully_covered,
                    partially_covered_actors=partially_covered,
                    uncovered_actors=uncovered_actors,
                )
        
        return rule_metrics, promo_metrics, threat_metrics
    
    def get_all_covered_ttps(self, client_id: str = None) -> Set[str]:
        """Get all TTPs covered by enabled detection rules.
        If client_id provided, restrict to that client's production SIEM spaces."""
        if client_id:
            return self.get_covered_ttps_for_client(client_id, "production")
        with self.get_connection() as conn:
            result = conn.execute(
                "SELECT DISTINCT unnest(mitre_ids) FROM detection_rules WHERE enabled = 1"
            ).fetchall()
            return {row[0].upper() for row in result if row[0]}
    
    def get_ttp_rule_counts(self, client_id: str = None) -> Dict[str, int]:
        """Get count of enabled rules per MITRE technique ID.
        If client_id provided, restrict to that client's production SIEM spaces."""
        if client_id:
            return self.get_technique_rule_counts_for_client(client_id, "production")
        with self.get_connection() as conn:
            result = conn.execute("""
                SELECT ttp_id, COUNT(*) as rule_count
                FROM (
                    SELECT unnest(mitre_ids) as ttp_id
                    FROM detection_rules 
                    WHERE enabled = 1
                )
                GROUP BY ttp_id
            """).fetchall()
            return {row[0].upper(): row[1] for row in result if row[0]}
    
    def get_sigma_coverage_data(self, client_id: str = None) -> Tuple[Set[str], Dict[str, int]]:
        """Get covered TTPs and rule counts in a single DB connection (for sigma page)."""
        if client_id:
            covered = self.get_covered_ttps_for_client(client_id, "production")
            counts = self.get_technique_rule_counts_for_client(client_id, "production")
            return covered, counts
        with self.get_connection() as conn:
            covered_result = conn.execute(
                "SELECT DISTINCT unnest(mitre_ids) FROM detection_rules WHERE enabled = 1"
            ).fetchall()
            covered_ttps = {row[0].upper() for row in covered_result if row[0]}
            
            count_result = conn.execute("""
                SELECT ttp_id, COUNT(*) as rule_count
                FROM (
                    SELECT unnest(mitre_ids) as ttp_id
                    FROM detection_rules 
                    WHERE enabled = 1
                )
                GROUP BY ttp_id
            """).fetchall()
            ttp_rule_counts = {row[0].upper(): row[1] for row in count_result if row[0]}
            
            return covered_ttps, ttp_rule_counts
    
    def get_technique_map(self) -> Dict[str, str]:
        """Get mapping of technique IDs to tactics."""
        with self.get_connection() as conn:
            result = conn.execute(
                "SELECT id, tactic FROM mitre_techniques"
            ).fetchall()
            return {row[0]: row[1] for row in result if row[0] and row[1]}
    
    def get_technique_names(self) -> Dict[str, str]:
        """Get mapping of technique IDs to names."""
        with self.get_connection() as conn:
            result = conn.execute(
                "SELECT id, name FROM mitre_techniques"
            ).fetchall()
            return {row[0]: row[1] for row in result if row[0] and row[1]}

    def get_mitre_techniques(self) -> List[Dict[str, str]]:
        """Return MITRE technique definitions for rule form selections."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT id, name, tactic, url "
                "FROM mitre_techniques "
                "WHERE id IS NOT NULL AND name IS NOT NULL "
                "ORDER BY COALESCE(tactic, ''), id"
            ).fetchall()
        return [
            {
                "id": row[0],
                "name": row[1],
                "tactic": row[2] or "",
                "url": row[3] or "",
            }
            for row in rows
        ]
    
    def get_rules_for_technique(self, technique_id: str, enabled_only: bool = True,
                                search: str = None, client_id: str = None,
                                environment_role: str = None) -> List[DetectionRule]:
        """Get all detection rules that cover a specific MITRE technique.
        
        Args:
            technique_id: MITRE technique ID (e.g., T1059)
            enabled_only: If True, only return enabled rules (default). Matches heatmap coverage logic.
            search: Optional search filter to further restrict rules (matches name, author, rule_id, mitre_ids)
            client_id: If provided, restrict to rules in spaces linked to this client.
            environment_role: If provided with client_id, restrict to production or staging spaces.
        """
        # Pre-fetch client spaces for filtering
        client_spaces = None
        if client_id:
            client_spaces = self.get_client_siem_spaces(client_id, environment_role)
            if not client_spaces:
                return []
        # Honour per-tenant validation thresholds when scoped to a client.
        thresholds = (
            self.get_client_validation_thresholds(client_id)
            if client_id else None
        )

        with self.get_connection() as conn:
            # Query rules where the technique ID is in the mitre_ids array
            ttp_upper = technique_id.upper()
            
            # Case-insensitive technique matching: unnest and upper-compare
            # to stay consistent with the count/coverage queries that UPPER() the IDs
            base_conditions = "EXISTS (SELECT 1 FROM (SELECT unnest(mitre_ids) AS mid) WHERE UPPER(mid) = ?)"
            params = [ttp_upper]
            
            if enabled_only:
                base_conditions += " AND enabled = 1"
            
            # Client-SIEM space filtering
            if client_spaces:
                placeholders = ", ".join("?" for _ in client_spaces)
                base_conditions += f" AND LOWER(space) IN ({placeholders})"
                params.extend([s.lower() for s in client_spaces])
            
            if search:
                # Apply same search logic as grid - match name, author, rule_id, OR mitre_ids
                # This ensures sidebar shows rules from the same result set as the grid
                search_term = f"%{search}%"
                base_conditions += """ AND (
                    LOWER(name) LIKE LOWER(?) 
                    OR LOWER(author) LIKE LOWER(?) 
                    OR LOWER(rule_id) LIKE LOWER(?)
                    OR LOWER(array_to_string(mitre_ids, ',')) LIKE LOWER(?)
                )"""
                params.extend([search_term, search_term, search_term, search_term])
            
            query = f"""
                SELECT * FROM detection_rules 
                WHERE {base_conditions}
                ORDER BY score DESC
            """
            
            result = conn.execute(query, params).fetchall()
            
            if not result:
                return []
            
            columns = [desc[0] for desc in conn.description]
            validation_data = self._load_validation_data()
            rules = []
            
            for row_tuple in result:
                row = dict(zip(columns, row_tuple))
                rules.append(self._row_to_rule(row, validation_data, thresholds))
            
            return rules
    
    # --- TRIGGERS (for background sync) ---
    
    def set_trigger(self, trigger_name: str):
        """Set a trigger file for the background worker."""
        path = os.path.join(self.trigger_dir, trigger_name)
        with open(path, 'w') as f:
            f.write("1")
    
    def check_and_clear_trigger(self, trigger_name: str) -> bool:
        """Check and clear a trigger file."""
        path = os.path.join(self.trigger_dir, trigger_name)
        if os.path.exists(path):
            try:
                os.remove(path)
                return True
            except:
                pass
        return False
    
    # --- DATA MANAGEMENT ---
    
    # --- APP SETTINGS ---
    
    def get_setting(self, key: str, default: str = None, client_id: str = None) -> str:
        """Get a single app setting by key, optionally scoped to a client."""
        with self.get_connection() as conn:
            if client_id:
                row = conn.execute(
                    "SELECT value FROM app_settings WHERE key = ? AND client_id = ?",
                    [key, client_id],
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT value FROM app_settings WHERE key = ? ORDER BY updated_at DESC LIMIT 1",
                    [key],
                ).fetchone()
            return row[0] if row else default
    
    def get_all_settings(self, client_id: str = None) -> Dict[str, str]:
        """Get all app settings as a dict, optionally scoped to a client."""
        with self.get_connection() as conn:
            if client_id:
                rows = conn.execute(
                    "SELECT key, value FROM app_settings WHERE client_id = ?",
                    [client_id],
                ).fetchall()
            else:
                rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
            return {r[0]: r[1] for r in rows}
    
    def save_setting(self, key: str, value: str, client_id: str = None):
        """Save a single app setting (upsert), optionally scoped to a client."""
        with self.get_connection() as conn:
            if client_id:
                conn.execute("""
                    INSERT INTO app_settings (key, value, client_id, updated_at)
                    VALUES (?, ?, ?, now())
                    ON CONFLICT (key, client_id) DO UPDATE SET
                        value = EXCLUDED.value,
                        updated_at = EXCLUDED.updated_at
                """, [key, value, client_id])
            else:
                # Fallback for global settings — use default client
                default_cid = self._get_default_client_id(conn)
                conn.execute("""
                    INSERT INTO app_settings (key, value, client_id, updated_at)
                    VALUES (?, ?, ?, now())
                    ON CONFLICT (key, client_id) DO UPDATE SET
                        value = EXCLUDED.value,
                        updated_at = EXCLUDED.updated_at
                """, [key, value, default_cid])
    
    def save_settings(self, settings_dict: Dict[str, str], client_id: str = None):
        """Save multiple settings at once, optionally scoped to a client."""
        with self.get_connection() as conn:
            cid = client_id or self._get_default_client_id(conn)
            for key, value in settings_dict.items():
                conn.execute("""
                    INSERT INTO app_settings (key, value, client_id, updated_at)
                    VALUES (?, ?, ?, now())
                    ON CONFLICT (key, client_id) DO UPDATE SET
                        value = EXCLUDED.value,
                        updated_at = EXCLUDED.updated_at
                """, [key, value, cid])
    
    def get_all_rules_for_export(
        self,
        siem_id: Optional[str] = None,
        space: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Get detection rules as dicts for JSON log export.

        Since 4.1.13 / Migration 45 `detection_rules` lives only in tenant
        DBs (the shared `detection_rules` table was dropped). This function
        therefore REQUIRES an active tenant context — the caller must wrap
        the invocation in `set_tenant_context(resolve_tenant_db_path(...))`
        first. If no tenant context is active we raise a clear RuntimeError
        instead of letting `self.get_connection()` route to the shared DB
        and crash with `Catalog Error: Table with name detection_rules does
        not exist!` (the 4.1.14 rule_logger regression).

        Args:
            siem_id: When provided, restrict to rows whose
                ``detection_rules.siem_id`` equals this value (4.0.13+ scoping).
            space: When provided, restrict to rows whose ``space`` matches.
                Accepts a single string OR a list/tuple of strings (so a SIEM
                can be configured to log multiple Kibana spaces in one file).
                Empty / falsy entries are dropped; an empty list after
                filtering is treated as 'no space filter'.
        """
        from app.services.tenant_manager import get_tenant_db_path
        if get_tenant_db_path() is None:
            raise RuntimeError(
                "get_all_rules_for_export requires an active tenant context. "
                "Since 4.1.13 (Migration 45) `detection_rules` lives only in "
                "tenant DBs. Wrap the call in `set_tenant_context("
                "resolve_tenant_db_path(client_id, data_dir))` first. See "
                "app/services/rule_logger.py:run_rule_log_export for the "
                "reference per-tenant iteration pattern."
            )

        clauses: List[str] = []
        params: List[Any] = []
        if siem_id:
            clauses.append("siem_id = ?")
            params.append(siem_id)
        if space:
            spaces = [space] if isinstance(space, str) else list(space)
            spaces = [s.strip() for s in spaces if s and str(s).strip()]
            if len(spaces) == 1:
                clauses.append("space = ?")
                params.append(spaces[0])
            elif len(spaces) > 1:
                placeholders = ",".join(["?"] * len(spaces))
                clauses.append(f"space IN ({placeholders})")
                params.extend(spaces)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

        with self.get_connection() as conn:
            rows = conn.execute(f"""
                SELECT rule_id, name, severity, author, enabled, space,
                       score, quality_score, meta_score,
                       score_mapping, score_field_type, score_search_time, score_language,
                       score_note, score_override, score_tactics, score_techniques,
                       score_author, score_highlights, mitre_ids
                FROM detection_rules{where}
                ORDER BY name
            """, params).fetchall()

            columns = ['rule_id', 'name', 'severity', 'author', 'enabled', 'space',
                       'score', 'quality_score', 'meta_score',
                       'score_mapping', 'score_field_type', 'score_search_time', 'score_language',
                       'score_note', 'score_override', 'score_tactics', 'score_techniques',
                       'score_author', 'score_highlights', 'mitre_ids']

            return [dict(zip(columns, row)) for row in rows]
    
    # --- EXISTING DATA MANAGEMENT ---
    
    def clear_detection_rules(self) -> int:
        """Clear all detection rules. Returns count of deleted rows."""
        with self.get_connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
            conn.execute("DELETE FROM detection_rules WHERE 1=1")
            conn.execute("CHECKPOINT")
            logger.info(f"Cleared {count} detection rules")
            return count
    
    def save_audit_results(self, audit_list: List[Dict[str, Any]], client_id: Optional[str] = None) -> int:
        """
        Save detection rules from Elastic sync to database.
        This replaces rules for each synced space to ensure live/accurate data.
        """
        if not audit_list:
            return 0
        
        df = pd.DataFrame(audit_list)
        
        df['enabled'] = df['enabled'].apply(lambda x: 1 if x else 0)
        
        # Parse author - handle list format like "['darral']" -> "darral"
        def parse_author(val):
            if not val or val == '-':
                return '-'
            s = str(val).strip()
            if s.startswith('[') and s.endswith(']'):
                inner = s[1:-1]
                authors = [a.strip().strip("'").strip('"') for a in inner.split(',') if a.strip()]
                return ', '.join(authors) if authors else '-'
            return s if s else '-'
        
        df['author'] = df['author_str'].apply(parse_author) if 'author_str' in df.columns else '-'
        df['space'] = df['space_id'].fillna('default') if 'space_id' in df.columns else 'default'
        df['last_updated'] = datetime.now()
        df['mitre_ids'] = df['mitre_ids'].apply(lambda x: x if isinstance(x, list) else [])

        # 4.0.13: every record must carry the originating siem_id so the new
        # composite PK (rule_id, siem_id) is satisfied and so subtractive
        # deletes can be scoped to the SIEM that returned the data. Records
        # missing siem_id are dropped with a warning rather than silently
        # colliding under a NULL key (which would also violate NOT NULL).
        if 'siem_id' not in df.columns:
            df['siem_id'] = None
        missing_siem = df['siem_id'].isna().sum()
        if missing_siem:
            logger.warning(
                "save_audit_results: dropping %d rule rows with no siem_id "
                "(caller must stamp siem_id on every record — see services/sync.py)",
                int(missing_siem),
            )
            df = df.dropna(subset=['siem_id'])
            if df.empty:
                return 0

        # Scope of this write: the (siem_id, space) pairs we are refreshing.
        # Anything matching one of these pairs in the DB will be replaced.
        synced_scopes = (
            df[['siem_id', 'space']]
            .drop_duplicates()
            .itertuples(index=False, name=None)
        )
        synced_scopes = list(synced_scopes)
        logger.info(f"Syncing rules for (siem_id, space) scopes: {synced_scopes}")
        
        # Build raw_data to include both the original rule AND the field mapping results
        def build_raw_data(row):
            raw = row.get('raw_data', {})
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except:
                    raw = {}
            # Merge in the field mapping results so UI can display them
            raw['results'] = row.get('results', [])
            raw['query'] = row.get('query', '')
            raw['search_time'] = row.get('search_time', 0)
            return json.dumps(raw, default=str)
        
        df['raw_data'] = df.apply(build_raw_data, axis=1)

        target_cols = [
            'rule_id', 'siem_id', 'name', 'severity', 'author', 'enabled', 'space',
            'score', 'quality_score', 'meta_score',
            'score_mapping', 'score_field_type', 'score_search_time', 
            'score_language', 'score_note', 'score_override', 'score_tactics',
            'score_techniques', 'score_author', 'score_highlights',
            'last_updated', 'mitre_ids', 'raw_data'
        ]
        
        # Ensure all columns exist
        for col in target_cols:
            if col not in df.columns:
                df[col] = None
        
        df_final = df[target_cols].copy()
        
        # Check for duplicates within the incoming data. The PK is
        # (rule_id, siem_id, space) since 4.1.12 (Migration 44) — the same
        # rule_id can legitimately appear in multiple Kibana spaces of the
        # SAME SIEM (e.g. cloned base rule promoted to ``one`` and ``two``).
        # Deduping by (rule_id, siem_id) here would silently drop the second
        # space's row before INSERT, causing tenants mapped to multiple
        # spaces of one SIEM to lose half their rules. Must dedupe on the
        # full PK triple to match the storage contract.
        duplicates = df_final[df_final.duplicated(subset=['rule_id', 'siem_id', 'space'], keep='first')]
        if not duplicates.empty:
            dup_names = duplicates['name'].tolist()
            logger.info(f"Skipping {len(dup_names)} duplicate rules (same rule_id + siem_id + space): {dup_names[:5]}{'...' if len(dup_names) > 5 else ''}")
            df_final = df_final.drop_duplicates(subset=['rule_id', 'siem_id', 'space'], keep='first')

        with self.get_connection() as conn:
            try:
                conn.execute("BEGIN TRANSACTION")
                
                # Delete existing rules from synced (siem_id, space) scopes so
                # rules removed upstream don't persist as ghosts. Scoped by
                # siem_id since 4.0.13 — a sync of SIEM A must NEVER touch
                # SIEM B's rows even if both share the same space name.
                for siem_id_v, space in synced_scopes:
                    conn.execute(
                        "DELETE FROM detection_rules "
                        "WHERE space = ? AND siem_id = ?",
                        [space, siem_id_v]
                    )
                    logger.debug(
                        f"Cleared rules from siem_id={siem_id_v} space='{space}'"
                    )
                
                # Insert fresh rules
                conn.register('rules_source', df_final)
                col_list = ', '.join(target_cols)
                conn.execute(f"""
                    INSERT INTO detection_rules ({col_list})
                    SELECT {col_list} FROM rules_source
                """)
                
                conn.execute("COMMIT")
                
                count = len(df_final)
                logger.info(
                    f"Synced {count} detection rules to database "
                    f"(replaced rules in scopes: {synced_scopes})"
                )

                score_cols = [
                    'rule_id', 'siem_id', 'space', 'score', 'quality_score',
                    'meta_score', 'score_mapping', 'score_field_type',
                    'score_search_time', 'score_language', 'score_note',
                    'score_override', 'score_tactics', 'score_techniques',
                    'score_author', 'score_highlights',
                ]
                snapshot_df = df_final[[col for col in score_cols if col in df_final.columns]].copy()
                for row in snapshot_df.to_dict(orient='records'):
                    try:
                        if client_id:
                            self.record_rule_score_snapshot(
                                row.get('rule_id'),
                                row.get('siem_id'),
                                row.get('space') or 'default',
                                client_id,
                                row,
                            )
                    except Exception:
                        logger.exception(
                            'Failed to record score snapshot for rule_id=%s siem_id=%s space=%s',
                            row.get('rule_id'), row.get('siem_id'), row.get('space'),
                        )
                
            except Exception as e:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                logger.error(f"Failed to save rules: {e}")
                raise
        
        # Checkpoint outside transaction context to avoid concurrency issues
        try:
            with self.get_connection() as conn:
                conn.execute("CHECKPOINT")
        except Exception:
            pass  # Auto-checkpoint will handle it
        
        return count

    def delete_rules_for_spaces(self, spaces: List[str],
                                siem_id: Optional[str] = None) -> int:
        """
        Delete all rules belonging to the given spaces (subtractive sync).
        Used to remove ghost rules when a space returns 0 rules from Elastic.

        Since 4.0.13, when ``siem_id`` is supplied the delete is scoped to that
        SIEM only — critical when two SIEMs share a space name and only one
        of them came back empty. When ``siem_id`` is None the call falls back
        to the legacy (space-only) behaviour and logs a WARN, because a
        space-only delete can wipe a healthy SIEM's rules.
        """
        if not spaces:
            return 0
        
        total_deleted = 0
        with self.get_connection() as conn:
            try:
                if siem_id is None:
                    logger.warning(
                        "delete_rules_for_spaces called without siem_id for spaces=%s — "
                        "this can remove rules from unrelated SIEMs that share a space "
                        "name. Update caller to pass siem_id.",
                        spaces,
                    )
                    for space in spaces:
                        before = conn.execute(
                            "SELECT COUNT(*) FROM detection_rules WHERE space = ?",
                            [space],
                        ).fetchone()[0]
                        if before > 0:
                            conn.execute(
                                "DELETE FROM detection_rules WHERE space = ?",
                                [space],
                            )
                            logger.info(
                                f"Subtractive sync: deleted {before} ghost rules "
                                f"from space '{space}' (no siem scope)"
                            )
                            total_deleted += before
                else:
                    for space in spaces:
                        before = conn.execute(
                            "SELECT COUNT(*) FROM detection_rules "
                            "WHERE space = ? AND siem_id = ?",
                            [space, siem_id],
                        ).fetchone()[0]
                        if before > 0:
                            conn.execute(
                                "DELETE FROM detection_rules "
                                "WHERE space = ? AND siem_id = ?",
                                [space, siem_id],
                            )
                            logger.info(
                                f"Subtractive sync: deleted {before} ghost rules "
                                f"from siem_id={siem_id} space='{space}'"
                            )
                            total_deleted += before
                conn.execute("CHECKPOINT")
            except Exception as e:
                logger.error(f"Failed to delete ghost rules: {e}")
        
        return total_deleted


    def reconcile_rules_for_siem_space(
        self,
        siem_id: str,
        space: str,
        keep_rule_ids: set,
    ) -> int:
        """Delete every detection_rules row for ``(siem_id, space)`` whose
        ``rule_id`` is NOT in ``keep_rule_ids``.

        Used as the second half of mirror-Kibana sync: after a *complete*
        per-space fetch (advertised total == fetched count), any DB row in
        that (siem, space) that did not appear in the fetched set must have
        been deleted in Kibana since the last sync, so we delete it here too.

        The caller MUST only invoke this for spaces with a clean fetch — a
        partial fetch would produce false orphans and silently delete
        healthy rules.
        """
        if not siem_id or not space:
            return 0
        with self.get_connection() as conn:
            try:
                if not keep_rule_ids:
                    # Empty space confirmed by Kibana — drop everything for
                    # this (siem, space).
                    before = conn.execute(
                        "SELECT COUNT(*) FROM detection_rules "
                        "WHERE siem_id = ? AND space = ?",
                        [siem_id, space],
                    ).fetchone()[0]
                    if before:
                        conn.execute(
                            "DELETE FROM detection_rules "
                            "WHERE siem_id = ? AND space = ?",
                            [siem_id, space],
                        )
                        logger.info(
                            f"Mirror sync: deleted {before} rules from "
                            f"siem_id={siem_id} space='{space}' (Kibana returned 0)"
                        )
                        conn.execute("CHECKPOINT")
                    return before

                # DuckDB parameterised IN list.
                placeholders = ",".join(["?"] * len(keep_rule_ids))
                params = [siem_id, space, *keep_rule_ids]
                orphans = conn.execute(
                    f"SELECT rule_id FROM detection_rules "
                    f"WHERE siem_id = ? AND space = ? "
                    f"AND rule_id NOT IN ({placeholders})",
                    params,
                ).fetchall()
                if not orphans:
                    return 0
                conn.execute(
                    f"DELETE FROM detection_rules "
                    f"WHERE siem_id = ? AND space = ? "
                    f"AND rule_id NOT IN ({placeholders})",
                    params,
                )
                logger.info(
                    f"Mirror sync: deleted {len(orphans)} orphan rule(s) from "
                    f"siem_id={siem_id} space='{space}' "
                    f"(no longer in Kibana): {[o[0] for o in orphans][:5]}"
                    f"{'...' if len(orphans) > 5 else ''}"
                )
                conn.execute("CHECKPOINT")
                return len(orphans)
            except Exception as e:
                logger.error(
                    f"reconcile_rules_for_siem_space failed for "
                    f"siem_id={siem_id} space='{space}': {e}"
                )
                return 0


    # ── External API Key management ──────────────────────────────────────

    def create_api_key(self, label: str, created_by_user_id: Optional[str] = None) -> str:
        """Generate a new API key, store its SHA-256 hash, return the raw key."""
        import secrets, hashlib
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        with self.get_connection() as conn:
            conn.execute(
                "INSERT INTO api_keys (key_hash, label, created_by_user_id) VALUES (?, ?, ?)",
                [key_hash, label, created_by_user_id],
            )
        logger.info(f"API key created: {label}")
        return raw_key

    def list_api_keys(self, created_by_user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return API key metadata. Non-admin views should pass created_by_user_id."""
        with self.get_connection() as conn:
            if created_by_user_id:
                rows = conn.execute(
                    "SELECT key_hash, label, created_at, last_used_at, created_by_user_id "
                    "FROM api_keys WHERE created_by_user_id = ? ORDER BY created_at DESC",
                    [created_by_user_id],
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT key_hash, label, created_at, last_used_at, created_by_user_id "
                    "FROM api_keys ORDER BY created_at DESC"
                ).fetchall()
        return [
            {
                "key_hash": r[0],
                "label": r[1],
                "created_at": r[2],
                "last_used_at": r[3],
                "created_by_user_id": r[4],
            }
            for r in rows
        ]

    def get_api_key(self, key_hash: str) -> Optional[Dict[str, Any]]:
        """Return API key metadata by hash."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT key_hash, label, created_at, last_used_at, created_by_user_id "
                "FROM api_keys WHERE key_hash = ?",
                [key_hash],
            ).fetchone()
        if not row:
            return None
        return {
            "key_hash": row[0],
            "label": row[1],
            "created_at": row[2],
            "last_used_at": row[3],
            "created_by_user_id": row[4],
        }

    def validate_api_key(self, raw_key: str) -> Optional[str]:
        """Validate an API key. Returns the key_hash if valid, else None."""
        import hashlib
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        with self.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT key_hash FROM api_keys WHERE key_hash = ?", [key_hash]
            ).fetchone()
            if row:
                # last_used_at is best-effort metadata. Under concurrent external-API
                # traffic DuckDB raises 'Constraint Error: Conflict on update' on the
                # shared connection — swallowing it keeps the request succeeding.
                try:
                    conn.execute(
                        "UPDATE api_keys SET last_used_at = now() WHERE key_hash = ?",
                        [key_hash],
                    )
                except Exception as exc:
                    logger.debug(f"validate_api_key: last_used_at update skipped ({exc})")
                return row[0]  # key_hash (truthy when valid)
        return None

    def validate_api_key_full(self, raw_key: str) -> Optional[Dict[str, Any]]:
        """Validate an API key and return the owner's accessible clients.

        Returns dict with 'user_id' and 'client_ids' (list of client_ids the
        owning user can access via user_clients), or None if the key is invalid.
        """
        import hashlib
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        with self.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT key_hash, created_by_user_id FROM api_keys WHERE key_hash = ?",
                [key_hash],
            ).fetchone()
            if not row:
                return None
            try:
                conn.execute(
                    "UPDATE api_keys SET last_used_at = now() WHERE key_hash = ?",
                    [key_hash],
                )
            except Exception as exc:
                logger.debug(f"validate_api_key_full: last_used_at update skipped ({exc})")
            user_id = row[1]
            if not user_id:
                return None  # legacy key with no owner — cannot resolve tenants
            # Resolve user's assigned clients
            client_rows = conn.execute(
                "SELECT uc.client_id, c.name, c.slug "
                "FROM user_clients uc JOIN clients c ON c.id = uc.client_id "
                "WHERE uc.user_id = ?",
                [user_id],
            ).fetchall()
            return {
                "user_id": user_id,
                "client_ids": [r[0] for r in client_rows],
                "clients": [
                    {"id": r[0], "name": r[1], "slug": r[2]}
                    for r in client_rows
                ],
            }

    def delete_api_key(self, key_hash: str) -> bool:
        """Revoke an API key by full hash."""
        with self.get_shared_connection() as conn:
            deleted = conn.execute(
                "DELETE FROM api_keys WHERE key_hash = ? RETURNING key_hash",
                [key_hash],
            ).fetchone()
        return deleted is not None

    # --- CLIENT / TENANT MANAGEMENT ---

    def _get_default_client_id(self, conn) -> str:
        """Get the default client id (used internally within open connection)."""
        row = conn.execute("SELECT id FROM clients WHERE is_default = true LIMIT 1").fetchone()
        return row[0] if row else None

    def get_default_client_id(self) -> Optional[str]:
        """Get the default (Primary) client id."""
        with self.get_shared_connection() as conn:
            return self._get_default_client_id(conn)

    def list_clients(self) -> List[Dict]:
        """List all clients."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT id, name, slug, description, is_default, db_filename, "
                "rule_validation_amber_weeks, rule_validation_expired_weeks, "
                "rule_validation_mode, "
                "rule_validation_low_amber_weeks, rule_validation_low_expired_weeks, "
                "rule_validation_medium_amber_weeks, rule_validation_medium_expired_weeks, "
                "rule_validation_high_amber_weeks, rule_validation_high_expired_weeks, "
                "rule_validation_critical_amber_weeks, rule_validation_critical_expired_weeks, "
                "created_at, updated_at "
                "FROM clients ORDER BY is_default DESC, name"
            ).fetchall()
            cols = ["id", "name", "slug", "description", "is_default", "db_filename",
                    "rule_validation_amber_weeks", "rule_validation_expired_weeks",
                    "rule_validation_mode",
                    "rule_validation_low_amber_weeks", "rule_validation_low_expired_weeks",
                    "rule_validation_medium_amber_weeks", "rule_validation_medium_expired_weeks",
                    "rule_validation_high_amber_weeks", "rule_validation_high_expired_weeks",
                    "rule_validation_critical_amber_weeks", "rule_validation_critical_expired_weeks",
                    "created_at", "updated_at"]
            return [dict(zip(cols, r)) for r in rows]

    def get_client(self, client_id: str) -> Optional[Dict]:
        """Get a single client by id."""
        with self.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT id, name, slug, description, is_default, db_filename, "
                "rule_validation_amber_weeks, rule_validation_expired_weeks, "
                "rule_validation_mode, "
                "rule_validation_low_amber_weeks, rule_validation_low_expired_weeks, "
                "rule_validation_medium_amber_weeks, rule_validation_medium_expired_weeks, "
                "rule_validation_high_amber_weeks, rule_validation_high_expired_weeks, "
                "rule_validation_critical_amber_weeks, rule_validation_critical_expired_weeks, "
                "created_at, updated_at "
                "FROM clients WHERE id = ?", [client_id]
            ).fetchone()
            if not row:
                return None
            return dict(zip(
                ["id", "name", "slug", "description", "is_default", "db_filename",
                 "rule_validation_amber_weeks", "rule_validation_expired_weeks",
                 "rule_validation_mode",
                 "rule_validation_low_amber_weeks", "rule_validation_low_expired_weeks",
                 "rule_validation_medium_amber_weeks", "rule_validation_medium_expired_weeks",
                 "rule_validation_high_amber_weeks", "rule_validation_high_expired_weeks",
                 "rule_validation_critical_amber_weeks", "rule_validation_critical_expired_weeks",
                 "created_at", "updated_at"], row
            ))

    def create_client(self, name: str, slug: str, description: str = None) -> Dict:
        """Create a new client. Returns the full client dict."""
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO clients (name, slug, description) VALUES (?, ?, ?)",
                [name, slug, description],
            )
            row = conn.execute(
                "SELECT id, name, slug, description, is_default, created_at, updated_at "
                "FROM clients WHERE slug = ?", [slug]
            ).fetchone()
            new_client = dict(zip(
                ["id", "name", "slug", "description", "is_default", "created_at", "updated_at"], row
            ))
            # Seed Role Template defaults for the new client by copying from
            # the default tenant (or, failing that, any tenant). Without this
            # the client would start with an empty matrix and every page would
            # 403 for ANALYST/ENGINEER users until an admin saved each cell.
            try:
                src = conn.execute(
                    "SELECT id FROM clients WHERE is_default = true LIMIT 1"
                ).fetchone()
                if not src:
                    src = conn.execute(
                        "SELECT id FROM clients WHERE id != ? LIMIT 1", [new_client["id"]]
                    ).fetchone()
                if src:
                    conn.execute(
                        "INSERT INTO role_permissions "
                        "(role_id, client_id, resource, can_read, can_write) "
                        "SELECT role_id, ?, resource, can_read, can_write "
                        "FROM role_permissions WHERE client_id = ? "
                        "ON CONFLICT DO NOTHING",
                        [new_client["id"], src[0]],
                    )
            except Exception as exc:  # pragma: no cover - best effort
                logger.warning(f"Could not seed role permissions for client {new_client['id']}: {exc}")
            return new_client

    def update_client(self, client_id: str, **fields) -> Optional[Dict]:
        """Update a client. Allowed fields: name, description,
        rule_validation_amber_weeks, rule_validation_expired_weeks,
        rule_validation_mode and per-severity validation thresholds.

        Pass an empty string / ``None`` for either threshold to clear
        the per-tenant override and fall back to the global default."""
        allowed = {
            "name", "description",
            "rule_validation_mode",
            "rule_validation_amber_weeks",
            "rule_validation_expired_weeks",
            "rule_validation_low_amber_weeks",
            "rule_validation_low_expired_weeks",
            "rule_validation_medium_amber_weeks",
            "rule_validation_medium_expired_weeks",
            "rule_validation_high_amber_weeks",
            "rule_validation_high_expired_weeks",
            "rule_validation_critical_amber_weeks",
            "rule_validation_critical_expired_weeks",
        }
        updates: dict = {}
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k == "rule_validation_mode":
                mode = str(v or "master").strip().lower()
                updates[k] = "criticality" if mode == "criticality" else "master"
                continue
            if k.startswith("rule_validation_"):
                # Empty string → NULL (clear override). Otherwise coerce
                # to int and reject non-positive values.
                if v in (None, "", "null"):
                    updates[k] = None
                    continue
                try:
                    iv = int(v)
                except (TypeError, ValueError):
                    continue
                updates[k] = iv if iv > 0 else None
            else:
                if v is None:
                    continue
                updates[k] = v
        if not updates:
            return self.get_client(client_id)
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [client_id]
        with self.get_shared_connection() as conn:
            conn.execute(
                f"UPDATE clients SET {set_clause}, updated_at = now() WHERE id = ?", values
            )
        return self.get_client(client_id)

    def get_client_validation_thresholds(
        self, client_id: Optional[str], severity: Optional[str] = None
    ) -> Tuple[int, int]:
        """Resolve the (amber_weeks, expired_weeks) thresholds for a tenant.

        In ``master`` mode, the legacy ``rule_validation_amber_weeks`` /
        ``rule_validation_expired_weeks`` pair is used. In
        ``criticality`` mode, severity-specific overrides are used when
        available; missing values fall back to the master pair and then
        to the global defaults.
        """
        amber = int(self.settings.rule_validation_amber_weeks)
        expired = int(self.settings.rule_validation_expired_weeks)
        if not client_id:
            return amber, expired
        try:
            row = self.get_client(client_id)
        except Exception:
            return amber, expired
        if not row:
            return amber, expired
        mode = str(row.get("rule_validation_mode") or "master").strip().lower()
        a = row.get("rule_validation_amber_weeks")
        e = row.get("rule_validation_expired_weeks")
        severity_key = (severity or "").strip().lower()
        severity_cols = {
            "low": ("rule_validation_low_amber_weeks", "rule_validation_low_expired_weeks"),
            "medium": ("rule_validation_medium_amber_weeks", "rule_validation_medium_expired_weeks"),
            "high": ("rule_validation_high_amber_weeks", "rule_validation_high_expired_weeks"),
            "critical": ("rule_validation_critical_amber_weeks", "rule_validation_critical_expired_weeks"),
        }
        if mode == "criticality" and severity_key in severity_cols:
            sa, se = severity_cols[severity_key]
            a = row.get(sa, a)
            e = row.get(se, e)
        if a is not None:
            try:
                amber = int(a)
            except (TypeError, ValueError):
                pass
        if e is not None:
            try:
                expired = int(e)
            except (TypeError, ValueError):
                pass
        return amber, expired

    def delete_client(self, client_id: str) -> bool:
        """Delete a client. Cannot delete the default client."""
        with self.get_shared_connection() as conn:
            is_default = conn.execute(
                "SELECT is_default FROM clients WHERE id = ?", [client_id]
            ).fetchone()
            if not is_default:
                return False
            if is_default[0]:
                raise ValueError("Cannot delete the default client")
            conn.execute("DELETE FROM user_clients WHERE client_id = ?", [client_id])
            conn.execute("DELETE FROM client_siem_configs WHERE client_id = ?", [client_id])
            conn.execute("DELETE FROM clients WHERE id = ?", [client_id])
        return True

    def get_user_clients(self, user_id: str) -> List[Dict]:
        """Get all clients assigned to a user."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT c.id, c.name, c.slug, c.is_default AS client_default, "
                "uc.is_default AS user_default "
                "FROM clients c JOIN user_clients uc ON c.id = uc.client_id "
                "WHERE uc.user_id = ? ORDER BY uc.is_default DESC, c.name",
                [user_id],
            ).fetchall()
            return [
                {"id": r[0], "name": r[1], "slug": r[2],
                 "client_default": r[3], "user_default": r[4]}
                for r in rows
            ]

    def get_user_client_ids(self, user_id: str) -> List[str]:
        """Get list of client IDs a user is assigned to."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT client_id FROM user_clients WHERE user_id = ?", [user_id]
            ).fetchall()
            return [r[0] for r in rows]

    def assign_user_to_client(self, user_id: str, client_id: str, is_default: bool = False):
        """Assign a user to a client."""
        with self.get_shared_connection() as conn:
            if is_default:
                conn.execute(
                    "UPDATE user_clients SET is_default = false WHERE user_id = ?",
                    [user_id],
                )
            conn.execute(
                "INSERT INTO user_clients (user_id, client_id, is_default) "
                "VALUES (?, ?, ?) ON CONFLICT (user_id, client_id) DO UPDATE SET is_default = EXCLUDED.is_default",
                [user_id, client_id, is_default],
            )

    def remove_user_from_client(self, user_id: str, client_id: str):
        """Remove a user from a client."""
        with self.get_shared_connection() as conn:
            conn.execute(
                "DELETE FROM user_clients WHERE user_id = ? AND client_id = ?",
                [user_id, client_id],
            )

    def get_client_users(self, client_id: str) -> List[Dict]:
        """Get all users assigned to a client."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT u.id, u.username, u.email, u.full_name, uc.is_default "
                "FROM users u JOIN user_clients uc ON u.id = uc.user_id "
                "WHERE uc.client_id = ? ORDER BY u.username",
                [client_id],
            ).fetchall()
            return [
                {"id": r[0], "username": r[1], "email": r[2],
                 "full_name": r[3], "is_default": r[4]}
                for r in rows
            ]

    # --- CLIENT SIEM CONFIGS ---

    def list_siem_configs(self, client_id: str) -> List[Dict]:
        """List SIEM configs for a client."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT id, client_id, siem_type, label, base_url, space_list, "
                "extra_config, is_active, created_at, updated_at "
                "FROM client_siem_configs WHERE client_id = ? ORDER BY label",
                [client_id],
            ).fetchall()
            cols = ["id", "client_id", "siem_type", "label", "base_url",
                    "space_list", "extra_config", "is_active", "created_at", "updated_at"]
            return [dict(zip(cols, r)) for r in rows]

    def get_siem_config(self, config_id: str) -> Optional[Dict]:
        """Get a single SIEM config by id."""
        with self.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT id, client_id, siem_type, label, base_url, api_token_enc, "
                "space_list, extra_config, is_active, created_at, updated_at "
                "FROM client_siem_configs WHERE id = ?", [config_id]
            ).fetchone()
            if not row:
                return None
            return dict(zip(
                ["id", "client_id", "siem_type", "label", "base_url", "api_token_enc",
                 "space_list", "extra_config", "is_active", "created_at", "updated_at"], row
            ))

    def create_siem_config(self, client_id: str, siem_type: str, label: str,
                           base_url: str = None, api_token_enc: str = None,
                           space_list: str = None, extra_config: dict = None) -> str:
        """Create a SIEM config for a client. Returns the config id."""
        import json as _json
        extra_json = _json.dumps(extra_config) if extra_config else None
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO client_siem_configs "
                "(client_id, siem_type, label, base_url, api_token_enc, space_list, extra_config) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [client_id, siem_type, label, base_url, api_token_enc, space_list, extra_json],
            )
            row = conn.execute(
                "SELECT id FROM client_siem_configs WHERE client_id = ? AND label = ? "
                "ORDER BY created_at DESC LIMIT 1",
                [client_id, label],
            ).fetchone()
            return row[0]

    def update_siem_config(self, config_id: str, **fields) -> bool:
        """Update a SIEM config."""
        allowed = {"label", "base_url", "api_token_enc", "space_list", "extra_config", "is_active"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return False
        if "extra_config" in updates and isinstance(updates["extra_config"], dict):
            import json as _json
            updates["extra_config"] = _json.dumps(updates["extra_config"])
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [config_id]
        with self.get_shared_connection() as conn:
            conn.execute(
                f"UPDATE client_siem_configs SET {set_clause}, updated_at = now() WHERE id = ?",
                values,
            )
        return True

    def delete_siem_config(self, config_id: str) -> bool:
        """Delete a SIEM config."""
        with self.get_shared_connection() as conn:
            deleted = conn.execute(
                "DELETE FROM client_siem_configs WHERE id = ? RETURNING id",
                [config_id],
            ).fetchone()
        return deleted is not None

    # --- SIEM INVENTORY (centralized, shared across clients) ---

    def list_siem_inventory(self) -> List[Dict]:
        """List all SIEMs in the centralized inventory."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT id, label, siem_type, elasticsearch_url, kibana_url, "
                "extra_config, is_active, "
                "last_test_status, last_test_at, last_test_message, "
                "log_enabled, log_target_space, log_schedule, log_retention_days, "
                "log_destination_path, "
                "created_at, updated_at "
                "FROM siem_inventory ORDER BY label"
            ).fetchall()
            cols = ["id", "label", "siem_type", "elasticsearch_url", "kibana_url",
                    "extra_config", "is_active",
                    "last_test_status", "last_test_at", "last_test_message",
                    "log_enabled", "log_target_space", "log_schedule", "log_retention_days",
                    "log_destination_path",
                    "created_at", "updated_at"]
            return [dict(zip(cols, r)) for r in rows]

    def get_siem_inventory_item(self, siem_id: str) -> Optional[Dict]:
        """Get a single SIEM from the inventory."""
        with self.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT id, label, siem_type, elasticsearch_url, kibana_url, "
                "api_token_enc, "
                "extra_config, is_active, created_at, updated_at "
                "FROM siem_inventory WHERE id = ?", [siem_id]
            ).fetchone()
            if not row:
                return None
            return dict(zip(
                ["id", "label", "siem_type", "elasticsearch_url", "kibana_url",
                 "api_token_enc",
                 "extra_config", "is_active", "created_at", "updated_at"], row
            ))

    def create_siem_inventory_item(self, siem_type: str, label: str,
                                   elasticsearch_url: str = None, kibana_url: str = None,
                                   api_token_enc: str = None,
                                   extra_config: dict = None) -> Dict:
        """Create a SIEM in the centralized inventory. Returns the full dict."""
        import json as _json
        extra_json = _json.dumps(extra_config) if extra_config else None
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO siem_inventory "
                 "(siem_type, label, elasticsearch_url, kibana_url, base_url, "
                 "api_token_enc, extra_config) "
                 "VALUES (?, ?, ?, ?, ?, ?, ?)",
                                [siem_type, label, elasticsearch_url, kibana_url, kibana_url,
                                 api_token_enc, extra_json],
            )
            row = conn.execute(
                "SELECT id, label, siem_type, elasticsearch_url, kibana_url, "
                "extra_config, "
                "is_active, created_at, updated_at "
                "FROM siem_inventory WHERE label = ? ORDER BY created_at DESC LIMIT 1",
                [label],
            ).fetchone()
            cols = ["id", "label", "siem_type", "elasticsearch_url", "kibana_url",
                    "extra_config", "is_active", "created_at", "updated_at"]
            return dict(zip(cols, row))

    def update_siem_inventory_item(self, siem_id: str, **fields) -> bool:
        """Update a SIEM in the inventory."""
        allowed = {"label", "elasticsearch_url", "kibana_url", "api_token_enc",
                   "extra_config", "is_active"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return False
        if "kibana_url" in updates:
            # Keep legacy base_url aligned for old diagnostics / exports.
            updates["base_url"] = updates["kibana_url"]
        if "extra_config" in updates and isinstance(updates["extra_config"], dict):
            import json as _json
            updates["extra_config"] = _json.dumps(updates["extra_config"])
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [siem_id]
        with self.get_shared_connection() as conn:
            conn.execute(
                f"UPDATE siem_inventory SET {set_clause}, updated_at = now() WHERE id = ?",
                values,
            )
        return True

    def delete_siem_inventory_item(self, siem_id: str) -> bool:
        """Delete a SIEM from the inventory and remove all client mappings."""
        with self.get_shared_connection() as conn:
            conn.execute("DELETE FROM client_siem_map WHERE siem_id = ?", [siem_id])
            deleted = conn.execute(
                "DELETE FROM siem_inventory WHERE id = ? RETURNING id",
                [siem_id],
            ).fetchone()
        return deleted is not None

    def get_siem_clients(self, siem_id: str) -> List[Dict]:
        """Get all clients linked to a SIEM."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT c.id, c.name, c.slug "
                "FROM clients c JOIN client_siem_map m ON c.id = m.client_id "
                "WHERE m.siem_id = ? ORDER BY c.name",
                [siem_id],
            ).fetchall()
            return [{"id": r[0], "name": r[1], "slug": r[2]} for r in rows]

    def get_client_siems(self, client_id: str, environment_role: str = None) -> List[Dict]:
        """Get all SIEMs linked to a client via the inventory.
        Optionally filter by environment_role ('production' or 'staging')."""
        with self.get_shared_connection() as conn:
            query = (
                "SELECT s.id, s.label, s.siem_type, s.elasticsearch_url, s.kibana_url, "
                "s.api_token_enc, "
                "m.environment_role, m.space, s.is_active, s.created_at "
                "FROM siem_inventory s JOIN client_siem_map m ON s.id = m.siem_id "
                "WHERE m.client_id = ?"
            )
            params = [client_id]
            if environment_role:
                query += " AND m.environment_role = ?"
                params.append(environment_role)
            query += " ORDER BY m.environment_role, s.label"
            rows = conn.execute(query, params).fetchall()
            cols = ["id", "label", "siem_type", "elasticsearch_url", "kibana_url",
                    "api_token_enc",
                    "environment_role", "space", "is_active", "created_at"]
            result = []
            for r in rows:
                d = dict(zip(cols, r))
                # Normalise NULL/empty space to 'default' (Kibana built-in space)
                if not d.get("space") or not str(d["space"]).strip():
                    d["space"] = "default"
                result.append(d)
            return result

    def link_client_siem(self, client_id: str, siem_id: str,
                         environment_role: str = "production", space: str = None):
        """Link a client to a SIEM from the inventory with an environment role."""
        # Normalise empty/None space to 'default' (Kibana's built-in space)
        if not space or not str(space).strip():
            space = "default"
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO client_siem_map (client_id, siem_id, environment_role, space) "
                "VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                [client_id, siem_id, environment_role, space],
            )
            # Bidirectional: also populate legacy client_siem_configs
            siem = conn.execute(
                "SELECT id, label, siem_type, kibana_url, api_token_enc "
                "FROM siem_inventory WHERE id = ?", [siem_id]
            ).fetchone()
            if siem:
                sid, lbl, stype, kurl, token = siem
                conn.execute(
                    "INSERT INTO client_siem_configs "
                    "(id, client_id, siem_type, label, base_url, api_token_enc, space_list) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                    [sid, client_id, stype, lbl, kurl, token, space],
                )

    def unlink_client_siem(self, client_id: str, siem_id: str, environment_role: str = None):
        """Unlink a client from a SIEM (bidirectional).
        If environment_role is provided, only remove that specific mapping."""
        with self.get_shared_connection() as conn:
            if environment_role:
                conn.execute(
                    "DELETE FROM client_siem_map "
                    "WHERE client_id = ? AND siem_id = ? AND environment_role = ?",
                    [client_id, siem_id, environment_role],
                )
            else:
                conn.execute(
                    "DELETE FROM client_siem_map WHERE client_id = ? AND siem_id = ?",
                    [client_id, siem_id],
                )
            # Also remove from legacy table
            conn.execute(
                "DELETE FROM client_siem_configs WHERE id = ? AND client_id = ?",
                [siem_id, client_id],
            )

    # --- OpenCTI Inventory ---

    # ------------------------------------------------------------------
    # Legacy OpenCTI GraphQL inventory (retired in 5.0.0 by migration 50)
    #
    # These methods used to read/write ``opencti_inventory`` and
    # ``client_opencti_map``. Both tables are dropped by migration 50,
    # so every method below is now a safe no-op that returns the
    # equivalent empty value. They are kept here only so any orphan
    # caller (e.g. an older diag script, an unfinished refactor in a
    # template renderer) does not raise ``AttributeError`` while the
    # last legacy import sites are being torn out. New code MUST use
    # ``cti_connectors`` / ``cti_connector_clients`` and the
    # multi-vendor framework in ``app.services.cti_connectors``.
    # ------------------------------------------------------------------

    def list_opencti_inventory(self) -> List[Dict]:
        return []

    def get_opencti_active_instances(self) -> List[Dict]:
        return []

    def create_opencti_inventory_item(self, label: str, url: str,
                                      token_enc: str = None,
                                      kind: str = "actors") -> Dict:
        raise RuntimeError(
            "Legacy OpenCTI GraphQL inventory was retired in 5.0.0. "
            "Register an 'opencti_taxii' connector under Management → "
            "Connectors instead."
        )

    def update_opencti_inventory_item(self, opencti_id: str, **fields) -> bool:
        return False

    def delete_opencti_inventory_item(self, opencti_id: str) -> bool:
        return False

    def get_opencti_clients(self, opencti_id: str) -> List[Dict]:
        return []

    def get_client_opencti_instances(self, client_id: str) -> List[Dict]:
        return []

    def get_client_opencti_config(self, client_id: str) -> Optional[Dict]:
        return None

    def link_client_opencti(self, client_id: str, opencti_id: str):
        return None

    def unlink_client_opencti(self, client_id: str, opencti_id: str):
        return None


    # --- CTI Connectors (generic per-vendor framework, Migration 47) ---

    _CONNECTOR_COLS = (
        "id", "vendor", "label", "is_active", "kind",
        "duration_period", "confidence_floor", "marking_definition",
        "config_json", "last_run_at", "last_status", "last_message",
        "sync_interval_minutes", "last_sync_started_at",
        "created_at", "updated_at",
    )

    def _row_to_connector(self, row) -> Dict:
        import json as _json
        rec = dict(zip(self._CONNECTOR_COLS, row))
        raw = rec.pop("config_json", None) or "{}"
        try:
            rec["config"] = _json.loads(raw)
        except Exception:
            rec["config"] = {}
        return rec

    def list_cti_connectors(self, *, vendor: Optional[str] = None,
                            only_active: bool = False) -> List[Dict]:
        """List CTI connectors, optionally filtered by vendor / active."""
        where = []
        params: list = []
        if vendor:
            where.append("vendor = ?")
            params.append(vendor)
        if only_active:
            where.append("is_active = true")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        cols = ", ".join(self._CONNECTOR_COLS)
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                f"SELECT {cols} FROM cti_connectors {clause} "
                "ORDER BY vendor, label", params,
            ).fetchall()
        return [self._row_to_connector(r) for r in rows]

    def get_cti_connector(self, connector_id: str) -> Optional[Dict]:
        cols = ", ".join(self._CONNECTOR_COLS)
        with self.get_shared_connection() as conn:
            row = conn.execute(
                f"SELECT {cols} FROM cti_connectors WHERE id = ?",
                [connector_id],
            ).fetchone()
        return self._row_to_connector(row) if row else None

    def create_cti_connector(
        self, *, vendor: str, label: str,
        kind: str = "cti",
        is_active: bool = True,
        duration_period: Optional[str] = None,
        confidence_floor: Optional[int] = None,
        marking_definition: Optional[str] = None,
        config: Optional[Dict] = None,
    ) -> Dict:
        """Create a connector row. ``config`` is the vendor-specific blob."""
        import json as _json
        if kind not in ("actors", "cti", "both"):
            kind = "cti"
        cfg = _json.dumps(config or {})
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO cti_connectors "
                "(vendor, label, is_active, kind, duration_period, "
                "confidence_floor, marking_definition, config_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [vendor, label, bool(is_active), kind, duration_period,
                 confidence_floor, marking_definition, cfg],
            )
            cols = ", ".join(self._CONNECTOR_COLS)
            row = conn.execute(
                f"SELECT {cols} FROM cti_connectors "
                "WHERE vendor = ? AND label = ? "
                "ORDER BY created_at DESC LIMIT 1",
                [vendor, label],
            ).fetchone()
        return self._row_to_connector(row)

    def update_cti_connector(self, connector_id: str, **fields) -> bool:
        """Update a connector. ``config`` (dict) is serialised to ``config_json``."""
        import json as _json
        allowed = {"label", "is_active", "kind", "duration_period",
                   "confidence_floor", "marking_definition",
                   "last_run_at", "last_status", "last_message",
                   "sync_interval_minutes", "last_sync_started_at"}
        # ``sync_interval_minutes`` is the one allow-listed column where
        # callers legitimately mean "set this back to NULL" (operator
        # turning auto-sync off in the modal). Skip the None-filter for
        # those keys so an explicit None survives to the UPDATE.
        nullable = {"sync_interval_minutes"}
        updates = {k: v for k, v in fields.items()
                   if k in allowed and (v is not None or k in nullable)}
        if "kind" in updates and updates["kind"] not in ("actors", "cti", "both"):
            updates["kind"] = "cti"
        if "config" in fields and fields["config"] is not None:
            updates["config_json"] = _json.dumps(fields["config"])
        if not updates:
            return False
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [connector_id]
        with self.get_shared_connection() as conn:
            conn.execute(
                f"UPDATE cti_connectors SET {set_clause}, "
                "updated_at = now() WHERE id = ?", params,
            )
        return True

    def delete_cti_connector(self, connector_id: str) -> bool:
        with self.get_shared_connection() as conn:
            conn.execute(
                "DELETE FROM cti_connector_clients WHERE connector_id = ?",
                [connector_id],
            )
            # Drop any TAXII watermark rows owned by this connector so
            # a re-create with the same id starts clean.
            try:
                conn.execute(
                    "DELETE FROM cti_taxii_cursors WHERE connector_id = ?",
                    [connector_id],
                )
            except Exception:
                # Table only exists from migration 49 onward; ignore on
                # older shared DBs that haven't migrated yet.
                pass
            deleted = conn.execute(
                "DELETE FROM cti_connectors WHERE id = ? RETURNING id",
                [connector_id],
            ).fetchone()
        return deleted is not None

    def get_cti_connector_clients(self, connector_id: str) -> List[Dict]:
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT c.id, c.name, c.slug FROM clients c "
                "JOIN cti_connector_clients m ON c.id = m.client_id "
                "WHERE m.connector_id = ? ORDER BY c.name",
                [connector_id],
            ).fetchall()
        return [{"id": r[0], "name": r[1], "slug": r[2]} for r in rows]

    def link_cti_connector_client(self, connector_id: str, client_id: str):
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO cti_connector_clients "
                "(connector_id, client_id) VALUES (?, ?) "
                "ON CONFLICT DO NOTHING",
                [connector_id, client_id],
            )

    def unlink_cti_connector_client(self, connector_id: str, client_id: str):
        with self.get_shared_connection() as conn:
            conn.execute(
                "DELETE FROM cti_connector_clients "
                "WHERE connector_id = ? AND client_id = ?",
                [connector_id, client_id],
            )

    # --- TAXII 2.1 cursor store (migration 49) ---

    def get_taxii_cursor(self, connector_id: str, api_root: str,
                         collection_id: str) -> Optional[str]:
        """Return the stored ``added_after`` watermark, if any."""
        with self.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT added_after FROM cti_taxii_cursors "
                "WHERE connector_id = ? AND api_root = ? "
                "AND collection_id = ?",
                [connector_id, api_root, collection_id],
            ).fetchone()
        return row[0] if row else None

    def set_taxii_cursor(self, connector_id: str, api_root: str,
                         collection_id: str, added_after: str) -> None:
        """Upsert the watermark for one (connector, root, collection)."""
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO cti_taxii_cursors "
                "(connector_id, api_root, collection_id, added_after, "
                "last_run_at) VALUES (?, ?, ?, ?, now()) "
                "ON CONFLICT (connector_id, api_root, collection_id) "
                "DO UPDATE SET added_after = excluded.added_after, "
                "last_run_at = now()",
                [connector_id, api_root, collection_id, added_after],
            )

    def list_taxii_cursors(self,
                           connector_id: Optional[str] = None) -> List[Dict]:
        """Return all cursors, optionally scoped to one connector.

        Used by the diag surface (step T8) to report per-collection lag.
        """
        sql = (
            "SELECT connector_id, api_root, collection_id, "
            "added_after, last_run_at FROM cti_taxii_cursors"
        )
        params: list = []
        if connector_id:
            sql += " WHERE connector_id = ?"
            params.append(connector_id)
        sql += " ORDER BY connector_id, api_root, collection_id"
        with self.get_shared_connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            {
                "connector_id": r[0], "api_root": r[1],
                "collection_id": r[2], "added_after": r[3],
                "last_run_at": r[4],
            }
            for r in rows
        ]

    def delete_taxii_cursors_for_connector(self, connector_id: str) -> int:
        """Drop every cursor row owned by a connector. Returns row count."""
        with self.get_shared_connection() as conn:
            n = conn.execute(
                "DELETE FROM cti_taxii_cursors WHERE connector_id = ? "
                "RETURNING connector_id",
                [connector_id],
            ).fetchall()
        return len(n)

    # --- GitLab Inventory ---

    def list_gitlab_inventory(self) -> List[Dict]:
        """List all GitLab instances in the centralized inventory."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT id, label, url, default_group, is_active, "
                "last_test_status, last_test_at, last_test_message, "
                "created_at, updated_at "
                "FROM gitlab_inventory ORDER BY label"
            ).fetchall()
            cols = ["id", "label", "url", "default_group", "is_active",
                    "last_test_status", "last_test_at", "last_test_message",
                    "created_at", "updated_at"]
            return [dict(zip(cols, r)) for r in rows]

    def create_gitlab_inventory_item(self, label: str, url: str,
                                     token_enc: str = None,
                                     default_group: str = None) -> Dict:
        """Create a GitLab instance in the inventory."""
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO gitlab_inventory (label, url, token_enc, default_group) "
                "VALUES (?, ?, ?, ?)",
                [label, url, token_enc, default_group],
            )
            row = conn.execute(
                "SELECT id, label, url, default_group, is_active, created_at, updated_at "
                "FROM gitlab_inventory WHERE label = ? ORDER BY created_at DESC LIMIT 1",
                [label],
            ).fetchone()
            cols = ["id", "label", "url", "default_group", "is_active", "created_at", "updated_at"]
            return dict(zip(cols, row))

    def update_gitlab_inventory_item(self, gitlab_id: str, **fields) -> bool:
        """Update a GitLab instance in the inventory."""
        allowed = {"label", "url", "token_enc", "default_group", "is_active"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return False
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [gitlab_id]
        with self.get_shared_connection() as conn:
            conn.execute(
                f"UPDATE gitlab_inventory SET {set_clause}, updated_at = now() WHERE id = ?",
                values,
            )
        return True

    def delete_gitlab_inventory_item(self, gitlab_id: str) -> bool:
        """Delete a GitLab instance from the inventory and remove all client mappings."""
        with self.get_shared_connection() as conn:
            conn.execute("DELETE FROM client_gitlab_map WHERE gitlab_id = ?", [gitlab_id])
            deleted = conn.execute(
                "DELETE FROM gitlab_inventory WHERE id = ? RETURNING id", [gitlab_id]
            ).fetchone()
        return deleted is not None

    def get_gitlab_clients(self, gitlab_id: str) -> List[Dict]:
        """Get all clients linked to a GitLab instance."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT c.id, c.name, c.slug FROM clients c "
                "JOIN client_gitlab_map m ON c.id = m.client_id "
                "WHERE m.gitlab_id = ? ORDER BY c.name",
                [gitlab_id],
            ).fetchall()
            return [{"id": r[0], "name": r[1], "slug": r[2]} for r in rows]

    def get_client_gitlab_instances(self, client_id: str) -> List[Dict]:
        """Get all GitLab instances linked to a client."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT g.id, g.label, g.url, g.default_group, g.is_active "
                "FROM gitlab_inventory g JOIN client_gitlab_map m ON g.id = m.gitlab_id "
                "WHERE m.client_id = ? ORDER BY g.label",
                [client_id],
            ).fetchall()
            cols = ["id", "label", "url", "default_group", "is_active"]
            return [dict(zip(cols, r)) for r in rows]

    def link_client_gitlab(self, client_id: str, gitlab_id: str):
        """Link a client to a GitLab instance."""
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO client_gitlab_map (client_id, gitlab_id) "
                "VALUES (?, ?) ON CONFLICT DO NOTHING",
                [client_id, gitlab_id],
            )

    def unlink_client_gitlab(self, client_id: str, gitlab_id: str):
        """Unlink a client from a GitLab instance."""
        with self.get_shared_connection() as conn:
            conn.execute(
                "DELETE FROM client_gitlab_map WHERE client_id = ? AND gitlab_id = ?",
                [client_id, gitlab_id],
            )

    # --- Keycloak Inventory ---

    def list_keycloak_inventory(self) -> List[Dict]:
        """List all Keycloak instances in the centralized inventory."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT id, label, url, realm, client_id_enc, client_secret_enc, "
                "is_active, last_test_status, last_test_at, last_test_message, "
                "created_at, updated_at "
                "FROM keycloak_inventory ORDER BY label"
            ).fetchall()
            cols = ["id", "label", "url", "realm", "client_id_enc", "client_secret_enc",
                    "is_active", "last_test_status", "last_test_at", "last_test_message",
                    "created_at", "updated_at"]
            return [dict(zip(cols, r)) for r in rows]

    def create_keycloak_inventory_item(self, label: str, url: str, realm: str = "master",
                                       client_id_enc: str = None,
                                       client_secret_enc: str = None) -> Dict:
        """Create a Keycloak instance in the inventory."""
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO keycloak_inventory (label, url, realm, client_id_enc, client_secret_enc) "
                "VALUES (?, ?, ?, ?, ?)",
                [label, url, realm, client_id_enc, client_secret_enc],
            )
            row = conn.execute(
                "SELECT id, label, url, realm, client_id_enc, client_secret_enc, is_active, "
                "created_at, updated_at FROM keycloak_inventory "
                "WHERE label = ? ORDER BY created_at DESC LIMIT 1",
                [label],
            ).fetchone()
            cols = ["id", "label", "url", "realm", "client_id_enc", "client_secret_enc",
                    "is_active", "created_at", "updated_at"]
            return dict(zip(cols, row))

    def update_keycloak_inventory_item(self, keycloak_id: str, **fields) -> bool:
        """Update a Keycloak instance in the inventory."""
        allowed = {"label", "url", "realm", "client_id_enc", "client_secret_enc", "is_active"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return False
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [keycloak_id]
        with self.get_shared_connection() as conn:
            conn.execute(
                f"UPDATE keycloak_inventory SET {set_clause}, updated_at = now() WHERE id = ?",
                values,
            )
        return True

    def delete_keycloak_inventory_item(self, keycloak_id: str) -> bool:
        """Delete a Keycloak instance from the inventory."""
        with self.get_shared_connection() as conn:
            deleted = conn.execute(
                "DELETE FROM keycloak_inventory WHERE id = ? RETURNING id", [keycloak_id]
            ).fetchone()
        return deleted is not None

    # --- Inventory test-status persistence (Migration 33) ---

    _INVENTORY_TABLE_BY_KIND = {
        "siems":    "siem_inventory",
        "siem":     "siem_inventory",
        "opencti":  "opencti_inventory",
        "gitlab":   "gitlab_inventory",
        "keycloak": "keycloak_inventory",
    }

    def update_inventory_test_status(self, kind: str, item_id: str,
                                     status: str, message: str = None) -> bool:
        """Persist the result of a Test-Connection click on an inventory item.

        ``kind`` is one of: 'siems' | 'opencti' | 'gitlab' | 'keycloak'.
        ``status`` is one of: 'pass' | 'fail' (legacy 'success' is mapped to
        'pass' so older callers keep working).
        """
        table = self._INVENTORY_TABLE_BY_KIND.get(kind)
        if not table:
            return False
        # Normalise legacy "success" → "pass" (pill renderer expects pass/fail).
        if status == "success":
            status = "pass"
        if status not in ("pass", "fail"):
            return False
        msg = (message or "")[:500]
        with self.get_shared_connection() as conn:
            conn.execute(
                f"UPDATE {table} SET last_test_status = ?, last_test_at = now(), "
                f"last_test_message = ? WHERE id = ?",
                [status, msg, item_id],
            )
        return True

    def update_siem_logging_config(self, siem_id: str, *, enabled: bool,
                                   target_space: str = None,
                                   schedule: str = "00:00",
                                   retention_days: int = 7,
                                   destination_path: str = None) -> bool:
        """Persist rule-score logging configuration on a SIEM inventory item.

        ``destination_path`` is an optional per-SIEM override for the output
        directory. ``None`` (or empty) keeps the container default.
        """
        with self.get_shared_connection() as conn:
            conn.execute(
                "UPDATE siem_inventory SET log_enabled = ?, log_target_space = ?, "
                "log_schedule = ?, log_retention_days = ?, log_destination_path = ?, "
                "updated_at = now() WHERE id = ?",
                [bool(enabled), target_space or None,
                 (schedule or "00:00").strip() or "00:00",
                 int(retention_days or 7),
                 (destination_path or "").strip() or None,
                 siem_id],
            )
        return True

    def list_logging_enabled_siems(self) -> List[Dict]:
        """Return every SIEM with ``log_enabled = TRUE``.

        Used by ``services/rule_logger.py`` to drive per-SIEM rule-score export.
        """
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT id, label, siem_type, kibana_url, elasticsearch_url, "
                "api_token_enc, log_target_space, log_schedule, log_retention_days, "
                "log_destination_path "
                "FROM siem_inventory WHERE log_enabled = TRUE ORDER BY label"
            ).fetchall()
            cols = ["id", "label", "siem_type", "kibana_url", "elasticsearch_url",
                    "api_token_enc", "log_target_space", "log_schedule",
                    "log_retention_days", "log_destination_path"]
            return [dict(zip(cols, r)) for r in rows]

    def get_all_kibana_spaces(self) -> List[str]:
        """Return every distinct Kibana space known to TIDE.

        Used by the per-SIEM Rule Logging picker so every SIEM card offers
        the same option set regardless of which `siem_inventory` row received
        the last rule sync (two aliases of the same backend would otherwise
        show different lists).

        Discovery union (in order, deduped):
        1. Every `space` value present in `detection_rules` (any SIEM, any
           tenant — the query runs against the shared connection so it sees
           the global table when not in multi-DB mode; in multi-DB mode the
           per-tenant tables are inspected).
        2. Every distinct ``client_siem_map.space`` value, so freshly-mapped
           SIEMs without a sync yet still surface their intended spaces.
        3. Every distinct ``siem_kibana_spaces.space`` value (Migration 41
           persistent test-connection cache).

        No name-based filtering is applied. Releases 4.1.5–4.1.7 stripped
        the literal strings ``'production'`` / ``'staging'`` from every
        source on the theory that they were always role-name confusion;
        that theory turned out to be wrong (Kibana permits space ids with
        those names and at least one standalone deployment uses them), and
        the filter was the cause of those legitimate spaces being invisible
        in the link-to-tenant picker on the airgapped box whenever the live
        Kibana lookup fell back to the persisted cache.
        """
        spaces: list[str] = []
        seen: set[str] = set()
        with self.get_shared_connection() as conn:
            try:
                rows = conn.execute(
                    "SELECT DISTINCT COALESCE(NULLIF(TRIM(space), ''), 'default') "
                    "FROM detection_rules ORDER BY 1"
                ).fetchall()
                for r in rows:
                    v = r[0]
                    if v and v not in seen:
                        spaces.append(v); seen.add(v)
            except Exception as exc:
                logger.debug(f"get_all_kibana_spaces: detection_rules scan failed: {exc}")
            try:
                extra = conn.execute(
                    "SELECT DISTINCT COALESCE(NULLIF(TRIM(space), ''), 'default') "
                    "FROM client_siem_map "
                    "WHERE space IS NOT NULL AND TRIM(space) <> ''"
                ).fetchall()
                for r in extra:
                    v = r[0]
                    if v and v not in seen:
                        spaces.append(v); seen.add(v)
            except Exception as exc:
                logger.debug(f"get_all_kibana_spaces: client_siem_map scan failed: {exc}")
            # Migration 41: union from the persistent test-connection cache so
            # freshly-discovered spaces appear in the picker even before any
            # rules have synced.
            try:
                rows = conn.execute(
                    "SELECT DISTINCT space FROM siem_kibana_spaces "
                    "WHERE space IS NOT NULL AND TRIM(space) <> ''"
                ).fetchall()
                for r in rows:
                    v = r[0]
                    if v and v not in seen:
                        spaces.append(v); seen.add(v)
            except Exception as exc:
                logger.debug(f"get_all_kibana_spaces: siem_kibana_spaces scan failed: {exc}")
        # Also union spaces from every tenant DB so multi-tenant deployments
        # see the full list. Ignored when not in multi-DB mode.
        try:
            from app.services.tenant_manager import is_multi_db_mode, _tenant_db_cache
            if is_multi_db_mode():
                from app.services.connection_pool import get_pool
                pool = get_pool()
                for client_id, _fname in list(_tenant_db_cache.items()):
                    from app.services.tenant_manager import resolve_tenant_db_path
                    import os as _os
                    tdb = resolve_tenant_db_path(client_id, _os.path.dirname(self.db_path))
                    if not tdb:
                        continue
                    try:
                        with pool.acquire(tdb) as tconn:
                            rows = tconn.execute(
                                "SELECT DISTINCT COALESCE(NULLIF(TRIM(space), ''), 'default') "
                                "FROM detection_rules"
                            ).fetchall()
                        for r in rows:
                            v = r[0]
                            if v and v not in seen:
                                spaces.append(v); seen.add(v)
                    except Exception as exc:
                        logger.debug(f"get_all_kibana_spaces: tenant {client_id} scan failed: {exc}")
        except Exception as exc:
            logger.debug(f"get_all_kibana_spaces: tenant fan-out failed: {exc}")
        return sorted(spaces)

    # --- Sigma asset (pipeline / template) tenant assignments (Migration 33) ---

    def list_sigma_asset_assignments(self, asset_type: str) -> Dict[str, List[Dict]]:
        """Return ``{filename: [{id, name}, ...]}`` for every assigned filename.

        ``asset_type`` is 'pipeline' or 'template'.
        """
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT a.filename, c.id, c.name FROM sigma_asset_assignments a "
                "JOIN clients c ON c.id = a.client_id "
                "WHERE a.asset_type = ? ORDER BY a.filename, c.name",
                [asset_type],
            ).fetchall()
        out: Dict[str, List[Dict]] = {}
        for fname, cid, cname in rows:
            out.setdefault(fname, []).append({"id": cid, "name": cname})
        return out

    def get_sigma_asset_clients(self, asset_type: str, filename: str) -> List[Dict]:
        """Return tenants assigned to a single sigma asset file."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT c.id, c.name FROM sigma_asset_assignments a "
                "JOIN clients c ON c.id = a.client_id "
                "WHERE a.asset_type = ? AND a.filename = ? ORDER BY c.name",
                [asset_type, filename],
            ).fetchall()
        return [{"id": r[0], "name": r[1]} for r in rows]

    def set_sigma_asset_assignments(self, asset_type: str, filename: str,
                                    client_ids: List[str]) -> int:
        """Replace the tenant assignment set for a sigma asset.

        Returns the number of assignment rows after the update.  Caller MUST
        validate that ``client_ids`` is non-empty (force-assign-on-save rule).
        """
        with self.get_shared_connection() as conn:
            conn.execute(
                "DELETE FROM sigma_asset_assignments WHERE asset_type = ? AND filename = ?",
                [asset_type, filename],
            )
            for cid in client_ids:
                conn.execute(
                    "INSERT INTO sigma_asset_assignments (asset_type, filename, client_id) "
                    "VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                    [asset_type, filename, cid],
                )
            count = conn.execute(
                "SELECT count(*) FROM sigma_asset_assignments "
                "WHERE asset_type = ? AND filename = ?",
                [asset_type, filename],
            ).fetchone()[0]
        return int(count)

    def delete_sigma_asset_assignments(self, asset_type: str, filename: str) -> int:
        """Remove all assignments for a sigma asset (called when the file is deleted)."""
        with self.get_shared_connection() as conn:
            removed = conn.execute(
                "DELETE FROM sigma_asset_assignments WHERE asset_type = ? AND filename = ? "
                "RETURNING client_id",
                [asset_type, filename],
            ).fetchall()
        return len(removed)

    def list_sigma_assets_for_client(self, asset_type: str, client_id: str) -> List[str]:
        """Return filenames of sigma assets assigned to a client."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT filename FROM sigma_asset_assignments "
                "WHERE asset_type = ? AND client_id = ? ORDER BY filename",
                [asset_type, client_id],
            ).fetchall()
        return [r[0] for r in rows]

    def get_all_sync_spaces(self) -> List[str]:
        """Get every distinct Kibana space across all client-SIEM mappings.
        NULL/empty values are normalised to 'default'.
        Used by the sync service to know which spaces to fetch rules from."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT COALESCE(NULLIF(TRIM(space), ''), 'default') "
                "FROM client_siem_map"
            ).fetchall()
            return [r[0] for r in rows if r[0]]

    def get_siem_spaces(self, siem_id: str) -> List[str]:
        """Get every distinct Kibana space mapped to a single SIEM via client_siem_map.
        NULL/empty values are normalised to 'default'."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT COALESCE(NULLIF(TRIM(space), ''), 'default') "
                "FROM client_siem_map WHERE siem_id = ?",
                [siem_id],
            ).fetchall()
            return [r[0] for r in rows if r[0]]

    def save_siem_spaces(self, siem_id: str, spaces: List[str]) -> int:
        """Replace the cached Kibana space set for a SIEM (Migration 41).

        Called by Management → SIEMs → Test Connection on success so the
        link-form spaces dropdown is populated immediately and survives an
        app restart. Returns the number of rows after the update.
        """
        clean = sorted({(s or "").strip() for s in (spaces or []) if s and s.strip()})
        with self.get_shared_connection() as conn:
            conn.execute("DELETE FROM siem_kibana_spaces WHERE siem_id = ?", [siem_id])
            for sp in clean:
                conn.execute(
                    "INSERT INTO siem_kibana_spaces (siem_id, space) VALUES (?, ?) "
                    "ON CONFLICT DO NOTHING",
                    [siem_id, sp],
                )
        return len(clean)

    def get_siem_spaces_cached(self, siem_id: str) -> List[str]:
        """Return persisted Kibana spaces for a SIEM (Migration 41).

        Used as a fallback when the live ``/api/spaces/space`` call fails so
        the link form is not silently empty after a Kibana hiccup.
        """
        with self.get_shared_connection() as conn:
            try:
                rows = conn.execute(
                    "SELECT space FROM siem_kibana_spaces WHERE siem_id = ? ORDER BY space",
                    [siem_id],
                ).fetchall()
            except Exception:
                return []
            return [r[0] for r in rows if r[0]]

    def record_sync_run(
        self,
        sync_kind: str,
        status: str,
        *,
        total_count: int = 0,
        duration_ms: int = 0,
        detail: dict = None,
        error: str = None,
    ) -> str:
        """Persist a single sync run into ``sync_history`` (Migration 42).

        Best-effort: on any DB failure the call swallows the exception and
        returns ``""`` so it can never break the sync that just happened.
        Returns the row id (uuid4 hex) on success.
        """
        import uuid as _uuid
        import json as _json
        run_id = _uuid.uuid4().hex
        try:
            payload = _json.dumps(detail or {}, default=str)[:8000]
        except Exception:
            payload = "{}"
        try:
            with self.get_shared_connection() as conn:
                conn.execute(
                    "INSERT INTO sync_history "
                    "(id, sync_kind, status, duration_ms, total_count, "
                    " detail_json, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [run_id, sync_kind, status, int(duration_ms),
                     int(total_count or 0), payload,
                     (str(error)[:2000] if error else None)],
                )
            return run_id
        except Exception as exc:
            logger.warning(f"record_sync_run({sync_kind}) failed: {exc!r}")
            return ""

    def list_sync_history(self, sync_kind: str = None, limit: int = 50) -> List[dict]:
        """Return recent ``sync_history`` rows, newest first. Used by the
        Query tab predefined searches and by ``diag_sync``."""
        sql = (
            "SELECT id, sync_kind, status, started_at, duration_ms, "
            "total_count, error FROM sync_history "
        )
        params: list = []
        if sync_kind:
            sql += "WHERE sync_kind = ? "
            params.append(sync_kind)
        sql += "ORDER BY started_at DESC LIMIT ?"
        params.append(int(limit))
        with self.get_shared_connection() as conn:
            try:
                rows = conn.execute(sql, params).fetchall()
            except Exception:
                return []
        return [
            {
                "id": r[0], "sync_kind": r[1], "status": r[2],
                "started_at": r[3], "duration_ms": r[4],
                "total_count": r[5], "error": r[6],
            }
            for r in rows
        ]

    def list_query_templates(self) -> List[dict]:
        """Return saved Management Query tab templates (shared DB)."""
        with self.get_shared_connection() as conn:
            try:
                rows = conn.execute(
                    "SELECT id, name, sql_text, target_key, created_by_user_id, "
                    "created_at, updated_at "
                    "FROM query_templates ORDER BY lower(name), created_at"
                ).fetchall()
            except Exception:
                return []
        return [
            {
                "id": r[0],
                "name": r[1],
                "sql_text": r[2],
                "target_key": r[3],
                "created_by_user_id": r[4],
                "created_at": r[5],
                "updated_at": r[6],
            }
            for r in rows
        ]

    def save_query_template(
        self,
        name: str,
        sql_text: str,
        target_key: str = "shared",
        created_by_user_id: str = None,
    ) -> tuple[dict, bool]:
        """Create or update a saved query template by name.

        Returns ``(row, created)``.
        """
        n = (name or "").strip()
        s = (sql_text or "").strip()
        t = (target_key or "shared").strip() or "shared"
        if not n:
            raise ValueError("Template name is required.")
        if not s:
            raise ValueError("SQL is required.")

        with self.get_shared_connection() as conn:
            existing = conn.execute(
                "SELECT id FROM query_templates WHERE lower(name) = lower(?) "
                "ORDER BY created_at DESC LIMIT 1",
                [n],
            ).fetchone()
            created = existing is None
            if created:
                conn.execute(
                    "INSERT INTO query_templates "
                    "(name, sql_text, target_key, created_by_user_id) "
                    "VALUES (?, ?, ?, ?)",
                    [n, s, t, created_by_user_id],
                )
            else:
                conn.execute(
                    "UPDATE query_templates "
                    "SET name = ?, sql_text = ?, target_key = ?, "
                    "created_by_user_id = ?, updated_at = now() "
                    "WHERE id = ?",
                    [n, s, t, created_by_user_id, existing[0]],
                )

            row = conn.execute(
                "SELECT id, name, sql_text, target_key, created_by_user_id, "
                "created_at, updated_at "
                "FROM query_templates WHERE lower(name) = lower(?) "
                "ORDER BY created_at DESC LIMIT 1",
                [n],
            ).fetchone()
        return ({
            "id": row[0],
            "name": row[1],
            "sql_text": row[2],
            "target_key": row[3],
            "created_by_user_id": row[4],
            "created_at": row[5],
            "updated_at": row[6],
        }, created)

    def delete_query_template(self, template_id: str) -> bool:
        """Delete a saved query template by id."""
        tid = (template_id or "").strip()
        if not tid:
            return False
        with self.get_shared_connection() as conn:
            deleted = conn.execute(
                "DELETE FROM query_templates WHERE id = ? RETURNING id",
                [tid],
            ).fetchone()
        return deleted is not None

    def get_client_siem_spaces(self, client_id: str, environment_role: str = None) -> List[str]:
        """Get the list of Kibana space names visible to a client.
        If environment_role is specified, filter to just production or staging.
        NULL/empty spaces are normalised to 'default' (Kibana's built-in space).

        .. warning::
           This method returns space names ONLY — it is NOT safe for filtering
           ``detection_rules`` rows when two SIEMs (different tenants) share a
           Kibana space name (e.g. both expose ``two``). Use
           :py:meth:`get_client_siem_scopes` for any query that selects from
           ``detection_rules``; that method returns ``(siem_id, space)`` tuples
           so the per-row ``siem_id`` can be matched too. The legacy
           space-only callers retained here are for display lookups
           (e.g. building the space dropdown).
        """
        with self.get_shared_connection() as conn:
            query = (
                "SELECT DISTINCT COALESCE(NULLIF(TRIM(m.space), ''), 'default') "
                "FROM client_siem_map m "
                "WHERE m.client_id = ?"
            )
            params = [client_id]
            if environment_role:
                query += " AND m.environment_role = ?"
                params.append(environment_role)
            rows = conn.execute(query, params).fetchall()
            return [r[0] for r in rows if r[0]]

    def get_client_siem_scopes(self, client_id: str, environment_role: str = None) -> List[Tuple[str, str]]:
        """Get the list of ``(siem_id, space)`` tuples a client is entitled to see.

        This is the tenant-isolation primitive for any query that pulls from
        ``detection_rules`` (whose PK is ``(rule_id, siem_id)`` since
        Migration 37). Filtering by space-name alone is insufficient when two
        SIEMs share a Kibana space name — every detection_rules row scoped to
        that space would surface for every client mapped to either SIEM,
        leaking rules across tenants. This method preserves the (siem_id,
        space) pairing so callers can build a ``(siem_id = ? AND
        LOWER(space) = ?)`` predicate with no cross-tenant bleed.

        Spaces are returned lower-cased for case-insensitive matching against
        DuckDB ``LOWER(space)``. NULL/empty spaces are normalised to
        ``'default'`` to match the Kibana built-in space.
        """
        with self.get_shared_connection() as conn:
            query = (
                "SELECT DISTINCT m.siem_id, "
                "LOWER(COALESCE(NULLIF(TRIM(m.space), ''), 'default')) "
                "FROM client_siem_map m "
                "WHERE m.client_id = ? AND m.siem_id IS NOT NULL"
            )
            params = [client_id]
            if environment_role:
                query += " AND m.environment_role = ?"
                params.append(environment_role)
            rows = conn.execute(query, params).fetchall()
            return [(sid, sp) for sid, sp in rows if sid and sp]

    def get_covered_ttps_for_client(self, client_id: str, environment_role: str = "production") -> Set[str]:
        """Get TTPs covered by enabled detection rules for a client's role-tagged
        ``(siem_id, space)`` pairs. Composite key is mandatory — a space-only
        filter would leak TTP coverage from a SIEM the tenant does not map
        (AGENTS.md §8.2 g4)."""
        scopes = self.get_client_siem_scopes(client_id, environment_role)
        if not scopes:
            return set()
        frag, params = _scope_predicate(scopes)
        with self.get_connection() as conn:
            result = conn.execute(f"""
                SELECT DISTINCT unnest(mitre_ids)
                FROM detection_rules
                WHERE enabled = 1 AND {frag}
            """, params).fetchall()
            return {row[0].upper() for row in result if row[0]}

    def get_technique_rule_counts_for_client(self, client_id: str, environment_role: str = "production") -> Dict[str, int]:
        """Get count of enabled rules per MITRE technique for the client's
        role-tagged ``(siem_id, space)`` pairs. Composite key is mandatory
        (AGENTS.md §8.2 g4)."""
        scopes = self.get_client_siem_scopes(client_id, environment_role)
        if not scopes:
            return {}
        frag, params = _scope_predicate(scopes)
        with self.get_connection() as conn:
            result = conn.execute(f"""
                WITH unnested AS (
                    SELECT UPPER(unnest(mitre_ids)) as technique
                    FROM detection_rules
                    WHERE enabled = 1 AND {frag}
                )
                SELECT technique, COUNT(*) as rule_count
                FROM unnested
                WHERE technique IS NOT NULL
                GROUP BY technique
            """, params).fetchall()
            return {row[0]: row[1] for row in result if row[0]}

    def get_rules_for_client(self, client_id: str, environment_role: str = None) -> List[Dict]:
        """Get all detection rules visible to a client via linked SIEMs.
        Filtered by composite ``(siem_id, space)`` so two SIEMs sharing a
        Kibana space name never bleed into each other (AGENTS.md §8.2 g4).
        If ``environment_role`` is specified, restrict to that role's pairs only."""
        scopes = self.get_client_siem_scopes(client_id, environment_role)
        if not scopes:
            return []
        frag, params = _scope_predicate(scopes)
        with self.get_connection() as conn:
            rows = conn.execute(f"""
                SELECT * FROM detection_rules
                WHERE {frag}
                ORDER BY name
            """, params).fetchall()
            if not rows:
                return []
            columns = [desc[0] for desc in conn.description]
            return [dict(zip(columns, r)) for r in rows]


# Singleton accessor
def get_database_service() -> DatabaseService:
    """Get the database service singleton."""
    return DatabaseService()
