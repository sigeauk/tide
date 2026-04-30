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
SCHEMA_VERSION = 37


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
    
    def get_rules(self, filters: RuleFilters) -> Tuple[List[DetectionRule], int, str]:
        """
        Get paginated list of detection rules with filters.
        Returns (rules, total_count, last_sync).
        """
        with self.get_connection() as conn:
            # Base query
            query = "SELECT * FROM detection_rules WHERE 1=1"
            params = []

            # Tenant isolation: restrict to spaces linked to the active
            # client. With per-tenant DB routing (Migration 29) this query
            # already runs against the tenant's own DB file, so the space
            # allow-list is sufficient \u2014 no SIEM cross-contamination is
            # possible because the other tenant's rows aren't in this file.
            if filters.allowed_spaces is not None:
                if not filters.allowed_spaces:
                    # Client has no SIEMs \u2192 zero rules visible
                    return [], 0, "Never"
                placeholders = ", ".join("?" for _ in filters.allowed_spaces)
                query += f" AND LOWER(space) IN ({placeholders})"
                params.extend([s.lower() for s in filters.allowed_spaces])
            
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
                rule = self._row_to_rule(row.to_dict(), validation_data)
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
        """Get set of (rule_id, siem_id) tuples for all rules in the database.
        Used for lazy mapping: skip Elasticsearch mapping checks for known rules.
        Keyed by ``siem_id`` since 4.0.13 — the same Elastic prebuilt rule_id can
        legitimately exist in multiple SIEMs and must not collide."""
        with self.get_connection() as conn:
            rows = conn.execute("SELECT rule_id, siem_id FROM detection_rules").fetchall()
            return {(row[0], row[1]) for row in rows}

    def get_existing_rule_data(self) -> dict:
        """Get existing rule scores and raw_data keyed by (rule_id, siem_id).
        Used to preserve mapping data for rules that skip mapping during lazy sync.
        Keyed by ``siem_id`` since 4.0.13 (see ``get_existing_rule_keys``)."""
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
                key = (d['rule_id'], d['siem_id'])
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
            conn.execute("CHECKPOINT")
        logger.info(
            "Moved rule %s from '%s' to '%s' in DB (siem_id=%s)",
            rule_id, from_space, to_space, siem_id or '<unscoped>',
        )

    def get_rule_by_id(self, rule_id: str, space: str = "default",
                       siem_id: Optional[str] = None) -> Optional[DetectionRule]:
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
                return self._row_to_rule(row, validation_data)

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

    def _row_to_rule(self, row: Dict[str, Any], validation_data: Dict) -> DetectionRule:
        """Convert database row to DetectionRule model."""
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
                    validation_status = "expired" if weeks > 12 else "valid"
                except:
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
        allowed_spaces: List[str] = None,
    ) -> RuleHealthMetrics:
        """Calculate comprehensive rule health metrics.
        With per-tenant DB routing the connection is already tenant-scoped,
        so ``allowed_spaces`` (the spaces this client is mapped to) is a
        sufficient filter."""
        with self.get_connection() as conn:
            if allowed_spaces is not None:
                if not allowed_spaces:
                    return RuleHealthMetrics()
                placeholders = ", ".join("?" for _ in allowed_spaces)
                df = conn.execute(
                    f"SELECT enabled, score, space, severity, name, raw_data FROM detection_rules "
                    f"WHERE LOWER(space) IN ({placeholders})",
                    [s.lower() for s in allowed_spaces],
                ).df()
            else:
                df = conn.execute(
                    "SELECT enabled, score, space, severity, name, raw_data FROM detection_rules"
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
            
            # Rules by space
            rules_by_space = {}
            if 'space' in df.columns:
                space_counts = df['space'].value_counts().to_dict()
                rules_by_space = {str(k): int(v) for k, v in space_counts.items()}
            
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
        
        if validation_data:
            now = datetime.now()
            for rule_name in df['name'].tolist():
                rule_v = validation_data.get(str(rule_name), {})
                if rule_v:
                    validated_count += 1
                    val_str = rule_v.get('last_checked_on', '')
                    if val_str:
                        try:
                            val_date = datetime.strptime(val_str[:10], "%Y-%m-%d")
                            weeks = (now - val_date).days / 7
                            if weeks > 12:
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
    
    def get_promotion_metrics(self, staging_spaces: List[str] = None,
                              production_spaces: List[str] = None) -> Dict[str, Any]:
        """Get metrics specifically for staging rules ready for promotion.

        Args:
            staging_spaces:  Kibana space names mapped as 'staging' environment_role.
            production_spaces: Kibana space names mapped as 'production' environment_role.
        If not provided, falls back to literal 'staging'/'production' space names.
        """
        with self.get_connection() as conn:
            # ── Build staging filter ──
            if staging_spaces:
                ph = ", ".join("?" for _ in staging_spaces)
                staging_df = conn.execute(
                    f"SELECT enabled, score, severity, name FROM detection_rules "
                    f"WHERE LOWER(space) IN ({ph})",
                    [s.lower() for s in staging_spaces],
                ).df()
            else:
                staging_df = conn.execute(
                    "SELECT enabled, score, severity, name FROM detection_rules WHERE LOWER(space) = 'staging'"
                ).df()

            # ── Build production count ──
            if production_spaces:
                ph = ", ".join("?" for _ in production_spaces)
                prod_result = conn.execute(
                    f"SELECT COUNT(*) FROM detection_rules WHERE LOWER(space) IN ({ph})",
                    [s.lower() for s in production_spaces],
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
    
    # --- THREAT ACTOR OPERATIONS ---

    def _client_has_opencti(self, client_id: Optional[str]) -> bool:
        """Return True when *client_id* has at least one OpenCTI instance linked.

        Used to decide whether OpenCTI-sourced threat actors should be visible
        to a tenant. ``None``/empty client_id is treated as "no link" so any
        unauthenticated / pre-tenant code paths see the MITRE baseline only.
        """
        if not client_id:
            return False
        try:
            with self.get_shared_connection() as conn:
                row = conn.execute(
                    "SELECT 1 FROM client_opencti_map WHERE client_id = ? LIMIT 1",
                    [client_id],
                ).fetchone()
            return bool(row)
        except Exception as exc:
            logger.warning(f"_client_has_opencti({client_id}) failed: {exc}")
            return False

    def get_threat_actors(self, client_id: Optional[str] = None) -> List[ThreatActor]:
        """Get all threat actors ordered by TTP count.

        When ``client_id`` is supplied and the tenant has **no** OpenCTI instance
        linked (`client_opencti_map`), actors whose ``source`` array does not
        include any MITRE source are filtered out so OpenCTI-only intel from
        another tenant does not leak into the Threat Landscape / Heatmap. The
        legacy ``client_id=None`` behaviour returns every actor unchanged so
        background sync jobs and report exports keep working.
        """
        include_opencti_only = client_id is None or self._client_has_opencti(client_id)
        with self.get_connection() as conn:
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

            if not include_opencti_only:
                # Tenant has no OpenCTI link — keep only actors that came from
                # at least one MITRE source. Anything sourced solely from a
                # different tenant's OpenCTI feed is hidden.
                _MITRE_SOURCES = {
                    "mitre", "enterprise", "mobile", "ics",
                    "mitre:enterprise", "mitre:mobile", "mitre:ics",
                    "mitre-enterprise", "mitre-mobile", "mitre-ics",
                }
                actors = [
                    a for a in actors
                    if any((s or "").strip().lower() in _MITRE_SOURCES for s in (a.source or []))
                ]

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
        If client_id provided, coverage is scoped to that client's production SIEM spaces."""
        from app.models.threats import ThreatLandscapeMetrics
        
        # Pre-fetch client production spaces outside the main connection
        prod_spaces = None
        if client_id:
            prod_spaces = self.get_client_siem_spaces(client_id, "production")
        
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
                _MITRE_SOURCES = {
                    "mitre", "enterprise", "mobile", "ics",
                    "mitre:enterprise", "mitre:mobile", "mitre:ics",
                    "mitre-enterprise", "mitre-mobile", "mitre-ics",
                }

                def _has_mitre(src) -> bool:
                    if src is None:
                        return False
                    if hasattr(src, 'tolist'):
                        src = src.tolist()
                    if not isinstance(src, list):
                        return False
                    return any((s or "").strip().lower() in _MITRE_SOURCES for s in src)

                df = df[df['source'].apply(_has_mitre)].reset_index(drop=True)
                if df.empty:
                    return ThreatLandscapeMetrics()
            
            # Get covered TTPs inline (avoid nested connection)
            if prod_spaces is not None:
                if prod_spaces:
                    placeholders = ", ".join("?" for _ in prod_spaces)
                    covered_result = conn.execute(f"""
                        SELECT DISTINCT unnest(mitre_ids) 
                        FROM detection_rules 
                        WHERE enabled = 1 AND LOWER(space) IN ({placeholders})
                    """, [s.lower() for s in prod_spaces]).fetchall()
                else:
                    # Client has 0 SIEMs — no covered TTPs
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
        
        # Resolve allowed spaces for tenant scoping
        allowed_spaces = None
        if client_id:
            allowed_spaces = self.get_client_siem_spaces(client_id)
        
        with self.get_connection() as conn:
            # ── Rule Health Metrics ──
            if allowed_spaces is not None:
                if allowed_spaces:
                    placeholders = ", ".join(["?"] * len(allowed_spaces))
                    rules_df = conn.execute(
                        f"SELECT enabled, score, space, severity, name FROM detection_rules WHERE space IN ({placeholders})",
                        list(allowed_spaces),
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
            if allowed_spaces is not None:
                if allowed_spaces:
                    placeholders = ", ".join(["?"] * len(allowed_spaces))
                    staging_df = conn.execute(
                        f"SELECT enabled, score, severity, name FROM detection_rules WHERE LOWER(space) = 'staging' AND space IN ({placeholders})",
                        list(allowed_spaces),
                    ).df()
                    prod_result = conn.execute(
                        f"SELECT COUNT(*) FROM detection_rules WHERE LOWER(space) = 'production' AND space IN ({placeholders})",
                        list(allowed_spaces),
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
            
            # Covered TTPs (reuse same connection, scoped to client's spaces)
            if allowed_spaces is not None:
                if allowed_spaces:
                    placeholders = ", ".join(["?"] * len(allowed_spaces))
                    covered_result = conn.execute(f"""
                        SELECT DISTINCT unnest(mitre_ids) 
                        FROM detection_rules 
                        WHERE enabled = 1 AND space IN ({placeholders})
                    """, list(allowed_spaces)).fetchall()
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
                rules.append(self._row_to_rule(row, validation_data))
            
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

        Args:
            siem_id: When provided, restrict to rows whose
                ``detection_rules.siem_id`` equals this value (4.0.13+ scoping).
            space: When provided, restrict to rows whose ``space`` matches.
                Accepts a single string OR a list/tuple of strings (so a SIEM
                can be configured to log multiple Kibana spaces in one file).
                Empty / falsy entries are dropped; an empty list after
                filtering is treated as 'no space filter'.
        """
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
    
    def save_audit_results(self, audit_list: List[Dict[str, Any]]) -> int:
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
        
        # Check for duplicates within the incoming data (same rule_id + siem_id)
        duplicates = df_final[df_final.duplicated(subset=['rule_id', 'siem_id'], keep='first')]
        if not duplicates.empty:
            dup_names = duplicates['name'].tolist()
            logger.info(f"Skipping {len(dup_names)} duplicate rules (same rule_id + siem_id): {dup_names[:5]}{'...' if len(dup_names) > 5 else ''}")
            df_final = df_final.drop_duplicates(subset=['rule_id', 'siem_id'], keep='first')

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
                "SELECT id, name, slug, description, is_default, db_filename, created_at, updated_at "
                "FROM clients ORDER BY is_default DESC, name"
            ).fetchall()
            cols = ["id", "name", "slug", "description", "is_default", "db_filename", "created_at", "updated_at"]
            return [dict(zip(cols, r)) for r in rows]

    def get_client(self, client_id: str) -> Optional[Dict]:
        """Get a single client by id."""
        with self.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT id, name, slug, description, is_default, db_filename, created_at, updated_at "
                "FROM clients WHERE id = ?", [client_id]
            ).fetchone()
            if not row:
                return None
            return dict(zip(
                ["id", "name", "slug", "description", "is_default", "db_filename", "created_at", "updated_at"], row
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
        """Update a client. Allowed fields: name, description. Returns updated client or None."""
        allowed = {"name", "description"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return self.get_client(client_id)
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [client_id]
        with self.get_shared_connection() as conn:
            conn.execute(
                f"UPDATE clients SET {set_clause}, updated_at = now() WHERE id = ?", values
            )
        return self.get_client(client_id)

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
                "production_space, staging_space, "
                "created_at, updated_at "
                "FROM siem_inventory ORDER BY label"
            ).fetchall()
            cols = ["id", "label", "siem_type", "elasticsearch_url", "kibana_url",
                    "extra_config", "is_active",
                    "last_test_status", "last_test_at", "last_test_message",
                    "log_enabled", "log_target_space", "log_schedule", "log_retention_days",
                    "log_destination_path",
                    "production_space", "staging_space",
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
                "(siem_type, label, elasticsearch_url, kibana_url, api_token_enc, "
                "extra_config) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [siem_type, label, elasticsearch_url, kibana_url, api_token_enc,
                 extra_json],
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

    def list_opencti_inventory(self) -> List[Dict]:
        """List all OpenCTI instances in the centralized inventory."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT id, label, url, token_enc, is_active, "
                "last_test_status, last_test_at, last_test_message, "
                "created_at, updated_at "
                "FROM opencti_inventory ORDER BY label"
            ).fetchall()
            cols = ["id", "label", "url", "token_enc", "is_active",
                    "last_test_status", "last_test_at", "last_test_message",
                    "created_at", "updated_at"]
            return [dict(zip(cols, r)) for r in rows]

    def get_opencti_active_instances(self) -> List[Dict]:
        """Return active OpenCTI instances with their tokens (for sync service)."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT id, label, url, token_enc "
                "FROM opencti_inventory WHERE is_active = true ORDER BY label"
            ).fetchall()
            cols = ["id", "label", "url", "token_enc"]
            return [dict(zip(cols, r)) for r in rows]

    def create_opencti_inventory_item(self, label: str, url: str,
                                      token_enc: str = None) -> Dict:
        """Create an OpenCTI instance in the inventory."""
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO opencti_inventory (label, url, token_enc) VALUES (?, ?, ?)",
                [label, url, token_enc],
            )
            row = conn.execute(
                "SELECT id, label, url, is_active, created_at, updated_at "
                "FROM opencti_inventory WHERE label = ? ORDER BY created_at DESC LIMIT 1",
                [label],
            ).fetchone()
            cols = ["id", "label", "url", "is_active", "created_at", "updated_at"]
            return dict(zip(cols, row))

    def update_opencti_inventory_item(self, opencti_id: str, **fields) -> bool:
        """Update an OpenCTI instance in the inventory."""
        allowed = {"label", "url", "token_enc", "is_active"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return False
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [opencti_id]
        with self.get_shared_connection() as conn:
            conn.execute(
                f"UPDATE opencti_inventory SET {set_clause}, updated_at = now() WHERE id = ?",
                values,
            )
        return True

    def delete_opencti_inventory_item(self, opencti_id: str) -> bool:
        """Delete an OpenCTI instance from the inventory and remove all client mappings."""
        with self.get_shared_connection() as conn:
            conn.execute("DELETE FROM client_opencti_map WHERE opencti_id = ?", [opencti_id])
            deleted = conn.execute(
                "DELETE FROM opencti_inventory WHERE id = ? RETURNING id", [opencti_id]
            ).fetchone()
        return deleted is not None

    def get_opencti_clients(self, opencti_id: str) -> List[Dict]:
        """Get all clients linked to an OpenCTI instance."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT c.id, c.name, c.slug FROM clients c "
                "JOIN client_opencti_map m ON c.id = m.client_id "
                "WHERE m.opencti_id = ? ORDER BY c.name",
                [opencti_id],
            ).fetchall()
            return [{"id": r[0], "name": r[1], "slug": r[2]} for r in rows]

    def get_client_opencti_instances(self, client_id: str) -> List[Dict]:
        """Get all OpenCTI instances linked to a client."""
        with self.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT o.id, o.label, o.url, o.is_active "
                "FROM opencti_inventory o JOIN client_opencti_map m ON o.id = m.opencti_id "
                "WHERE m.client_id = ? ORDER BY o.label",
                [client_id],
            ).fetchall()
            cols = ["id", "label", "url", "is_active"]
            return [dict(zip(cols, r)) for r in rows]

    def get_client_opencti_config(self, client_id: str) -> Optional[Dict]:
        """Return the first active OpenCTI instance (with token) linked to a client.

        Used by tenant-scoped enrichment paths to avoid cross-tenant data leakage.
        Returns None when the client has no OpenCTI assigned.
        """
        with self.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT o.id, o.label, o.url, o.token_enc "
                "FROM opencti_inventory o JOIN client_opencti_map m ON o.id = m.opencti_id "
                "WHERE m.client_id = ? AND COALESCE(o.is_active, TRUE) = TRUE "
                "ORDER BY o.label LIMIT 1",
                [client_id],
            ).fetchone()
            if not row:
                return None
            return {"id": row[0], "label": row[1], "url": row[2], "token": row[3]}

    def link_client_opencti(self, client_id: str, opencti_id: str):
        """Link a client to an OpenCTI instance."""
        with self.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO client_opencti_map (client_id, opencti_id) "
                "VALUES (?, ?) ON CONFLICT DO NOTHING",
                [client_id, opencti_id],
            )

    def unlink_client_opencti(self, client_id: str, opencti_id: str):
        """Unlink a client from an OpenCTI instance."""
        with self.get_shared_connection() as conn:
            conn.execute(
                "DELETE FROM client_opencti_map WHERE client_id = ? AND opencti_id = ?",
                [client_id, opencti_id],
            )

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
        2. Every `production_space` / `staging_space` configured on any
           `siem_inventory` row, so freshly-registered SIEMs without a sync
           yet still surface their intended spaces.
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
                    "SELECT DISTINCT TRIM(production_space) FROM siem_inventory "
                    "WHERE production_space IS NOT NULL AND TRIM(production_space) <> '' "
                    "UNION "
                    "SELECT DISTINCT TRIM(staging_space) FROM siem_inventory "
                    "WHERE staging_space IS NOT NULL AND TRIM(staging_space) <> ''"
                ).fetchall()
                for r in extra:
                    v = r[0]
                    if v and v not in seen:
                        spaces.append(v); seen.add(v)
            except Exception as exc:
                logger.debug(f"get_all_kibana_spaces: siem_inventory scan failed: {exc}")
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

    def get_client_siem_spaces(self, client_id: str, environment_role: str = None) -> List[str]:
        """Get the list of Kibana space names visible to a client.
        If environment_role is specified, filter to just production or staging.
        NULL/empty spaces are normalised to 'default' (Kibana's built-in space).

        .. warning::
           This method returns space names ONLY \u2014 it is NOT safe for filtering
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
        SIEMs share a Kibana space name \u2014 every detection_rules row scoped to
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
        """Get TTPs covered by enabled detection rules in spaces linked to client for a given role."""
        spaces = self.get_client_siem_spaces(client_id, environment_role)
        if not spaces:
            return set()
        with self.get_connection() as conn:
            placeholders = ", ".join("?" for _ in spaces)
            result = conn.execute(f"""
                SELECT DISTINCT unnest(mitre_ids)
                FROM detection_rules
                WHERE enabled = 1 AND LOWER(space) IN ({placeholders})
            """, [s.lower() for s in spaces]).fetchall()
            return {row[0].upper() for row in result if row[0]}

    def get_technique_rule_counts_for_client(self, client_id: str, environment_role: str = "production") -> Dict[str, int]:
        """Get count of enabled rules per MITRE technique for client's spaces by role."""
        spaces = self.get_client_siem_spaces(client_id, environment_role)
        if not spaces:
            return {}
        with self.get_connection() as conn:
            placeholders = ", ".join("?" for _ in spaces)
            result = conn.execute(f"""
                WITH unnested AS (
                    SELECT UPPER(unnest(mitre_ids)) as technique
                    FROM detection_rules
                    WHERE enabled = 1 AND LOWER(space) IN ({placeholders})
                )
                SELECT technique, COUNT(*) as rule_count
                FROM unnested
                WHERE technique IS NOT NULL
                GROUP BY technique
            """, [s.lower() for s in spaces]).fetchall()
            return {row[0]: row[1] for row in result if row[0]}

    def get_rules_for_client(self, client_id: str, environment_role: str = None) -> List[Dict]:
        """Get all detection rules visible to a client via linked SIEMs.
        If environment_role is specified, restrict to that role's spaces only."""
        spaces = self.get_client_siem_spaces(client_id, environment_role)
        if not spaces:
            return []
        with self.get_connection() as conn:
            placeholders = ", ".join("?" for _ in spaces)
            rows = conn.execute(f"""
                SELECT * FROM detection_rules
                WHERE LOWER(space) IN ({placeholders})
                ORDER BY name
            """, [s.lower() for s in spaces]).fetchall()
            if not rows:
                return []
            columns = [desc[0] for desc in conn.description]
            return [dict(zip(columns, r)) for r in rows]


# Singleton accessor
def get_database_service() -> DatabaseService:
    """Get the database service singleton."""
    return DatabaseService()
