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
SCHEMA_VERSION = 22


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
        Always use read_only=False for consistent reads in WAL mode.
        """
        conn = None
        attempt = 0
        
        while attempt < retries:
            try:
                with self._conn_lock:
                    conn = duckdb.connect(self.db_path, read_only=False)
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
            finally:
                if conn:
                    conn.close()
        
        raise duckdb.IOException("Database locked by another process.")
    
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
        """Initialize database and run migrations."""
        with self.get_connection() as conn:
            self._run_migrations(conn)
            self._validate_legacy_tables(conn)
            self._ensure_users_table(conn)
    
    def _ensure_users_table(self, conn):
        """Bootstrap default admin user if no users exist."""
        try:
            row = conn.execute("SELECT count(*) FROM users").fetchone()
            if row and row[0] == 0:
                import bcrypt
                default_pw = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode()
                conn.execute(
                    "INSERT INTO users (username, email, full_name, password_hash, auth_provider, is_active) "
                    "VALUES ('admin', 'admin@localhost', 'Default Admin', ?, 'local', true)",
                    [default_pw],
                )
                # Assign ADMIN role to the bootstrap user
                admin_user_id = conn.execute(
                    "SELECT id FROM users WHERE username = 'admin'"
                ).fetchone()[0]
                admin_role_id = conn.execute(
                    "SELECT id FROM roles WHERE name = 'ADMIN'"
                ).fetchone()[0]
                conn.execute(
                    "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
                    [admin_user_id, admin_role_id],
                )
                logger.info("Bootstrap admin user created (username: admin, password: admin)")
            else:
                logger.info(f"Users table has {row[0]} user(s), skipping bootstrap")
        except Exception as e:
            logger.warning(f"Could not bootstrap admin user: {e}")
    
    # --- USER / RBAC DATA ---

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT id, username, email, full_name, password_hash, keycloak_id, "
                "auth_provider, is_active, created_at, updated_at, last_login "
                "FROM users WHERE username = ?", [username]
            ).fetchone()
            if not row:
                return None
            return dict(zip(
                ["id", "username", "email", "full_name", "password_hash", "keycloak_id",
                 "auth_provider", "is_active", "created_at", "updated_at", "last_login"], row
            ))

    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT id, username, email, full_name, password_hash, keycloak_id, "
                "auth_provider, is_active, created_at, updated_at, last_login "
                "FROM users WHERE id = ?", [user_id]
            ).fetchone()
            if not row:
                return None
            return dict(zip(
                ["id", "username", "email", "full_name", "password_hash", "keycloak_id",
                 "auth_provider", "is_active", "created_at", "updated_at", "last_login"], row
            ))

    def get_user_by_keycloak_id(self, keycloak_id: str) -> Optional[Dict]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT id, username, email, full_name, password_hash, keycloak_id, "
                "auth_provider, is_active, created_at, updated_at, last_login "
                "FROM users WHERE keycloak_id = ?", [keycloak_id]
            ).fetchone()
            if not row:
                return None
            return dict(zip(
                ["id", "username", "email", "full_name", "password_hash", "keycloak_id",
                 "auth_provider", "is_active", "created_at", "updated_at", "last_login"], row
            ))

    def get_all_users(self) -> List[Dict]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT id, username, email, full_name, keycloak_id, "
                "auth_provider, is_active, created_at, last_login FROM users ORDER BY username"
            ).fetchall()
            cols = ["id", "username", "email", "full_name", "keycloak_id",
                    "auth_provider", "is_active", "created_at", "last_login"]
            return [dict(zip(cols, r)) for r in rows]

    def create_user(self, username: str, email: str = None, full_name: str = None,
                    password_hash: str = None, keycloak_id: str = None,
                    auth_provider: str = "local") -> str:
        with self.get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, email, full_name, password_hash, keycloak_id, auth_provider) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [username, email, full_name, password_hash, keycloak_id, auth_provider],
            )
            row = conn.execute("SELECT id FROM users WHERE username = ?", [username]).fetchone()
            return row[0]

    def update_user(self, user_id: str, **fields) -> bool:
        allowed = {"username", "email", "full_name", "password_hash", "is_active", "keycloak_id", "last_login"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return False
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [user_id]
        with self.get_connection() as conn:
            conn.execute(
                f"UPDATE users SET {set_clause}, updated_at = now() WHERE id = ?", values
            )
        return True

    def delete_user(self, user_id: str):
        with self.get_connection() as conn:
            conn.execute("DELETE FROM user_roles WHERE user_id = ?", [user_id])
            conn.execute("DELETE FROM users WHERE id = ?", [user_id])

    def get_user_roles(self, user_id: str) -> List[str]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id "
                "WHERE ur.user_id = ?", [user_id]
            ).fetchall()
            return [r[0] for r in rows]

    def get_all_roles(self) -> List[Dict]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT id, name, description FROM roles ORDER BY name").fetchall()
            return [dict(zip(["id", "name", "description"], r)) for r in rows]

    def set_user_roles(self, user_id: str, role_names: List[str]):
        with self.get_connection() as conn:
            conn.execute("DELETE FROM user_roles WHERE user_id = ?", [user_id])
            for rn in role_names:
                role_row = conn.execute("SELECT id FROM roles WHERE name = ?", [rn]).fetchone()
                if role_row:
                    conn.execute(
                        "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
                        [user_id, role_row[0]],
                    )

    def jit_provision_keycloak_user(self, keycloak_id: str, username: str,
                                     email: str = None, full_name: str = None) -> Dict:
        existing = self.get_user_by_keycloak_id(keycloak_id)
        if existing:
            self.update_user(existing["id"], email=email, full_name=full_name, last_login=datetime.now())
            return self.get_user_by_keycloak_id(keycloak_id)
        # Link existing local account by username (e.g. admin created locally, then logs in via SSO)
        by_name = self.get_user_by_username(username)
        if by_name:
            self.update_user(by_name["id"], keycloak_id=keycloak_id, email=email,
                            full_name=full_name, last_login=datetime.now())
            # Upgrade auth_provider to hybrid so the user can use both methods
            with self.get_connection() as conn:
                conn.execute("UPDATE users SET auth_provider = 'hybrid' WHERE id = ?", [by_name["id"]])
            return self.get_user_by_id(by_name["id"])
        uid = self.create_user(
            username=username, email=email, full_name=full_name,
            keycloak_id=keycloak_id, auth_provider="keycloak",
        )
        # Default new Keycloak users to ANALYST role
        role_row = None
        with self.get_connection() as conn:
            role_row = conn.execute("SELECT id FROM roles WHERE name = 'ANALYST'").fetchone()
        if role_row:
            self.set_user_roles(uid, ["ANALYST"])
        return self.get_user_by_id(uid)

    # --- ROLE PERMISSIONS ---

    def get_permissions_for_role(self, role_id: str) -> List[Dict]:
        """Get all permissions for a role."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT id, resource, can_read, can_write FROM role_permissions "
                "WHERE role_id = ? ORDER BY resource", [role_id]
            ).fetchall()
            return [dict(zip(["id", "resource", "can_read", "can_write"], r)) for r in rows]

    def get_permissions_matrix(self) -> List[Dict]:
        """Get full permissions matrix: all roles × resources."""
        with self.get_connection() as conn:
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
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT resource FROM role_permissions ORDER BY resource"
            ).fetchall()
            return [r[0] for r in rows]

    def set_permission(self, role_id: str, resource: str, can_read: bool, can_write: bool):
        """Set a single role×resource permission (upsert)."""
        with self.get_connection() as conn:
            existing = conn.execute(
                "SELECT id FROM role_permissions WHERE role_id = ? AND resource = ?",
                [role_id, resource],
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE role_permissions SET can_read = ?, can_write = ? WHERE id = ?",
                    [can_read, can_write, existing[0]],
                )
            else:
                conn.execute(
                    "INSERT INTO role_permissions (role_id, resource, can_read, can_write) "
                    "VALUES (?, ?, ?, ?)",
                    [role_id, resource, can_read, can_write],
                )

    def check_permission(self, role_names: List[str], resource: str) -> Dict[str, bool]:
        """Check permission for a set of roles on a resource.
        Returns {'can_read': bool, 'can_write': bool} where True if ANY role grants it."""
        if not role_names:
            return {"can_read": False, "can_write": False}
        with self.get_connection() as conn:
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

    def get_user_permissions(self, user_id: str) -> Dict[str, Dict[str, bool]]:
        """Get all permissions for a user based on their roles.
        Returns {resource: {can_read, can_write}}."""
        roles = self.get_user_roles(user_id)
        if not roles:
            return {}
        with self.get_connection() as conn:
            placeholders = ", ".join("?" for _ in roles)
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
        """Get set of (rule_id, space) tuples for all rules in the database.
        Used for lazy mapping: skip Elasticsearch mapping checks for known rules."""
        with self.get_connection() as conn:
            rows = conn.execute("SELECT rule_id, space FROM detection_rules").fetchall()
            return {(row[0], row[1]) for row in rows}
    
    def get_existing_rule_data(self) -> dict:
        """Get existing rule scores and raw_data keyed by (rule_id, space).
        Used to preserve mapping data for rules that skip mapping during lazy sync."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT rule_id, space, score, quality_score, meta_score, "
                "score_mapping, score_field_type, score_search_time, score_language, "
                "score_note, score_override, score_tactics, score_techniques, "
                "score_author, score_highlights, raw_data "
                "FROM detection_rules"
            ).fetchall()
            columns = [desc[0] for desc in conn.description]
            result = {}
            for row in rows:
                d = dict(zip(columns, row))
                key = (d['rule_id'], d['space'])
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
    
    def move_rule_space(self, rule_id: str, from_space: str, to_space: str):
        """Move a rule from one space to another in DuckDB (for instant UI update after promotion)."""
        with self.get_connection() as conn:
            # Delete any existing rule with same ID in target space (avoid PK conflict)
            conn.execute(
                "DELETE FROM detection_rules WHERE rule_id = ? AND space = ?",
                [rule_id, to_space]
            )
            # Move the rule
            conn.execute(
                "UPDATE detection_rules SET space = ? WHERE rule_id = ? AND space = ?",
                [to_space, rule_id, from_space]
            )
            conn.execute("CHECKPOINT")
        logger.info(f"Moved rule {rule_id} from '{from_space}' to '{to_space}' in DB")
    
    def get_rule_by_id(self, rule_id: str, space: str = "default") -> Optional[DetectionRule]:
        """Get a single rule by ID and space."""
        with self.get_connection() as conn:
            result = conn.execute(
                "SELECT * FROM detection_rules WHERE rule_id = ? AND space = ?",
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
    
    def get_rule_health_metrics(self) -> RuleHealthMetrics:
        """Calculate comprehensive rule health metrics."""
        with self.get_connection() as conn:
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
    
    def get_unique_spaces(self) -> List[str]:
        """Get list of unique Kibana spaces."""
        with self.get_connection() as conn:
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
    
    def get_promotion_metrics(self) -> Dict[str, Any]:
        """Get metrics specifically for staging rules ready for promotion."""
        with self.get_connection() as conn:
            # Get staging rules
            staging_df = conn.execute(
                "SELECT enabled, score, severity, name FROM detection_rules WHERE LOWER(space) = 'staging'"
            ).df()
            
            # Get production rules count
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
    
    def get_threat_actors(self) -> List[ThreatActor]:
        """Get all threat actors ordered by TTP count."""
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
    
    def get_threat_landscape_metrics(self) -> "ThreatLandscapeMetrics":
        """Calculate comprehensive threat landscape metrics."""
        from app.models.threats import ThreatLandscapeMetrics
        
        with self.get_connection() as conn:
            df = conn.execute(
                "SELECT ttp_count, ttps, origin, source FROM threat_actors"
            ).df()
            
            if df.empty:
                return ThreatLandscapeMetrics()
            
            # Get covered TTPs inline (avoid nested connection)
            covered_result = conn.execute("""
                SELECT DISTINCT unnest(mitre_ids) 
                FROM detection_rules 
                WHERE enabled = 1 AND LOWER(space) = LOWER('production')
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
    
    def get_dashboard_metrics(self) -> Tuple[RuleHealthMetrics, Dict[str, Any], "ThreatLandscapeMetrics"]:
        """
        Get all three metric sets for the dashboard in a single DB connection.
        Loads validation data once and reuses it across rule health + promotion.
        Much faster than calling the three methods individually.
        """
        from app.models.threats import ThreatLandscapeMetrics
        
        # Load validation data once
        validation_data = self._load_validation_data()
        now = datetime.now()
        
        with self.get_connection() as conn:
            # ── Rule Health Metrics ──
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
            
            # Covered TTPs (reuse same connection)
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
    
    def get_all_covered_ttps(self) -> Set[str]:
        """Get all TTPs covered by enabled detection rules."""
        with self.get_connection() as conn:
            result = conn.execute(
                "SELECT DISTINCT unnest(mitre_ids) FROM detection_rules WHERE enabled = 1"
            ).fetchall()
            return {row[0].upper() for row in result if row[0]}
    
    def get_ttp_rule_counts(self) -> Dict[str, int]:
        """Get count of enabled rules per MITRE technique ID."""
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
    
    def get_sigma_coverage_data(self) -> Tuple[Set[str], Dict[str, int]]:
        """Get covered TTPs and rule counts in a single DB connection (for sigma page)."""
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
    
    def get_rules_for_technique(self, technique_id: str, enabled_only: bool = True, search: str = None) -> List[DetectionRule]:
        """Get all detection rules that cover a specific MITRE technique.
        
        Args:
            technique_id: MITRE technique ID (e.g., T1059)
            enabled_only: If True, only return enabled rules (default). Matches heatmap coverage logic.
            search: Optional search filter to further restrict rules (matches name, author, rule_id, mitre_ids)
        """
        with self.get_connection() as conn:
            # Query rules where the technique ID is in the mitre_ids array
            ttp_upper = technique_id.upper()
            
            # Build query with search filter if provided
            # Use list_contains (DuckDB's array membership function)
            base_conditions = "(list_contains(mitre_ids, ?) OR list_contains(mitre_ids, ?))"
            params = [ttp_upper, technique_id]
            
            if enabled_only:
                base_conditions += " AND enabled = 1"
            
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
    
    def get_setting(self, key: str, default: str = None) -> str:
        """Get a single app setting by key."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT value FROM app_settings WHERE key = ?", [key]
            ).fetchone()
            return row[0] if row else default
    
    def get_all_settings(self) -> Dict[str, str]:
        """Get all app settings as a dict."""
        with self.get_connection() as conn:
            rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
            return {r[0]: r[1] for r in rows}
    
    def save_setting(self, key: str, value: str):
        """Save a single app setting (upsert)."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, now())
                ON CONFLICT (key) DO UPDATE SET
                    value = EXCLUDED.value,
                    updated_at = EXCLUDED.updated_at
            """, [key, value])
    
    def save_settings(self, settings_dict: Dict[str, str]):
        """Save multiple settings at once."""
        with self.get_connection() as conn:
            for key, value in settings_dict.items():
                conn.execute("""
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES (?, ?, now())
                    ON CONFLICT (key) DO UPDATE SET
                        value = EXCLUDED.value,
                        updated_at = EXCLUDED.updated_at
                """, [key, value])
    
    def get_all_rules_for_export(self) -> List[Dict[str, Any]]:
        """Get all detection rules as dicts for JSON log export."""
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT rule_id, name, severity, author, enabled, space,
                       score, quality_score, meta_score,
                       score_mapping, score_field_type, score_search_time, score_language,
                       score_note, score_override, score_tactics, score_techniques,
                       score_author, score_highlights, mitre_ids
                FROM detection_rules
                ORDER BY name
            """).fetchall()
            
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
        
        # Get unique spaces being synced - we'll delete all rules from these spaces first
        synced_spaces = df['space'].unique().tolist()
        logger.info(f"Syncing rules for spaces: {synced_spaces}")
        
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
            'rule_id', 'name', 'severity', 'author', 'enabled', 'space',
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
        
        # Check for duplicates within the incoming data (same rule_id + space)
        duplicates = df_final[df_final.duplicated(subset=['rule_id', 'space'], keep='first')]
        if not duplicates.empty:
            dup_names = duplicates['name'].tolist()
            logger.info(f"Skipping {len(dup_names)} duplicate rules (same rule_id + space): {dup_names[:5]}{'...' if len(dup_names) > 5 else ''}")
            df_final = df_final.drop_duplicates(subset=['rule_id', 'space'], keep='first')

        with self.get_connection() as conn:
            try:
                conn.execute("BEGIN TRANSACTION")
                
                # Delete existing rules from synced spaces to ensure live data
                # This ensures removed rules don't persist in the database
                for space in synced_spaces:
                    deleted = conn.execute(
                        "DELETE FROM detection_rules WHERE space = ?",
                        [space]
                    ).fetchone()
                    logger.debug(f"Cleared rules from space '{space}'")
                
                # Insert fresh rules
                conn.register('rules_source', df_final)
                conn.execute("""
                    INSERT INTO detection_rules 
                    SELECT * FROM rules_source
                """)
                
                conn.execute("COMMIT")
                
                count = len(df_final)
                logger.info(f"Synced {count} detection rules to database (replaced rules in spaces: {synced_spaces})")
                
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

    def delete_rules_for_spaces(self, spaces: List[str]) -> int:
        """
        Delete all rules belonging to the given spaces (subtractive sync).
        Used to remove ghost rules when a space returns 0 rules from Elastic.
        """
        if not spaces:
            return 0
        
        total_deleted = 0
        with self.get_connection() as conn:
            try:
                for space in spaces:
                    before = conn.execute(
                        "SELECT COUNT(*) FROM detection_rules WHERE space = ?", [space]
                    ).fetchone()[0]
                    if before > 0:
                        conn.execute("DELETE FROM detection_rules WHERE space = ?", [space])
                        logger.info(f"Subtractive sync: deleted {before} ghost rules from space '{space}'")
                        total_deleted += before
                conn.execute("CHECKPOINT")
            except Exception as e:
                logger.error(f"Failed to delete ghost rules: {e}")
        
        return total_deleted


    # ── External API Key management ──────────────────────────────────────

    def create_api_key(self, label: str) -> str:
        """Generate a new API key, store its SHA-256 hash, return the raw key."""
        import secrets, hashlib
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        with self.get_connection() as conn:
            conn.execute(
                "INSERT INTO api_keys (key_hash, label) VALUES (?, ?)",
                [key_hash, label],
            )
        logger.info(f"API key created: {label}")
        return raw_key

    def list_api_keys(self) -> List[Dict[str, Any]]:
        """Return all API key metadata (never the hash)."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT key_hash, label, created_at, last_used_at "
                "FROM api_keys ORDER BY created_at DESC"
            ).fetchall()
        return [
            {"key_hash": r[0], "label": r[1], "created_at": r[2], "last_used_at": r[3]}
            for r in rows
        ]

    def validate_api_key(self, raw_key: str) -> bool:
        """Return True if the key is valid; also touch last_used_at."""
        import hashlib
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT key_hash FROM api_keys WHERE key_hash = ?", [key_hash]
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE api_keys SET last_used_at = now() WHERE key_hash = ?",
                    [key_hash],
                )
                return True
        return False

    def delete_api_key(self, key_hash: str) -> bool:
        """Revoke an API key by its hash prefix or full hash."""
        with self.get_connection() as conn:
            deleted = conn.execute(
                "DELETE FROM api_keys WHERE key_hash = ? RETURNING key_hash",
                [key_hash],
            ).fetchone()
        return deleted is not None


# Singleton accessor
def get_database_service() -> DatabaseService:
    """Get the database service singleton."""
    return DatabaseService()
