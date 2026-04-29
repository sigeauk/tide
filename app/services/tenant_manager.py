"""
Tenant Connection Manager for TIDE multi-tenant architecture.

Manages physical database-per-tenant routing using Python contextvars.
When a tenant context is active, DatabaseService.get_connection() returns
a connection to the tenant's dedicated DuckDB file instead of the shared DB.

Shared reference data (mitre_techniques, threat_actors, siem_inventory,
client_siem_map) is synced from the shared DB into each tenant DB so that
existing queries work without cross-DB ATTACH.
"""

import contextvars
import duckdb
import logging
import os
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Context variable for tenant routing ──────────────────────────────
# When set, DatabaseService.get_connection() connects to this path
# instead of the shared DB.  Set by deps.get_active_client().
_tenant_db_path: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "tenant_db_path", default=None
)


def set_tenant_context(db_path: str):
    """Set the tenant DB path for the current async/thread context."""
    _tenant_db_path.set(db_path)


def clear_tenant_context():
    """Clear the tenant DB path for the current context."""
    _tenant_db_path.set(None)


def get_tenant_db_path() -> Optional[str]:
    """Get the current tenant DB path, or None if not in tenant context."""
    return _tenant_db_path.get(None)


# ── Tenant DB cache ─────────────────────────────────────────────────
# Maps client_id → db_filename (e.g. "dc_8bab9263.duckdb")
_tenant_db_cache: Dict[str, str] = {}
_cache_lock = Lock()


def resolve_tenant_db_path(client_id: str, data_dir: str) -> Optional[str]:
    """Resolve the physical DB file path for a given client_id.
    Returns None if the client has no dedicated tenant DB yet."""
    with _cache_lock:
        filename = _tenant_db_cache.get(client_id)
    if filename:
        return os.path.join(data_dir, filename)
    return None


def refresh_tenant_cache(data_dir: str, shared_db_path: str):
    """Reload the client_id → db_filename mapping from the shared database."""
    try:
        # 4.1.0 P3 — must NOT pass read_only=True. The connection pool keeps
        # a writable handle on shared_db_path alive between requests, and
        # DuckDB refuses to open the same file with a different read_only
        # config ("Can't open a connection to same database file with a
        # different configuration than existing connections"). Writable is
        # safe here: we only run SELECT.
        conn = duckdb.connect(shared_db_path, read_only=False)
        try:
            # Check if db_filename column exists
            cols = conn.execute("DESCRIBE clients").fetchall()
            col_names = {c[0] for c in cols}
            if "db_filename" not in col_names:
                logger.info("Tenant DB cache: db_filename column not yet present — legacy mode")
                return

            rows = conn.execute(
                "SELECT id, db_filename FROM clients WHERE db_filename IS NOT NULL"
            ).fetchall()
        finally:
            conn.close()

        with _cache_lock:
            _tenant_db_cache.clear()
            for client_id, db_filename in rows:
                full_path = os.path.join(data_dir, db_filename)
                if os.path.exists(full_path):
                    _tenant_db_cache[client_id] = db_filename
                else:
                    logger.warning(
                        f"Tenant DB file missing for client {client_id}: {full_path}"
                    )

        logger.info(f"Tenant DB cache refreshed: {len(_tenant_db_cache)} tenant(s)")
    except Exception as e:
        logger.error(f"Failed to refresh tenant cache: {e}")


def is_multi_db_mode() -> bool:
    """Return True if any tenant DBs are registered."""
    with _cache_lock:
        return len(_tenant_db_cache) > 0


def tenant_context_for(client_id: str):
    """Context manager that temporarily sets the tenant DB context for
    *client_id*, then restores the previous context on exit.

    Usage::

        with tenant_context_for(some_client_id):
            # get_connection() now routes to that client's DB
            rows = engine.list_systems(client_id=some_client_id)
    """
    from contextlib import contextmanager
    from app.config import get_settings

    @contextmanager
    def _ctx():
        settings = get_settings()
        new_path = resolve_tenant_db_path(client_id, settings.data_dir)
        old_path = _tenant_db_path.get(None)
        if new_path:
            _tenant_db_path.set(new_path)
        try:
            yield
        finally:
            if old_path:
                _tenant_db_path.set(old_path)
            else:
                _tenant_db_path.set(None)

    return _ctx()


# ── Tenant DB creation ──────────────────────────────────────────────

def create_tenant_db(
    client_id: str,
    slug: str,
    data_dir: str,
    shared_db_path: str,
) -> str:
    """Create a new physical tenant database file.
    Returns the db_filename (relative to data_dir)."""
    short_id = client_id[:8]
    db_filename = f"{slug}_{short_id}.duckdb"
    db_path = os.path.join(data_dir, db_filename)

    if os.path.exists(db_path):
        logger.warning(f"Tenant DB already exists: {db_path}")
        return db_filename

    logger.info(f"Creating tenant DB: {db_filename}")
    conn = duckdb.connect(db_path)
    try:
        _create_tenant_schema(conn)
        # Sync shared reference data
        conn.execute(f"ATTACH '{shared_db_path}' AS shared (READ_ONLY)")
        _sync_reference_tables(conn)
        conn.execute("DETACH shared")
    finally:
        conn.close()

    # Register in shared DB
    shared_conn = duckdb.connect(shared_db_path)
    try:
        shared_conn.execute(
            "UPDATE clients SET db_filename = ? WHERE id = ?",
            [db_filename, client_id],
        )
    finally:
        shared_conn.close()

    # Update cache
    with _cache_lock:
        _tenant_db_cache[client_id] = db_filename

    logger.info(f"Created tenant DB: {db_filename} for client {client_id}")
    return db_filename


# ── Tenant schema definition ────────────────────────────────────────

def _create_tenant_schema(conn):
    """Create all tables in a new tenant database.
    Mirrors the shared DB schema but scoped to a single tenant.
    client_id columns are retained for backward compatibility."""

    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER,
            applied_at TIMESTAMP DEFAULT now()
        )
    """)
    conn.execute("INSERT INTO schema_version (version) VALUES (1)")

    # ── Asset inventory ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS systems (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            name VARCHAR NOT NULL,
            hostname_pattern VARCHAR,
            description VARCHAR,
            classification VARCHAR,
            client_id VARCHAR,
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        )
    """)
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
            client_id VARCHAR,
            created_at TIMESTAMP DEFAULT now()
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS software_inventory (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            host_id VARCHAR,
            system_id VARCHAR NOT NULL,
            name VARCHAR NOT NULL,
            version VARCHAR,
            vendor VARCHAR,
            cpe VARCHAR,
            source VARCHAR DEFAULT 'manual',
            client_id VARCHAR,
            created_at TIMESTAMP DEFAULT now()
        )
    """)

    # ── Detection rules ──
    # PK is (rule_id, siem_id) since 4.0.13 (Migration 37 in shared schema):
    # the same Elastic prebuilt rule can exist in multiple SIEMs and the old
    # (rule_id, space) PK collided. ``space`` is retained as a data column
    # because the Kibana preview/Test Rule URL still needs it.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS detection_rules (
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
            client_id VARCHAR,
            PRIMARY KEY (rule_id, siem_id)
        )
    """)

    # ── Baselines / Playbooks ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS playbooks (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            name VARCHAR NOT NULL,
            description VARCHAR DEFAULT '',
            client_id VARCHAR,
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS playbook_steps (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            playbook_id VARCHAR NOT NULL,
            step_number INTEGER NOT NULL,
            title VARCHAR NOT NULL,
            technique_id VARCHAR DEFAULT '',
            required_rule VARCHAR DEFAULT '',
            description VARCHAR DEFAULT '',
            tactic VARCHAR DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS step_techniques (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            step_id VARCHAR NOT NULL,
            technique_id VARCHAR NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS step_detections (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            step_id VARCHAR NOT NULL,
            rule_ref VARCHAR DEFAULT '',
            note VARCHAR DEFAULT '',
            source VARCHAR DEFAULT 'manual'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS system_baselines (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            system_id VARCHAR NOT NULL,
            playbook_id VARCHAR NOT NULL,
            client_id VARCHAR,
            applied_at TIMESTAMP DEFAULT now()
        )
    """)
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
            count_grey INTEGER DEFAULT 0,
            client_id VARCHAR
        )
    """)

    # ── Vulnerability tracking ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vuln_detections (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            cve_id VARCHAR NOT NULL,
            rule_ref VARCHAR,
            note TEXT,
            source VARCHAR DEFAULT 'manual',
            client_id VARCHAR,
            created_at TIMESTAMP DEFAULT now()
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS applied_detections (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            detection_id VARCHAR NOT NULL,
            system_id VARCHAR,
            host_id VARCHAR,
            client_id VARCHAR,
            applied_at TIMESTAMP DEFAULT now()
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_technique_overrides (
            cve_id VARCHAR NOT NULL,
            technique_id VARCHAR NOT NULL,
            client_id VARCHAR,
            PRIMARY KEY (cve_id, technique_id)
        )
    """)

    # ── Classifications ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS classifications (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            name VARCHAR NOT NULL UNIQUE,
            color VARCHAR NOT NULL DEFAULT '#6b7280',
            client_id VARCHAR
        )
    """)
    for name, color in [
        ("Official", "#22c55e"),
        ("Confidential", "#f59e0b"),
        ("Secret", "#ef4444"),
        ("Top Secret", "#dc2626"),
    ]:
        conn.execute(
            "INSERT INTO classifications (name, color) VALUES (?, ?) ON CONFLICT DO NOTHING",
            [name, color],
        )

    # ── Blind spots ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blind_spots (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            entity_type VARCHAR NOT NULL,
            entity_id VARCHAR NOT NULL,
            system_id VARCHAR,
            host_id VARCHAR,
            reason VARCHAR NOT NULL,
            created_by VARCHAR DEFAULT '',
            override_type VARCHAR DEFAULT 'gap',
            client_id VARCHAR,
            created_at TIMESTAMP DEFAULT now()
        )
    """)

    # ── App settings (key-only PK in tenant DB) ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key VARCHAR NOT NULL,
            value VARCHAR,
            client_id VARCHAR NOT NULL,
            updated_at TIMESTAMP DEFAULT now(),
            PRIMARY KEY (key, client_id)
        )
    """)

    # ── Validation tracking ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS checkedRule (
            rule_name VARCHAR,
            last_checked_on TIMESTAMP,
            checked_by VARCHAR DEFAULT 'unknown'
        )
    """)

    # ── Synced reference tables (populated by sync_shared_data) ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_techniques (
            id VARCHAR PRIMARY KEY,
            name VARCHAR,
            tactic VARCHAR,
            url VARCHAR
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_actors (
            name VARCHAR PRIMARY KEY,
            description VARCHAR,
            ttps VARCHAR[],
            ttp_count INTEGER,
            aliases VARCHAR,
            origin VARCHAR,
            last_updated TIMESTAMP,
            source VARCHAR[],
            client_id VARCHAR
        )
    """)
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
            elasticsearch_url VARCHAR,
            kibana_url VARCHAR,
            production_space VARCHAR,
            staging_space VARCHAR,
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS client_siem_map (
            client_id VARCHAR NOT NULL,
            siem_id VARCHAR NOT NULL,
            environment_role VARCHAR NOT NULL DEFAULT 'production',
            space VARCHAR,
            assigned_at TIMESTAMP DEFAULT now(),
            PRIMARY KEY (client_id, siem_id, environment_role)
        )
    """)

    # ── Coverage Quest persistence (4.1.0 P6) ──
    # New tenant DBs get the table up front; pre-existing tenant DBs
    # have it lazily created on first use by app/services/quest.py.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS quests (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            user_id VARCHAR NOT NULL,
            threat_actor_id VARCHAR,
            system_id VARCHAR,
            baseline_id VARCHAR,
            current_technique_id VARCHAR,
            completed_technique_ids VARCHAR[],
            status VARCHAR DEFAULT 'active',
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        )
    """)

    logger.info("Tenant schema created successfully")


# ── Shared data sync ────────────────────────────────────────────────

def _sync_reference_tables(conn):
    """Sync reference tables from an ATTACHed 'shared' DB into the tenant DB.
    Caller must have already: ATTACH '...' AS shared (READ_ONLY)"""

    for table in ("mitre_techniques", "threat_actors", "siem_inventory", "client_siem_map"):
        try:
            conn.execute(f"DELETE FROM {table}")
            conn.execute(f"INSERT INTO {table} SELECT * FROM shared.{table}")
        except Exception as e:
            logger.warning(f"Sync {table} failed: {e}")

    count = conn.execute("SELECT COUNT(*) FROM mitre_techniques").fetchone()[0]
    logger.debug(f"Synced reference data: {count} MITRE techniques")


def sync_shared_data(
    data_dir: str,
    shared_db_path: str,
    client_id: Optional[str] = None,
):
    """Sync reference tables from the shared DB to tenant DB(s).

    If client_id is provided, sync only that tenant.
    Otherwise sync all registered tenants.
    Called after: startup, MITRE sync, SIEM inventory changes.
    """
    with _cache_lock:
        if client_id and client_id in _tenant_db_cache:
            targets = {client_id: _tenant_db_cache[client_id]}
        else:
            targets = dict(_tenant_db_cache)

    if not targets:
        return

    synced = 0
    for cid, db_filename in targets.items():
        db_path = os.path.join(data_dir, db_filename)
        if not os.path.exists(db_path):
            logger.warning(f"Tenant DB missing during sync: {db_path}")
            continue
        try:
            conn = duckdb.connect(db_path)
            try:
                conn.execute(f"ATTACH '{shared_db_path}' AS shared (READ_ONLY)")
                _sync_reference_tables(conn)
                conn.execute("DETACH shared")
                synced += 1
            finally:
                conn.close()
        except Exception as e:
            logger.error(f"Sync shared data failed for tenant {cid}: {e}")

    logger.info(f"Shared data synced to {synced}/{len(targets)} tenant DB(s)")
