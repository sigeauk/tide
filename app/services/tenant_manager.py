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

    new_file = not os.path.exists(db_path)
    if new_file:
        logger.info(f"Creating tenant DB: {db_filename}")
        # Step 1 \u2014 create the tenant DB file with its full schema. This is
        # a standalone connection to a brand-new file; no conflict possible.
        conn = duckdb.connect(db_path)
        try:
            _create_tenant_schema(conn)
        finally:
            conn.close()
    else:
        # Recover a partially-provisioned tenant: file exists but the
        # ``clients.db_filename`` registration / reference-data sync may
        # have failed previously. Fall through and re-run the registration
        # step \u2014 it is idempotent (DELETE + INSERT, UPDATE).
        logger.info(
            f"Tenant DB exists, ensuring registration: {db_filename}"
        )

    # Step 2 \u2014 sync reference data + register db_filename via the shared
    # connection pool. We attach the tenant DB FROM the shared connection
    # (rather than the other way round) because in a single Python process
    # DuckDB will not let the same physical file be attached twice; the
    # shared DB is already open as ``main`` (and auto-aliased to its file
    # stem) inside the pool, so attempting ``ATTACH '/app/data/tide.duckdb'
    # AS shared`` from a fresh tenant connection raises ``Unique file
    # handle conflict``. Reversing the direction sidesteps that entirely.
    from app.services.database import get_database_service
    tenant_alias = f"t_{client_id.replace('-', '_')}"
    # See sync._distribute_rules_to_tenants for the full rationale: if the
    # per-path pool already holds an open handle on this tenant DB, DuckDB
    # will reject the cross-connection ATTACH below. Evict so the ATTACH
    # has the only handle in the process; the pool reopens on demand.
    try:
        from app.services.connection_pool import get_pool
        get_pool().evict(db_path)
    except Exception:  # pragma: no cover
        pass
    try:
        with get_database_service().get_shared_connection() as shared_conn:
            shared_conn.execute(f"ATTACH '{db_path}' AS {tenant_alias}")
            try:
                for table in (
                    "mitre_techniques", "threat_actors",
                    "siem_inventory", "client_siem_map",
                ):
                    try:
                        # CREATE OR REPLACE avoids column-count drift between
                        # the shared schema and the tenant schema (these are
                        # reference tables, owned by the shared DB, mirrored
                        # into the tenant for ATTACH-free reads).
                        shared_conn.execute(
                            f"CREATE OR REPLACE TABLE {tenant_alias}.{table} AS "
                            f"SELECT * FROM {table}"
                        )
                    except Exception as e:
                        logger.warning(
                            f"Sync {table} into {db_filename} failed: {e}"
                        )
                shared_conn.execute(
                    "UPDATE clients SET db_filename = ? WHERE id = ?",
                    [db_filename, client_id],
                )
            finally:
                shared_conn.execute(f"DETACH {tenant_alias}")
    except Exception:
        # Fallback for very early bootstrap before the pool exists.
        shared_conn = duckdb.connect(shared_db_path)
        try:
            shared_conn.execute(f"ATTACH '{db_path}' AS {tenant_alias}")
            try:
                for table in (
                    "mitre_techniques", "threat_actors",
                    "siem_inventory", "client_siem_map",
                ):
                    try:
                        shared_conn.execute(
                            f"CREATE OR REPLACE TABLE {tenant_alias}.{table} AS "
                            f"SELECT * FROM {table}"
                        )
                    except Exception as e:
                        logger.warning(
                            f"Sync {table} into {db_filename} failed: {e}"
                        )
                shared_conn.execute(
                    "UPDATE clients SET db_filename = ? WHERE id = ?",
                    [db_filename, client_id],
                )
            finally:
                shared_conn.execute(f"DETACH {tenant_alias}")
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

    from app.services.database import get_database_service
    synced = 0
    try:
        with get_database_service().get_shared_connection() as shared_conn:
            for cid, db_filename in targets.items():
                db_path = os.path.join(data_dir, db_filename)
                if not os.path.exists(db_path):
                    logger.warning(f"Tenant DB missing during sync: {db_path}")
                    continue
                tenant_alias = f"t_{cid.replace('-', '_')}"
                try:
                    from app.services.connection_pool import get_pool
                    get_pool().evict(db_path)
                except Exception:  # pragma: no cover
                    pass
                try:
                    shared_conn.execute(f"ATTACH '{db_path}' AS {tenant_alias}")
                    try:
                        for table in (
                            "mitre_techniques", "threat_actors",
                            "siem_inventory", "client_siem_map",
                        ):
                            try:
                                shared_conn.execute(
                                    f"CREATE OR REPLACE TABLE "
                                    f"{tenant_alias}.{table} AS "
                                    f"SELECT * FROM {table}"
                                )
                            except Exception as e:
                                logger.warning(
                                    f"Sync {table} into {db_filename} failed: {e}"
                                )
                        synced += 1
                    finally:
                        shared_conn.execute(f"DETACH {tenant_alias}")
                except Exception as e:
                    logger.error(f"Sync shared data failed for tenant {cid}: {e}")
    except Exception as e:
        logger.error(f"Sync shared data failed: {e}")

    logger.info(f"Shared data synced to {synced}/{len(targets)} tenant DB(s)")


# ── Legacy data backfill (one-shot recovery) ────────────────────────
#
# Pre-4.1.2, ``is_multi_db_mode()`` returned False because no tenant DB
# files existed (Migration 29 added the column but nothing called
# ``create_tenant_db``). Every write — systems, hosts, software,
# baselines, playbook steps, blind spots, snapshots, etc. — therefore
# landed in the *shared* ``tide.duckdb``. After 4.1.2 routes those
# reads to the freshly-provisioned (and empty) tenant DB files, the
# rows are still on disk but invisible to the UI.
#
# This pass copies any per-client rows from the shared DB into each
# tenant's DB. It is **idempotent and conservative**: a table is only
# backfilled when the tenant copy is empty AND the shared copy has at
# least one row for that ``client_id`` — so re-running it on a tenant
# that already added new data after backfill is a no-op.

# Tables that carry a ``client_id`` column on the shared schema and
# need to be partitioned per tenant. Order matters for FK-style
# references that rely on a parent row existing first.
_PARENT_TABLES = (
    "systems",
    "playbooks",
    "threat_actors",
    "classifications",
    "system_baselines",
    "system_baseline_snapshots",
    "software_inventory",
    "vuln_detections",
    "applied_detections",
    "cve_technique_overrides",
    "blind_spots",
    "app_settings",
)

# Child tables that have no ``client_id`` column — backfilled by
# joining through their parent. Each entry: (table, parent_table,
# join_predicate). The predicate references ``main.<parent>`` (shared)
# and uses the child's own column to filter.
_CHILD_TABLES = (
    # hosts.system_id -> systems.id (filter via shared.systems.client_id)
    ("hosts", "systems", "system_id"),
    # playbook_steps.playbook_id -> playbooks.id
    ("playbook_steps", "playbooks", "playbook_id"),
)

# Step-derived tables (two hops: step -> playbook -> client).
_STEP_CHILD_TABLES = ("step_techniques", "step_detections")


def _common_columns(conn, table: str, tenant_alias: str) -> list:
    """Return columns present in BOTH the shared ``main.<table>`` and the
    attached ``<tenant_alias>.<table>``, ordered as they appear in the
    tenant table. Used by the backfill so we never rely on positional
    ``SELECT *`` semantics — column order drifted between the original
    shared schema and the tenant schema in `_create_tenant_schema`."""
    try:
        shared_cols = {
            r[0] for r in conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_catalog = current_database() "
                "AND table_schema = 'main' AND table_name = ?",
                [table],
            ).fetchall()
        }
        tenant_rows = conn.execute(
            "SELECT column_name, ordinal_position "
            "FROM information_schema.columns "
            "WHERE table_catalog = ? AND table_name = ? "
            "ORDER BY ordinal_position",
            [tenant_alias, table],
        ).fetchall()
        return [r[0] for r in tenant_rows if r[0] in shared_cols]
    except Exception as e:
        logger.warning(f"_common_columns({table}) failed: {e}")
        return []


def backfill_legacy_tenant_data(data_dir: str) -> dict:
    """One-shot copy of per-client rows from shared DB into tenant DBs.

    Safe to run on every startup: a table on a tenant is only
    backfilled when the tenant currently has zero rows in it (so user
    edits made post-backfill are never duplicated or overwritten).

    Returns a summary dict ``{client_id: {table: rows_copied}}``.
    """
    summary: dict = {}
    with _cache_lock:
        targets = dict(_tenant_db_cache)
    if not targets:
        return summary

    from app.services.database import get_database_service
    from app.services.connection_pool import get_pool

    try:
        with get_database_service().get_shared_connection() as shared_conn:
            for cid, db_filename in targets.items():
                db_path = os.path.join(data_dir, db_filename)
                if not os.path.exists(db_path):
                    continue
                tenant_alias = f"t_{cid.replace('-', '_')}"
                client_summary: dict = {}
                try:
                    get_pool().evict(db_path)
                except Exception:  # pragma: no cover
                    pass
                try:
                    shared_conn.execute(f"ATTACH '{db_path}' AS {tenant_alias}")
                except Exception as e:
                    logger.error(f"Backfill ATTACH failed for {cid}: {e}")
                    continue
                try:
                    # Parent tables — direct WHERE client_id = ?.
                    for table in _PARENT_TABLES:
                        try:
                            tenant_count = shared_conn.execute(
                                f"SELECT COUNT(*) FROM {tenant_alias}.{table}"
                            ).fetchone()[0]
                            if tenant_count > 0:
                                continue
                            shared_count = shared_conn.execute(
                                f"SELECT COUNT(*) FROM {table} WHERE client_id = ?",
                                [cid],
                            ).fetchone()[0]
                            if shared_count == 0:
                                continue
                            cols = _common_columns(
                                shared_conn, table, tenant_alias
                            )
                            if not cols:
                                continue
                            col_list = ", ".join(cols)
                            shared_conn.execute(
                                f"INSERT INTO {tenant_alias}.{table} ({col_list}) "
                                f"SELECT {col_list} FROM {table} WHERE client_id = ?",
                                [cid],
                            )
                            client_summary[table] = shared_count
                            logger.info(
                                f"Backfilled {shared_count} row(s) of {table} "
                                f"into tenant {cid[:8]}"
                            )
                        except Exception as e:
                            logger.warning(
                                f"Backfill {table} for {cid}: {e}"
                            )

                    # Child tables — join through parent's client_id.
                    for child, parent, fk in _CHILD_TABLES:
                        try:
                            tenant_count = shared_conn.execute(
                                f"SELECT COUNT(*) FROM {tenant_alias}.{child}"
                            ).fetchone()[0]
                            if tenant_count > 0:
                                continue
                            shared_count = shared_conn.execute(
                                f"SELECT COUNT(*) FROM {child} c "
                                f"WHERE EXISTS (SELECT 1 FROM {parent} p "
                                f"WHERE p.id = c.{fk} AND p.client_id = ?)",
                                [cid],
                            ).fetchone()[0]
                            if shared_count == 0:
                                continue
                            cols = _common_columns(
                                shared_conn, child, tenant_alias
                            )
                            if not cols:
                                continue
                            col_list = ", ".join(f"c.{c}" for c in cols)
                            insert_cols = ", ".join(cols)
                            shared_conn.execute(
                                f"INSERT INTO {tenant_alias}.{child} ({insert_cols}) "
                                f"SELECT {col_list} FROM {child} c "
                                f"WHERE EXISTS (SELECT 1 FROM {parent} p "
                                f"WHERE p.id = c.{fk} AND p.client_id = ?)",
                                [cid],
                            )
                            client_summary[child] = shared_count
                            logger.info(
                                f"Backfilled {shared_count} row(s) of {child} "
                                f"into tenant {cid[:8]}"
                            )
                        except Exception as e:
                            logger.warning(
                                f"Backfill {child} for {cid}: {e}"
                            )

                    # Step-derived (two-hop: step -> playbook -> client).
                    for child in _STEP_CHILD_TABLES:
                        try:
                            tenant_count = shared_conn.execute(
                                f"SELECT COUNT(*) FROM {tenant_alias}.{child}"
                            ).fetchone()[0]
                            if tenant_count > 0:
                                continue
                            shared_count = shared_conn.execute(
                                f"SELECT COUNT(*) FROM {child} c "
                                f"WHERE EXISTS ("
                                f"  SELECT 1 FROM playbook_steps s "
                                f"  JOIN playbooks p ON p.id = s.playbook_id "
                                f"  WHERE s.id = c.step_id AND p.client_id = ?"
                                f")",
                                [cid],
                            ).fetchone()[0]
                            if shared_count == 0:
                                continue
                            cols = _common_columns(
                                shared_conn, child, tenant_alias
                            )
                            if not cols:
                                continue
                            col_list = ", ".join(f"c.{c}" for c in cols)
                            insert_cols = ", ".join(cols)
                            shared_conn.execute(
                                f"INSERT INTO {tenant_alias}.{child} ({insert_cols}) "
                                f"SELECT {col_list} FROM {child} c "
                                f"WHERE EXISTS ("
                                f"  SELECT 1 FROM playbook_steps s "
                                f"  JOIN playbooks p ON p.id = s.playbook_id "
                                f"  WHERE s.id = c.step_id AND p.client_id = ?"
                                f")",
                                [cid],
                            )
                            client_summary[child] = shared_count
                            logger.info(
                                f"Backfilled {shared_count} row(s) of {child} "
                                f"into tenant {cid[:8]}"
                            )
                        except Exception as e:
                            logger.warning(
                                f"Backfill {child} for {cid}: {e}"
                            )
                finally:
                    try:
                        shared_conn.execute(f"DETACH {tenant_alias}")
                    except Exception:
                        pass
                if client_summary:
                    summary[cid] = client_summary
    except Exception as e:
        logger.error(f"Legacy backfill failed: {e}")

    if summary:
        total_clients = len(summary)
        total_rows = sum(sum(v.values()) for v in summary.values())
        logger.info(
            f"Legacy data backfilled: {total_rows} row(s) restored "
            f"to {total_clients} tenant DB(s)"
        )
    return summary
