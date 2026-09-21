"""
Tenant Connection Manager for TIDE multi-tenant architecture.

Manages physical database-per-tenant routing using Python contextvars.
When a tenant context is active, DatabaseService.get_connection() returns
a connection to the tenant's dedicated DuckDB file instead of the shared DB.

Shared data (siem_inventory, client_siem_map) is synced from the shared DB into each
tenant DB so that existing queries work without cross-DB ATTACH. ATT&CK / NIST / Sigma
reference data is attached read-only from reference.duckdb (see reference_db.py).
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
        full_path = os.path.join(data_dir, filename)
        if os.path.exists(full_path):
            return full_path
        # Cache can go stale if the file is removed/renamed out-of-band.
        with _cache_lock:
            _tenant_db_cache.pop(client_id, None)

    # Fallback: re-check shared catalog when cache miss occurs (e.g. fresh
    # worker, stale cache, or failed startup cache refresh).
    try:
        from app.config import get_settings

        settings = get_settings()
        shared_db_path = settings.db_path
        conn = duckdb.connect(shared_db_path, read_only=False)
        try:
            row = conn.execute(
                "SELECT db_filename, slug FROM clients WHERE id = ?",
                [client_id],
            ).fetchone()
        finally:
            conn.close()

        if not row:
            return None

        db_filename, slug = row
        candidates: List[str] = []
        if db_filename:
            candidates.append(db_filename)

        # Legacy/recovery patterns when db_filename was not persisted.
        short_id = (client_id or "")[:8]
        if slug:
            candidates.append(f"{slug}_{short_id}.duckdb")
        candidates.append(f"dc_{short_id}.duckdb")
        candidates.append(f"primary_{short_id}.duckdb")

        for candidate in candidates:
            full_path = os.path.join(data_dir, candidate)
            if not os.path.exists(full_path):
                continue
            with _cache_lock:
                _tenant_db_cache[client_id] = candidate
            # Heal catalog registration if it was missing.
            if not db_filename:
                try:
                    conn2 = duckdb.connect(shared_db_path, read_only=False)
                    try:
                        conn2.execute(
                            "UPDATE clients SET db_filename = ? WHERE id = ?",
                            [candidate, client_id],
                        )
                    finally:
                        conn2.close()
                except Exception as _exc:
                    logger.warning(
                        "Tenant DB resolve: failed to backfill clients.db_filename "
                        "for %s: %s",
                        client_id,
                        _exc,
                    )
            return full_path
    except Exception as exc:
        logger.warning(
            "Tenant DB resolve fallback failed for %s: %s",
            client_id,
            exc,
        )

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
    # 4.1.5 — ``threat_actors`` is intentionally NOT mirrored. MITRE actors
    # live exclusively in the shared DB (read by every tenant via
    # ``get_shared_connection``); per-tenant OpenCTI actors are written
    # directly into the tenant's own ``threat_actors`` table by the OpenCTI
    # sync phase. Mirroring here would either leak another tenant's
    # OpenCTI data or be wiped on the next sync.
    try:
        with get_database_service().get_shared_connection() as shared_conn:
            shared_conn.execute(f"ATTACH '{db_path}' AS {tenant_alias}")
            try:
                for table in (
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

    # Every new tenant starts with the default baselines.
    try:
        from app.inventory_engine import seed_default_playbooks
        with tenant_context_for(client_id):
            seed_default_playbooks()
    except Exception as e:
        logger.warning(f"Default baselines not seeded for {db_filename}: {e}")

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
    # PK is (rule_id, siem_id, space) since 4.1.12 (Migration 44 in shared
    # schema). The earlier (rule_id, siem_id) PK from 4.0.13 collided
    # whenever an operator exposed the same Elastic prebuilt rule in more
    # than one Kibana space inside a single SIEM (e.g. ``one`` and ``two``
    # for staging vs production routing). Bumping the PK to include
    # ``space`` lets those legitimately co-exist while preserving the
    # cross-SIEM uniqueness fix from 4.0.13.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS detection_rules (
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
            client_id VARCHAR,
            deprecated BOOLEAN DEFAULT false,
            source_rule_id VARCHAR,
            PRIMARY KEY (rule_id, siem_id, space)
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
            logical_rule_id VARCHAR,
            note VARCHAR DEFAULT '',
            source VARCHAR DEFAULT 'manual'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rule_migrations (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            source_rule_id VARCHAR NOT NULL,
            source_siem_id VARCHAR NOT NULL,
            source_space VARCHAR NOT NULL,
            target_rule_id VARCHAR NOT NULL,
            target_siem_id VARCHAR NOT NULL,
            target_space VARCHAR NOT NULL,
            master_rule_id VARCHAR NOT NULL,
            master_siem_id VARCHAR NOT NULL,
            master_space VARCHAR NOT NULL,
            source_retained BOOLEAN DEFAULT false,
            actor_user_id VARCHAR,
            actor_name VARCHAR,
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logical_rule_identities (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            canonical_rule_id VARCHAR NOT NULL,
            master_rule_id VARCHAR,
            master_siem_id VARCHAR,
            master_space VARCHAR,
            state VARCHAR DEFAULT 'deprecated',
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logical_rule_members (
            logical_rule_id VARCHAR NOT NULL,
            rule_id VARCHAR NOT NULL,
            siem_id VARCHAR NOT NULL,
            space VARCHAR NOT NULL,
            relation VARCHAR DEFAULT 'associated',
            created_at TIMESTAMP DEFAULT now(),
            PRIMARY KEY (logical_rule_id, rule_id, siem_id, space)
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
            rule_id VARCHAR,
            rule_name VARCHAR,
            last_checked_on TIMESTAMP,
            checked_by VARCHAR DEFAULT 'unknown'
        )
    """)

    # ── Synced tables (populated by sync_shared_data). ATT&CK / NIST / Sigma
    # reference data is not stored here; it is attached from reference.duckdb.
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
    Caller must have already: ATTACH '...' AS shared (READ_ONLY)

    4.1.5 — ``threat_actors`` is deliberately excluded. MITRE actors are
    read directly from the shared DB by ``get_threat_actors``; the tenant's
    own ``threat_actors`` table is reserved for that tenant's OpenCTI
    instance(s) and must not be overwritten by this generic mirror."""

    for table in ("siem_inventory", "client_siem_map"):
        try:
            conn.execute(f"DELETE FROM {table}")
            conn.execute(f"INSERT INTO {table} SELECT * FROM shared.{table}")
        except Exception as e:
            logger.warning(f"Sync {table} failed: {e}")


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
                        # 4.1.19: ``threat_actors`` is intentionally
                        # excluded. The tenant's own ``threat_actors`` table
                        # holds the per-tenant OpenCTI rows (and is created
                        # with a PRIMARY KEY on ``name`` so the OCTI upsert
                        # can use ``ON CONFLICT``). ``CREATE OR REPLACE
                        # TABLE … AS SELECT`` would drop the PK, clobber the
                        # OCTI rows with the shared MITRE-only contents, and
                        # break the next OCTI sync with a binder error.
                        # MITRE actors are served to every tenant from the
                        # shared DB by ``get_threat_actors``.
                        for table in (
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
                        shared_conn.execute(f"""
                            CREATE TABLE IF NOT EXISTS {tenant_alias}.rule_migrations (
                                id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                                source_rule_id VARCHAR NOT NULL,
                                source_siem_id VARCHAR NOT NULL,
                                source_space VARCHAR NOT NULL,
                                target_rule_id VARCHAR NOT NULL,
                                target_siem_id VARCHAR NOT NULL,
                                target_space VARCHAR NOT NULL,
                                master_rule_id VARCHAR NOT NULL,
                                master_siem_id VARCHAR NOT NULL,
                                master_space VARCHAR NOT NULL,
                                source_retained BOOLEAN DEFAULT false,
                                actor_user_id VARCHAR,
                                actor_name VARCHAR,
                                created_at TIMESTAMP DEFAULT now(),
                                updated_at TIMESTAMP DEFAULT now()
                            )
                        """)
                        shared_conn.execute(f"""
                            CREATE TABLE IF NOT EXISTS {tenant_alias}.logical_rule_identities (
                                id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                                canonical_rule_id VARCHAR NOT NULL,
                                master_rule_id VARCHAR,
                                master_siem_id VARCHAR,
                                master_space VARCHAR,
                                state VARCHAR DEFAULT 'deprecated',
                                created_at TIMESTAMP DEFAULT now(),
                                updated_at TIMESTAMP DEFAULT now()
                            )
                        """)
                        shared_conn.execute(f"""
                            CREATE TABLE IF NOT EXISTS {tenant_alias}.logical_rule_members (
                                logical_rule_id VARCHAR NOT NULL,
                                rule_id VARCHAR NOT NULL,
                                siem_id VARCHAR NOT NULL,
                                space VARCHAR NOT NULL,
                                relation VARCHAR DEFAULT 'associated',
                                created_at TIMESTAMP DEFAULT now(),
                                PRIMARY KEY (logical_rule_id, rule_id, siem_id, space)
                            )
                        """)
                        shared_conn.execute(
                            f"ALTER TABLE {tenant_alias}.step_detections "
                            "ADD COLUMN IF NOT EXISTS logical_rule_id VARCHAR"
                        )
                        synced += 1
                    finally:
                        shared_conn.execute(f"DETACH {tenant_alias}")
                except Exception as e:
                    logger.error(f"Sync shared data failed for tenant {cid}: {e}")
    except Exception as e:
        logger.error(f"Sync shared data failed: {e}")

    logger.info(f"Shared data synced to {synced}/{len(targets)} tenant DB(s)")


# ── Legacy validation import ────────────────────────────────────────

def import_legacy_validation_file(data_dir: str) -> dict:
    """Import ``<data_dir>/checkedRule.json`` into the tenant DBs, once.

    Validations used to live in one JSON file shared by every tenant. Each
    entry is now stored in the ``checkedRule`` table of every tenant that
    owns a rule with that name. Entries no tenant owns a rule for (yet) go to
    the default client, so a validation is never lost and returns with its
    rule. The file is then renamed to ``checkedRule.json.imported`` so the
    import never runs twice.

    Returns ``{client_id: rows_imported}`` (empty when there is no file).
    """
    import json
    from datetime import datetime
    from app.services.database import get_database_service

    path = os.path.join(data_dir, "checkedRule.json")
    if not os.path.exists(path):
        return {}

    legacy: dict = {}
    for candidate in (path, path + ".bak"):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                legacy = (json.load(fh) or {}).get("rules") or {}
        except (OSError, ValueError):
            continue
        if legacy:
            break

    def _row(name, rec):
        try:
            checked_on = datetime.strptime(
                str(rec.get("last_checked_on", ""))[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            checked_on = None
        return (name, checked_on, rec.get("checked_by") or "unknown")

    def _insert(cid, wanted):
        """Add the entries in *wanted* this tenant does not already have."""
        with tenant_context_for(cid), db.get_connection() as conn:
            have = {r[0] for r in conn.execute("SELECT rule_name FROM checkedRule").fetchall()}
            rows = [_row(n, legacy[n]) for n in wanted if n not in have]
            if rows:
                conn.executemany(
                    "INSERT INTO checkedRule (rule_name, last_checked_on, checked_by) "
                    "VALUES (?, ?, ?)", rows)
            db._ensure_checked_rule(conn)
            db._bind_checked_rule_ids(conn)
            return len(rows)

    with _cache_lock:
        client_ids = list(_tenant_db_cache)
    db = get_database_service()
    summary: dict = {}
    owned_anywhere: set = set()
    try:
        for cid in client_ids:
            with tenant_context_for(cid), db.get_connection() as conn:
                owned = {r[0] for r in conn.execute(
                    "SELECT DISTINCT name FROM detection_rules").fetchall()}
            owned_anywhere |= owned
            summary[cid] = _insert(cid, [n for n in legacy if n in owned])

        leftover = [n for n in legacy if n not in owned_anywhere]
        if leftover and client_ids:
            with db.get_shared_connection() as shared:
                row = shared.execute(
                    "SELECT id FROM clients WHERE is_default ORDER BY created_at LIMIT 1").fetchone()
            default_cid = row[0] if row and row[0] in client_ids else client_ids[0]
            summary[default_cid] = summary.get(default_cid, 0) + _insert(default_cid, leftover)
    except Exception as exc:
        logger.error(f"Validation import failed: {exc}")
        return summary  # leave the file in place so the next start retries

    os.replace(path, path + ".imported")
    if os.path.exists(path + ".bak"):
        os.remove(path + ".bak")
    logger.info(
        f"Imported {sum(summary.values())} of {len(legacy)} legacy rule validations into "
        f"tenant DBs; original kept as checkedRule.json.imported"
    )
    return summary
