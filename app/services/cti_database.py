"""
Per-tenant CTI DuckDB storage for TIDE Native CTI Engine.

Design — `Plan Phase 1 §1`:
    * Each tenant owns a dedicated ``cti_<slug>_<short_id>.duckdb`` file
      under :pydata:`app.config.Settings.data_dir`. Mirrors the slug/short_id
      convention used by
      :func:`app.services.tenant_manager.create_tenant_db` so the two files
      sit side by side for the same tenant and are obvious to an operator.
    * Connection management routes through the **existing**
      :class:`app.services.connection_pool.ConnectionPool` (keyed by absolute
      file path). That pool already enforces "one writer at a time per file"
      via a bounded per-slot ``Queue``, so manual sync jobs (OpenCTI GraphQL
      pull, diode ingestor) cannot livelock against user read requests —
      they queue. We do NOT open ``duckdb.connect`` ourselves anywhere in
      this module.
    * Independent schema ladder (:data:`CTI_SCHEMA_VERSION`). The CTI file
      never shares the catalogue with ``tide.duckdb`` or any tenant rule DB,
      so it never participates in the ``SCHEMA_VERSION`` ladder under
      :pymod:`app.services.database` (which `AGENTS.md §8.4` lists as a
      hard-stop fragile zone).
    * Module is import-safe: importing it does not create files or open
      connections. Files are created lazily on the first
      :func:`open_cti_db` call for a given client.

Phase 2 (diode) will reuse this module unchanged — only the ingest writers
in :pymod:`app.services.cti_ingest` and the forwarder/ingestor file watchers
will be new.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from contextlib import contextmanager
from typing import Iterator, Optional

import duckdb

from app.config import get_settings
from app.services.connection_pool import get_pool

logger = logging.getLogger(__name__)


# ── Schema versioning ────────────────────────────────────────────────
# Independent ladder. Bump when a migration is added below; never reuse a
# version number. Migrations must be additive and idempotent.
#
# v1 → initial schema (indicators, intrusion_sets, indicator_actor,
#                      provenance, egress_targets).
# v2 → adds cti_actors, cti_reports, cti_relationships; adds kind /
#      folder_path / diode_endpoint columns on cti_egress_targets;
#      back-fills cti_actors and cti_relationships from the legacy
#      cti_intrusion_sets / cti_indicator_actor tables (which are kept
#      around for one release while the ingest writer is rewired).
# v3 → drops the legacy ``cti_intrusion_sets`` / ``cti_indicator_actor``
#      tables now that all reads/writes route through v2 tables.
# v4 → adds ``stix_id`` + ``stix_modified`` to ``cti_indicators`` and
#      ``cti_actors``, and ``stix_modified`` to ``cti_reports``. Powers
#      strict STIX 2.1 version control in ``cti_ingest`` (only commit
#      when incoming ``modified`` is greater than the stored value;
#      drop ``revoked: true`` indicators from the active latest state).
# v5 → hard-wipe legacy ``source_id LIKE 'opencti:%'`` rows left behind
#      by the retired OpenCTI GraphQL ingest path (see _migrate_to_v5).
# v6 → scrubs every legacy ``pattern_type='_review'`` indicator row.
#      The 5.0.x ingest writer now extracts the leading SCO type from
#      complex STIX patterns instead of stamping the ``_review``
#      sentinel, so these orphan rows would otherwise persist forever
#      and keep polluting the indicator type-filter dropdown. The next
#      sync re-pulls them with their real ``pattern_type``.
CTI_SCHEMA_VERSION: int = 6


# ── Path resolver ────────────────────────────────────────────────────

# Single shared lock guarding tenant-file creation. Cheap: we only hold
# it long enough to confirm the file exists / run the bootstrap DDL.
_CREATE_LOCK = threading.Lock()

# Per-process cache of CTI DB files whose schema bootstrap has run.
# Keyed by absolute path so each file is checked exactly once per worker.
_BOOTSTRAPPED: set[str] = set()


def _sanitise_slug(slug: str) -> str:
    """Normalise a client slug for use in a filename.

    Mirrors the lax rules
    :func:`app.services.tenant_manager.create_tenant_db` already accepts
    (it does no sanitisation itself; the slug comes from the clients UI).
    We are stricter here because we own a brand new file naming scheme:
    allow ``[a-z0-9_-]`` only, lowercase, fall back to ``client`` on empty.
    """
    cleaned = re.sub(r"[^a-z0-9_-]+", "_", (slug or "").lower()).strip("_-")
    return cleaned or "client"


def get_cti_db_path(client_id: str, slug: Optional[str] = None) -> str:
    """Return the absolute path of ``cti_<slug>_<short_id>.duckdb`` for *client_id*.

    The file is not created here; call :func:`open_cti_db` to create-on-first-use.

    Parameters
    ----------
    client_id:
        Full client UUID. The first 8 characters are used as ``short_id``.
    slug:
        Optional human-readable slug (e.g. ``"primary"``, ``"marvel"``).
        When omitted, falls back to looking up
        ``clients.slug`` via the shared DB. If even that fails we use
        ``"client"`` so the file is still locatable.
    """
    if not client_id:
        raise ValueError("client_id is required to resolve a CTI DB path")
    settings = get_settings()
    short_id = client_id[:8]
    resolved_slug = slug
    if not resolved_slug:
        resolved_slug = _lookup_slug_from_shared(client_id) or "client"
    filename = f"cti_{_sanitise_slug(resolved_slug)}_{short_id}.duckdb"
    return os.path.join(settings.data_dir, filename)


def _lookup_slug_from_shared(client_id: str) -> Optional[str]:
    """Best-effort lookup of a tenant's slug.

    Strategy (cheap → expensive):
      1. Reuse the in-process ``tenant_manager`` cache. Its filenames are
         already ``{slug}_{short_id}.duckdb`` so we can recover the slug
         without touching the shared DB at all. This is the hot path in
         the running app and the only path that works inside an
         out-of-process ``docker exec`` diagnostic where the uvicorn
         worker already holds the shared-DB writer lock.
      2. Fall back to a pool-routed read of ``clients.slug``.
      3. Return ``None`` if both fail — caller substitutes ``"client"``
         so the CTI file is still locatable.
    """
    try:
        from app.services.tenant_manager import resolve_tenant_db_path

        settings = get_settings()
        tenant_path = resolve_tenant_db_path(client_id, settings.data_dir)
        if tenant_path:
            base = os.path.basename(tenant_path)
            if base.endswith(".duckdb"):
                base = base[: -len(".duckdb")]
            short_id = client_id[:8]
            suffix = f"_{short_id}"
            if base.endswith(suffix):
                candidate = base[: -len(suffix)]
                if candidate:
                    return candidate
    except Exception as exc:  # pragma: no cover - cache lookup must never raise
        logger.debug("cti_database: tenant cache slug lookup failed: %s", exc)

    settings = get_settings()
    shared = os.path.join(settings.data_dir, "tide.duckdb")
    try:
        with get_pool().acquire(shared) as conn:
            row = conn.execute(
                "SELECT slug FROM clients WHERE id = ?", [client_id]
            ).fetchone()
            return row[0] if row and row[0] else None
    except Exception as exc:
        logger.debug(
            "cti_database: shared-DB slug lookup failed for client_id=%s: %s",
            client_id, exc,
        )
        return None


# ── Connection context manager ───────────────────────────────────────

@contextmanager
def open_cti_db(
    client_id: str,
    slug: Optional[str] = None,
) -> Iterator[duckdb.DuckDBPyConnection]:
    """Yield a pooled DuckDB connection to the tenant's CTI file.

    Creates the file (and runs the schema bootstrap) on first use. All
    subsequent acquisitions hit the connection pool's per-file slot, so:

      * Concurrent readers share the cached connections (up to
        :data:`app.services.connection_pool.MAX_PER_TENANT`).
      * A single writer at any moment — second writer blocks on the
        slot's ``Queue`` until the first releases. DuckDB itself only
        permits one writer per file, so this matches the engine.
      * Exceptions inside the ``with`` body close the connection rather
        than recycling it (poisoned-connection protection from the pool).

    Usage::

        with open_cti_db(client_id) as conn:
            conn.execute("INSERT INTO cti_indicators ...")
    """
    db_path = get_cti_db_path(client_id, slug)
    _ensure_initialised(db_path)
    with get_pool().acquire(db_path) as conn:
        yield conn


def _ensure_initialised(db_path: str) -> None:
    """Create the CTI file (if missing) and run the schema bootstrap once
    per process per file. Cheap fast-path when already bootstrapped."""
    if db_path in _BOOTSTRAPPED:
        return
    with _CREATE_LOCK:
        if db_path in _BOOTSTRAPPED:
            return
        new_file = not os.path.exists(db_path)
        if new_file:
            logger.info("cti_database: creating new CTI DB at %s", db_path)
        # Route through the pool so the bootstrap DDL runs under the same
        # single-writer guarantee that user requests use. The pool will
        # open the file (creating it on disk if missing) on first acquire.
        with get_pool().acquire(db_path) as conn:
            _apply_schema(conn)
        _BOOTSTRAPPED.add(db_path)


# ── Schema bootstrap ─────────────────────────────────────────────────

# Every DDL statement here must be idempotent (``IF NOT EXISTS``) because
# the bootstrap runs once per process per file but multiple processes (or
# a restart after partial creation) could land here on a half-built file.
_BOOTSTRAP_DDL: tuple[str, ...] = (
    # Version metadata.
    """
    CREATE TABLE IF NOT EXISTS cti_schema_version (
        version     INTEGER PRIMARY KEY,
        applied_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,

    # Core indicator state. ``id`` is the canonical STIX indicator id
    # *after* dedup (oldest valid_from wins). For multi-value patterns
    # ``needs_review`` flags rows for the operator surface.
    """
    CREATE TABLE IF NOT EXISTS cti_indicators (
        id                VARCHAR PRIMARY KEY,
        pattern_type      VARCHAR NOT NULL,
        observable_value  VARCHAR NOT NULL,
        pattern           VARCHAR,
        valid_from        TIMESTAMP,
        valid_until       TIMESTAMP,
        tlp               VARCHAR,
        confidence        INTEGER,
        source_id         VARCHAR,
        first_seen        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        kill_chain        JSON,
        mitre_techniques  VARCHAR[],
        raw_stix          JSON,
        needs_review      BOOLEAN DEFAULT FALSE
    )
    """,
    # Unique on the dedup key so the upsert in cti_ingest can use
    # ``ON CONFLICT (pattern_type, observable_value)``.
    """
    CREATE UNIQUE INDEX IF NOT EXISTS cti_indicators_dedup
        ON cti_indicators(pattern_type, observable_value)
    """,
    """
    CREATE INDEX IF NOT EXISTS cti_indicators_source
        ON cti_indicators(source_id)
    """,

    # Provenance ledger: every ingest event that produced or reinforced
    # an indicator row. Lets the dedup logic prove which bundle delivered
    # the canonical record and which were duplicates folded in.
    """
    CREATE TABLE IF NOT EXISTS cti_provenance (
        indicator_id   VARCHAR NOT NULL,
        source_id      VARCHAR,
        bundle_id      VARCHAR,
        ingested_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        was_canonical  BOOLEAN
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS cti_provenance_indicator
        ON cti_provenance(indicator_id)
    """,

    # Egress targets — Phase 1 §4, extended in v2 with the ``kind``
    # discriminator that selects an egress driver (Elasticsearch _bulk,
    # STIX bundle dropped to a folder, or diode push). Owned per tenant
    # rather than per platform so a tenant's Elastic key never leaves
    # their database. ``siem_id`` references the shared
    # ``siem_inventory.id`` in tide.duckdb; the value is stored as a
    # plain VARCHAR (no FK across files) and validated at the API layer.
    """
    CREATE TABLE IF NOT EXISTS cti_egress_targets (
        id              VARCHAR PRIMARY KEY,
        label           VARCHAR NOT NULL,
        kind            VARCHAR NOT NULL DEFAULT 'elastic',
        siem_id         VARCHAR,
        index_pattern   VARCHAR NOT NULL,
        latest_index    VARCHAR NOT NULL,
        api_key_enc     VARCHAR,
        folder_path     VARCHAR,
        diode_endpoint  VARCHAR,
        tlp_ceiling     VARCHAR DEFAULT 'amber',
        is_active       BOOLEAN DEFAULT TRUE,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,

    # ── v2 tables ────────────────────────────────────────────────────
    # Generalised actor table. Supersedes ``cti_intrusion_sets``;
    # carries a ``stix_type`` discriminator so threat-actors and
    # intrusion-sets coexist without table sprawl.
    """
    CREATE TABLE IF NOT EXISTS cti_actors (
        stix_type    VARCHAR NOT NULL,
        name         VARCHAR NOT NULL,
        aliases      VARCHAR[],
        description  VARCHAR,
        origin       VARCHAR,
        first_seen   TIMESTAMP,
        last_seen    TIMESTAMP,
        source_id    VARCHAR,
        raw_stix     JSON,
        PRIMARY KEY (stix_type, name)
    )
    """,

    # CTI reports (STIX report SDOs). The detail page renders the
    # description plus relationship panels (named actors, referenced
    # indicators) driven by ``cti_relationships``.
    """
    CREATE TABLE IF NOT EXISTS cti_reports (
        id           VARCHAR PRIMARY KEY,
        name         VARCHAR,
        description  VARCHAR,
        published    TIMESTAMP,
        labels       VARCHAR[],
        source_id    VARCHAR,
        raw_stix     JSON
    )
    """,

    # General STIX edge table. Supersedes ``cti_indicator_actor`` and
    # powers every cross-link in the /cti/... UI. ``src_id`` / ``dst_id``
    # are the natural keys of the endpoint rows (indicator id, actor
    # name, report id) — not STIX ids — so joins stay cheap.
    """
    CREATE TABLE IF NOT EXISTS cti_relationships (
        id          VARCHAR PRIMARY KEY,
        src_type    VARCHAR NOT NULL,
        src_id      VARCHAR NOT NULL,
        rel_type    VARCHAR NOT NULL,
        dst_type    VARCHAR NOT NULL,
        dst_id      VARCHAR NOT NULL,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_id   VARCHAR,
        raw_stix    JSON
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS cti_relationships_edge
        ON cti_relationships(src_type, src_id, rel_type, dst_type, dst_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS cti_relationships_src
        ON cti_relationships(src_type, src_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS cti_relationships_dst
        ON cti_relationships(dst_type, dst_id)
    """,
)


# ── Idempotent ALTERs (run after every bootstrap) ────────────────────
# These cover existing v1 files that were created before a v2 column
# was added. DuckDB's ``ADD COLUMN IF NOT EXISTS`` makes this safe to
# run on a fresh v2 file too.
_ALTER_DDL: tuple[str, ...] = (
    "ALTER TABLE cti_egress_targets ADD COLUMN IF NOT EXISTS "
    "kind VARCHAR NOT NULL DEFAULT 'elastic'",
    "ALTER TABLE cti_egress_targets ADD COLUMN IF NOT EXISTS "
    "folder_path VARCHAR",
    "ALTER TABLE cti_egress_targets ADD COLUMN IF NOT EXISTS "
    "diode_endpoint VARCHAR",
    # v4 — STIX 2.1 version-control columns. ``stix_id`` records the
    # incoming object's STIX id even when the row's PK is a derived
    # natural key (indicator row id, actor name); ``stix_modified``
    # stores the canonical ``modified`` timestamp used by the
    # ingest-time freshness gate.
    "ALTER TABLE cti_indicators ADD COLUMN IF NOT EXISTS "
    "stix_id VARCHAR",
    "ALTER TABLE cti_indicators ADD COLUMN IF NOT EXISTS "
    "stix_modified TIMESTAMP",
    "ALTER TABLE cti_actors ADD COLUMN IF NOT EXISTS "
    "stix_id VARCHAR",
    "ALTER TABLE cti_actors ADD COLUMN IF NOT EXISTS "
    "stix_modified TIMESTAMP",
    "ALTER TABLE cti_reports ADD COLUMN IF NOT EXISTS "
    "stix_modified TIMESTAMP",
    # 5.0.0 — cache the upstream PDF bytes (Falcon Intel report-files,
    # OpenCTI x_opencti_files) on the report row so the viewer never
    # has to hit the source again per request. The first attachment
    # fetch populates these; subsequent requests stream straight from
    # DuckDB.
    "ALTER TABLE cti_reports ADD COLUMN IF NOT EXISTS pdf_blob BLOB",
    "ALTER TABLE cti_reports ADD COLUMN IF NOT EXISTS pdf_mime VARCHAR",
    "ALTER TABLE cti_reports ADD COLUMN IF NOT EXISTS pdf_filename VARCHAR",
    "ALTER TABLE cti_reports ADD COLUMN IF NOT EXISTS pdf_fetched_at TIMESTAMP",
)


def _apply_schema(conn: duckdb.DuckDBPyConnection) -> None:
    """Run the bootstrap DDL, apply additive ALTERs, run any pending
    one-shot migrations, then record the applied version.

    Order matters: CREATE TABLE IF NOT EXISTS first so ALTER targets
    exist; ALTERs next so the migration block can rely on the new
    columns; migrations last so they can copy from legacy → v2 tables.
    """
    for stmt in _BOOTSTRAP_DDL:
        conn.execute(stmt)
    for stmt in _ALTER_DDL:
        try:
            conn.execute(stmt)
        except Exception as exc:  # pragma: no cover - older DuckDB fallbacks
            logger.debug("cti_database: ALTER skipped (%s): %s", stmt, exc)

    current = conn.execute(
        "SELECT MAX(version) FROM cti_schema_version"
    ).fetchone()[0]
    if current is None or current < 2:
        _migrate_to_v2(conn)
    if current is None or current < 3:
        _migrate_to_v3(conn)
    if current is None or current < 5:
        _migrate_to_v5(conn)
    if current is None or current < 6:
        _migrate_to_v6(conn)

    conn.execute(
        "INSERT INTO cti_schema_version (version) "
        "SELECT ? WHERE NOT EXISTS ("
        "  SELECT 1 FROM cti_schema_version WHERE version = ?"
        ")",
        [CTI_SCHEMA_VERSION, CTI_SCHEMA_VERSION],
    )

    # Flush bootstrap DDL + migrations into the main .duckdb file. Without
    # this, the new CREATE TABLEs sit in the .wal until an organic
    # checkpoint; if the process is killed (uvicorn reload, docker stop
    # -t 0, OOM) before that happens, the next startup's WAL replay can
    # hit an internal DuckDB binder bug (observed on cti_*.duckdb.wal in
    # 4.1.19, stack: WriteAheadLogDeserializer::ReplayAlter ->
    # BindDefaultValues -> BindAndQualifyFunction with "no default
    # database set") and crash the process, taking the CTI pages down.
    #
    # Plain ``CHECKPOINT`` is best-effort and silently no-ops if any
    # other connection holds the cached DB instance; ``FORCE CHECKPOINT``
    # aborts conflicting txns and guarantees the WAL is truncated.
    try:
        conn.execute("FORCE CHECKPOINT")
    except Exception as exc:  # pragma: no cover
        logger.warning(
            "cti_database: FORCE CHECKPOINT after bootstrap failed: %s", exc,
        )


def _migrate_to_v2(conn: duckdb.DuckDBPyConnection) -> None:
    """v1 → v2: back-fill cti_actors + cti_relationships from the legacy
    cti_intrusion_sets / cti_indicator_actor tables.

    Both INSERTs are guarded by ``WHERE NOT EXISTS`` so re-running this
    migration (e.g. against a partially-migrated file) is a no-op. The
    legacy tables themselves are dropped later by :func:`_migrate_to_v3`.
    A fresh v3+ file never had these tables to begin with, so we skip
    the back-fill entirely if they're absent.
    """
    legacy = {
        r[0] for r in conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'main' "
            "  AND table_name IN ('cti_intrusion_sets', "
            "                     'cti_indicator_actor')"
        ).fetchall()
    }
    if "cti_intrusion_sets" in legacy:
        try:
            conn.execute(
                "INSERT INTO cti_actors ("
                "  stix_type, name, aliases, description, origin, "
                "  first_seen, last_seen, source_id, raw_stix"
                ") "
                "SELECT 'intrusion-set', i.name, i.aliases, i.description, "
                "       i.origin, i.first_seen, i.last_seen, i.source_id, "
                "       i.raw_stix "
                "FROM cti_intrusion_sets i "
                "WHERE NOT EXISTS ("
                "  SELECT 1 FROM cti_actors a "
                "  WHERE a.stix_type = 'intrusion-set' AND a.name = i.name"
                ")"
            )
        except Exception as exc:
            logger.warning(
                "cti_database: v2 migration (actors) skipped: %s", exc,
            )

    if "cti_indicator_actor" in legacy:
        try:
            conn.execute(
                "INSERT INTO cti_relationships ("
                "  id, src_type, src_id, rel_type, dst_type, dst_id, source_id"
                ") "
                "SELECT md5(a.indicator_id || '|indicates|' || a.actor_name), "
                "       'indicator', a.indicator_id, 'indicates', "
                "       'intrusion-set', a.actor_name, NULL "
                "FROM cti_indicator_actor a "
                "WHERE NOT EXISTS ("
                "  SELECT 1 FROM cti_relationships r "
                "  WHERE r.src_type = 'indicator' "
                "    AND r.src_id = a.indicator_id "
                "    AND r.rel_type = 'indicates' "
                "    AND r.dst_type = 'intrusion-set' "
                "    AND r.dst_id = a.actor_name"
                ")"
            )
        except Exception as exc:
            logger.warning(
                "cti_database: v2 migration (relationships) skipped: %s",
                exc,
            )


def _migrate_to_v3(conn: duckdb.DuckDBPyConnection) -> None:
    """v2 → v3: drop the legacy ``cti_intrusion_sets`` and
    ``cti_indicator_actor`` tables now that ingest and egress both
    route through ``cti_actors`` / ``cti_relationships``. Safe to run
    on fresh files (the tables won't exist).
    """
    for table in ("cti_indicator_actor", "cti_intrusion_sets"):
        try:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        except Exception as exc:
            logger.warning(
                "cti_database: v3 drop of %s skipped: %s", table, exc,
            )


def _migrate_to_v5(conn: duckdb.DuckDBPyConnection) -> None:
    """v4 → v5: hard-wipe every row sourced from the retired OpenCTI
    GraphQL ingest path.

    The 5.0.0 release dropped the shared ``opencti_inventory`` /
    ``client_opencti_map`` tables, but per-tenant CTI rows the
    GraphQL fetcher had already written stayed behind with
    ``source_id LIKE 'opencti:%'``. That left the CTI surfaces
    (indicators, actors, reports, Threat Landscape) showing
    "OpenCTI (legacy)" rows from a dead pipeline and offering a
    Source-dropdown option for a connector that no longer exists.

    This migration scrubs them. Operators that still want a baseline
    re-pull the data through the TAXII 2.1 connector. Counts are logged
    so the operator can see what was removed.
    """
    targets = [
        "cti_indicators",
        "cti_actors",
        "cti_reports",
        "cti_relationships",
        "cti_objects",
    ]
    for table in targets:
        try:
            removed = conn.execute(
                f"DELETE FROM {table} WHERE source_id LIKE 'opencti:%'"
            ).fetchone()
            # DuckDB DELETE returns the affected row count on .rowcount
            # only via the cursor — fall back to a follow-up COUNT(*).
            try:
                affected = conn.execute("SELECT changes()").fetchone()[0]
            except Exception:
                affected = "?"
            logger.info(
                "cti_database: v5 purged legacy opencti:* rows from %s "
                "(removed=%s)", table, affected,
            )
        except Exception as exc:
            # Older per-tenant DBs may not carry every table — skip
            # cleanly so the migration always advances.
            logger.debug(
                "cti_database: v5 skipped %s (%s)", table, exc,
            )


def _migrate_to_v6(conn: duckdb.DuckDBPyConnection) -> None:
    """v5 → v6: scrub legacy ``pattern_type='_review'`` indicator rows.

    The 5.0.x ingest writer no longer stamps the ``_review`` sentinel
    when a STIX pattern isn't a simple equality — it now extracts the
    leading SCO type and stores the raw pattern as ``observable_value``
    with ``needs_review=TRUE``. Existing review rows would otherwise
    keep showing up in the indicator type-filter dropdown indefinitely.

    Deleting (rather than rewriting in place) avoids dedup-key
    collisions: a re-parsed row could collide with a row already
    written under its true SCO type. The next sync repopulates with
    the correct shape; provenance is left intact so the audit trail
    survives.
    """
    try:
        conn.execute("DELETE FROM cti_indicators WHERE pattern_type = '_review'")
        try:
            removed = conn.execute("SELECT changes()").fetchone()[0]
        except Exception:
            removed = "?"
        logger.info(
            "cti_database: v6 purged legacy _review indicator rows "
            "(removed=%s)", removed,
        )
    except Exception as exc:
        logger.debug("cti_database: v6 skipped (%s)", exc)


# ── Diagnostic helpers ───────────────────────────────────────────────

def cti_db_stats(client_id: str, slug: Optional[str] = None) -> dict:
    """Return a dict describing the tenant's CTI DB state.

    Safe to call before the file exists (returns ``exists=False`` with
    zero counts and does NOT create the file). Used by
    :pymod:`app.scripts.diag_sync` section 12.
    """
    db_path = get_cti_db_path(client_id, slug)
    if not os.path.exists(db_path):
        return {
            "path": db_path,
            "exists": False,
            "schema_version": None,
            "indicators": 0,
            "actors": 0,
            "reports": 0,
            "relationships": 0,
            "egress_targets": 0,
        }

    def _count(conn, table: str) -> int:
        try:
            return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except Exception:
            return 0

    with open_cti_db(client_id, slug) as conn:
        try:
            version = conn.execute(
                "SELECT MAX(version) FROM cti_schema_version"
            ).fetchone()[0]
        except Exception:
            version = None
        indicators = _count(conn, "cti_indicators")
        actors = _count(conn, "cti_actors")
        reports = _count(conn, "cti_reports")
        relationships = _count(conn, "cti_relationships")
        egress_targets = _count(conn, "cti_egress_targets")
    return {
        "path": db_path,
        "exists": True,
        "schema_version": version,
        "indicators": indicators,
        "actors": actors,
        "reports": reports,
        "relationships": relationships,
        "egress_targets": egress_targets,
    }


# ── Egress target CRUD ───────────────────────────────────────────────
#
# ``cti_egress_targets`` lives inside each tenant's CTI DB (see schema
# v1 above). The siem_id column is a soft reference to the shared
# ``siem_inventory`` row in tide.duckdb — we deliberately do NOT enforce
# a FK across files because the two databases are separate engines.
# Validation that the siem_id exists is the API-layer's job (step 8).
#
# All helpers below take ``client_id`` so the caller never needs to
# touch a DuckDB handle directly; routing through the per-tenant pool
# preserves the single-writer-per-file invariant.

import uuid  # noqa: E402  (kept at module bottom; only used by CRUD)


_EGRESS_TARGET_COLS = [
    "id", "label", "kind", "siem_id", "index_pattern", "latest_index",
    "api_key_enc", "folder_path", "diode_endpoint",
    "tlp_ceiling", "is_active", "created_at",
]

_EGRESS_SELECT_SQL = (
    "SELECT id, label, kind, siem_id, index_pattern, latest_index, "
    "api_key_enc, folder_path, diode_endpoint, "
    "tlp_ceiling, is_active, created_at "
    "FROM cti_egress_targets"
)

_VALID_EGRESS_KINDS = {"elastic", "stix_folder", "diode"}


def _coerce_egress_kind(value: Optional[str]) -> str:
    v = (value or "").strip().lower()
    return v if v in _VALID_EGRESS_KINDS else "elastic"


def _row_to_egress_target(row) -> dict:
    return dict(zip(_EGRESS_TARGET_COLS, row))


def list_egress_targets(client_id: str, *,
                        slug: Optional[str] = None,
                        active_only: bool = False) -> list[dict]:
    """Return all egress targets for ``client_id`` (newest first)."""
    sql = _EGRESS_SELECT_SQL
    params: list = []
    if active_only:
        sql += " WHERE COALESCE(is_active, TRUE) = TRUE"
    sql += " ORDER BY created_at DESC, label"
    with open_cti_db(client_id, slug) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_egress_target(r) for r in rows]


def get_egress_target(client_id: str, target_id: str, *,
                      slug: Optional[str] = None) -> Optional[dict]:
    """Look up a single egress target by id."""
    with open_cti_db(client_id, slug) as conn:
        row = conn.execute(
            _EGRESS_SELECT_SQL + " WHERE id = ?",
            [target_id],
        ).fetchone()
    return _row_to_egress_target(row) if row else None


_VALID_TLP_CEILINGS = {"clear", "white", "green", "amber", "red"}


def _coerce_tlp_ceiling(value: Optional[str]) -> str:
    v = (value or "").strip().lower()
    return v if v in _VALID_TLP_CEILINGS else "amber"


def create_egress_target(client_id: str, *,
                         label: str,
                         kind: str = "elastic",
                         siem_id: Optional[str] = None,
                         index_pattern: str = "logs-ti_tide.indicator-*",
                         latest_index: str = "logs-ti_tide_latest",
                         api_key_enc: Optional[str] = None,
                         folder_path: Optional[str] = None,
                         diode_endpoint: Optional[str] = None,
                         tlp_ceiling: str = "amber",
                         is_active: bool = True,
                         slug: Optional[str] = None) -> dict:
    """Create an egress target row and return it.

    ``kind`` selects the egress driver:
      * ``elastic`` — push to ``siem_id``'s Elasticsearch via _bulk
        (latest index + daily history). Optional ``api_key_enc`` lets
        operators override with a least-privilege CTI-write-only key.
      * ``stix_folder`` — drop STIX bundles into ``folder_path``.
      * ``diode`` — push to ``diode_endpoint``.
    """
    if not (label or "").strip():
        raise ValueError("label is required")
    target_id = str(uuid.uuid4())
    ceiling = _coerce_tlp_ceiling(tlp_ceiling)
    kind_v = _coerce_egress_kind(kind)
    with open_cti_db(client_id, slug) as conn:
        conn.execute(
            "INSERT INTO cti_egress_targets "
            "(id, label, kind, siem_id, index_pattern, latest_index, "
            " api_key_enc, folder_path, diode_endpoint, "
            " tlp_ceiling, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [target_id, label.strip(), kind_v, siem_id or None,
             index_pattern or "logs-ti_tide.indicator-*",
             latest_index or "logs-ti_tide_latest",
             api_key_enc or None,
             (folder_path or None),
             (diode_endpoint or None),
             ceiling, bool(is_active)],
        )
    created = get_egress_target(client_id, target_id, slug=slug)
    assert created is not None  # we just wrote it under the same pool
    return created


_EGRESS_TARGET_UPDATABLE = {
    "label", "kind", "siem_id", "index_pattern", "latest_index",
    "api_key_enc", "folder_path", "diode_endpoint",
    "tlp_ceiling", "is_active",
}


def update_egress_target(client_id: str, target_id: str, *,
                         slug: Optional[str] = None,
                         **fields) -> Optional[dict]:
    """Patch an egress target. Unknown keys are ignored.

    Returns the updated row, or ``None`` if the target does not exist.
    """
    if not fields:
        return get_egress_target(client_id, target_id, slug=slug)
    sets: list[str] = []
    params: list = []
    for k, v in fields.items():
        if k not in _EGRESS_TARGET_UPDATABLE:
            continue
        if k == "tlp_ceiling":
            v = _coerce_tlp_ceiling(v)
        if k == "kind":
            v = _coerce_egress_kind(v)
        if k == "is_active":
            v = bool(v)
        sets.append(f"{k} = ?")
        params.append(v)
    if not sets:
        return get_egress_target(client_id, target_id, slug=slug)
    params.append(target_id)
    with open_cti_db(client_id, slug) as conn:
        conn.execute(
            f"UPDATE cti_egress_targets SET {', '.join(sets)} WHERE id = ?",
            params,
        )
    return get_egress_target(client_id, target_id, slug=slug)


def delete_egress_target(client_id: str, target_id: str, *,
                         slug: Optional[str] = None) -> bool:
    """Delete an egress target. Returns True if a row was removed."""
    with open_cti_db(client_id, slug) as conn:
        before = conn.execute(
            "SELECT COUNT(*) FROM cti_egress_targets WHERE id = ?",
            [target_id],
        ).fetchone()[0]
        if not before:
            return False
        conn.execute(
            "DELETE FROM cti_egress_targets WHERE id = ?", [target_id],
        )
    return True
