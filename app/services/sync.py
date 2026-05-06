"""
Sync service for TIDE - handles synchronization with Elastic and MITRE.
"""

import duckdb
import logging
import os
import sys

logger = logging.getLogger(__name__)


# Canonical column list for the tenant ``detection_rules`` table. Order
# matches the SELECT in ``_distribute_rules_to_tenants``. Anything in this
# list that's missing from a given tenant DB will be added by
# ``_ensure_tenant_detection_rules_schema`` below as a nullable column.
_TENANT_DETECTION_RULES_COLUMNS: tuple = (
    ("rule_id",            "VARCHAR"),
    ("siem_id",            "VARCHAR"),
    ("name",               "VARCHAR"),
    ("severity",           "VARCHAR"),
    ("author",             "VARCHAR"),
    ("enabled",            "INTEGER"),
    ("space",              "VARCHAR"),
    ("score",              "INTEGER"),
    ("quality_score",      "INTEGER"),
    ("meta_score",         "INTEGER"),
    ("score_mapping",      "INTEGER"),
    ("score_field_type",   "INTEGER"),
    ("score_search_time",  "INTEGER"),
    ("score_language",     "INTEGER"),
    ("score_note",         "INTEGER"),
    ("score_override",     "INTEGER"),
    ("score_tactics",      "INTEGER"),
    ("score_techniques",   "INTEGER"),
    ("score_author",       "INTEGER"),
    ("score_highlights",   "INTEGER"),
    ("last_updated",       "TIMESTAMP"),
    ("mitre_ids",          "VARCHAR[]"),
    ("raw_data",           "JSON"),
    ("client_id",          "VARCHAR"),
)


def _ensure_tenant_detection_rules_schema(
    conn,
    table_ref: str = "detection_rules",
    label: str = "tenant",
) -> None:
    """Ensure ``table_ref`` (``detection_rules`` on the tenant DB, or an
    ``<alias>.detection_rules`` reference when called via an ATTACHed
    shared connection) has every column listed in
    ``_TENANT_DETECTION_RULES_COLUMNS``.

    Two distinct legacy states this repairs:

    * **Pre-4.0.13 tenant DB** \u2014 missing ``siem_id`` entirely. We can't
      ``ADD COLUMN siem_id NOT NULL`` non-destructively, and the table is
      pure cache (no operator state), so when ``siem_id`` is absent we
      drop and recreate the whole table from the canonical column list.
      ``_distribute_rules_to_tenants`` repopulates it on the same call.

    * **Post-4.0.13 tenant DB created before ``client_id`` was added**
      (the production failure mode behind "table detection_rules has 23
      columns but 24 values were supplied"). The table already has
      ``siem_id`` and the operator state we'd lose by recreating it is
      still purely cached rule rows, but additive ALTERs are cheaper and
      preserve any in-flight rows so we prefer ``ADD COLUMN IF NOT EXISTS``
      for every missing column other than ``siem_id``.

    Idempotent: a tenant DB already at the canonical schema is a no-op
    (one DESCRIBE, no DDL).
    """
    try:
        cols = conn.execute(f"DESCRIBE {table_ref}").fetchall()
        existing = {c[0] for c in cols}
    except Exception:
        # Table doesn't exist on this tenant \u2014 create it from scratch.
        existing = set()

    canonical_names = {name for name, _ in _TENANT_DETECTION_RULES_COLUMNS}
    pk_not_null = ("rule_id", "siem_id", "space")

    if not existing:
        logger.info(
            "%s DB: creating detection_rules table from canonical schema "
            "(%d columns)", label, len(_TENANT_DETECTION_RULES_COLUMNS),
        )
        col_defs = ",\n            ".join(
            f"{n} {t}" + (" NOT NULL" if n in pk_not_null else "")
            for n, t in _TENANT_DETECTION_RULES_COLUMNS
        )
        conn.execute(f"""
            CREATE TABLE {table_ref} (
                {col_defs},
                PRIMARY KEY (rule_id, siem_id, space)
            )
        """)
        return

    # Pre-4.0.13 schema \u2014 no siem_id column at all. Cannot ALTER in a
    # NOT NULL PK column on a non-empty table; cache-only data, safe to drop.
    # Pre-4.1.12 PK was (rule_id, siem_id) which collides when the same
    # SIEM exposes the same rule in two spaces. If we detect the legacy
    # 2-column PK (or no siem_id at all), drop and recreate — cache only,
    # next sync repopulates.
    needs_pk_rebuild = False
    if "siem_id" not in existing:
        needs_pk_rebuild = True
        legacy_reason = "missing siem_id (pre-4.0.13 schema)"
    else:
        try:
            # DuckDB PRAGMA table_info columns:
            #   row[0]=cid (int), row[1]=name, row[2]=type,
            #   row[3]=notnull, row[4]=dflt_value, row[5]=pk
            # row[5] is the 1-based PK ordinal position (0 = not in PK).
            pk_cols = [
                row[1] for row in conn.execute(
                    f"PRAGMA table_info({table_ref})"
                ).fetchall() if row[5]
            ]
        except Exception:
            pk_cols = []
        if pk_cols and "space" not in pk_cols:
            needs_pk_rebuild = True
            legacy_reason = (
                f"PK {pk_cols} predates 4.1.12 (Migration 44 needs space in PK)"
            )

    if needs_pk_rebuild:
        logger.warning(
            "%s DB: detection_rules %s — dropping and recreating from "
            "canonical schema. The next sync will repopulate.",
            label, legacy_reason,
        )
        conn.execute(f"DROP TABLE IF EXISTS {table_ref}")
        col_defs = ",\n            ".join(
            f"{n} {t}" + (" NOT NULL" if n in pk_not_null else "")
            for n, t in _TENANT_DETECTION_RULES_COLUMNS
        )
        conn.execute(f"""
            CREATE TABLE {table_ref} (
                {col_defs},
                PRIMARY KEY (rule_id, siem_id, space)
            )
        """)
        return

    # Post-4.0.13 schema with one or more newer columns missing
    # (the production "23 columns but 24 values supplied" failure mode).
    missing = [
        (n, t) for n, t in _TENANT_DETECTION_RULES_COLUMNS
        if n not in existing
    ]
    if not missing:
        return
    for name, ddl_type in missing:
        try:
            conn.execute(
                f"ALTER TABLE {table_ref} ADD COLUMN IF NOT EXISTS "
                f"{name} {ddl_type}"
            )
        except Exception as exc:
            logger.error(
                "%s DB: failed to add detection_rules column %s %s: %s",
                label, name, ddl_type, exc,
            )
            raise
    # Surface stray columns as a warning \u2014 they're harmless for INSERT
    # (we name every column explicitly) but indicate schema drift the
    # operator should know about.
    stray = sorted(existing - canonical_names)
    if stray:
        logger.info(
            "%s DB: detection_rules has %d extra column(s) not in canonical "
            "schema: %s (left in place)", label, len(stray), stray,
        )
    logger.warning(
        "%s DB: detection_rules schema repaired \u2014 added %d missing column(s): %s",
        label, len(missing), [n for n, _ in missing],
    )


def ensure_all_tenant_detection_rules_schemas() -> None:
    """Walk every registered tenant DB and bring its ``detection_rules``
    schema in line with the canonical column list. Called from the app
    lifespan on startup so an operator-triggered Sync from the UI works
    on the very first click after upgrade \u2014 no separate script needed
    on the standalone / air-gapped box.
    """
    from app.config import get_settings
    from app.services.database import get_database_service
    from app.services.connection_pool import get_pool

    settings = get_settings()
    data_dir = settings.data_dir

    try:
        with get_database_service().get_shared_connection() as shared_conn:
            try:
                clients = shared_conn.execute(
                    "SELECT id, db_filename FROM clients "
                    "WHERE db_filename IS NOT NULL"
                ).fetchall()
            except Exception as exc:
                logger.info(
                    "Tenant detection_rules schema check skipped: %s "
                    "(clients table not yet migrated)", exc,
                )
                return

            for client_id, db_filename in clients:
                tenant_path = os.path.join(data_dir, db_filename)
                if not os.path.exists(tenant_path):
                    continue
                tenant_alias = f"t_{client_id.replace('-', '_')}"
                try:
                    get_pool().evict(tenant_path)
                except Exception:  # pragma: no cover - eviction best effort
                    pass
                try:
                    shared_conn.execute(
                        f"ATTACH '{tenant_path}' AS {tenant_alias}"
                    )
                    try:
                        _ensure_tenant_detection_rules_schema(
                            shared_conn,
                            table_ref=f"{tenant_alias}.detection_rules",
                            label=f"tenant {client_id[:8]}",
                        )
                    finally:
                        shared_conn.execute(f"DETACH {tenant_alias}")
                except Exception as exc:
                    logger.error(
                        "Tenant detection_rules schema check failed for "
                        "%s (%s): %s", client_id[:8], db_filename, exc,
                    )
    except Exception as exc:
        logger.error(
            "Tenant detection_rules schema sweep failed: %s", exc,
        )


# Back-compat alias \u2014 some external callers / tests imported the old name.
_ensure_tenant_detection_rules_v37 = _ensure_tenant_detection_rules_schema


def _distribute_rules_to_tenants():
    """Copy detection rules from shared DB to each tenant DB,
    filtered by the client's (siem_id, space) mappings.
    Called after a global elastic sync.

    Filter is by (siem_id, LOWER(space)) since 4.0.13 \u2014 a client mapped to
    SIEM A's 'production' space must NOT receive rules from SIEM B's
    identically-named 'production' space (they're different Kibana instances
    with different rules).

    Implementation note: this used to open the tenant DB and ATTACH the
    shared DB read-only into it. That fails inside the running tide-app
    process because DuckDB will not let the same physical file be attached
    twice in one process \u2014 the connection pool already holds a writable
    handle on the shared DB and the auto-aliased name (file stem) collides.
    We therefore drive everything from the shared connection pool and
    ATTACH the tenant DB onto it instead.
    """
    from app.services.tenant_manager import is_multi_db_mode
    if not is_multi_db_mode():
        return

    from app.config import get_settings
    from app.services.database import get_database_service
    settings = get_settings()
    data_dir = settings.data_dir

    try:
        with get_database_service().get_shared_connection() as shared_conn:
            clients = shared_conn.execute(
                "SELECT id, db_filename FROM clients WHERE db_filename IS NOT NULL"
            ).fetchall()

            for client_id, db_filename in clients:
                scope_rows = shared_conn.execute(
                    "SELECT DISTINCT siem_id, "
                    "LOWER(COALESCE(NULLIF(TRIM(space), ''), 'default')) "
                    "FROM client_siem_map "
                    "WHERE client_id = ? AND siem_id IS NOT NULL",
                    [client_id],
                ).fetchall()
                scopes = [(sid, sp) for sid, sp in scope_rows if sid and sp]
                if not scopes:
                    continue

                tenant_path = os.path.join(data_dir, db_filename)
                if not os.path.exists(tenant_path):
                    continue

                tenant_alias = f"t_{client_id.replace('-', '_')}"
                # Evict the tenant from the per-path connection pool first.
                # If a request previously routed to this tenant, the pool
                # already holds an open handle to the file as MAIN database
                # (auto-aliased to its file basename), and DuckDB rejects a
                # second cross-connection ATTACH on the same file with
                # ``Unique file handle conflict``. Eviction closes those
                # cached connections so the file is free for ATTACH; the
                # pool will lazily reopen on the next request.
                try:
                    from app.services.connection_pool import get_pool
                    get_pool().evict(tenant_path)
                except Exception:  # pragma: no cover - eviction best effort
                    pass
                try:
                    shared_conn.execute(f"ATTACH '{tenant_path}' AS {tenant_alias}")
                    try:
                        # Defensive schema repair: legacy tenant DBs
                        # provisioned before ``client_id`` was added to the
                        # canonical detection_rules schema have a 23-column
                        # table; the INSERT below supplies 24 values and
                        # explodes with "table detection_rules has 23
                        # columns but 24 values were supplied". Idempotent
                        # \u2014 a tenant already at the canonical schema is a
                        # one-DESCRIBE no-op.
                        _ensure_tenant_detection_rules_schema(
                            shared_conn,
                            table_ref=f"{tenant_alias}.detection_rules",
                            label=f"tenant {client_id[:8]}",
                        )

                        pair_predicates = " OR ".join(
                            "(siem_id = ? AND LOWER(space) = ?)" for _ in scopes
                        )
                        params = [v for pair in scopes for v in pair]

                        shared_conn.execute(
                            f"DELETE FROM {tenant_alias}.detection_rules"
                        )
                        shared_conn.execute(f"""
                            INSERT INTO {tenant_alias}.detection_rules (
                                rule_id, siem_id, name, severity, author, enabled, space,
                                score, quality_score, meta_score,
                                score_mapping, score_field_type, score_search_time,
                                score_language, score_note, score_override,
                                score_tactics, score_techniques, score_author,
                                score_highlights, last_updated, mitre_ids, raw_data,
                                client_id
                            )
                            SELECT rule_id, siem_id, name, severity, author, enabled, space,
                                   score, quality_score, meta_score,
                                   score_mapping, score_field_type, score_search_time,
                                   score_language, score_note, score_override,
                                   score_tactics, score_techniques, score_author,
                                   score_highlights, last_updated, mitre_ids, raw_data,
                                   '{client_id}' AS client_id
                            FROM detection_rules
                            WHERE {pair_predicates}
                        """, params)

                        count = shared_conn.execute(
                            f"SELECT COUNT(*) FROM {tenant_alias}.detection_rules"
                        ).fetchone()[0]
                        logger.info(
                            f"Distributed {count} rules to tenant {client_id[:8]} "
                            f"(scopes: {scopes})"
                        )
                    finally:
                        shared_conn.execute(f"DETACH {tenant_alias}")
                except Exception as e:
                    logger.error(f"Rule distribution failed for {client_id[:8]}: {e}")
    except Exception as e:
        logger.error(f"Rule distribution failed: {e}")


def run_mitre_sync():
    """Run the MITRE + OpenCTI threat-actor sync.

    Returns a structured dict (4.1.7 Phase C) with stable keys so the API
    layer can render success / partial-success / failure toasts without
    string-parsing log lines:

    ``{ "status": "success"|"partial"|"failed",
        "total": int,                 # mitre_count + octi_count
        "mitre_count": int,           # actors loaded from local STIX files
        "octi_count": int,            # actors loaded from OpenCTI instances
        "mitre_files": int,           # *-attack.json files processed (>=0)
        "warnings": [str, ...],       # non-fatal: missing dir, empty source, etc
        "errors":   [str, ...],       # fatal-per-instance OpenCTI / STIX failures
        "duration_ms": int,
        "error": str | None }         # top-level fatal (status=='failed' only)

    ``status`` is computed last:
      * ``failed``  → top-level exception OR (errors and total == 0)
      * ``partial`` → errors present but at least one source produced rows
      * ``success`` → no errors
    """
    import time as _time
    _t0 = _time.perf_counter()
    result: dict = {
        "status": "failed",
        "total": 0,
        "mitre_count": 0,
        "octi_count": 0,
        "mitre_files": 0,
        "warnings": [],
        "errors": [],
        "duration_ms": 0,
        "error": None,
    }

    services_dir = os.path.dirname(os.path.abspath(__file__))
    app_dir = os.path.dirname(services_dir)

    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)

    try:
        original_cwd = os.getcwd()
        os.chdir(app_dir)
        
        try:
            import cti_helper
            from app.services.database import get_database_service
            from app.config import get_settings
            
            db = get_database_service()
            settings = get_settings()
            
            # Clear threat_actors table for a fresh sync (live data)
            from app.database import clear_threat_actors
            cleared = clear_threat_actors()
            logger.info(f"Cleared {cleared} stale threat actors for fresh sync.")
            
            # --- Phase 1: Sync from local MITRE JSON files ---
            mitre_actors = 0
            mitre_files = 0
            logger.info("Starting MITRE file sync...")
            mitre_dir = "/opt/repos/mitre"

            if os.path.exists(mitre_dir):
                for file in os.listdir(mitre_dir):
                    if not file.endswith('-attack.json'):
                        continue
                    source_path = os.path.join(mitre_dir, file)
                    short_name = file.replace('-attack.json', '')
                    # Per-file isolation: a malformed STIX bundle in one
                    # source must not poison the others. The previous loop
                    # would bubble any parse / save exception out to the
                    # top-level handler and abort the entire sync, taking
                    # the OpenCTI phase down with it.
                    try:
                        json_data = cti_helper.fetch_stix_data(source_path)
                        if not json_data:
                            result["warnings"].append(
                                f"MITRE source '{short_name}' returned no data."
                            )
                            continue
                        df_actors = cti_helper.process_stix_bundle(
                            json_data, source_name=short_name
                        )
                        if not df_actors.empty:
                            from app.database import save_threat_data
                            count = save_threat_data(df_actors)
                            mitre_actors += count
                            logger.info(f"   Loaded {count} actors from {short_name}")
                        df_defs = cti_helper.process_mitre_definitions(json_data)
                        if not df_defs.empty:
                            from app.database import save_mitre_definitions
                            save_mitre_definitions(df_defs)
                        mitre_files += 1
                    except Exception as exc:
                        msg = f"MITRE source '{short_name}' failed: {exc}"
                        logger.error(msg, exc_info=True)
                        result["errors"].append(msg)
            else:
                msg = f"MITRE directory not found: {mitre_dir}"
                logger.warning(msg)
                result["warnings"].append(msg)

            result["mitre_count"] = mitre_actors
            result["mitre_files"] = mitre_files
            logger.info(f"MITRE file sync complete. Updated {mitre_actors} actors across {mitre_files} file(s).")
            
            # --- Phase 2: Sync from OpenCTI (per-tenant, isolated) ---
            # 4.1.5: OpenCTI is per-tenant intel. Iterate the
            # client_opencti_map so each (client, instance) pair writes into
            # the **tenant's** DB (or shared DB for the legacy primary
            # client which has no tenant DB file). MITRE rows in shared are
            # left untouched; only OpenCTI-sourced rows are wiped before
            # the fresh fetch.
            octi_actors = 0
            from app.services.tenant_manager import tenant_context_for

            client_octi_pairs = []
            try:
                with db.get_shared_connection() as conn:
                    rows = conn.execute(
                        """
                        SELECT m.client_id, c.name, o.id, o.label,
                               o.url, o.token_enc
                        FROM client_opencti_map m
                        JOIN opencti_inventory o ON o.id = m.opencti_id
                        JOIN clients c ON c.id = m.client_id
                        WHERE COALESCE(o.is_active, TRUE) = TRUE
                        ORDER BY c.name, o.label
                        """
                    ).fetchall()
                client_octi_pairs = [
                    {
                        "client_id": r[0], "client_name": r[1],
                        "opencti_id": r[2], "opencti_label": r[3],
                        "url": r[4], "token": r[5],
                    }
                    for r in rows
                ]
            except Exception as e:
                logger.warning(f"OpenCTI: could not load client_opencti_map: {e}")

            # Legacy env-var fallback is no longer routed: without a
            # client_opencti_map row there is no tenant to attribute the
            # data to, and dumping it into shared would re-create the
            # cross-tenant leak that 4.1.5 fixes. Surface a one-line
            # warning so operators migrate to the Management UI.
            if not client_octi_pairs:
                if settings.opencti_url and settings.opencti_token:
                    logger.warning(
                        "OpenCTI: OPENCTI_URL/OPENCTI_TOKEN env vars are "
                        "set but no client_opencti_map rows exist. "
                        "Configure the instance via Management → OpenCTI "
                        "and link it to a client; env-var fallback is "
                        "deprecated in 4.1.5 to prevent cross-tenant data "
                        "leakage."
                    )
                else:
                    logger.info(
                        "OpenCTI: no (client, instance) mappings configured — "
                        "skipping per-tenant OpenCTI sync."
                    )

            # Group by client so we wipe the tenant's OpenCTI rows once,
            # then upsert from each linked instance in turn.
            from collections import defaultdict
            by_client = defaultdict(list)
            for p in client_octi_pairs:
                by_client[p["client_id"]].append(p)

            for client_id, pairs in by_client.items():
                client_name = pairs[0]["client_name"]
                try:
                    with tenant_context_for(client_id):
                        wiped = db.clear_octi_threat_actors_in_active_db()
                        if wiped:
                            logger.info(
                                f"OpenCTI: cleared {wiped} stale actor(s) "
                                f"for {client_name}"
                            )
                        for p in pairs:
                            octi_url = p["url"]
                            octi_token = p["token"]
                            octi_label = p["opencti_label"]
                            if not (octi_url and octi_token):
                                continue
                            logger.info(
                                f"OpenCTI sync for {client_name}: "
                                f"{octi_label} ({octi_url})..."
                            )
                            try:
                                df_octi = cti_helper.get_threat_landscape(
                                    octi_url, octi_token
                                )
                                if df_octi is None or df_octi.empty:
                                    logger.warning(
                                        f"OpenCTI: no actors returned from "
                                        f"{octi_label} for {client_name}."
                                    )
                                    continue
                                df_octi['source'] = df_octi['source'].apply(
                                    lambda x: "OCTI" if isinstance(x, str) else x
                                )
                                count = db.save_octi_threat_actors_to_active_db(
                                    df_octi
                                )
                                octi_actors += count
                                logger.info(
                                    f"OpenCTI sync complete for "
                                    f"{client_name} / {octi_label}: "
                                    f"{count} actors."
                                )
                            except Exception as e:
                                msg = (
                                    f"OpenCTI sync failed for "
                                    f"{client_name} / {octi_label}: {e}"
                                )
                                logger.error(msg, exc_info=True)
                                result["errors"].append(msg)
                except Exception as e:
                    msg = (
                        f"OpenCTI tenant context failed for "
                        f"{client_name}: {e}"
                    )
                    logger.error(msg, exc_info=True)
                    result["errors"].append(msg)

            result["octi_count"] = octi_actors
            total = mitre_actors + octi_actors
            result["total"] = total
            logger.info(f"Total threat sync complete. {mitre_actors} MITRE + {octi_actors} OCTI = {total} actors.")
            
            # Sync shared reference data (threat actors, MITRE) to tenant DBs
            try:
                from app.services.tenant_manager import sync_shared_data, is_multi_db_mode
                if is_multi_db_mode():
                    sync_shared_data(settings.data_dir if hasattr(settings, 'data_dir') else '/app/data',
                                     settings.db_path)
            except Exception as e:
                msg = f"Shared data sync to tenants failed: {e}"
                logger.warning(msg)
                result["warnings"].append(msg)

            # Status classification (4.1.7 Phase C):
            #   * any errors AND nothing loaded -> failed
            #   * any errors AND something loaded -> partial
            #   * no errors -> success
            if result["errors"] and total == 0:
                result["status"] = "failed"
            elif result["errors"]:
                result["status"] = "partial"
            else:
                result["status"] = "success"
            return result
        finally:
            os.chdir(original_cwd)

    except Exception as e:
        logger.error(f"MITRE sync failed: {e}", exc_info=True)
        result["status"] = "failed"
        result["error"] = str(e)
        return result
    finally:
        result["duration_ms"] = int((_time.perf_counter() - _t0) * 1000)
        # Best-effort persistence to sync_history (Migration 42 / Phase D).
        try:
            from app.services.database import get_database_service
            get_database_service().record_sync_run(
                "mitre",
                result.get("status", "failed"),
                total_count=result.get("total", 0),
                duration_ms=result.get("duration_ms", 0),
                detail={
                    "mitre_count": result.get("mitre_count", 0),
                    "octi_count": result.get("octi_count", 0),
                    "mitre_files": result.get("mitre_files", 0),
                    "warnings": result.get("warnings", []),
                    "errors": result.get("errors", []),
                },
                error=result.get("error"),
            )
        except Exception as _exc:  # noqa: BLE001
            logger.debug(f"sync_history insert (mitre) failed: {_exc!r}")


def run_elastic_sync(force_mapping=False, client_id: str | None = None):
    """
    Synchronous function to fetch rules from Elastic and save to database.
    This runs in a thread pool to avoid blocking the async event loop.
    force_mapping: if True, skip lazy mapping and re-check all field mappings from Elastic.
    client_id: if provided, restrict the sync to ONLY the (siem_id, space) pairs
               in ``client_siem_map WHERE client_id = ?`` for that tenant. SIEMs
               not mapped to this client are skipped entirely; mapped SIEMs are
               fetched only for the spaces this client has linked. The global
               scheduled sync (no client_id) preserves the previous behaviour
               of iterating every active SIEM × every mapped space, so any
               (siem, space) pair that no longer belongs to a client still
               gets reconciled on the next interval.
               Per AGENTS.md §8.2 g4 / §8.3 the scope axis is the composite
               ``(siem_id, space)`` pair — NEVER ``space`` alone.
    """
    # Determine the app directory (where elastic_helper.py lives)
    # sync.py is at: app/services/sync.py
    # So: dirname(sync.py) -> app/services, dirname again -> app
    services_dir = os.path.dirname(os.path.abspath(__file__))
    app_dir = os.path.dirname(services_dir)  # This is 'app'
    project_root = os.path.dirname(app_dir)   # This is the project root
    
    # Add app directory to path so 'import log' and 'import elastic_helper' work
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)
    
    try:
        # Change to app dir so relative imports in elastic_helper work
        original_cwd = os.getcwd()
        os.chdir(app_dir)
        
        try:
            import time as _time
            import elastic_helper
            from app.services.database import get_database_service
            
            db = get_database_service()
            
            logger.info("Starting Elastic sync...")
            _t_start = _time.perf_counter()
            
            # Lazy Mapping: get existing rule data from DB so we can skip mapping for known rules
            existing_rule_data = db.get_existing_rule_data()
            if force_mapping:
                existing_rule_keys = set()  # Force full mapping for all rules
                logger.info(f"[perf] Force mapping enabled — will re-check all rules")
            else:
                # Only skip mapping for rules that actually HAVE stored results
                existing_rule_keys = set()
                for key, data in existing_rule_data.items():
                    raw = data.get('raw_data', {})
                    if isinstance(raw, dict) and raw.get('results'):
                        existing_rule_keys.add(key)
            logger.info(f"[perf] Loaded {len(existing_rule_data)} existing rules, {len(existing_rule_keys)} with mapping data, in {(_time.perf_counter() - _t_start)*1000:.0f}ms")

            # Iterate every active SIEM in the inventory and fetch its rules
            # using its OWN kibana_url + api_token + elasticsearch_url. The
            # legacy global ELASTIC_URL/ELASTIC_API_KEY env-var fallback was
            # removed in 4.0.10 — every SIEM must self-describe in
            # siem_inventory or it will not be synced.
            siems = [s for s in db.list_siem_inventory() if s.get("is_active")]
            if not siems:
                logger.warning("No active SIEMs in inventory — nothing to sync. "
                               "Add a SIEM via the Management page.")
                return 0

            # Per-client scope (optional). When client_id is set we collapse
            # this client's client_siem_map rows into {siem_id: {space, ...}}
            # and use it to (a) drop SIEMs the client isn't mapped to and
            # (b) override db.get_siem_spaces(siem_id) (which is global)
            # with just the spaces this client has linked.
            client_scope: dict[str, set[str]] | None = None
            if client_id:
                pairs = db.get_client_siem_scopes(client_id) or []
                client_scope = {}
                for sid, sp in pairs:
                    client_scope.setdefault(sid, set()).add(sp)
                if not client_scope:
                    logger.warning(
                        f"Per-client sync requested for client_id={client_id} "
                        f"but client_siem_map has no rows for this client — "
                        f"nothing to sync."
                    )
                    return 0
                before = len(siems)
                siems = [s for s in siems if s.get("id") in client_scope]
                logger.info(
                    f"Per-client sync: client_id={client_id} restricted to "
                    f"{len(siems)}/{before} SIEM(s), "
                    f"{sum(len(v) for v in client_scope.values())} "
                    f"(siem,space) pair(s)."
                )

            _t_fetch = _time.perf_counter()
            import pandas as _pd
            frames = []
            # Track per-SIEM the spaces we attempted to sync, so the
            # subtractive-delete pass can be scoped per-SIEM (4.0.13). Two
            # SIEMs can share a space name so a global "this space is empty"
            # check is unsafe \u2014 it would delete the other SIEM's rules.
            siem_spaces_attempted: dict = {}
            siem_spaces_synced: dict = {}
            # Per-SIEM per-space diagnostics from elastic_helper. Used by the
            # mirror-sync passes below to skip rule deletion in any
            # (siem, space) where the fetch was incomplete (Kibana outage,
            # transient 5xx, network drop). This is the safety half of the
            # mirror-Kibana behaviour: clean fetch == authoritative source of
            # truth; partial fetch == preserve existing rows.
            siem_diagnostics: dict = {}
            for siem in siems:
                # Re-read to get the encrypted/raw token (list_siem_inventory omits it)
                full = db.get_siem_inventory_item(siem["id"]) or {}
                kurl = full.get("kibana_url") or siem.get("kibana_url")
                token = full.get("api_token_enc")
                es_url = full.get("elasticsearch_url") or siem.get("elasticsearch_url")
                if client_scope is not None:
                    # Per-client mode: only the spaces this client has linked
                    # for this SIEM. Sorted for stable log output.
                    spaces = sorted(client_scope.get(siem["id"], set()))
                else:
                    spaces = db.get_siem_spaces(siem["id"])
                if not spaces:
                    # No client_siem_map row yet. Two reasons this can
                    # happen: (a) brand-new standalone deployment where the
                    # operator hasn't linked the SIEM to a tenant yet; (b)
                    # an existing SIEM that lost its mapping. In either case
                    # we still want the link-to-tenant dropdown to be
                    # populated, which means the persistent
                    # ``siem_kibana_spaces`` cache (Migration 41) needs
                    # spaces in it. Pre-4.1.7 the cache was only seeded by a
                    # successful Test Connection click; sync silently did
                    # nothing, which is exactly how a standalone client
                    # ended up with an empty dropdown despite a working
                    # SIEM. Now: bootstrap the cache via the shared
                    # space_resolver, then skip the rule fetch (still no
                    # attribution target). Rule attribution stays gated on
                    # client_siem_map — we are NOT broadening tenant
                    # visibility, only seeding the picker.
                    try:
                        from app.services.space_resolver import (
                            resolve_discoverable_spaces, REASON_LIVE, REASON_PERSISTED,
                        )
                        discovered, reason = resolve_discoverable_spaces(
                            db, siem["id"],
                            kibana_url=kurl, api_token=token,
                            allow_live=True,
                        )
                    except Exception as _exc:  # noqa: BLE001
                        discovered, reason = set(), f"resolver_error:{_exc!r}"
                    if discovered:
                        logger.info(
                            "Skipping rule fetch for SIEM '%s' — no "
                            "client_siem_map rows. Bootstrapped %d Kibana "
                            "space(s) into the persistent cache via %s so "
                            "the link-to-tenant dropdown will populate. "
                            "Link this SIEM to a tenant in the Management "
                            "UI to enable sync.",
                            siem.get("label"), len(discovered), reason,
                        )
                    else:
                        logger.info(
                            "Skipping SIEM '%s' — no client_siem_map rows "
                            "and space discovery returned nothing "
                            "(reason=%s). Link it to a client in the "
                            "Management UI; if the dropdown is still "
                            "empty, run Test Connection on the SIEM card "
                            "to surface the underlying error.",
                            siem.get("label"), reason,
                        )
                    continue
                if not (kurl and token and spaces):
                    logger.info(f"Skipping SIEM '{siem.get('label')}' \u2014 missing url/token/spaces")
                    continue
                siem_id = siem["id"]
                siem_spaces_attempted[siem_id] = set(spaces)
                # Per-SIEM lazy-mapping keys: only pass keys that belong to this
                # SIEM, otherwise the fetcher would think a rule already has
                # mapping data when really another SIEM owns that row.
                per_siem_known = {
                    rid for (rid, sid, _sp) in existing_rule_keys if sid == siem_id
                }
                logger.info(
                    f"Fetching from SIEM '{siem.get('label')}' (siem_id={siem_id}) "
                    f"@ {kurl} spaces={spaces}"
                )
                try:
                    # When force_mapping is on, drop the per-pattern mapping
                    # cache so the re-check actually re-hits Elastic.
                    if force_mapping:
                        try:
                            elastic_helper.invalidate_mapping_cache()
                        except AttributeError:
                            pass
                    siem_df = elastic_helper.fetch_detection_rules(
                        kibana_url=kurl,
                        api_key=token,
                        spaces=spaces,
                        check_mappings=True,
                        # fetch_detection_rules expects a set of rule_id strings
                        # OR (rule_id, space) tuples \u2014 it does not know about
                        # siem_id. Pass plain rule_ids scoped to this SIEM.
                        known_rule_keys=per_siem_known,
                        elasticsearch_url=es_url,
                    )
                    # Pull per-space drift diagnostics so the subtractive
                    # passes below can be skipped for any (siem, space) where
                    # the fetch was incomplete (e.g. Kibana outage mid-sync).
                    diag = {}
                    try:
                        diag = elastic_helper.last_sync_diagnostics.get(
                            id(siem_df), {}
                        ) or elastic_helper.last_sync_diagnostics.get(
                            (kurl.rstrip('/'), tuple(sorted(spaces))), {}
                        )
                    except Exception:
                        diag = {}
                    siem_diagnostics[siem_id] = diag
                    if siem_df is not None and not siem_df.empty:
                        # Stamp every row with its originating siem_id BEFORE
                        # frames get concatenated. save_audit_results requires
                        # this to satisfy the new (rule_id, siem_id) PK.
                        siem_df = siem_df.copy()
                        siem_df['siem_id'] = siem_id
                        siem_spaces_synced[siem_id] = set(
                            siem_df['space_id'].dropna().unique()
                        ) if 'space_id' in siem_df.columns else set()
                        frames.append(siem_df)
                    else:
                        siem_spaces_synced[siem_id] = set()
                except Exception as e:
                    logger.error(f"Fetch failed for SIEM '{siem.get('label')}': {e}")
                    siem_diagnostics[siem_id] = {}

            df = _pd.concat(frames, ignore_index=True) if frames else _pd.DataFrame()

            if df is not None and not df.empty:
                _t_save = _time.perf_counter()
                logger.info(f"[perf] fetch_detection_rules (per-SIEM) completed in {(_t_save - _t_fetch)*1000:.0f}ms")
                audit_records = df.to_dict('records')
                
                # Lazy Mapping: restore scores and mapping data for rules that were skipped.
                # Key by (rule_id, siem_id, space) since 4.1.12 (Migration 44) — a single
                # rule_id can exist in multiple SIEMs and the same rule can be exposed in
                # multiple spaces of one SIEM, each requiring its own restored row.
                restored_count = 0
                for rec in audit_records:
                    key = (
                        rec.get('rule_id'),
                        rec.get('siem_id'),
                        rec.get('space') or rec.get('space_id') or 'default',
                    )
                    if key in existing_rule_data and not rec.get('results'):
                        existing = existing_rule_data[key]
                        # Restore mapping results from existing raw_data
                        existing_raw = existing.get('raw_data', {})
                        if isinstance(existing_raw, dict) and existing_raw.get('results'):
                            rec['results'] = existing_raw['results']
                        # Recalculate all scores so dynamic metrics (e.g. search_time) stay fresh
                        rec = elastic_helper.calculate_score(rec)
                        restored_count += 1
                
                if restored_count:
                    logger.info(f"[perf] Lazy mapping: restored scores/mappings for {restored_count} existing rules")
                
                count = db.save_audit_results(audit_records)
                logger.info(f"[perf] save_audit_results completed in {(_time.perf_counter() - _t_save)*1000:.0f}ms")
                logger.info(f"[perf] Total sync time: {(_time.perf_counter() - _t_start)*1000:.0f}ms")
                
                # --- Mirror-Kibana sync (drift-aware) ---
                # For each (siem_id, space):
                #   * Clean fetch (advertised total == fetched count):
                #       - Empty space → delete all rows for that (siem, space)
                #         via delete_rules_for_spaces (existing helper).
                #       - Non-empty space → reconcile_rules_for_siem_space()
                #         removes any DB row whose rule_id was not in the
                #         fetched set (rule deleted in Kibana since last sync).
                #   * Incomplete fetch (drift > 0, or page-fetch error):
                #       - Preserve existing rows, log WARN. Per Consideration 2
                #         in the plan: a Kibana outage must not cascade into
                #         row deletions on the TIDE side.
                for siem_id, attempted in siem_spaces_attempted.items():
                    diag = siem_diagnostics.get(siem_id, {}) or {}
                    synced = siem_spaces_synced.get(siem_id, set())
                    siem_label = next(
                        (s.get('label', '?') for s in siems if s.get('id') == siem_id),
                        '?',
                    )
                    for space in attempted:
                        space_diag = diag.get(space)
                        # Missing diagnostic = the fetch never produced one
                        # (exception during fetch, network failure before page
                        # 1, etc.). Treat as incomplete — preserve.
                        if not space_diag:
                            logger.warning(
                                f"WARN sync incomplete for SIEM '{siem_label}' "
                                f"(siem_id={siem_id}) space '{space}' — no "
                                f"diagnostics returned; preserving existing rows."
                            )
                            continue
                        if not space_diag.get("complete"):
                            logger.warning(
                                f"WARN sync incomplete for SIEM '{siem_label}' "
                                f"(siem_id={siem_id}) space '{space}' — "
                                f"{space_diag.get('fetched', 0)}/"
                                f"{space_diag.get('total', '?')} rules; "
                                f"preserving existing rows."
                            )
                            continue
                        # Clean fetch — authoritative reconcile.
                        keep_ids = space_diag.get("rule_ids") or set()
                        if space in synced and keep_ids:
                            removed = db.reconcile_rules_for_siem_space(
                                siem_id=siem_id,
                                space=space,
                                keep_rule_ids=keep_ids,
                            )
                            if removed:
                                logger.info(
                                    f"Mirror sync: SIEM '{siem_label}' space "
                                    f"'{space}' removed {removed} orphan(s)."
                                )
                        else:
                            # Confirmed empty by Kibana — drop all rows for
                            # this (siem, space).
                            logger.info(
                                f"Mirror sync: SIEM '{siem_label}' space "
                                f"'{space}' returned 0 rules (clean fetch); "
                                f"clearing TIDE rows for that (siem, space)."
                            )
                            db.delete_rules_for_spaces([space], siem_id=siem_id)

                logger.info(f"Synced {count} rules from {len(siems)} SIEM(s)")

                # Distribute rules to per-tenant databases
                try:
                    _distribute_rules_to_tenants()
                except Exception as e:
                    logger.warning(f"Rule distribution to tenants failed: {e}")
                
                return count
            else:
                # No rules returned from Elastic — this is likely a connectivity or auth issue.
                # DO NOT delete existing rules — preserve the baseline to avoid data loss.
                logger.warning("No rules fetched from any SIEM — preserving existing rules in database. "
                               "Check the per-SIEM kibana_url, api_token, and space configuration "
                               "in the Management page.")
                return 0
        finally:
            os.chdir(original_cwd)
            
    except Exception as e:
        logger.error(f"Elastic sync failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return -1


async def trigger_sync(force_mapping=False, client_id: str | None = None):
    """
    Async wrapper to run the sync in a thread pool.
    Use this from async endpoints.

    client_id: optional tenant scope. See ``run_elastic_sync`` for semantics.
    """
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: run_elastic_sync(force_mapping=force_mapping, client_id=client_id),
    )
