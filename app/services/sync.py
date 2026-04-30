"""
Sync service for TIDE - handles synchronization with Elastic and MITRE.
"""

import duckdb
import logging
import os
import sys

logger = logging.getLogger(__name__)


def _ensure_tenant_detection_rules_v37(tenant_conn) -> None:
    """Ensure the tenant DB's ``detection_rules`` table has the v37 schema
    (composite PK on (rule_id, siem_id) with NOT NULL ``siem_id`` column).

    Older tenant DBs created before 4.0.13 have the legacy schema and lack
    ``siem_id``. We rebuild the table from scratch \u2014 there is no operator
    state to preserve since the table is purely a cache of upstream rules
    that ``_distribute_rules_to_tenants`` repopulates on every sync.
    """
    try:
        cols = tenant_conn.execute("DESCRIBE detection_rules").fetchall()
        col_names = {c[0] for c in cols}
    except Exception:
        col_names = set()
    if 'siem_id' in col_names:
        return
    logger.info(
        "Tenant DB: rebuilding detection_rules with v37 schema "
        "(adding siem_id column)"
    )
    tenant_conn.execute("DROP TABLE IF EXISTS detection_rules")
    tenant_conn.execute("""
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
            client_id VARCHAR,
            PRIMARY KEY (rule_id, siem_id)
        )
    """)


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
                        pair_predicates = " OR ".join(
                            "(siem_id = ? AND LOWER(space) = ?)" for _ in scopes
                        )
                        params = [v for pair in scopes for v in pair]

                        shared_conn.execute(
                            f"DELETE FROM {tenant_alias}.detection_rules"
                        )
                        shared_conn.execute(f"""
                            INSERT INTO {tenant_alias}.detection_rules
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
    """
    Synchronous function to load MITRE ATT&CK data from local files AND OpenCTI.
    Returns a dict with 'mitre_count' and 'octi_count' keys, or an int for backward compat.
    """
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
            logger.info("Starting MITRE file sync...")
            mitre_dir = "/opt/repos/mitre"
            
            if os.path.exists(mitre_dir):
                for file in os.listdir(mitre_dir):
                    if file.endswith('-attack.json'):
                        source_path = os.path.join(mitre_dir, file)
                        short_name = file.replace('-attack.json', '')
                        
                        json_data = cti_helper.fetch_stix_data(source_path)
                        if json_data:
                            df_actors = cti_helper.process_stix_bundle(json_data, source_name=short_name)
                            if not df_actors.empty:
                                from app.database import save_threat_data
                                count = save_threat_data(df_actors)
                                mitre_actors += count
                                logger.info(f"   Loaded {count} actors from {short_name}")
                            
                            df_defs = cti_helper.process_mitre_definitions(json_data)
                            if not df_defs.empty:
                                from app.database import save_mitre_definitions
                                save_mitre_definitions(df_defs)
            else:
                logger.warning(f"MITRE directory not found: {mitre_dir}")
            
            logger.info(f"MITRE file sync complete. Updated {mitre_actors} actors.")
            
            # --- Phase 2: Sync from OpenCTI ---
            octi_actors = 0

            # Prefer instances configured in the Management panel (DB); fall back to env vars.
            octi_instances = db.get_opencti_active_instances() if hasattr(db, "get_opencti_active_instances") else []
            if not octi_instances and settings.opencti_url and settings.opencti_token:
                octi_instances = [{"url": settings.opencti_url, "token_enc": settings.opencti_token, "label": "env-config"}]

            for _octi in octi_instances:
                octi_url = _octi.get("url")
                octi_token = _octi.get("token_enc")
                octi_label = _octi.get("label", "OpenCTI")
                if not (octi_url and octi_token):
                    continue
                logger.info(f"Starting OpenCTI sync from {octi_label} ({octi_url})...")
                try:
                    df_octi = cti_helper.get_threat_landscape(octi_url, octi_token)
                    if not df_octi.empty:
                        df_octi['source'] = df_octi['source'].apply(
                            lambda x: "OCTI" if isinstance(x, str) else x
                        )
                        from app.database import save_threat_data
                        count = save_threat_data(df_octi)
                        octi_actors += count
                        logger.info(f"OpenCTI sync complete for {octi_label}. Updated {count} actors.")
                    else:
                        logger.warning(f"No actors returned from OpenCTI ({octi_label}).")
                except Exception as e:
                    logger.error(f"OpenCTI sync failed for {octi_label}: {e}")
                    import traceback
                    logger.error(traceback.format_exc())

            if not octi_instances:
                logger.info("OpenCTI not configured, skipping.")
            
            total = mitre_actors + octi_actors
            logger.info(f"Total threat sync complete. {mitre_actors} MITRE + {octi_actors} OCTI = {total} actors.")
            
            # Sync shared reference data (threat actors, MITRE) to tenant DBs
            try:
                from app.services.tenant_manager import sync_shared_data, is_multi_db_mode
                if is_multi_db_mode():
                    sync_shared_data(settings.data_dir if hasattr(settings, 'data_dir') else '/app/data',
                                     settings.db_path)
            except Exception as e:
                logger.warning(f"Shared data sync to tenants failed: {e}")
            
            return total
        finally:
            os.chdir(original_cwd)
            
    except Exception as e:
        logger.error(f"MITRE sync failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return -1


def run_elastic_sync(force_mapping=False):
    """
    Synchronous function to fetch rules from Elastic and save to database.
    This runs in a thread pool to avoid blocking the async event loop.
    force_mapping: if True, skip lazy mapping and re-check all field mappings from Elastic.
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
                spaces = db.get_siem_spaces(siem["id"])
                if not spaces:
                    # SIEM exists but no client mapping yet \u2014 fall back to its declared
                    # production/staging spaces so logging/preview still discover rules.
                    spaces = [sp for sp in [siem.get("production_space"),
                                            siem.get("staging_space")] if sp]
                if not (kurl and token and spaces):
                    logger.info(f"Skipping SIEM '{siem.get('label')}' \u2014 missing url/token/spaces")
                    continue
                siem_id = siem["id"]
                siem_spaces_attempted[siem_id] = set(spaces)
                # Per-SIEM lazy-mapping keys: only pass keys that belong to this
                # SIEM, otherwise the fetcher would think a rule already has
                # mapping data when really another SIEM owns that row.
                per_siem_known = {
                    rid for (rid, sid) in existing_rule_keys if sid == siem_id
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
                # Key by (rule_id, siem_id) since 4.0.13 \u2014 a single rule_id can exist in
                # multiple SIEMs and each must restore from its own row.
                restored_count = 0
                for rec in audit_records:
                    key = (rec.get('rule_id'), rec.get('siem_id'))
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


async def trigger_sync(force_mapping=False):
    """
    Async wrapper to run the sync in a thread pool.
    Use this from async endpoints.
    """
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: run_elastic_sync(force_mapping=force_mapping))
