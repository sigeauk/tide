"""
Sync service for TIDE - handles synchronization with Elastic and MITRE.
"""

import duckdb
import logging
import os
import sys

logger = logging.getLogger(__name__)


def _distribute_rules_to_tenants():
    """Copy detection rules from shared DB to each tenant DB,
    filtered by the client's SIEM space mappings.
    Called after a global elastic sync."""
    from app.services.tenant_manager import is_multi_db_mode
    if not is_multi_db_mode():
        return

    from app.config import get_settings
    settings = get_settings()
    shared_db_path = settings.db_path
    data_dir = settings.data_dir

    try:
        shared_conn = duckdb.connect(shared_db_path, read_only=True)
        clients = shared_conn.execute(
            "SELECT id, db_filename FROM clients WHERE db_filename IS NOT NULL"
        ).fetchall()

        for client_id, db_filename in clients:
            spaces = shared_conn.execute(
                "SELECT DISTINCT space FROM client_siem_map "
                "WHERE client_id = ? AND space IS NOT NULL",
                [client_id],
            ).fetchall()
            space_list = [s[0] for s in spaces if s[0]]
            if not space_list:
                continue

            tenant_path = os.path.join(data_dir, db_filename)
            if not os.path.exists(tenant_path):
                continue

            try:
                tenant_conn = duckdb.connect(tenant_path)
                tenant_conn.execute(
                    f"ATTACH '{shared_db_path}' AS shared (READ_ONLY)"
                )

                placeholders = ", ".join("?" for _ in space_list)
                tenant_conn.execute("DELETE FROM detection_rules")
                tenant_conn.execute(f"""
                    INSERT INTO detection_rules
                    SELECT rule_id, name, severity, author, enabled, space,
                           score, quality_score, meta_score,
                           score_mapping, score_field_type, score_search_time,
                           score_language, score_note, score_override,
                           score_tactics, score_techniques, score_author,
                           score_highlights, last_updated, mitre_ids, raw_data,
                           '{client_id}' AS client_id
                    FROM shared.detection_rules
                    WHERE LOWER(space) IN ({placeholders})
                """, [s.lower() for s in space_list])

                tenant_conn.execute("DETACH shared")
                count = tenant_conn.execute(
                    "SELECT COUNT(*) FROM detection_rules"
                ).fetchone()[0]
                tenant_conn.close()
                logger.info(
                    f"Distributed {count} rules to tenant {client_id[:8]} "
                    f"(spaces: {space_list})"
                )
            except Exception as e:
                logger.error(f"Rule distribution failed for {client_id[:8]}: {e}")

        shared_conn.close()
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
            octi_url = settings.opencti_url
            octi_token = settings.opencti_token
            
            if octi_url and octi_token:
                logger.info("Starting OpenCTI sync...")
                try:
                    df_octi = cti_helper.get_threat_landscape(octi_url, octi_token)
                    if not df_octi.empty:
                        # Ensure source column says "OCTI"
                        df_octi['source'] = df_octi['source'].apply(
                            lambda x: "OCTI" if isinstance(x, str) else x
                        )
                        from app.database import save_threat_data
                        octi_actors = save_threat_data(df_octi)
                        logger.info(f"OpenCTI sync complete. Updated {octi_actors} actors.")
                    else:
                        logger.warning("No actors returned from OpenCTI.")
                except Exception as e:
                    logger.error(f"OpenCTI sync failed: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
            else:
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
            
            _t_fetch = _time.perf_counter()
            df = elastic_helper.fetch_detection_rules(check_mappings=True, known_rule_keys=existing_rule_keys)
            
            if df is not None and not df.empty:
                _t_save = _time.perf_counter()
                logger.info(f"[perf] fetch_detection_rules completed in {(_t_save - _t_fetch)*1000:.0f}ms")
                audit_records = df.to_dict('records')
                
                # Lazy Mapping: restore scores and mapping data for rules that were skipped
                restored_count = 0
                for rec in audit_records:
                    key = (rec.get('rule_id'), rec.get('space_id', 'default'))
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
                
                # --- Subtractive sync: remove ghost rules from empty spaces ---
                # Determine which configured spaces were NOT in the fetched data
                from app.config import get_settings
                settings = get_settings()
                configured_spaces = settings.kibana_space_list
                synced_spaces = set(df['space_id'].dropna().unique()) if 'space_id' in df.columns else set()
                empty_spaces = [s for s in configured_spaces if s not in synced_spaces]
                
                if empty_spaces:
                    logger.info(f"Subtractive sync: clearing ghost rules from empty spaces: {empty_spaces}")
                    db.delete_rules_for_spaces(empty_spaces)
                
                logger.info(f"Synced {count} rules from Elastic")
                
                # Distribute rules to per-tenant databases
                try:
                    _distribute_rules_to_tenants()
                except Exception as e:
                    logger.warning(f"Rule distribution to tenants failed: {e}")
                
                return count
            else:
                # No rules returned from Elastic — this is likely a connectivity or auth issue.
                # DO NOT delete existing rules — preserve the baseline to avoid data loss.
                logger.warning("No rules fetched from Elastic — preserving existing rules in database. "
                               "Check ELASTIC_URL, ELASTIC_API_KEY, and KIBANA_SPACES configuration.")
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
