"""
Sync service for TIDE - handles synchronization with Elastic and MITRE.
"""

import logging
import os
import sys
import pandas as pd

logger = logging.getLogger(__name__)


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
            return total
        finally:
            os.chdir(original_cwd)
            
    except Exception as e:
        logger.error(f"MITRE sync failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return -1


def run_elastic_sync():
    """
    Synchronous function to fetch rules from Elastic and save to database.
    This runs in a thread pool to avoid blocking the async event loop.
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
            import elastic_helper
            from app.services.database import get_database_service
            
            db = get_database_service()
            
            logger.info("Starting Elastic sync...")
            df = elastic_helper.fetch_detection_rules(check_mappings=True)
            
            if df is not None and not df.empty:
                audit_records = df.to_dict('records')
                count = db.save_audit_results(audit_records)
                logger.info(f"Synced {count} rules from Elastic")
                return count
            else:
                logger.warning("No rules fetched from Elastic - check connection settings")
                return 0
        finally:
            os.chdir(original_cwd)
            
    except Exception as e:
        logger.error(f"Elastic sync failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return -1


async def trigger_sync():
    """
    Async wrapper to run the sync in a thread pool.
    Use this from async endpoints.
    """
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, run_elastic_sync)
