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
    Synchronous function to load MITRE ATT&CK data from local files.
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
            
            db = get_database_service()
            
            logger.info("🔄 Starting MITRE sync...")
            mitre_dir = "/opt/repos/mitre"
            
            if not os.path.exists(mitre_dir):
                logger.warning(f"⚠️ MITRE directory not found: {mitre_dir}")
                return 0
            
            total_actors = 0
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
                            total_actors += count
                            logger.info(f"   Loaded {count} actors from {short_name}")
                        
                        df_defs = cti_helper.process_mitre_definitions(json_data)
                        if not df_defs.empty:
                            from app.database import save_mitre_definitions
                            save_mitre_definitions(df_defs)
            
            logger.info(f"✅ MITRE sync complete. Updated {total_actors} actors.")
            return total_actors
        finally:
            os.chdir(original_cwd)
            
    except Exception as e:
        logger.error(f"❌ MITRE sync failed: {e}")
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
            
            logger.info("🔄 Starting Elastic sync...")
            df = elastic_helper.fetch_detection_rules(check_mappings=True)
            
            if df is not None and not df.empty:
                audit_records = df.to_dict('records')
                count = db.save_audit_results(audit_records)
                logger.info(f"✅ Synced {count} rules from Elastic")
                return count
            else:
                logger.warning("⚠️ No rules fetched from Elastic - check connection settings")
                return 0
        finally:
            os.chdir(original_cwd)
            
    except Exception as e:
        logger.error(f"❌ Elastic sync failed: {e}")
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
