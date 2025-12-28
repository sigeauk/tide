import time
import os
import schedule
import importlib 
from datetime import datetime
from dotenv import load_dotenv

# --- LOCAL MODULES ---
import database as db
from log import log_info, log_error, log_debug

# --- HELPER MODULES (Initial Import) ---
try:
    import elastic_helper
except ImportError:
    elastic_helper = None
    log_error("❌ WORKER: Could not load elastic_helper")

try:
    import cti_helper
except ImportError:
    cti_helper = None
    log_error("❌ WORKER: Could not load cti_helper")

try:
    import gitlab_helper
except ImportError:
    gitlab_helper = None
    log_error("❌ WORKER: Could not load gitlab_helper")

# --- CONFIG ---
load_dotenv()

def get_interval():
    try:
        return int(os.getenv("SYNC_INTERVAL_MINUTES", 5))
    except:
        return 5

# ==========================================
# --- JOB FUNCTIONS ---
# ==========================================

def run_elastic_sync():
    if elastic_helper:
        try:
            importlib.reload(elastic_helper)
        except Exception as e:
            log_error(f"⚠️ WORKER: Failed to reload elastic_helper: {e}")

    if not elastic_helper: return
    log_info("🔄 WORKER: Starting Elastic Sync...")
    try:
        df = elastic_helper.fetch_detection_rules(check_mappings=True)
        if not df.empty:
            audit_records = df.to_dict('records')
            count = db.save_audit_results(audit_records)
            log_info(f"✅ WORKER: Synced {count} Elastic rules.")
        else:
            log_error("⚠️ WORKER: No rules fetched from Elastic.")
    except Exception as e:
        log_error(f"❌ WORKER: Elastic Sync Failed: {e}")
        import traceback
        log_error(traceback.format_exc())

def run_opencti_sync():
    # Hot Reload CTI Helper too
    if cti_helper:
        try:
            importlib.reload(cti_helper)
        except: pass

    if not cti_helper: return
    log_info("🔄 WORKER: Starting OpenCTI Sync...")
    try:
        url = os.getenv("OPENCTI_URL")
        token = os.getenv("OPENCTI_TOKEN")
        if not url or not token:
            return

        df = cti_helper.get_threat_landscape(api_url=url, api_token=token)
        if not df.empty:
            count = db.save_threat_data(df)
            log_info(f"✅ WORKER: Saved {count} Threat Actors.")
    except Exception as e:
        log_error(f"❌ WORKER: OpenCTI Sync Failed: {e}")

def run_mitre_sync():
    # Hot Reload Database and CTI Helper (Shared modules)
    if db:
        try:
            importlib.reload(db)
        except: pass
    if cti_helper:
        try:
            importlib.reload(cti_helper)
        except: pass

    # Ensure DB schema is up to date
    db.init_db()

    if not cti_helper: return
    log_info("🔄 WORKER: Starting MITRE Feed Sync...")
    try:
        mitre_dir = "/opt/repos/mitre"
        if not os.path.exists(mitre_dir):
            log_error(f"MITRE directory not found: {mitre_dir}")
            return

        total_actors = 0
        # List all .json files in the directory
        for file in os.listdir(mitre_dir):
            if file.endswith('-attack.json'):
                source_path = os.path.join(mitre_dir, file)
                # Extract short name (e.g., "enterprise" from "enterprise-attack.json")
                short_name = file.replace('-attack.json', '')
                json_data = cti_helper.fetch_stix_data(source_path)
                if json_data:
                    df_actors = cti_helper.process_stix_bundle(json_data, source_name=short_name)
                    if not df_actors.empty:
                        count = db.save_threat_data(df_actors)
                        total_actors += count

                    # Definitions (unchanged)
                    df_defs = cti_helper.process_mitre_definitions(json_data)
                    if not df_defs.empty:
                        db.save_mitre_definitions(df_defs)

        log_info(f"✅ WORKER: MITRE Sync Complete. Updated {total_actors} actors.")
    except Exception as e:
        log_error(f"❌ WORKER: MITRE Sync Failed: {e}")

def run_gitlab_sync():
    # Hot Reload GitLab Helper
    if gitlab_helper:
        try:
            importlib.reload(gitlab_helper)
        except: pass

    if not gitlab_helper: return
    log_info("🔄 WORKER: Starting GitLab Sync...")
    try:
        url = os.getenv("GITLAB_URL")
        token = os.getenv("GITLAB_TOKEN")
        df = gitlab_helper.fetch_rules(url=url, token=token)
        if not df.empty:
            count = db.save_audit_results(df.to_dict('records'))
            log_info(f"✅ WORKER: Saved {count} rules from GitLab.")
    except Exception as e:
        log_error(f"❌ WORKER: GitLab Sync Failed: {e}")

def run_scheduled_job():
    """Runs the full suite of background tasks"""
    log_info("⏰ WORKER: Running Scheduled Full Sync...")
    run_elastic_sync()
    run_mitre_sync() 
    # run_opencti_sync() 

# ==========================================
# --- MAIN LOOP ---
# ==========================================

def main():
    log_info("🚀 WORKER: Initializing Database...")
    db.init_db()

    interval = get_interval()
    log_info(f"📅 WORKER: Schedule set to run every {interval} minutes.")
    
    schedule.every(interval).minutes.do(run_scheduled_job)

    log_info("⚡ WORKER: Executing Initial Boot Sync (This runs immediately)...")
    run_scheduled_job()

    log_info("👀 WORKER: Watching for triggers...")

    while True:
        try:
            if db.check_and_clear_trigger("sync_elastic"): run_elastic_sync()
            if db.check_and_clear_trigger("sync_opencti"): run_opencti_sync()
            if db.check_and_clear_trigger("sync_mitre"): run_mitre_sync()
            if db.check_and_clear_trigger("sync_gitlab"): run_gitlab_sync()

            schedule.run_pending()
            time.sleep(2)

        except KeyboardInterrupt:
            log_info("🛑 WORKER: Stopping...")
            break
        except Exception as e:
            log_error(f"❌ WORKER: Loop Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()