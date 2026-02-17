"""
Rule Logger Service for TIDE - Phase 5: Historical Logging.

Exports detection rule statistics as JSON lines for SIEM ingestion.
Files are written daily to a configurable log directory and retained
for a configurable number of days (default 7).

Dual-write behaviour:
- Logs are ALWAYS written to the app path  (/app/data/log/rules).
- If a separate host mount exists at /mnt/rule-logs, logs are copied
  there too (mount provided by RULE_LOG_PATH in docker-compose).
"""

import json
import os
import logging
import glob
from datetime import datetime, timedelta
from typing import Optional, List

logger = logging.getLogger(__name__)

# Canonical paths inside the container
APP_LOG_PATH = "/app/data/log/rules"
HOST_LOG_MOUNT = "/mnt/rule-logs"


def _is_separate_mount(path_a: str, path_b: str) -> bool:
    """Return True if path_b exists and is NOT the same directory as path_a."""
    if not os.path.isdir(path_b):
        return False
    try:
        return not os.path.samefile(path_a, path_b)
    except (OSError, ValueError):
        return True


def _get_write_paths() -> List[str]:
    """
    Return the list of directories the rule logger should write to.
    Always includes APP_LOG_PATH; includes HOST_LOG_MOUNT when it is a
    separate mount point (i.e. RULE_LOG_PATH was set in docker-compose).
    """
    os.makedirs(APP_LOG_PATH, exist_ok=True)
    paths = [APP_LOG_PATH]
    if _is_separate_mount(APP_LOG_PATH, HOST_LOG_MOUNT):
        paths.append(HOST_LOG_MOUNT)
    return paths


def export_rule_logs(db, log_path: str, validation_data: dict = None) -> int:
    """
    Export all detection rules as JSON lines to a daily log file.
    
    Args:
        db: DatabaseService instance
        log_path: Directory to write log files
        validation_data: Optional dict of {rule_name: {last_checked_on, checked_by}}
    
    Returns:
        Number of rules exported
    """
    try:
        os.makedirs(log_path, exist_ok=True)
        
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = os.path.join(log_path, f"{today}-rules.log")
        
        # Get all rules from DB
        rules = db.get_all_rules_for_export()
        if not rules:
            logger.warning("No detection rules to export")
            return 0
        
        # Load validation data if not provided
        if validation_data is None:
            validation_data = db._load_validation_data()
        
        # Write JSON lines
        count = 0
        with open(log_file, 'w') as f:
            for rule in rules:
                # Build the log entry matching Phase 5 spec
                entry = {
                    "date": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "rule_id": rule.get("rule_id", ""),
                    "name": rule.get("name", ""),
                    "space": rule.get("space", ""),
                    "severity": rule.get("severity", ""),
                    "author": rule.get("author", ""),
                    "enabled": bool(rule.get("enabled", False)),
                    "score_mapping": rule.get("score_mapping", 0),
                    "score_search_time": rule.get("score_search_time", 0),
                    "score_field_type": rule.get("score_field_type", 0),
                    "score_language": rule.get("score_language", 0),
                    "quality_score": rule.get("quality_score", 0),
                    "score_note": rule.get("score_note", 0),
                    "score_override": rule.get("score_override", 0),
                    "score_tactics": rule.get("score_tactics", 0),
                    "score_techniques": rule.get("score_techniques", 0),
                    "score_author": rule.get("score_author", 0),
                    "score_highlights": rule.get("score_highlights", 0),
                    "meta_score": rule.get("meta_score", 0),
                    "score": rule.get("score", 0),
                    "mitre_ids": rule.get("mitre_ids", []),
                }
                
                # Add validation info from checkedRule data
                rule_name = rule.get("name", "")
                if rule_name in validation_data:
                    vd = validation_data[rule_name]
                    entry["last_checked_on"] = vd.get("last_checked_on", "")
                    entry["checked_by"] = vd.get("checked_by", "")
                else:
                    entry["last_checked_on"] = ""
                    entry["checked_by"] = ""
                
                f.write(json.dumps(entry) + "\n")
                count += 1
        
        logger.info(f"Exported {count} rules to {log_file}")
        return count
        
    except Exception as e:
        logger.error(f"Rule log export failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return 0


def cleanup_old_logs(log_path: str, retention_days: int = 7) -> int:
    """
    Remove log files older than retention_days.
    
    Args:
        log_path: Directory containing log files
        retention_days: Number of days to retain (default 7)
    
    Returns:
        Number of files removed
    """
    if not os.path.exists(log_path):
        return 0
    
    cutoff = datetime.now() - timedelta(days=retention_days)
    removed = 0
    
    for filepath in glob.glob(os.path.join(log_path, "*-rules.log")):
        try:
            filename = os.path.basename(filepath)
            # Parse date from filename: YYYY-MM-DD-rules.log
            date_str = filename.replace("-rules.log", "")
            file_date = datetime.strptime(date_str, "%Y-%m-%d")
            
            if file_date < cutoff:
                os.remove(filepath)
                removed += 1
                logger.debug(f"  Removed old log: {filename}")
        except (ValueError, OSError) as e:
            logger.warning(f"Could not process {filepath}: {e}")
    
    if removed:
        logger.info(f"Cleaned up {removed} old rule log files (>{retention_days} days)")
    
    return removed


def run_rule_log_export(db) -> int:
    """
    Main entry point for scheduled rule log export.
    Reads settings from app_settings table, exports if enabled, and cleans up
    old files.  Writes to ALL active paths (app data dir + host mount).
    
    Args:
        db: DatabaseService instance
    
    Returns:
        Number of rules exported (0 if disabled)
    """
    try:
        settings = db.get_all_settings()
        
        enabled = settings.get("rule_log_enabled", "false").lower() == "true"
        if not enabled:
            logger.debug("Rule logging is disabled, skipping export")
            return 0
        
        retention_days = int(settings.get("rule_log_retention_days", "7"))
        write_paths = _get_write_paths()
        
        # Export current rules to every active path
        count = 0
        for path in write_paths:
            n = export_rule_logs(db, path)
            if n > count:
                count = n
        
        # Clean up old logs in every active path
        for path in write_paths:
            cleanup_old_logs(path, retention_days)
        
        if len(write_paths) > 1:
            logger.info(f"Rule logs written to {len(write_paths)} locations: {write_paths}")
        
        return count
        
    except Exception as e:
        logger.error(f"Rule log export job failed: {e}")
        return 0
