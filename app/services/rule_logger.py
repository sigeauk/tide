"""
Rule Logger Service for TIDE - Phase 5: Historical Logging.

Exports detection rule statistics as JSON lines for SIEM ingestion.
Files are written daily to a configurable log directory and retained
for a configurable number of days (default 7).
"""

import json
import os
import logging
import glob
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


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
    Reads settings from app_settings table, exports if enabled, and cleans up old files.
    
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
        
        log_path = "/app/data/log/rules"
        retention_days = int(settings.get("rule_log_retention_days", "7"))
        
        # Export current rules
        count = export_rule_logs(db, log_path)
        
        # Clean up old logs
        cleanup_old_logs(log_path, retention_days)
        
        return count
        
    except Exception as e:
        logger.error(f"Rule log export job failed: {e}")
        return 0
