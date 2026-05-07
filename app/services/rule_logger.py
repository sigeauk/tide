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
from typing import Optional, List, Dict

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


def export_rule_logs(
    db,
    log_path: str,
    validation_data: dict = None,
    siem_id: Optional[str] = None,
    space: Optional[str] = None,
    filename: Optional[str] = None,
) -> int:
    """
    Export all detection rules as JSON lines to a daily log file.

    Args:
        db: DatabaseService instance
        log_path: Directory to write log files
        validation_data: Optional dict of {rule_name: {last_checked_on, checked_by}}
        siem_id: When set, restrict the export to rules belonging to this SIEM
            (matches ``detection_rules.siem_id``). Required for per-SIEM
            scoping; omitted callers get the legacy global behaviour.
        space: When set, additionally restrict to rules in this Kibana space
            (matches ``detection_rules.space``). Drives the per-SIEM
            "Target space" field on the Rule Logging accordion.

    Returns:
        Number of rules exported
    """
    try:
        os.makedirs(log_path, exist_ok=True)
        
        today = datetime.now().strftime("%Y-%m-%d")
        # Caller can override the filename so multiple per-space files can
        # coexist in the same SIEM directory (e.g. 2026-04-29-default-rules.log).
        log_file = os.path.join(log_path, filename or f"{today}-rules.log")

        # Since 4.1.13 (Migration 45) `detection_rules` lives only in tenant
        # DBs. Iterate every tenant, set tenant context, fetch the
        # SIEM/space-scoped slice from each, and dedupe by rule_id (rules
        # for a given (siem_id, space) are identical across tenants that
        # mapped that pair, so first-write-wins is correct).
        from app.services.tenant_manager import (
            resolve_tenant_db_path,
            set_tenant_context,
            clear_tenant_context,
            get_tenant_db_path,
        )
        from app.config import get_settings
        data_dir = get_settings().data_dir
        prev_ctx = get_tenant_db_path()
        rules_by_id: Dict[str, Dict] = {}
        try:
            tenants = db.list_clients() or []
        except Exception as exc:
            logger.error(f"export_rule_logs: list_clients() failed: {exc}")
            return 0
        for tenant in tenants:
            cid = tenant.get("id")
            tname = tenant.get("name") or cid
            tpath = resolve_tenant_db_path(cid, data_dir) if cid else None
            if not tpath or not os.path.exists(tpath):
                logger.debug(
                    f"export_rule_logs: tenant '{tname}' ({cid}) has no "
                    f"tenant DB on disk yet; skipping."
                )
                continue
            try:
                set_tenant_context(tpath)
                tenant_rules = db.get_all_rules_for_export(
                    siem_id=siem_id, space=space
                )
            except Exception as exc:
                logger.warning(
                    f"export_rule_logs: tenant '{tname}' ({cid}) read failed: "
                    f"{type(exc).__name__}: {exc}"
                )
                tenant_rules = []
            finally:
                # Restore prior context (None when called from scheduler).
                if prev_ctx is None:
                    clear_tenant_context()
                else:
                    set_tenant_context(prev_ctx)
            for r in tenant_rules:
                rid = r.get("rule_id")
                if rid and rid not in rules_by_id:
                    rules_by_id[rid] = r
        rules = list(rules_by_id.values())

        if not rules:
            logger.warning(
                f"No detection rules to export (siem_id={siem_id or '<any>'}, "
                f"space={space or '<any>'})"
            )
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
            # Filename may be either YYYY-MM-DD-rules.log (legacy) or
            # YYYY-MM-DD-<space>-rules.log (per-space). Date is always the
            # first 10 characters.
            file_date = datetime.strptime(filename[:10], "%Y-%m-%d")
            
            if file_date < cutoff:
                os.remove(filepath)
                removed += 1
                logger.debug(f"  Removed old log: {filename}")
        except (ValueError, OSError) as e:
            logger.warning(f"Could not process {filepath}: {e}")
    
    if removed:
        logger.info(f"Cleaned up {removed} old rule log files (>{retention_days} days)")
    
    return removed


def run_rule_log_export(db, siem_id: Optional[str] = None) -> int:
    """Main entry point for scheduled rule log export.

    v4.0.8+: Iterates ``db.list_logging_enabled_siems()`` and writes a per-SIEM
    log file under ``/app/data/log/rules/<siem_label>/``. Each SIEM carries its
    own retention. Falls back to the legacy global behaviour (driven by
    ``app_settings.rule_log_enabled`` / ``rule_log_retention_days``) when no
    SIEM has logging turned on.

    Args:
        db: DatabaseService instance
        siem_id: Optional SIEM id. When provided, restrict the per-SIEM export
            to that single SIEM (used by the per-SIEM scheduler so each cron
            fires only its owning SIEM). Has no effect on the legacy fallback.

    Returns:
        Total number of rules exported across all targets (0 if disabled).
    """
    try:
        per_siem: List[Dict] = []
        try:
            per_siem = db.list_logging_enabled_siems() or []
        except Exception as exc:
            logger.warning(f"list_logging_enabled_siems failed, falling back to legacy: {exc}")

        if siem_id and per_siem:
            per_siem = [s for s in per_siem if str(s.get("id")) == str(siem_id)]
            if not per_siem:
                logger.debug(
                    f"run_rule_log_export: siem_id={siem_id} not in logging-enabled set, skipping"
                )
                return 0

        # ---- Per-SIEM export path (preferred) ----
        if per_siem:
            base_paths = _get_write_paths()
            total = 0
            for siem in per_siem:
                sid = siem.get("id")
                label = (siem.get("label") or sid or "siem").strip()
                # Sanitise the label for use as a directory name.
                safe_label = "".join(
                    c if c.isalnum() or c in ("-", "_", ".") else "_"
                    for c in label
                ) or "siem"
                retention = int(siem.get("log_retention_days") or 7)
                # Per-SIEM target space(s) — stored as comma-separated string.
                # Empty / missing => discover every space this SIEM owns and
                # log each one into its own file.
                raw_space = (siem.get("log_target_space") or "").strip()
                target_spaces = [s.strip() for s in raw_space.split(",") if s.strip()]
                if not target_spaces:
                    try:
                        target_spaces = db.get_all_kibana_spaces() or []
                    except Exception as exc:
                        logger.warning(f"get_all_kibana_spaces failed: {exc}")
                        target_spaces = []
                # Belt-and-braces: if we still have nothing, drop a single
                # "_all" file holding every rule for the SIEM so the operator
                # at least sees output.
                fanout = target_spaces or [None]

                today = datetime.now().strftime("%Y-%m-%d")
                count_for_siem = 0
                for space in fanout:
                    if space is None:
                        safe_space = "all"
                    else:
                        safe_space = "".join(
                            c if c.isalnum() or c in ("-", "_", ".") else "_"
                            for c in space
                        ) or "unknown"
                    # All space files for a SIEM live in the SAME directory,
                    # named <date>-<space>-rules.log, so an operator browsing
                    # the SIEM folder sees every space side by side.
                    fname = f"{today}-{safe_space}-rules.log"
                    targets = [
                        os.path.join(base, safe_label) for base in base_paths
                    ]
                    space_count = 0
                    for target_dir in targets:
                        n = export_rule_logs(
                            db, target_dir, siem_id=sid,
                            space=space, filename=fname,
                        )
                        if n > space_count:
                            space_count = n
                        cleanup_old_logs(target_dir, retention)
                    logger.info(
                        f"Rule log export for SIEM '{label}' space "
                        f"'{space or '<all>'}' (siem_id={sid}, "
                        f"retention={retention}d): {space_count} rules -> {fname}"
                    )
                    count_for_siem += space_count
                total += count_for_siem
            return total

        # ---- Legacy global path (back-compat) ----
        settings = db.get_all_settings()
        enabled = settings.get("rule_log_enabled", "false").lower() == "true"
        if not enabled:
            logger.debug("Rule logging is disabled (no per-SIEM config and global flag is off), skipping export")
            return 0

        retention_days = int(settings.get("rule_log_retention_days", "7"))
        write_paths = _get_write_paths()

        count = 0
        for path in write_paths:
            n = export_rule_logs(db, path)
            if n > count:
                count = n

        for path in write_paths:
            cleanup_old_logs(path, retention_days)

        if len(write_paths) > 1:
            logger.info(f"Rule logs written to {len(write_paths)} locations: {write_paths}")

        return count

    except Exception as e:
        logger.error(f"Rule log export job failed: {e}")
        return 0
