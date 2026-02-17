"""
Settings API endpoints for TIDE.
Handles reading/writing app settings and triggering rule log exports.
"""

import logging
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse

from app.api.deps import DbDep, CurrentUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("", response_class=HTMLResponse)
def get_settings_data(request: Request, db: DbDep, user: CurrentUser):
    """Get current app settings as JSON."""
    settings = db.get_all_settings()
    import json
    return HTMLResponse(json.dumps(settings), media_type="application/json")


@router.post("/save", response_class=HTMLResponse)
async def save_settings(request: Request, db: DbDep, user: CurrentUser):
    """
    Save app settings from form submission.
    Returns a toast notification on success.
    """
    form = await request.form()
    
    # Extract settings from form
    settings_to_save = {}
    
    # Rule logging settings
    settings_to_save["rule_log_enabled"] = "true" if form.get("rule_log_enabled") == "on" else "false"
    
    schedule = form.get("rule_log_schedule", "").strip()
    if schedule:
        settings_to_save["rule_log_schedule"] = schedule
    
    retention = form.get("rule_log_retention_days", "").strip()
    if retention:
        try:
            days = int(retention)
            if 1 <= days <= 365:
                settings_to_save["rule_log_retention_days"] = str(days)
        except ValueError:
            pass
    
    db.save_settings(settings_to_save)
    
    # Reschedule rule log job if needed
    try:
        from app.main import reschedule_rule_log_job
        reschedule_rule_log_job()
    except Exception as e:
        logger.warning(f"Could not reschedule rule log job: {e}")
    
    logger.info(f"Settings saved: {list(settings_to_save.keys())}")
    
    return HTMLResponse("""
    <div id="settings-toast" hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">Settings saved successfully</div>
    </div>
    """)


@router.post("/rule-log/export", response_class=HTMLResponse)
def trigger_rule_log_export(request: Request, db: DbDep, user: CurrentUser):
    """Manually trigger a rule log export to all active paths."""
    from app.services.rule_logger import export_rule_logs, cleanup_old_logs, _get_write_paths
    
    settings = db.get_all_settings()
    retention_days = int(settings.get("rule_log_retention_days", "7"))
    write_paths = _get_write_paths()
    
    count = 0
    for path in write_paths:
        n = export_rule_logs(db, path)
        if n > count:
            count = n
        cleanup_old_logs(path, retention_days)
    
    path_list = ", ".join(write_paths)
    if count > 0:
        return HTMLResponse(f"""
        <div id="export-toast" hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-success">Exported {count} rules to {path_list}</div>
        </div>
        """)
    else:
        return HTMLResponse("""
        <div id="export-toast" hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">No rules to export. Run a sync first.</div>
        </div>
        """)

