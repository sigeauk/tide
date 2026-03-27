"""
Settings API endpoints for TIDE.
Handles reading/writing app settings, API key management, and triggering rule log exports.
"""

import logging
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from app.api.deps import DbDep, CurrentUser, RequireUser

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


# ── External API Key management ──────────────────────────────────────────────

@router.get("/api-keys", response_class=HTMLResponse)
def list_api_keys(request: Request, db: DbDep, user: RequireUser):
    """Return the API key list as an HTML partial."""
    keys = db.list_api_keys()
    if not keys:
        return HTMLResponse('<p class="text-muted" style="font-size:0.85rem;">No API keys created yet.</p>')
    rows = ""
    for k in keys:
        created = str(k["created_at"])[:19] if k["created_at"] else "-"
        used = str(k["last_used_at"])[:19] if k["last_used_at"] else "Never"
        short_hash = k["key_hash"][:12] + "…"
        rows += f"""<tr>
            <td>{k["label"]}</td>
            <td style="font-family:monospace;font-size:0.8rem;">{short_hash}</td>
            <td>{created}</td>
            <td>{used}</td>
            <td>
                <button class="btn btn-danger btn-sm"
                        hx-delete="/api/settings/api-keys/{k["key_hash"]}"
                        hx-target="#api-key-list"
                        hx-confirm="Revoke this API key?">Revoke</button>
            </td>
        </tr>"""
    return HTMLResponse(f"""
    <table class="mapping-table">
        <thead><tr><th>Label</th><th>Key ID</th><th>Created</th><th>Last Used</th><th></th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
    """)


@router.post("/api-keys", response_class=HTMLResponse)
async def create_api_key(request: Request, db: DbDep, user: RequireUser):
    """Create a new API key and return the raw key (shown once)."""
    form = await request.form()
    label = str(form.get("api_key_label", "")).strip()
    if not label:
        label = "Untitled key"
    raw_key = db.create_api_key(label)
    return HTMLResponse(f"""
    <div id="api-key-created-toast" hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">API key created — copy it now, it won't be shown again.</div>
    </div>
    <div class="alert alert-success mb-md" style="font-size:0.85rem;">
        <strong>New API Key (copy now — shown only once):</strong><br>
        <code style="display:block;margin-top:0.5rem;padding:0.5rem;background:var(--color-bg-secondary);border-radius:var(--radius-sm);word-break:break-all;user-select:all;">{raw_key}</code>
    </div>
    <div id="api-key-list" hx-get="/api/settings/api-keys" hx-trigger="load" hx-swap="innerHTML"></div>
    """)


@router.delete("/api-keys/{key_hash}", response_class=HTMLResponse)
def revoke_api_key(request: Request, key_hash: str, db: DbDep, user: RequireUser):
    """Revoke (delete) an API key."""
    db.delete_api_key(key_hash)
    keys = db.list_api_keys()
    if not keys:
        return HTMLResponse('<p class="text-muted" style="font-size:0.85rem;">No API keys created yet.</p>')
    # Return updated list
    return list_api_keys(request, db, user)

