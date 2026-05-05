"""
Settings API endpoints for TIDE.
Handles reading/writing app settings, API key management, user management, and triggering rule log exports.
"""

import logging
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from app.api.deps import ActiveClient, DbDep, CurrentUser, RequireUser, RequireAdmin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _is_local_only_account(db_user: dict) -> bool:
    return (db_user.get("auth_provider") or "").lower() == "local"


@router.get("", response_class=HTMLResponse)
def get_settings_data(request: Request, db: DbDep, user: CurrentUser, client_id: ActiveClient):
    """Get current app settings as JSON."""
    settings = db.get_all_settings(client_id=client_id)
    import json
    return HTMLResponse(json.dumps(settings), media_type="application/json")


@router.post("/save", response_class=HTMLResponse)
async def save_settings(request: Request, db: DbDep, user: CurrentUser, client_id: ActiveClient):
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
    
    db.save_settings(settings_to_save, client_id=client_id)
    
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
def trigger_rule_log_export(request: Request, db: DbDep, user: CurrentUser, client_id: ActiveClient):
    """Manually trigger a rule log export.

    Honours the per-SIEM model (``siem_inventory.log_enabled`` /
    ``log_destination_path`` / ``log_retention_days``) by delegating to
    ``run_rule_log_export``, which falls back to the legacy global path when no
    SIEM has logging turned on.
    """
    from app.services.rule_logger import run_rule_log_export, _get_write_paths

    count = run_rule_log_export(db)

    # Build a human-readable destination string for the toast: per-SIEM
    # destinations when configured, otherwise the legacy fan-out paths.
    try:
        per_siem = db.list_logging_enabled_siems() or []
    except Exception:
        per_siem = []
    if per_siem:
        dests = []
        base_paths = _get_write_paths()
        for s in per_siem:
            label = (s.get("label") or s.get("id") or "siem").strip()
            safe_label = "".join(
                c if c.isalnum() or c in ("-", "_", ".") else "_" for c in label
            ) or "siem"
            for base in base_paths:
                dests.append(f"{base}/{safe_label}/")
        path_list = ", ".join(dests) if dests else "(no destinations)"
    else:
        path_list = ", ".join(_get_write_paths())

    if count > 0:
        return HTMLResponse(f"""
        <div id="export-toast" hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-success">Exported {count} rules to {path_list}</div>
        </div>
        """)
    else:
        return HTMLResponse("""
        <div id="export-toast" hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">No rules exported. Check that at least one SIEM has logging enabled, then run a sync first.</div>
        </div>
        """)


# ── External API Key management ──────────────────────────────────────────────

@router.get("/api-keys", response_class=HTMLResponse)
def list_api_keys(request: Request, db: DbDep, user: RequireUser):
    """Return the API key list as an HTML partial."""
    is_admin = user.is_admin()
    keys = db.list_api_keys() if is_admin else db.list_api_keys(created_by_user_id=user.id)
    if not keys:
        return HTMLResponse('<p class="text-muted" style="font-size:0.85rem;">No API keys created yet.</p>')
    rows = ""
    for k in keys:
        created = str(k["created_at"])[:19] if k["created_at"] else "-"
        used = str(k["last_used_at"])[:19] if k["last_used_at"] else "Never"
        short_hash = k["key_hash"][:12] + "…"
        owner = k.get("created_by_user_id") or "legacy"
        owner_col = f"<td style=\"font-family:monospace;font-size:0.75rem;\">{owner}</td>" if is_admin else ""
        rows += f"""<tr>
            <td>{k["label"]}</td>
            <td style="font-family:monospace;font-size:0.8rem;">{short_hash}</td>
            <td>{created}</td>
            <td>{used}</td>
            {owner_col}
            <td>
                <button class="btn btn-danger btn-sm"
                        hx-delete="/api/settings/api-keys/{k["key_hash"]}"
                        hx-target="#api-key-list"
                        hx-confirm="Revoke this API key?">Revoke</button>
            </td>
        </tr>"""
    owner_head = "<th>Owner</th>" if is_admin else ""
    return HTMLResponse(f"""
    <table class="mapping-table">
        <thead><tr><th>Label</th><th>Key ID</th><th>Created</th><th>Last Used</th>{owner_head}<th></th></tr></thead>
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
    raw_key = db.create_api_key(label, created_by_user_id=user.id)
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
    key = db.get_api_key(key_hash)
    if not key:
        return list_api_keys(request, db, user)

    owner_id = key.get("created_by_user_id")
    can_revoke = user.is_admin() or (owner_id is not None and owner_id == user.id)
    if not can_revoke:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">You can only revoke your own API keys unless you are an admin.</div>
        </div>
        """ + list_api_keys(request, db, user).body.decode())

    db.delete_api_key(key_hash)
    return list_api_keys(request, db, user)


# ── Profile Management (self-service; local-only accounts) ───────────────────

@router.post("/profile/email", response_class=HTMLResponse)
async def update_profile_email(request: Request, db: DbDep, user: RequireUser):
    """Update the authenticated user's email (local-only accounts)."""
    form = await request.form()
    new_email = str(form.get("email", "")).strip().lower()

    if not new_email or "@" not in new_email:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Enter a valid email address.</div>
        </div>""")

    db_user = db.get_user_by_id(user.id)
    if not db_user:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">User account not found.</div>
        </div>""")

    if not _is_local_only_account(db_user):
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">This account is managed by SSO.</div>
        </div>""")

    existing = db.get_user_by_email(new_email)
    if existing and existing.get("id") != user.id:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Email address is already in use.</div>
        </div>""")

    db.update_user(user.id, email=new_email)
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">Email updated to {new_email}.</div>
    </div>""")


@router.post("/profile/password", response_class=HTMLResponse)
async def update_profile_password(request: Request, db: DbDep, user: RequireUser):
    """Update the authenticated user's password (local-only accounts)."""
    form = await request.form()
    current_password = str(form.get("current_password", ""))
    new_password = str(form.get("new_password", ""))
    confirm_password = str(form.get("confirm_password", ""))

    if len(new_password) < 8:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">New password must be at least 8 characters.</div>
        </div>""")

    if new_password != confirm_password:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">New password and confirmation do not match.</div>
        </div>""")

    db_user = db.get_user_by_id(user.id)
    if not db_user:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">User account not found.</div>
        </div>""")

    if not _is_local_only_account(db_user):
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">This account is managed by SSO.</div>
        </div>""")

    stored_hash = db_user.get("password_hash")
    if not stored_hash:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">No local password is set for this account.</div>
        </div>""")

    import bcrypt
    if not bcrypt.checkpw(current_password.encode(), stored_hash.encode()):
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Current password is incorrect.</div>
        </div>""")

    pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    db.update_user(user.id, password_hash=pw_hash, change_on_next_login=False)
    return HTMLResponse("""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">Password updated successfully.</div>
    </div>""")


# ── User Management (ADMIN only) ────────────────────────────────────────────

def _render_user_row(u: dict, all_roles: list, user_roles: list) -> str:
    """Render a single user table row HTML."""
    provider = (u.get("auth_provider") or "local").lower()
    if provider == "keycloak":
        source_badge = '<span class="badge badge-info">SSO</span>'
    elif provider == "hybrid":
        source_badge = '<span class="badge badge-primary">Hybrid</span>'
    else:
        source_badge = '<span class="badge badge-secondary">Local</span>'
    active_checked = "checked" if u.get("is_active") else ""
    role_checkboxes = ""
    for r in all_roles:
        checked = "checked" if r["name"] in user_roles else ""
        role_checkboxes += (
            f'<label class="role-checkbox"><input type="checkbox" name="roles" '
            f'value="{r["name"]}" {checked}> {r["name"]}</label> '
        )
    last_login = str(u["last_login"])[:19] if u.get("last_login") else "Never"
    reset_controls = ""
    reset_controls = f'''
        <form class="inline-role-form"
              hx-post="/api/settings/users/{u['id']}/reset-password"
              hx-swap="none"
              style="margin-top:0.45rem; display:flex; flex-wrap:wrap; gap:0.35rem; align-items:center;">
            <input type="password" name="new_password" class="form-input" minlength="8" required
                   placeholder="New password" style="max-width:180px; font-size:0.75rem;">
            <label class="role-checkbox" style="font-size:0.72rem;">
                <input type="checkbox" name="change_on_next_login" checked> Require change next login
            </label>
            <button type="submit" class="btn btn-sm btn-secondary">Reset</button>
        </form>
    '''
    return f"""<tr id="user-row-{u['id']}">
        <td>{u['username']}</td>
        <td>{u.get('email') or '-'}</td>
        <td>{source_badge}</td>
        <td>
            <form class="inline-role-form"
                  hx-post="/api/settings/users/{u['id']}/roles"
                  hx-target="#user-list"
                  hx-swap="innerHTML">
                {role_checkboxes}
                <button type="submit" class="btn btn-sm btn-secondary">Save</button>
            </form>
        </td>
        <td>
            <label class="toggle-switch toggle-sm">
                <input type="checkbox" {active_checked}
                       hx-post="/api/settings/users/{u['id']}/toggle-active"
                       hx-target="#user-list"
                       hx-swap="innerHTML">
                <span class="toggle-slider"></span>
            </label>
        </td>
        <td>{last_login}</td>
        <td>
            <button class="btn btn-danger btn-sm"
                    hx-delete="/api/settings/users/{u['id']}"
                    hx-target="#user-list"
                    hx-swap="innerHTML"
                    hx-confirm="Delete user {u['username']}?">Delete</button>
            {reset_controls}
        </td>
    </tr>"""


def _render_user_table(db) -> str:
    """Render the full users table HTML."""
    users = db.get_all_users()
    all_roles = db.get_all_roles()
    if not users:
        return '<p class="text-muted" style="font-size:0.85rem;">No users found.</p>'
    rows = ""
    for u in users:
        user_roles = db.get_user_roles(u["id"])
        rows += _render_user_row(u, all_roles, user_roles)
    return f"""
    <table class="mapping-table">
        <thead><tr>
            <th>Username</th><th>Email</th><th>Source</th>
            <th>Roles</th><th>Active</th><th>Last Login</th><th></th>
        </tr></thead>
        <tbody>{rows}</tbody>
    </table>"""


@router.get("/users", response_class=HTMLResponse)
def list_users(request: Request, db: DbDep, user: RequireAdmin):
    """Return the users list as an HTML partial (ADMIN only)."""
    return HTMLResponse(_render_user_table(db))


@router.post("/users", response_class=HTMLResponse)
async def create_user(request: Request, db: DbDep, user: RequireAdmin):
    """Create a new local user (ADMIN only)."""
    form = await request.form()
    username = str(form.get("new_username", "")).strip()
    email = str(form.get("new_email", "")).strip() or None
    full_name = str(form.get("new_full_name", "")).strip() or None
    password = str(form.get("new_password", ""))
    roles = form.getlist("new_roles")

    if not username or not password:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Username and password are required.</div>
        </div>""")

    if len(password) < 8:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Password must be at least 8 characters.</div>
        </div>""")

    # Check uniqueness
    existing = db.get_user_by_username(username)
    if existing:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Username already exists.</div>
        </div>""")

    import bcrypt
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    uid = db.create_user(username=username, email=email, full_name=full_name,
                         password_hash=pw_hash, auth_provider="local")
    if roles:
        db.set_user_roles(uid, roles)

    html = _render_user_table(db)
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">User '{username}' created.</div>
    </div>
    {html}""")


@router.post("/users/{user_id}/roles", response_class=HTMLResponse)
async def update_user_roles(request: Request, user_id: str, db: DbDep, user: RequireAdmin):
    """Update roles for a user (ADMIN only)."""
    form = await request.form()
    roles = form.getlist("roles")
    db.set_user_roles(user_id, roles)
    return HTMLResponse(_render_user_table(db))


@router.post("/users/{user_id}/toggle-active", response_class=HTMLResponse)
def toggle_user_active(request: Request, user_id: str, db: DbDep, user: RequireAdmin):
    """Toggle user active status (ADMIN only)."""
    db_user = db.get_user_by_id(user_id)
    if not db_user:
        return HTMLResponse(_render_user_table(db))
    new_status = not db_user.get("is_active", True)
    db.update_user(user_id, is_active=new_status)
    return HTMLResponse(_render_user_table(db))


@router.post("/users/{user_id}/reset-password", response_class=HTMLResponse)
async def reset_user_password(request: Request, user_id: str, db: DbDep, user: RequireAdmin):
    """Reset any user's local password (ADMIN only)."""
    form = await request.form()
    new_password = str(form.get("new_password", ""))
    change_on_next_login = str(form.get("change_on_next_login", "on")).lower() in {"on", "true", "1"}
    if len(new_password) < 8:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Password must be at least 8 characters.</div>
        </div>""")

    target_user = db.get_user_by_id(user_id)
    if not target_user:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">User not found.</div>
        </div>""")

    import bcrypt
    pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    provider = (target_user.get("auth_provider") or "local").lower()
    update_fields = {
        "password_hash": pw_hash,
        "change_on_next_login": change_on_next_login,
    }
    # Preserve SSO while enabling local login when admin sets a local hash.
    if provider == "keycloak":
        update_fields["auth_provider"] = "hybrid"
    db.update_user(user_id, **update_fields)
    status_text = "Password reset. User must change it at next login." if change_on_next_login else "Password reset successfully."
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">{status_text}</div>
    </div>""")


@router.delete("/users/{user_id}", response_class=HTMLResponse)
def delete_user(request: Request, user_id: str, db: DbDep, user: RequireAdmin):
    """Delete a user (ADMIN only). Cannot delete yourself."""
    if user_id == user.id:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">You cannot delete your own account.</div>
        </div>""")
    db.delete_user(user_id)
    return HTMLResponse(_render_user_table(db))


# ── Permissions Management (ADMIN only) ─────────────────────────────────────

def _render_permissions_table(db) -> str:
    """Render the full permissions matrix as an HTML table."""
    # Exclude ADMIN – admins always have full access to prevent lockouts
    roles = [r for r in db.get_all_roles() if r["name"] != "ADMIN"]
    resources = db.get_all_resources()
    matrix = db.get_permissions_matrix()

    # Build a lookup: (role_name, resource) -> {can_read, can_write}
    lookup = {}
    for entry in matrix:
        lookup[(entry["role_name"], entry["resource"])] = {
            "can_read": entry["can_read"],
            "can_write": entry["can_write"],
            "role_id": entry["role_id"],
        }

    if not roles or not resources:
        return '<p class="text-muted" style="font-size:0.85rem;">No permissions configured.</p>'

    # Separate page and tab resources
    page_resources = sorted([r for r in resources if r.startswith("page:")])
    tab_resources = [r for r in resources if r.startswith("tab:")]

    # Keep settings-tab order predictable with Profile first.
    tab_order = [
        "tab:profile",
        "tab:classifications",
        "tab:integrations",
        "tab:logging",
        "tab:sigma",
        "tab:users",
    ]
    tab_resources = [res for res in tab_order if res in tab_resources] + [res for res in tab_resources if res not in tab_order]

    def _resource_label(res: str) -> str:
        """Human-readable label for a resource."""
        parts = res.split(":", 1)
        name = parts[1] if len(parts) > 1 else res
        return name.replace("_", " ").title()

    def _resource_type_badge(res: str) -> str:
        if res.startswith("page:"):
            return '<span class="badge badge-info" style="font-size:0.65rem;">Page</span>'
        return '<span class="badge badge-secondary" style="font-size:0.65rem;">Tab</span>'

    def _build_rows(resource_list: list) -> str:
        rows = ""
        for res in resource_list:
            rows += f'<tr><td>{_resource_type_badge(res)} {_resource_label(res)}</td>'
            for role in roles:
                key = (role["name"], res)
                perm = lookup.get(key, {"can_read": False, "can_write": False, "role_id": role["id"]})
                role_id = role["id"]
                r_checked = "checked" if perm["can_read"] else ""
                w_checked = "checked" if perm["can_write"] else ""
                rows += f'''<td style="text-align:center;">
                    <div style="display:flex; gap:0.5rem; justify-content:center; align-items:center;">
                        <label class="role-checkbox" title="Read">
                            <input type="checkbox" name="perm" {r_checked}
                                hx-post="/api/settings/permissions"
                                hx-vals='{{"role_id":"{role_id}","resource":"{res}","access":"read","state":"{("off" if r_checked else "on")}"}}'
                                hx-target="#permissions-matrix"
                                hx-swap="innerHTML"> R
                        </label>
                        <label class="role-checkbox" title="Write">
                            <input type="checkbox" name="perm" {w_checked}
                                hx-post="/api/settings/permissions"
                                hx-vals='{{"role_id":"{role_id}","resource":"{res}","access":"write","state":"{("off" if w_checked else "on")}"}}'
                                hx-target="#permissions-matrix"
                                hx-swap="innerHTML"> W
                        </label>
                    </div>
                </td>'''
            rows += '</tr>'
        return rows

    role_headers = "".join(f'<th style="text-align:center;">{r["name"]}</th>' for r in roles)

    html = f'''
    <table class="mapping-table">
        <thead><tr><th>Resource</th>{role_headers}</tr></thead>
        <tbody>
            <tr><td colspan="{len(roles) + 1}" style="font-weight:600; background:var(--color-bg-elevated); padding:0.5rem;">Pages</td></tr>
            {_build_rows(page_resources)}
            <tr><td colspan="{len(roles) + 1}" style="font-weight:600; background:var(--color-bg-elevated); padding:0.5rem;">Settings Tabs</td></tr>
            {_build_rows(tab_resources)}
        </tbody>
    </table>'''
    return html


@router.get("/permissions", response_class=HTMLResponse)
def get_permissions(request: Request, db: DbDep, user: RequireAdmin):
    """Return permissions matrix as HTML partial (ADMIN only)."""
    return HTMLResponse(_render_permissions_table(db))


@router.post("/permissions", response_class=HTMLResponse)
async def update_permission(request: Request, db: DbDep, user: RequireAdmin):
    """Toggle a single permission (ADMIN only)."""
    form = await request.form()
    role_id = str(form.get("role_id", ""))
    resource = str(form.get("resource", ""))
    access = str(form.get("access", ""))  # 'read' or 'write'
    state = str(form.get("state", ""))    # 'on' or 'off'

    if not role_id or not resource or access not in ("read", "write"):
        return HTMLResponse(_render_permissions_table(db))

    # Block edits to ADMIN role – admins always have full access
    with db.get_shared_connection() as conn:
        admin_check = conn.execute(
            "SELECT name FROM roles WHERE id = ?", [role_id]
        ).fetchone()
    if admin_check and admin_check[0] == "ADMIN":
        return HTMLResponse(_render_permissions_table(db))

    # Get current permission
    current = db.check_permission([], resource)  # need role-specific lookup
    # Direct DB lookup for this specific role+resource
    with db.get_shared_connection() as conn:
        row = conn.execute(
            "SELECT can_read, can_write FROM role_permissions WHERE role_id = ? AND resource = ?",
            [role_id, resource],
        ).fetchone()
    cur_read = row[0] if row else False
    cur_write = row[1] if row else False

    new_val = state == "on"
    if access == "read":
        db.set_permission(role_id, resource, new_val, cur_write)
    else:
        db.set_permission(role_id, resource, cur_read, new_val)

    return HTMLResponse(_render_permissions_table(db))

