"""
Management Hub API endpoints for TIDE v4.0.0.
Centralized admin area for Clients, SIEM Inventory, Users, and Permissions.
All endpoints require ADMIN role.
"""

import logging
import threading
import uuid as _uuid
from html import escape as _esc
from typing import Optional

import requests as http_requests
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from app.api.deps import DbDep, RequireAdmin, ActiveClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory move-task tracker (async move system)
# ---------------------------------------------------------------------------
_move_tasks: dict = {}   # task_id -> { status, message, client_id, result }

router = APIRouter(prefix="/api/management", tags=["management"])


# ---------------------------------------------------------------------------
# Tab partials -- HTMX tab switching
# ---------------------------------------------------------------------------

@router.get("/tab/clients", response_class=HTMLResponse)
def tab_clients(request: Request, db: DbDep, user: RequireAdmin, client_id: ActiveClient):
    """Clients tab partial for the management hub.

    Super-admins see every tenant; tenant admins only see clients they belong
    to (which always includes the active client).
    """
    from app.inventory_engine import count_systems, count_playbooks
    from app.services.tenant_manager import tenant_context_for
    if user.is_superadmin:
        clients = db.list_clients()
    else:
        allowed = set(db.get_user_client_ids(user.id))
        clients = [c for c in db.list_clients() if c["id"] in allowed]
    for c in clients:
        try:
            c["_siem_count"] = len(db.get_client_siems(c["id"]))
        except Exception:
            logger.exception("tab_clients: get_client_siems failed for %s", c["id"])
            c["_siem_count"] = 0
        try:
            c["_user_count"] = len(db.get_client_users(c["id"]))
        except Exception:
            logger.exception("tab_clients: get_client_users failed for %s", c["id"])
            c["_user_count"] = 0
        try:
            with tenant_context_for(c["id"]):
                c["_system_count"] = count_systems(client_id=c["id"])
                c["_baseline_count"] = count_playbooks(client_id=c["id"])
        except Exception:
            logger.exception("tab_clients: tenant counts failed for %s", c["id"])
            c["_system_count"] = 0
            c["_baseline_count"] = 0
    return _render_clients_tab(clients)


@router.get("/tab/siems", response_class=HTMLResponse)
def tab_siems(request: Request, db: DbDep, user: RequireAdmin, client_id: ActiveClient):
    """SIEMs tab partial for the management hub. Tenant admins see SIEMs linked to
    their clients **plus** any unassigned SIEMs (so freshly-created or orphaned
    inventory items don't vanish on the next refresh — see 4.0.12 fix)."""
    siems = db.list_siem_inventory()
    for s in siems:
        s["_clients"] = db.get_siem_clients(s["id"])
    if not user.is_superadmin:
        allowed = set(db.get_user_client_ids(user.id))
        siems = [
            s for s in siems
            if not s.get("_clients")  # unassigned — visible to every admin
            or any(c.get("id") in allowed for c in (s.get("_clients") or []))
        ]
    return _render_siems_tab(siems)


def _filter_users_for_admin(db, user, users):
    """Return only users that share a tenant with the requesting admin.

    Super-admins see everyone. Tenant admins see users who are members of any
    client they themselves administer.
    """
    if user.is_superadmin:
        return users
    admin_clients = {
        cid for cid, roles in (user.client_roles or {}).items()
        if any(r.upper() == "ADMIN" for r in roles)
    }
    if not admin_clients:
        return []
    return [
        u for u in users
        if admin_clients & set(db.get_user_client_ids(u["id"]))
    ]


@router.get("/tab/users", response_class=HTMLResponse)
def tab_users(request: Request, db: DbDep, user: RequireAdmin, client_id: ActiveClient):
    """Users tab partial for the management hub."""
    users = _filter_users_for_admin(db, user, db.get_all_users())
    all_roles = db.get_all_roles()
    for u in users:
        u["_roles"] = db.get_user_roles(u["id"], client_id=client_id)
        u["_client_ids"] = db.get_user_client_ids(u["id"])
    if user.is_superadmin:
        clients = db.list_clients()
    else:
        allowed = set(db.get_user_client_ids(user.id))
        clients = [c for c in db.list_clients() if c["id"] in allowed]
    return _render_users_tab(users, all_roles, clients)


def _refresh_users_tab(db, user=None, client_id: Optional[str] = None) -> str:
    """Re-render the management users tab after a mutation."""
    users = db.get_all_users()
    if user is not None:
        users = _filter_users_for_admin(db, user, users)
    all_roles = db.get_all_roles()
    for u in users:
        u["_roles"] = db.get_user_roles(u["id"], client_id=client_id)
        u["_client_ids"] = db.get_user_client_ids(u["id"])
    if user is not None and not user.is_superadmin:
        allowed = set(db.get_user_client_ids(user.id))
        clients = [c for c in db.list_clients() if c["id"] in allowed]
    else:
        clients = db.list_clients()
    return _render_users_tab(users, all_roles, clients)


@router.post("/users", response_class=HTMLResponse)
async def mgmt_create_user(request: Request, db: DbDep, user: RequireAdmin, client_id: ActiveClient):
    """Create a local user from the management hub.

    The new user is assigned to the *active* client. Role assignment now happens
    per-tenant from the Client Detail page — the create form has no roles field.
    """
    form = await request.form()
    username = str(form.get("new_username", "")).strip()
    email = str(form.get("new_email", "")).strip() or None
    full_name = str(form.get("new_full_name", "")).strip() or None
    password = str(form.get("new_password", ""))
    # Roles are no longer assigned at creation time \u2014 they are managed per-tenant
    # from the Client Detail page.

    if not username or not password:
        return HTMLResponse(
            '<div hx-swap-oob="afterbegin:#toast-container">'
            '<div class="toast toast-warning">Username and password are required.</div></div>'
        )
    if len(password) < 8:
        return HTMLResponse(
            '<div hx-swap-oob="afterbegin:#toast-container">'
            '<div class="toast toast-warning">Password must be at least 8 characters.</div></div>'
        )
    existing = db.get_user_by_username(username)
    if existing:
        return HTMLResponse(
            '<div hx-swap-oob="afterbegin:#toast-container">'
            '<div class="toast toast-warning">Username already exists.</div></div>'
        )

    import bcrypt
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    uid = db.create_user(username=username, email=email, full_name=full_name,
                         password_hash=pw_hash, auth_provider="local")
    db.assign_user_to_client(uid, client_id, is_default=True)

    html = _refresh_users_tab(db, user=user, client_id=client_id)
    return HTMLResponse(
        f'<div hx-swap-oob="afterbegin:#toast-container">'
        f'<div class="toast toast-success">User \'{_esc(username)}\' created. Assign roles from the client detail page.</div></div>{html}'
    )


@router.post("/users/{user_id}/roles", response_class=HTMLResponse)
async def mgmt_update_user_roles(request: Request, user_id: str, db: DbDep,
                                  user: RequireAdmin, client_id: ActiveClient):
    """Update roles for a user in the *active* client only."""
    # Tenant admins can only mutate users that share their admin tenants.
    if not user.is_superadmin:
        target_clients = set(db.get_user_client_ids(user_id))
        admin_clients = {
            cid for cid, roles in (user.client_roles or {}).items()
            if any(r.upper() == "ADMIN" for r in roles)
        }
        if not (target_clients & admin_clients):
            return HTMLResponse(
                '<div hx-swap-oob="afterbegin:#toast-container">'
                '<div class="toast toast-warning">You do not administer any tenant this user belongs to.</div></div>',
                status_code=200,
            )
        if client_id not in admin_clients:
            return HTMLResponse(
                '<div hx-swap-oob="afterbegin:#toast-container">'
                '<div class="toast toast-warning">You can only edit roles for the tenant you administer.</div></div>',
                status_code=200,
            )
    form = await request.form()
    roles = form.getlist("roles")
    db.set_user_roles(user_id, roles, client_id=client_id)
    return HTMLResponse(_refresh_users_tab(db, user=user, client_id=client_id))


@router.post("/users/{user_id}/toggle-active", response_class=HTMLResponse)
def mgmt_toggle_user_active(request: Request, user_id: str, db: DbDep,
                             user: RequireAdmin, client_id: ActiveClient):
    """Toggle user active status from the management hub."""
    db_user = db.get_user_by_id(user_id)
    if db_user:
        db.update_user(user_id, is_active=not db_user.get("is_active", True))
    return HTMLResponse(_refresh_users_tab(db, user=user, client_id=client_id))


@router.delete("/users/{user_id}", response_class=HTMLResponse)
def mgmt_delete_user(request: Request, user_id: str, db: DbDep, user: RequireAdmin):
    """Delete a user from the management hub."""
    if user_id == user.id:
        return HTMLResponse(
            '<div hx-swap-oob="afterbegin:#toast-container">'
            '<div class="toast toast-warning">You cannot delete your own account.</div></div>'
        )
    db.delete_user(user_id)
    return HTMLResponse(_refresh_users_tab(db))


@router.get("/tab/permissions", response_class=HTMLResponse)
def tab_permissions(request: Request, db: DbDep, user: RequireAdmin):
    """Permissions tab partial for the management hub."""
    return _render_permissions_tab(db)


@router.get("/tab/threat-intel", response_class=HTMLResponse)
def tab_threat_intel(request: Request, db: DbDep, user: RequireAdmin):
    """Threat Intel tab partial for the management hub."""
    instances = db.list_opencti_inventory()
    for i in instances:
        i["_clients"] = db.get_opencti_clients(i["id"])
    return HTMLResponse(_render_threat_intel_tab(instances))


@router.get("/tab/gitlab", response_class=HTMLResponse)
def tab_gitlab(request: Request, db: DbDep, user: RequireAdmin):
    """GitLab tab partial for the management hub."""
    instances = db.list_gitlab_inventory()
    for i in instances:
        i["_clients"] = db.get_gitlab_clients(i["id"])
    return HTMLResponse(_render_gitlab_tab(instances))


@router.get("/tab/keycloak", response_class=HTMLResponse)
def tab_keycloak(request: Request, db: DbDep, user: RequireAdmin):
    """Keycloak tab partial for the management hub."""
    instances = db.list_keycloak_inventory()
    return HTMLResponse(_render_keycloak_tab(instances))


# ---------------------------------------------------------------------------
# Keycloak Inventory CRUD
# ---------------------------------------------------------------------------

@router.post("/keycloak/test-connection", response_class=HTMLResponse)
async def test_keycloak_connection(request: Request, db: DbDep, user: RequireAdmin):
    """Test connectivity to a Keycloak instance via its OIDC discovery endpoint."""
    form = await request.form()
    kc_id = str(form.get("keycloak_id", "")).strip()
    url = str(form.get("url", "")).strip()
    realm = str(form.get("realm", "master")).strip() or "master"

    if not url:
        return HTMLResponse('<span class="badge badge-warning">URL is required</span>')

    def _persist(status: str, msg: str) -> None:
        if not kc_id:
            return
        try:
            db.update_inventory_test_status("keycloak", kc_id, status, msg[:140])
        except Exception:
            pass

    try:
        import requests as _req
        discovery_url = f"{url.rstrip('/')}/realms/{realm}/.well-known/openid-configuration"
        resp = _req.get(discovery_url, timeout=8, verify=False)
        if resp.status_code == 200:
            _persist("pass", f"Realm '{realm}' discovered")
            return HTMLResponse(
                f'<span class="badge badge-success">Connected &mdash; realm <strong>{_esc(realm)}</strong> found</span>'
            )
        elif resp.status_code == 404:
            _persist("fail", f"Realm '{realm}' not found (404)")
            return HTMLResponse(
                f'<span class="badge badge-danger">Realm &ldquo;{_esc(realm)}&rdquo; not found (404)</span>'
            )
        else:
            _persist("fail", f"HTTP {resp.status_code}")
            return HTMLResponse(f'<span class="badge badge-danger">HTTP {resp.status_code}</span>')
    except Exception as exc:
        logger.warning(f"Keycloak test-connection error: {exc}")
        _persist("fail", str(exc)[:140])
        return HTMLResponse(f'<span class="badge badge-danger">Error &mdash; {str(exc)[:120]}</span>')


@router.post("/keycloak", response_class=HTMLResponse)
async def create_keycloak(request: Request, db: DbDep, user: RequireAdmin):
    """Create a Keycloak instance in the centralized inventory."""
    form = await request.form()
    label = str(form.get("label", "")).strip()
    url = str(form.get("url", "")).strip()
    realm = str(form.get("realm", "master")).strip() or "master"
    client_id_val = str(form.get("client_id", "")).strip() or None
    client_secret = str(form.get("client_secret", "")).strip() or None

    if not label or not url:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Label and URL are required.</div>
        </div>""")

    db.create_keycloak_inventory_item(label=label, url=url, realm=realm,
                                      client_id_enc=client_id_val,
                                      client_secret_enc=client_secret)
    logger.info(f"Keycloak instance created: {label} by {user.username}")

    instances = db.list_keycloak_inventory()
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">Keycloak '{_esc(label)}' created.</div>
    </div>
    {_render_keycloak_tab(instances)}""")


@router.put("/keycloak/{keycloak_id}", response_class=HTMLResponse)
async def update_keycloak(request: Request, keycloak_id: str, db: DbDep, user: RequireAdmin):
    """Update a Keycloak instance."""
    form = await request.form()
    updates = {}
    for field in ("label", "url", "realm"):
        val = form.get(field)
        if val is not None and str(val).strip():
            updates[field] = str(val).strip()
    # client_id and client_secret: only update if a new value was explicitly provided
    cid = form.get("client_id")
    if cid is not None and str(cid).strip():
        updates["client_id_enc"] = str(cid).strip()
    csecret = form.get("client_secret")
    if csecret is not None and str(csecret).strip():
        updates["client_secret_enc"] = str(csecret).strip()
    is_active = form.get("is_active")
    if is_active is not None:
        updates["is_active"] = str(is_active).lower() in ("true", "on", "1")

    db.update_keycloak_inventory_item(keycloak_id, **updates)
    logger.info(f"Keycloak instance updated: {keycloak_id} by {user.username}")

    instances = db.list_keycloak_inventory()
    return HTMLResponse(_render_keycloak_tab(instances))


@router.delete("/keycloak/{keycloak_id}", response_class=HTMLResponse)
def delete_keycloak(request: Request, keycloak_id: str, db: DbDep, user: RequireAdmin):
    """Delete a Keycloak instance from the inventory."""
    ok = db.delete_keycloak_inventory_item(keycloak_id)
    if not ok:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Keycloak instance not found.</div>
        </div>""")
    logger.info(f"Keycloak instance deleted: {keycloak_id} by {user.username}")

    instances = db.list_keycloak_inventory()
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">Keycloak instance deleted.</div>
    </div>
    {_render_keycloak_tab(instances)}""")



@router.post("/opencti/test-connection", response_class=HTMLResponse)
async def test_opencti_connection(request: Request, db: DbDep, user: RequireAdmin):
    """Test connectivity to an OpenCTI instance via its GraphQL API."""
    form = await request.form()
    opencti_id = str(form.get("opencti_id", "")).strip()
    url = str(form.get("url", "")).strip()
    token = str(form.get("token", "")).strip()

    if not url:
        return HTMLResponse('<span class="badge badge-warning">URL is required</span>')

    # When editing an existing instance the token field may be blank ("keep existing").
    # Fall back to the stored token.
    if not token and opencti_id:
        stored = db.get_opencti_active_instances()
        # get_opencti_active_instances only returns active; fetch directly
        try:
            with db.get_shared_connection() as conn:
                row = conn.execute(
                    "SELECT token_enc FROM opencti_inventory WHERE id = ?", [opencti_id]
                ).fetchone()
                if row:
                    token = row[0] or ""
        except Exception:
            pass

    if not token:
        return HTMLResponse('<span class="badge badge-warning">Token is required (no stored token found)</span>')

    try:
        import requests as _req
        gql_url = url.rstrip("/") + "/graphql"
        payload = {"query": "{ me { name } }"}
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        resp = _req.post(gql_url, json=payload, headers=headers, timeout=10, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            if "errors" in data:
                msg = data["errors"][0].get("message", "Invalid token")[:140]
                if opencti_id:
                    try: db.update_inventory_test_status("opencti", opencti_id, "fail", msg)
                    except Exception: pass
                return HTMLResponse(
                    f'<span class="badge badge-danger">Auth failed &mdash; {msg[:80]}</span>'
                )
            name = data.get("data", {}).get("me", {}).get("name", "unknown")
            if opencti_id:
                try: db.update_inventory_test_status("opencti", opencti_id, "pass", f"Logged in as {name}")
                except Exception: pass
            return HTMLResponse(f'<span class="badge badge-success">Connected &mdash; logged in as {_esc(name)}</span>')
        elif resp.status_code in (401, 403):
            if opencti_id:
                try: db.update_inventory_test_status("opencti", opencti_id, "fail", "Authentication failed (invalid token)")
                except Exception: pass
            return HTMLResponse('<span class="badge badge-danger">Authentication failed (invalid token)</span>')
        else:
            if opencti_id:
                try: db.update_inventory_test_status("opencti", opencti_id, "fail", f"HTTP {resp.status_code}")
                except Exception: pass
            return HTMLResponse(f'<span class="badge badge-danger">HTTP {resp.status_code}</span>')
    except Exception as exc:
        logger.warning(f"OpenCTI test-connection error: {exc}")
        return HTMLResponse(f'<span class="badge badge-danger">Error &mdash; {str(exc)[:120]}</span>')


@router.post("/opencti", response_class=HTMLResponse)
async def create_opencti(request: Request, db: DbDep, user: RequireAdmin):
    """Create an OpenCTI instance in the centralized inventory."""
    form = await request.form()
    label = str(form.get("label", "")).strip()
    url = str(form.get("url", "")).strip()
    token = str(form.get("token", "")).strip() or None

    if not label or not url:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Label and URL are required.</div>
        </div>""")

    db.create_opencti_inventory_item(label=label, url=url, token_enc=token)
    logger.info(f"OpenCTI instance created: {label} by {user.username}")

    instances = db.list_opencti_inventory()
    for i in instances:
        i["_clients"] = db.get_opencti_clients(i["id"])
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">OpenCTI '{_esc(label)}' created.</div>
    </div>
    {_render_threat_intel_tab(instances)}""")


@router.put("/opencti/{opencti_id}", response_class=HTMLResponse)
async def update_opencti(request: Request, opencti_id: str, db: DbDep, user: RequireAdmin):
    """Update an OpenCTI instance."""
    form = await request.form()
    updates = {}
    for field in ("label", "url"):
        val = form.get(field)
        if val is not None:
            updates[field] = str(val).strip() or None
    # The form sends 'token'; map to the DB column 'token_enc'.
    # Only update if a new value was provided (blank = keep existing).
    token_val = form.get("token")
    if token_val is not None and str(token_val).strip():
        updates["token_enc"] = str(token_val).strip()
    is_active = form.get("is_active")
    if is_active is not None:
        updates["is_active"] = str(is_active).lower() in ("true", "on", "1")

    db.update_opencti_inventory_item(opencti_id, **updates)
    logger.info(f"OpenCTI instance updated: {opencti_id} by {user.username}")

    instances = db.list_opencti_inventory()
    for i in instances:
        i["_clients"] = db.get_opencti_clients(i["id"])
    return HTMLResponse(_render_threat_intel_tab(instances))


@router.delete("/opencti/{opencti_id}", response_class=HTMLResponse)
def delete_opencti(request: Request, opencti_id: str, db: DbDep, user: RequireAdmin):
    """Delete an OpenCTI instance from the inventory."""
    ok = db.delete_opencti_inventory_item(opencti_id)
    if not ok:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">OpenCTI instance not found.</div>
        </div>""")
    logger.info(f"OpenCTI instance deleted: {opencti_id} by {user.username}")

    instances = db.list_opencti_inventory()
    for i in instances:
        i["_clients"] = db.get_opencti_clients(i["id"])
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">OpenCTI instance deleted.</div>
    </div>
    {_render_threat_intel_tab(instances)}""")


@router.post("/clients/{client_id}/opencti", response_class=HTMLResponse)
async def link_opencti_to_client(request: Request, client_id: str, db: DbDep, user: RequireAdmin):
    """Link an OpenCTI instance to a client."""
    form = await request.form()
    opencti_id = str(form.get("opencti_id", "")).strip()
    if not opencti_id:
        return HTMLResponse("")
    db.link_client_opencti(client_id, opencti_id)
    logger.info(f"OpenCTI {opencti_id} linked to client {client_id} by {user.username}")
    return _render_client_opencti_partial(client_id, db, toast="Threat Intel instance linked.")


@router.delete("/clients/{client_id}/opencti/{opencti_id}", response_class=HTMLResponse)
def unlink_opencti_from_client(request: Request, client_id: str, opencti_id: str,
                               db: DbDep, user: RequireAdmin):
    """Unlink an OpenCTI instance from a client."""
    db.unlink_client_opencti(client_id, opencti_id)
    logger.info(f"OpenCTI {opencti_id} unlinked from client {client_id} by {user.username}")
    return _render_client_opencti_partial(client_id, db, toast="Threat Intel instance unlinked.")


# ---------------------------------------------------------------------------
# GitLab Inventory CRUD
# ---------------------------------------------------------------------------

@router.post("/gitlab", response_class=HTMLResponse)
async def create_gitlab(request: Request, db: DbDep, user: RequireAdmin):
    """Create a GitLab instance in the centralized inventory."""
    form = await request.form()
    label = str(form.get("label", "")).strip()
    url = str(form.get("url", "")).strip()
    token = str(form.get("token", "")).strip() or None
    default_group = str(form.get("default_group", "")).strip() or None

    if not label or not url:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Label and URL are required.</div>
        </div>""")

    db.create_gitlab_inventory_item(label=label, url=url, token_enc=token,
                                    default_group=default_group)
    logger.info(f"GitLab instance created: {label} by {user.username}")

    instances = db.list_gitlab_inventory()
    for i in instances:
        i["_clients"] = db.get_gitlab_clients(i["id"])
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">GitLab '{_esc(label)}' created.</div>
    </div>
    {_render_gitlab_tab(instances)}""")


@router.put("/gitlab/{gitlab_id}", response_class=HTMLResponse)
async def update_gitlab(request: Request, gitlab_id: str, db: DbDep, user: RequireAdmin):
    """Update a GitLab instance."""
    form = await request.form()
    updates = {}
    for field in ("label", "url", "default_group"):
        val = form.get(field)
        if val is not None:
            updates[field] = str(val).strip() or None
    if form.get("token") is not None:
        updates["token_enc"] = str(form.get("token")).strip() or None
    is_active = form.get("is_active")
    if is_active is not None:
        updates["is_active"] = str(is_active).lower() in ("true", "on", "1")

    db.update_gitlab_inventory_item(gitlab_id, **updates)
    logger.info(f"GitLab instance updated: {gitlab_id} by {user.username}")

    instances = db.list_gitlab_inventory()
    for i in instances:
        i["_clients"] = db.get_gitlab_clients(i["id"])
    return HTMLResponse(_render_gitlab_tab(instances))


@router.delete("/gitlab/{gitlab_id}", response_class=HTMLResponse)
def delete_gitlab(request: Request, gitlab_id: str, db: DbDep, user: RequireAdmin):
    """Delete a GitLab instance from the inventory."""
    ok = db.delete_gitlab_inventory_item(gitlab_id)
    if not ok:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">GitLab instance not found.</div>
        </div>""")
    logger.info(f"GitLab instance deleted: {gitlab_id} by {user.username}")

    instances = db.list_gitlab_inventory()
    for i in instances:
        i["_clients"] = db.get_gitlab_clients(i["id"])
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">GitLab instance deleted.</div>
    </div>
    {_render_gitlab_tab(instances)}""")


@router.post("/clients/{client_id}/gitlab", response_class=HTMLResponse)
async def link_gitlab_to_client(request: Request, client_id: str, db: DbDep, user: RequireAdmin):
    """Link a GitLab instance to a client."""
    form = await request.form()
    gitlab_id = str(form.get("gitlab_id", "")).strip()
    if not gitlab_id:
        return HTMLResponse("")
    db.link_client_gitlab(client_id, gitlab_id)
    logger.info(f"GitLab {gitlab_id} linked to client {client_id} by {user.username}")
    instances = db.list_gitlab_inventory()
    for i in instances:
        i["_clients"] = db.get_gitlab_clients(i["id"])
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">GitLab linked to client.</div>
    </div>
    {_render_gitlab_tab(instances)}""")


@router.delete("/clients/{client_id}/gitlab/{gitlab_id}", response_class=HTMLResponse)
def unlink_gitlab_from_client(request: Request, client_id: str, gitlab_id: str,
                              db: DbDep, user: RequireAdmin):
    """Unlink a GitLab instance from a client."""
    db.unlink_client_gitlab(client_id, gitlab_id)
    logger.info(f"GitLab {gitlab_id} unlinked from client {client_id} by {user.username}")
    instances = db.list_gitlab_inventory()
    for i in instances:
        i["_clients"] = db.get_gitlab_clients(i["id"])
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">GitLab unlinked.</div>
    </div>
    {_render_gitlab_tab(instances)}""")


# ---------------------------------------------------------------------------
# SIEM Inventory CRUD
# ---------------------------------------------------------------------------

@router.post("/siems", response_class=HTMLResponse)
async def create_siem(request: Request, db: DbDep, user: RequireAdmin):
    """Create a SIEM in the centralized inventory."""
    form = await request.form()
    siem_type = str(form.get("siem_type", "elastic")).strip()
    label = str(form.get("label", "")).strip()
    elasticsearch_url = str(form.get("elasticsearch_url", "")).strip() or None
    kibana_url = str(form.get("kibana_url", "")).strip() or None
    api_token = str(form.get("api_token", "")).strip() or None

    if not label:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">SIEM label is required.</div>
        </div>""")

    if siem_type not in ("elastic", "splunk", "sentinel"):
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">Invalid SIEM type.</div>
        </div>""")

    db.create_siem_inventory_item(
        siem_type=siem_type, label=label,
        elasticsearch_url=elasticsearch_url, kibana_url=kibana_url,
        api_token_enc=api_token,
    )
    logger.info(f"SIEM inventory item created: {label} by {user.username}")

    siems = db.list_siem_inventory()
    for s in siems:
        s["_clients"] = db.get_siem_clients(s["id"])
    html = _render_siems_tab(siems)
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">SIEM '{label}' created.</div>
    </div>
    {html}""")


@router.put("/siems/{siem_id}", response_class=HTMLResponse)
async def update_siem(request: Request, siem_id: str, db: DbDep, user: RequireAdmin):
    """Update a SIEM in the inventory."""
    form = await request.form()
    updates = {}
    for field in ("label", "elasticsearch_url", "kibana_url", "api_token_enc"):
        val = form.get(field)
        if val is not None:
            updates[field] = str(val).strip() or None
    is_active = form.get("is_active")
    if is_active is not None:
        updates["is_active"] = str(is_active).lower() in ("true", "on", "1")

    db.update_siem_inventory_item(siem_id, **updates)
    logger.info(f"SIEM inventory item updated: {siem_id} by {user.username}")

    siems = db.list_siem_inventory()
    for s in siems:
        s["_clients"] = db.get_siem_clients(s["id"])
    return HTMLResponse(_render_siems_tab(siems))


@router.delete("/siems/{siem_id}", response_class=HTMLResponse)
def delete_siem(request: Request, siem_id: str, db: DbDep, user: RequireAdmin):
    """Delete a SIEM from the inventory."""
    ok = db.delete_siem_inventory_item(siem_id)
    if not ok:
        return HTMLResponse("""
        <div hx-swap-oob="afterbegin:#toast-container">
            <div class="toast toast-warning">SIEM not found.</div>
        </div>""")
    logger.info(f"SIEM inventory item deleted: {siem_id} by {user.username}")

    siems = db.list_siem_inventory()
    for s in siems:
        s["_clients"] = db.get_siem_clients(s["id"])
    return HTMLResponse(f"""
    <div hx-swap-oob="afterbegin:#toast-container">
        <div class="toast toast-success">SIEM deleted.</div>
    </div>
    {_render_siems_tab(siems)}""")


# ---------------------------------------------------------------------------
# Test Connection
# ---------------------------------------------------------------------------

@router.post("/siems/test-connection", response_class=HTMLResponse)
async def test_siem_connection(request: Request, db: DbDep, user: RequireAdmin):
    """Test connectivity to a SIEM (Elastic only for now)."""
    form = await request.form()
    siem_id = str(form.get("siem_id", "")).strip()
    kibana_url = str(form.get("kibana_url", "")).strip()
    api_token = str(form.get("api_token", "")).strip()
    siem_type = str(form.get("siem_type", "elastic")).strip()

    if siem_type != "elastic":
        return HTMLResponse(
            '<span class="badge badge-secondary">Test not available for this SIEM type</span>'
        )
    if not kibana_url:
        return HTMLResponse(
            '<span class="badge badge-warning">Kibana URL is required</span>'
        )
    # When editing an existing SIEM the token field is left blank ("keep existing").
    # Fall back to the stored token from the inventory.
    if not api_token and siem_id:
        stored = db.get_siem_inventory_item(siem_id)
        if stored:
            api_token = stored.get("api_token_enc") or ""
    if not api_token:
        return HTMLResponse(
            '<span class="badge badge-warning">API key is required (no stored key found)</span>'
        )

    try:
        from app.elastic_helper import test_elastic_connection
        ok, detail = test_elastic_connection(kibana_url, api_token)
        if siem_id:
            try:
                db.update_inventory_test_status(
                    "siems", siem_id, "pass" if ok else "fail", str(detail)[:140]
                )
            except Exception:  # pragma: no cover - best effort
                pass
        if ok:
            return HTMLResponse(
                f'<span class="badge badge-success">Connected &mdash; {detail}</span>'
            )
        else:
            return HTMLResponse(
                f'<span class="badge badge-danger">Failed &mdash; {detail}</span>'
            )
    except Exception as exc:
        logger.warning(f"SIEM test-connection error: {exc}")
        return HTMLResponse(
            f'<span class="badge badge-danger">Error &mdash; {str(exc)[:120]}</span>'
        )


# ---------------------------------------------------------------------------
# Unified per-card Test Connection (persists last_test_status)
# ---------------------------------------------------------------------------

def _run_inventory_test(kind: str, item: dict) -> tuple[bool, str]:
    """Dispatch to the appropriate live test for a stored inventory item.

    Returns ``(ok, short_message)``. The message is bounded to ~140 chars so
    it fits cleanly inside the status-pill tooltip.
    """
    try:
        if kind == "siems":
            stype = (item.get("siem_type") or "").lower()
            if stype != "elastic":
                return False, f"Test not supported for SIEM type '{stype}'"
            kibana_url = (item.get("kibana_url") or "").strip()
            api_token = (item.get("api_token_enc") or "").strip()
            if not kibana_url or not api_token:
                return False, "Missing Kibana URL or API token"
            from app.elastic_helper import test_elastic_connection
            ok, detail = test_elastic_connection(kibana_url, api_token)
            return ok, str(detail)[:140]

        if kind == "opencti":
            url = (item.get("url") or "").strip()
            token = (item.get("token_enc") or "").strip()
            if not url or not token:
                return False, "Missing URL or token"
            gql_url = url.rstrip("/") + "/graphql"
            resp = http_requests.post(
                gql_url,
                json={"query": "{ me { name } }"},
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=10,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                if "errors" in data:
                    return False, (data["errors"][0].get("message", "auth failed"))[:140]
                name = data.get("data", {}).get("me", {}).get("name", "unknown")
                return True, f"Logged in as {name}"
            if resp.status_code in (401, 403):
                return False, "Authentication failed (invalid token)"
            return False, f"HTTP {resp.status_code}"

        if kind == "gitlab":
            url = (item.get("url") or "").strip()
            token = (item.get("token_enc") or "").strip()
            if not url:
                return False, "Missing URL"
            api_url = url.rstrip("/") + "/api/v4/version"
            headers = {}
            if token:
                headers["PRIVATE-TOKEN"] = token
            resp = http_requests.get(api_url, headers=headers, timeout=10, verify=False)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    ver = data.get("version", "unknown")
                    return True, f"GitLab {ver}"
                except Exception:
                    return True, "Reachable (non-JSON response)"
            if resp.status_code in (401, 403):
                return False, "Authentication failed (token missing or invalid)"
            return False, f"HTTP {resp.status_code}"

        if kind == "keycloak":
            url = (item.get("url") or "").strip()
            realm = (item.get("realm") or "master").strip() or "master"
            if not url:
                return False, "Missing URL"
            discovery_url = f"{url.rstrip('/')}/realms/{realm}/.well-known/openid-configuration"
            resp = http_requests.get(discovery_url, timeout=8, verify=False)
            if resp.status_code == 200:
                return True, f"Realm '{realm}' discovered"
            if resp.status_code == 404:
                return False, f"Realm '{realm}' not found (404)"
            return False, f"HTTP {resp.status_code}"

        return False, f"Unknown integration kind '{kind}'"
    except Exception as exc:  # pragma: no cover - network errors
        logger.warning(f"{kind} card test-connection error: {exc}")
        return False, str(exc)[:140]


def _fetch_inventory_item(db, kind: str, item_id: str) -> dict | None:
    """Read a single row from the kind's inventory table for the test runner."""
    table = {
        "siems": "siem_inventory",
        "opencti": "opencti_inventory",
        "gitlab": "gitlab_inventory",
        "keycloak": "keycloak_inventory",
    }.get(kind)
    if not table:
        return None
    try:
        with db.get_shared_connection() as conn:
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info('{table}')").fetchall()]
            row = conn.execute(
                f"SELECT * FROM {table} WHERE id = ?", [item_id]
            ).fetchone()
            if not row:
                return None
            return dict(zip(cols, row))
    except Exception as exc:
        logger.warning(f"Could not fetch {kind} item {item_id}: {exc}")
        return None


@router.post("/{kind}/{item_id}/test", response_class=HTMLResponse)
async def test_inventory_card(
    kind: str,
    item_id: str,
    db: DbDep,
    user: RequireAdmin,
):
    """Run a live connection test against a stored inventory item and persist
    the result. Returns the refreshed status pill HTML for HTMX swap.
    """
    if kind not in _KIND_TO_INVENTORY:
        return HTMLResponse(
            _status_pill_html(
                {"last_test_status": "fail", "last_test_message": f"Unknown kind '{kind}'"},
                target_id=f"{kind}-status-{item_id}",
            )
        )

    item = _fetch_inventory_item(db, kind, item_id)
    if not item:
        return HTMLResponse(
            _status_pill_html(
                {"last_test_status": "fail", "last_test_message": "Item not found"},
                target_id=f"{kind}-status-{item_id}",
            )
        )

    ok, msg = _run_inventory_test(kind, item)
    status = "pass" if ok else "fail"
    db.update_inventory_test_status(_KIND_TO_INVENTORY[kind], item_id, status, msg)

    # Re-fetch so the rendered pill carries the just-persisted timestamp.
    refreshed = _fetch_inventory_item(db, kind, item_id) or {
        "last_test_status": status,
        "last_test_message": msg,
    }
    logger.info(
        f"{kind} test-connection on {item_id} by {user.username}: {status} ({msg})"
    )
    return HTMLResponse(_status_pill_html(refreshed, target_id=f"{kind}-status-{item_id}"))


@router.post("/siems/{siem_id}/logging", response_class=HTMLResponse)
async def update_siem_logging(
    request: Request,
    siem_id: str,
    db: DbDep,
    user: RequireAdmin,
):
    """Persist per-SIEM rule-logging configuration. Returns refreshed SIEMs partial.

    Also reschedules the daily rule-log job so the new HH:MM takes effect immediately.
    """
    form = await request.form()
    enabled = (form.get("enabled") or "").lower() in ("on", "true", "1")
    # Multi-select: a SIEM may log rules from one or more Kibana spaces. Stored
    # as a CSV in `siem_inventory.log_target_space` (no schema migration).
    selected_spaces = [s.strip() for s in form.getlist("target_space") if s and s.strip()]
    target_space = ",".join(selected_spaces) if selected_spaces else None
    schedule = (form.get("schedule") or "00:00").strip() or "00:00"
    try:
        retention_days = max(1, min(365, int(form.get("retention_days") or 7)))
    except (TypeError, ValueError):
        retention_days = 7

    db.update_siem_logging_config(
        siem_id,
        enabled=enabled,
        target_space=target_space,
        schedule=schedule,
        retention_days=retention_days,
        destination_path=None,
    )
    logger.info(
        f"siem logging updated for {siem_id} by {user.username}: "
        f"enabled={enabled} spaces={selected_spaces or '<any>'} "
        f"schedule={schedule} retention={retention_days}"
    )

    # Reschedule the daily job so a new HH:MM is honoured without a restart.
    try:
        from app.main import reschedule_rule_log_job
        reschedule_rule_log_job()
    except Exception as exc:
        logger.warning(f"could not reschedule rule_log job: {exc}")

    siems = db.list_siem_inventory()
    for s in siems:
        s["_clients"] = db.get_siem_clients(s["id"])
    return HTMLResponse(_render_siems_tab(siems))


# ---------------------------------------------------------------------------
# Client-SIEM linking (returns partial for client detail page)
# ---------------------------------------------------------------------------

@router.post("/clients/{client_id}/siems", response_class=HTMLResponse)
async def link_siem_to_client(request: Request, client_id: str, db: DbDep, user: RequireAdmin):
    """Link a SIEM to a client with an environment role and space."""
    form = await request.form()
    siem_id = str(form.get("siem_id", "")).strip()
    environment_role = str(form.get("environment_role", "production")).strip()
    space = str(form.get("space", "")).strip() or "default"
    if not siem_id:
        return HTMLResponse("")
    if environment_role not in ("production", "staging"):
        environment_role = "production"
    db.link_client_siem(client_id, siem_id, environment_role=environment_role, space=space)
    logger.info(f"SIEM {siem_id} linked to client {client_id} as {environment_role} by {user.username}")
    return _render_client_siems_partial(client_id, db, toast="SIEM linked successfully.")


@router.delete("/clients/{client_id}/siems/{siem_id}", response_class=HTMLResponse)
def unlink_siem_from_client(request: Request, client_id: str, siem_id: str,
                            db: DbDep, user: RequireAdmin):
    """Unlink a SIEM from a client."""
    env_role = request.query_params.get("environment_role")
    db.unlink_client_siem(client_id, siem_id, environment_role=env_role)
    logger.info(f"SIEM {siem_id} ({env_role or 'all'}) unlinked from client {client_id} by {user.username}")
    return _render_client_siems_partial(client_id, db, toast="SIEM unlinked.")


# ---------------------------------------------------------------------------
# Client-System assignment (from client detail page)
# ---------------------------------------------------------------------------

@router.post("/clients/{client_id}/systems", response_class=HTMLResponse)
async def assign_system_to_client(request: Request, client_id: str, db: DbDep, user: RequireAdmin):
    """Assign an existing system to a client."""
    from app.inventory_engine import assign_system_to_client as _assign
    form = await request.form()
    system_id = str(form.get("system_id", "")).strip()
    if not system_id:
        return HTMLResponse("")
    try:
        result = _assign(system_id, client_id)
        if not result:
            return _render_client_systems_partial(client_id, db, toast="System not found.")
    except ValueError as e:
        return _render_client_systems_partial(client_id, db, toast=str(e))
    logger.info(f"System {system_id} assigned to client {client_id} by {user.username}")
    return _render_client_systems_partial(client_id, db, toast="System assigned.")


@router.delete("/clients/{client_id}/systems/{system_id}", response_class=HTMLResponse)
def remove_system_from_client(request: Request, client_id: str, system_id: str,
                              db: DbDep, user: RequireAdmin):
    """Remove a system from a client (reassign to default)."""
    from app.inventory_engine import unassign_system_from_client as _unassign
    default_cid = db.get_default_client_id()
    _unassign(system_id, client_id, default_client_id=default_cid)
    logger.info(f"System {system_id} removed from client {client_id} by {user.username}")
    return _render_client_systems_partial(client_id, db, toast="System removed.")


# ---------------------------------------------------------------------------
# Move System between clients (with SIEM validation)
# ---------------------------------------------------------------------------

@router.get("/clients/{client_id}/move-check", response_class=HTMLResponse)
def system_move_check(request: Request, client_id: str,
                      db: DbDep, user: RequireAdmin):
    """Pre-flight check for moving a system. Returns dependency summary HTML."""
    from html import escape
    from app.inventory_engine import move_system_check
    system_id = request.query_params.get("system_id", "").strip()
    target_client_id = request.query_params.get("target_client_id", "").strip()
    if not target_client_id or not system_id:
        return HTMLResponse('<p style="color:var(--color-muted);padding:0.5rem;">Select a target client above.</p>')

    target_client = db.get_client(target_client_id)
    if not target_client:
        return HTMLResponse('<p style="color:var(--color-danger);padding:0.5rem;">Target client not found.</p>')

    check = move_system_check(system_id, client_id, target_client_id)
    if not check:
        return HTMLResponse('<p style="color:var(--color-danger);padding:0.5rem;">System not found.</p>')

    # Build dependency summary HTML
    html_parts = ['<div style="display:flex;flex-direction:column;gap:0.75rem;">']

    # SIEM compatibility warning
    if not check["siem_compatible"]:
        html_parts.append(
            '<div class="alert alert-warning" style="padding:0.75rem;border-radius:var(--radius-md);'
            'background:var(--color-warning-bg, rgba(245,158,11,0.12));border-left:3px solid var(--color-warning);">'
            '<strong>&#x26A0; SIEM Mismatch:</strong> The target client uses different SIEM spaces. '
            f'<strong>{check["applied_detections_count"]}</strong> applied detection(s) will be <strong>reset</strong> '
            'to prevent ghost detections from an inaccessible SIEM.</div>'
        )
    else:
        html_parts.append(
            '<div style="padding:0.5rem;border-radius:var(--radius-md);'
            'background:var(--color-success-bg, rgba(34,197,94,0.12));border-left:3px solid var(--color-success);">'
            f'&#x2705; <strong>SIEM Compatible</strong> — shared spaces: {", ".join(check["shared_spaces"]) or "none"}. '
            'Rule coverage will persist.</div>'
        )

    # Assets summary
    html_parts.append(
        f'<div style="font-size:0.875rem;color:var(--color-text-muted);">'
        f'<strong>{check["host_count"]}</strong> device(s) and '
        f'<strong>{check["software_count"]}</strong> package(s) will move with the system.</div>'
    )

    # Baselines
    if check["baselines"]:
        bl_list = ", ".join(escape(b["name"]) for b in check["baselines"])
        html_parts.append(
            f'<div style="font-size:0.875rem;"><strong>{len(check["baselines"])}</strong> '
            f'linked baseline(s): {bl_list}</div>'
        )

    html_parts.append('</div>')
    return HTMLResponse("".join(html_parts))


@router.post("/clients/{client_id}/move-system", response_class=HTMLResponse)
async def move_system(request: Request, client_id: str,
                      db: DbDep, user: RequireAdmin):
    """Kick off an async move and return an HTMX polling snippet."""
    from app.inventory_engine import move_system_to_client
    form = await request.form()
    system_id = str(form.get("system_id", "")).strip()
    target_client_id = str(form.get("target_client_id", "")).strip()
    move_baselines = form.get("move_baselines") == "on"

    if not system_id:
        return _render_client_systems_partial(client_id, db, toast="No system specified.")

    if not target_client_id or target_client_id == client_id:
        return _render_client_systems_partial(client_id, db, toast="Invalid target client.")

    target_client = db.get_client(target_client_id)
    if not target_client:
        return _render_client_systems_partial(client_id, db, toast="Target client not found.")

    # Create a task and start in background
    task_id = str(_uuid.uuid4())
    _move_tasks[task_id] = {
        "status": "running",
        "message": "Moving system…",
        "client_id": client_id,
        "result": None,
        "user": user.username,
        "target_name": target_client["name"],
    }

    def _run():
        try:
            result = move_system_to_client(
                system_id, client_id, target_client_id,
                move_baselines=move_baselines,
            )
            parts = [f"System \"{result['system_name']}\" moved to {target_client['name']}."]
            if result["coverage_reset"]:
                parts.append(f" {result['applied_detections_removed']} detection(s) reset.")
            if result["baselines_moved"]:
                parts.append(f" {len(result['baselines_moved'])} baseline(s) moved.")
            _move_tasks[task_id].update(
                status="done", message="".join(parts), result=result,
            )
            logger.info(
                f"System {system_id} moved from {client_id} to {target_client_id} "
                f"by {user.username} (coverage_reset={result['coverage_reset']}, "
                f"baselines_moved={len(result['baselines_moved'])})"
            )
        except Exception as exc:
            _move_tasks[task_id].update(status="error", message=str(exc))
            logger.exception(f"Async move failed for system {system_id}: {exc}")

    threading.Thread(target=_run, daemon=True).start()

    # Return a polling snippet that replaces the systems section
    return HTMLResponse(
        f'<div id="move-progress" '
        f'hx-get="/api/management/move-status/{task_id}?client_id={client_id}" '
        f'hx-trigger="every 1s" hx-swap="innerHTML" hx-target="#client-systems-section">'
        f'<div style="display:flex;align-items:center;gap:0.75rem;padding:2rem;justify-content:center;">'
        f'<svg class="icon spin" width="20" height="20" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="2"><path d="M12 2v4"/>'
        f'<path d="m16.2 7.8 2.9-2.9"/><path d="M18 12h4"/>'
        f'<path d="m16.2 16.2 2.9 2.9"/><path d="M12 18v4"/>'
        f'<path d="m4.9 19.1 2.9-2.9"/><path d="M2 12h4"/>'
        f'<path d="m4.9 4.9 2.9 2.9"/></svg>'
        f'<span>Moving system to {_esc(target_client["name"])}…</span>'
        f'</div></div>'
    )


@router.get("/move-status/{task_id}", response_class=HTMLResponse)
def move_status(task_id: str, client_id: str = "", db: DbDep = None):
    """Poll endpoint for async move progress. Returns updated systems partial when done."""
    task = _move_tasks.get(task_id)
    if not task:
        return HTMLResponse('<p style="color:var(--color-danger);">Unknown move task.</p>')

    if task["status"] == "running":
        # Still in progress — re-render the spinner (HTMX will poll again)
        return HTMLResponse(
            f'<div id="move-progress" '
            f'hx-get="/api/management/move-status/{task_id}?client_id={client_id}" '
            f'hx-trigger="every 1s" hx-swap="innerHTML" hx-target="#client-systems-section">'
            f'<div style="display:flex;align-items:center;gap:0.75rem;padding:2rem;justify-content:center;">'
            f'<svg class="icon spin" width="20" height="20" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="2"><path d="M12 2v4"/>'
            f'<path d="m16.2 7.8 2.9-2.9"/><path d="M18 12h4"/>'
            f'<path d="m16.2 16.2 2.9 2.9"/><path d="M12 18v4"/>'
            f'<path d="m4.9 19.1 2.9-2.9"/><path d="M2 12h4"/>'
            f'<path d="m4.9 4.9 2.9 2.9"/></svg>'
            f'<span>{_esc(task["message"])}</span>'
            f'</div></div>'
        )

    # Done or error — clean up and render final state
    cid = client_id or task["client_id"]
    toast = task["message"]
    del _move_tasks[task_id]

    if task["status"] == "error":
        return _render_client_systems_partial(cid, db, toast=f"Move failed: {toast}")

    return _render_client_systems_partial(cid, db, toast=toast)


# ---------------------------------------------------------------------------
# Client-Baseline assignment (from client detail page)
# ---------------------------------------------------------------------------

@router.post("/clients/{client_id}/baselines", response_class=HTMLResponse)
async def assign_baseline_to_client(request: Request, client_id: str, db: DbDep, user: RequireAdmin):
    """Assign an existing baseline to a client."""
    from app.inventory_engine import assign_baseline_to_client as _assign
    form = await request.form()
    baseline_id = str(form.get("baseline_id", "")).strip()
    if not baseline_id:
        return HTMLResponse("")
    try:
        _assign(baseline_id, client_id)
    except ValueError as e:
        return _render_client_baselines_partial(client_id, db, toast=str(e))
    logger.info(f"Baseline {baseline_id} assigned to client {client_id} by {user.username}")
    return _render_client_baselines_partial(client_id, db, toast="Baseline assigned.")


@router.delete("/clients/{client_id}/baselines/{baseline_id}", response_class=HTMLResponse)
def remove_baseline_from_client(request: Request, client_id: str, baseline_id: str,
                                db: DbDep, user: RequireAdmin):
    """Remove a baseline from a client (reassign to default)."""
    from app.inventory_engine import unassign_baseline_from_client as _unassign
    default_cid = db.get_default_client_id()
    _unassign(baseline_id, client_id, default_client_id=default_cid)
    logger.info(f"Baseline {baseline_id} removed from client {client_id} by {user.username}")
    return _render_client_baselines_partial(client_id, db, toast="Baseline removed.")


# ---------------------------------------------------------------------------
# Cross-Tenant Baseline Cloning
# ---------------------------------------------------------------------------

@router.get("/clients/{client_id}/clone-baseline/baselines", response_class=HTMLResponse)
def clone_baseline_source_options(request: Request, client_id: str,
                                  db: DbDep, user: RequireAdmin):
    """Return <option> elements for baselines available in a given source
    tenant.  Called by the clone modal when the user picks a source client."""
    source_client_id = request.query_params.get("source_client_id", "").strip()
    if not source_client_id:
        return HTMLResponse(
            '<option value="" disabled selected>Select a source client first&hellip;</option>'
        )
    from app.inventory_engine import list_playbooks
    from app.services.tenant_manager import tenant_context_for
    with tenant_context_for(source_client_id):
        baselines = list_playbooks(client_id=source_client_id)
    if not baselines:
        return HTMLResponse(
            '<option value="" disabled selected>No baselines in that client</option>'
        )
    opts = '<option value="" disabled selected>Select a baseline&hellip;</option>'
    for b in baselines:
        desc = f" — {b.description[:40]}" if b.description else ""
        opts += f'<option value="{_esc(b.id)}">{_esc(b.name)}{_esc(desc)}</option>'
    return HTMLResponse(opts)


@router.post("/clients/{client_id}/clone-baseline", response_class=HTMLResponse)
async def clone_baseline(request: Request, client_id: str,
                         db: DbDep, user: RequireAdmin):
    """Clone a baseline from another tenant into this client's database."""
    from app.inventory_engine import clone_baseline_cross_tenant
    form = await request.form()
    source_client_id = str(form.get("source_client_id", "")).strip()
    baseline_id = str(form.get("baseline_id", "")).strip()
    if not source_client_id or not baseline_id:
        return _render_client_baselines_partial(
            client_id, db, toast="Missing source client or baseline.")
    try:
        result = clone_baseline_cross_tenant(
            source_client_id=source_client_id,
            target_client_id=client_id,
            baseline_id=baseline_id,
        )
    except ValueError as e:
        return _render_client_baselines_partial(client_id, db, toast=str(e))
    logger.info(
        f"Baseline '{result['name']}' cloned into client {client_id} "
        f"by {user.username} ({result['steps']} steps)"
    )
    return _render_client_baselines_partial(
        client_id, db,
        toast=f"Cloned '{result['name']}' ({result['steps']} steps).",
    )


# ---------------------------------------------------------------------------
# Move System FROM another client (reverse move)
# ---------------------------------------------------------------------------

@router.get("/clients/{client_id}/move-from/systems", response_class=HTMLResponse)
def move_from_systems(request: Request, client_id: str,
                      db: DbDep, user: RequireAdmin):
    """Return <option> elements for systems in the selected source client."""
    source_client_id = request.query_params.get("source_client_id", "").strip()
    if not source_client_id:
        return HTMLResponse(
            '<option value="" disabled selected>Select a source client first&hellip;</option>'
        )
    from app.inventory_engine import list_systems
    from app.services.tenant_manager import tenant_context_for
    with tenant_context_for(source_client_id):
        systems = list_systems(client_id=source_client_id)
    if not systems:
        return HTMLResponse(
            '<option value="" disabled selected>No systems in that client</option>'
        )
    opts = '<option value="" disabled selected>Select a system&hellip;</option>'
    for s in systems:
        cls = f" ({s.classification})" if s.classification else ""
        opts += f'<option value="{_esc(s.id)}">{_esc(s.name)}{_esc(cls)}</option>'
    return HTMLResponse(opts)


@router.post("/clients/{client_id}/move-from", response_class=HTMLResponse)
async def move_from(request: Request, client_id: str,
                    db: DbDep, user: RequireAdmin):
    """Move a system FROM source client INTO this client (async)."""
    from app.inventory_engine import move_system_to_client
    form = await request.form()
    source_client_id = str(form.get("source_client_id", "")).strip()
    system_id = str(form.get("system_id", "")).strip()
    move_baselines = form.get("move_baselines") == "on"

    if not source_client_id or not system_id:
        return _render_client_systems_partial(client_id, db, toast="Missing source or system.")

    source_client = db.get_client(source_client_id)
    if not source_client:
        return _render_client_systems_partial(client_id, db, toast="Source client not found.")

    task_id = str(_uuid.uuid4())
    _move_tasks[task_id] = {
        "status": "running",
        "message": "Moving system…",
        "client_id": client_id,
        "result": None,
        "user": user.username,
        "target_name": db.get_client(client_id)["name"],
    }

    def _run():
        try:
            result = move_system_to_client(
                system_id, source_client_id, client_id,
                move_baselines=move_baselines,
            )
            parts = [f"System \"{result['system_name']}\" moved from {source_client['name']}."]
            if result["coverage_reset"]:
                parts.append(f" {result['applied_detections_removed']} detection(s) reset.")
            if result["baselines_moved"]:
                parts.append(f" {len(result['baselines_moved'])} baseline(s) moved.")
            _move_tasks[task_id].update(status="done", message="".join(parts), result=result)
            logger.info(
                f"System {system_id} moved from {source_client_id} to {client_id} "
                f"by {user.username}"
            )
        except Exception as exc:
            _move_tasks[task_id].update(status="error", message=str(exc))
            logger.exception(f"Async move-from failed for system {system_id}: {exc}")

    threading.Thread(target=_run, daemon=True).start()

    return HTMLResponse(
        f'<div hx-get="/api/management/move-status/{task_id}?client_id={client_id}" '
        f'hx-trigger="every 1s" hx-swap="innerHTML" hx-target="#client-systems-section">'
        f'<div style="display:flex;align-items:center;gap:0.75rem;padding:2rem;justify-content:center;">'
        f'<svg class="icon spin" width="20" height="20" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="2"><path d="M12 2v4"/>'
        f'<path d="m16.2 7.8 2.9-2.9"/><path d="M18 12h4"/>'
        f'<path d="m16.2 16.2 2.9 2.9"/><path d="M12 18v4"/>'
        f'<path d="m4.9 19.1 2.9-2.9"/><path d="M2 12h4"/>'
        f'<path d="m4.9 4.9 2.9 2.9"/></svg>'
        f'<span>Moving system from {_esc(source_client["name"])}…</span>'
        f'</div></div>'
    )


# ---------------------------------------------------------------------------
# Client-User assignment (from client detail page)
# ---------------------------------------------------------------------------

@router.post("/clients/{client_id}/users", response_class=HTMLResponse)
async def assign_user_to_client(request: Request, client_id: str, db: DbDep, user: RequireAdmin):
    """Assign a user to a client, optionally with a tenant-scoped role."""
    form = await request.form()
    user_id = str(form.get("user_id", "")).strip()
    role_name = str(form.get("role", "")).strip()
    if not user_id:
        return HTMLResponse("")
    db.assign_user_to_client(user_id, client_id)
    if role_name:
        db.set_user_roles(user_id, [role_name], client_id=client_id)
    logger.info(
        f"User {user_id} assigned to client {client_id} "
        f"(role={role_name or 'none'}) by {user.username}"
    )
    return _render_client_users_partial(client_id, db, toast="User assigned.")


@router.put("/clients/{client_id}/users/{user_id}/role", response_class=HTMLResponse)
async def update_client_user_role(request: Request, client_id: str, user_id: str,
                                  db: DbDep, user: RequireAdmin):
    """Replace the user's role for THIS tenant only. Empty role clears it."""
    form = await request.form()
    role_name = str(form.get("role", "")).strip()
    db.set_user_roles(user_id, [role_name] if role_name else [], client_id=client_id)
    logger.info(
        f"User {user_id} role on client {client_id} set to '{role_name or 'none'}' by {user.username}"
    )
    return _render_client_users_partial(
        client_id, db,
        toast=f"Role updated to {role_name or 'none'}.",
    )


# ---------------------------------------------------------------------------
# Per-client Role Templates (permissions matrix scoped to one tenant)
# ---------------------------------------------------------------------------

@router.get("/clients/{client_id}/permissions", response_class=HTMLResponse)
def get_client_permissions(request: Request, client_id: str, db: DbDep, user: RequireAdmin):
    """Render the per-tenant Role Templates matrix for this client."""
    return HTMLResponse(_render_permissions_tab(db, client_id=client_id))


@router.post("/clients/{client_id}/permissions", response_class=HTMLResponse)
async def update_client_permission(request: Request, client_id: str,
                                    db: DbDep, user: RequireAdmin):
    """Toggle a single role\u00d7resource permission scoped to this tenant."""
    form = await request.form()
    role_id = str(form.get("role_id", "")).strip()
    resource = str(form.get("resource", "")).strip()
    access = str(form.get("access", "")).strip()  # 'read' | 'write'
    state = str(form.get("state", "")).strip()    # 'on' | 'off'

    if not role_id or not resource or access not in ("read", "write"):
        return HTMLResponse(_render_permissions_tab(db, client_id=client_id))

    # ADMIN role always has full access \u2014 do not let it be edited away.
    with db.get_connection() as conn:
        admin_check = conn.execute(
            "SELECT name FROM roles WHERE id = ?", [role_id]
        ).fetchone()
        if admin_check and admin_check[0] == "ADMIN":
            return HTMLResponse(_render_permissions_tab(db, client_id=client_id))
        row = conn.execute(
            "SELECT can_read, can_write FROM role_permissions "
            "WHERE role_id = ? AND resource = ? AND client_id = ?",
            [role_id, resource, client_id],
        ).fetchone()
    cur_read = bool(row[0]) if row else False
    cur_write = bool(row[1]) if row else False
    new_val = state == "on"
    if access == "read":
        db.set_permission(role_id, resource, new_val, cur_write, client_id=client_id)
    else:
        db.set_permission(role_id, resource, cur_read, new_val, client_id=client_id)
    logger.info(
        f"Permission {role_id}/{resource}/{access}={new_val} on client "
        f"{client_id} by {user.username}"
    )
    return HTMLResponse(_render_permissions_tab(db, client_id=client_id))


@router.delete("/clients/{client_id}/users/{user_id}", response_class=HTMLResponse)
def remove_user_from_client_detail(request: Request, client_id: str, user_id: str,
                                   db: DbDep, user: RequireAdmin):
    """Remove a user from a client."""
    db.remove_user_from_client(user_id, client_id)
    logger.info(f"User {user_id} removed from client {client_id} by {user.username}")
    return _render_client_users_partial(client_id, db, toast="User removed.")


# ---------------------------------------------------------------------------
# User-Client assignment (Manage Clients checklist)
# ---------------------------------------------------------------------------

@router.post("/users/{user_id}/clients", response_class=HTMLResponse)
async def update_user_clients(request: Request, user_id: str, db: DbDep, user: RequireAdmin):
    """Update the client assignments for a user via checklist."""
    form = await request.form()
    selected_client_ids = form.getlist("client_ids")

    current_ids = set(db.get_user_client_ids(user_id))
    new_ids = set(selected_client_ids)

    # Remove unselected
    for cid in current_ids - new_ids:
        db.remove_user_from_client(user_id, cid)
    # Add newly selected
    for cid in new_ids - current_ids:
        db.assign_user_to_client(user_id, cid)

    logger.info(f"User {user_id} client assignments updated by {user.username}: {list(new_ids)}")

    users = db.get_all_users()
    all_roles = db.get_all_roles()
    for u in users:
        u["_roles"] = db.get_user_roles(u["id"])
        u["_client_ids"] = db.get_user_client_ids(u["id"])
    clients = db.list_clients()
    return HTMLResponse(_render_users_tab(users, all_roles, clients))


# ---------------------------------------------------------------------------
# HTML renderers (inline partials)
# ---------------------------------------------------------------------------

# Maps the URL kind segment used by the unified test-connection route to the
# DB inventory key understood by ``DatabaseService.update_inventory_test_status``.
_KIND_TO_INVENTORY = {
    "siems": "siems",
    "opencti": "opencti",
    "gitlab": "gitlab",
    "keycloak": "keycloak",
}


def _status_pill_html(item: dict, *, target_id: str | None = None) -> str:
    """Render the persisted last-test status as a coloured pill.

    ``target_id`` is set as the element's ``id`` so that an HTMX
    ``hx-target`` from the per-card Test button can swap the pill in place.
    """
    status = (item.get("last_test_status") or "").lower()
    when = item.get("last_test_at")
    msg = (item.get("last_test_message") or "").strip()
    when_str = ""
    try:
        when_str = when.strftime("%Y-%m-%d %H:%M") if when else ""
    except Exception:
        when_str = str(when) if when else ""

    id_attr = f' id="{target_id}"' if target_id else ""

    if status == "pass":
        title = f"Last tested {when_str}: {msg}" if (when_str and msg) else (
            f"Last tested {when_str}" if when_str else "Connection OK"
        )
        return (
            f'<span{id_attr} class="status-pill status-pill--ok" title="{_esc(title)}">'
            f'<span class="status-dot"></span>Active</span>'
        )
    if status == "fail":
        title = f"Last tested {when_str}: {msg}" if (when_str and msg) else (
            msg or (f"Failed at {when_str}" if when_str else "Connection failed")
        )
        return (
            f'<span{id_attr} class="status-pill status-pill--fail" title="{_esc(title)}">'
            f'<span class="status-dot"></span>Failed</span>'
        )
    return (
        f'<span{id_attr} class="status-pill status-pill--unknown" title="Not yet tested">'
        f'<span class="status-dot"></span>Untested</span>'
    )


def _tenant_chips_html(clients: list, *, all_tenants: bool = False) -> str:
    """Render deduplicated tenant chips as links to ``/clients/{id}``.

    Set ``all_tenants=True`` to render a single "All tenants" pill (used for
    Keycloak which is a global singleton).
    """
    if all_tenants:
        return (
            '<span class="tenant-chip tenant-chip--all" '
            'title="Available to all tenants">All tenants</span>'
        )
    if not clients:
        return (
            '<span class="text-secondary" style="font-size:0.8125rem;">'
            'No clients linked</span>'
        )
    seen: set[str] = set()
    chips: list[str] = []
    for c in clients:
        cid = c.get("id")
        if not cid or cid in seen:
            continue
        seen.add(cid)
        nm = _esc(c.get("name") or cid)
        chips.append(
            f'<a href="/clients/{cid}" target="_blank" rel="noopener" '
            f'class="tenant-chip" title="Open {nm} in new tab">{nm}</a>'
        )
    return " ".join(chips)


def _test_button_html(kind: str, item_id: str, target_id: str) -> str:
    """Per-card Test Connection button that persists status server-side."""
    return (
        f'<button class="btn btn-ghost btn-sm" '
        f'hx-post="/api/management/{kind}/{item_id}/test" '
        f'hx-target="#{target_id}" hx-swap="outerHTML" '
        f'title="Run test connection now" '
        f'aria-label="Test connection">'
        f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        f'<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>'
        f'</svg></button>'
    )


def _render_clients_tab(clients: list) -> str:
    """Render the Clients tab as system-card style cards with View Details."""
    from html import escape
    count = len(clients)
    cards = ""

    for c in clients:
        siem_count = c.get("_siem_count", 0)
        user_count = c.get("_user_count", 0)
        system_count = c.get("_system_count", 0)
        baseline_count = c.get("_baseline_count", 0)
        cid = c["id"]
        name_esc = escape(c["name"])
        slug_esc = escape(c["slug"])
        desc_esc = escape(c.get("description") or "")
        created = c["created_at"].strftime('%Y-%m-%d') if c.get("created_at") else "N/A"

        # Badge top-right
        if c.get("is_default"):
            badge_html = '<span class="badge badge-info">Default</span>'
        elif siem_count == 0:
            badge_html = '<span class="badge badge-warning">No SIEMs</span>'
        else:
            badge_html = f'<span class="badge badge-success">{siem_count} SIEM{"s" if siem_count != 1 else ""}</span>'

        # SIEM type pills for footer
        from app.services.database import get_database_service
        _db = get_database_service()
        client_siems = _db.get_client_siems(cid)
        siem_pills = " ".join(
            f'<span class="badge badge-muted">{escape(cs["label"])}</span>'
            for cs in client_siems
        ) or '<span class="text-secondary" style="font-size:0.8rem;">No SIEMs linked</span>'

        cards += f'''
        <div class="system-card">
            <div class="system-card__badge">{badge_html}</div>
            <div class="system-card__title-wrap">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M18 21a8 8 0 0 0-16 0"/><circle cx="10" cy="8" r="5"/>
                    <path d="M22 20c0-3.37-2-6.5-4-8a5 5 0 0 0-.45-8.3"/>
                </svg>
                <a href="/clients/{cid}" class="system-card__title" title="{name_esc}">{name_esc}</a>
            </div>
            <div>
                <span class="system-card__classification">{slug_esc}</span>
            </div>
            {"<p class='system-card__desc'>" + desc_esc + "</p>" if desc_esc else ""}
            <div class="system-card__footer" style="flex-wrap:wrap;">
                <span class="system-card__stat">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>
                    {siem_count} SIEM{"s" if siem_count != 1 else ""}
                </span>
                <span class="system-card__stat">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>
                    {user_count} user{"s" if user_count != 1 else ""}
                </span>
                <span class="system-card__stat">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>
                    {system_count} system{"s" if system_count != 1 else ""}
                </span>
                <span class="system-card__stat">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>
                    {baseline_count} baseline{"s" if baseline_count != 1 else ""}
                </span>
            </div>
            <a href="/clients/{cid}" class="btn btn-secondary btn-sm btn-block">Manage Assets &rarr;</a>
        </div>'''

    empty = ""
    if not clients:
        empty = '''
        <div class="empty-output" style="padding:4rem 2rem;text-align:center;">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.3;">
                <path d="M18 21a8 8 0 0 0-16 0"/><circle cx="10" cy="8" r="5"/>
                <path d="M22 20c0-3.37-2-6.5-4-8a5 5 0 0 0-.45-8.3"/>
            </svg>
            <p style="margin-top:1rem;color:var(--color-text-muted);">No clients configured yet.</p>
        </div>'''

    return f'''
    <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:1.5rem;">
        <span class="text-secondary">{count} client{"s" if count != 1 else ""} configured</span>
        <button class="btn btn-primary" onclick="showCreateClientModal()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            New Client
        </button>
    </div>
    <div class="systems-grid">{cards}</div>
    {empty}'''


def _siem_logging_block_html(s: dict) -> str:
    """Render the per-SIEM 'Rule Logging' <details> block embedded inside a SIEM card.

    Posts to ``POST /api/management/siems/{id}/logging`` (handled in this file).
    """
    from html import escape
    sid = s["id"]
    enabled = bool(s.get("log_enabled"))
    raw_target = s.get("log_target_space") or ""
    selected_spaces = {p.strip() for p in raw_target.split(",") if p.strip()}
    schedule = s.get("log_schedule") or "00:00"
    retention = s.get("log_retention_days") or 7
    prod = s.get("production_space") or ""
    stage = s.get("staging_space") or ""

    # Pull the *actual* set of spaces this SIEM has rules in. The
    # production/staging fields on `siem_inventory` only ever name two of
    # them, but a SIEM can host arbitrarily many Kibana spaces — and the
    # operator wants to be able to log any of them. Fall back to the
    # prod/stage pair if the rule table is empty (fresh SIEM).
    discovered_spaces: list[str] = []
    try:
        from app.services.database import get_database_service
        discovered_spaces = get_database_service().get_all_kibana_spaces() or []
    except Exception as exc:
        logger.warning(
            f"_siem_logging_block_html({sid}): get_all_kibana_spaces failed: {exc!r}"
        )
        discovered_spaces = []
    logger.info(
        f"_siem_logging_block_html({sid}) discovered_spaces={discovered_spaces} "
        f"prod={prod!r} stage={stage!r} saved={sorted(selected_spaces)}"
    )
    # Build the union: discovered ∪ prod ∪ stage ∪ already-saved selections,
    # preserving discovery order then adding anything missing alphabetically.
    ordered: list[str] = []
    seen: set[str] = set()
    for sp in discovered_spaces:
        if sp and sp not in seen:
            ordered.append(sp); seen.add(sp)
    for sp in (prod, stage):
        if sp and sp not in seen:
            ordered.append(sp); seen.add(sp)
    for sp in sorted(selected_spaces):
        if sp not in seen:
            ordered.append(sp); seen.add(sp)

    # Build a compact single-line picker that opens a checkbox panel on click.
    # Native <select multiple> takes too much vertical space and forces
    # operators to know the Ctrl/Cmd-click trick. <details>/<summary> gives
    # us a zero-JS dropdown with proper checkbox semantics; the form picks
    # them up via form.getlist("target_space").
    if not ordered:
        space_picker = (
            '<input type="text" name="target_space" class="form-input" '
            f'value="{escape(raw_target)}" placeholder="space-a, space-b" '
            'style="font-size:0.8rem;padding:0.25rem 0.4rem;" '
            'title="Comma-separated Kibana space names. Leave blank to log every space.">'
        )
    else:
        if not selected_spaces:
            summary_text = "All spaces"
        elif len(selected_spaces) == 1:
            summary_text = next(iter(selected_spaces))
        else:
            summary_text = f"{len(selected_spaces)} spaces selected"

        checkbox_rows = []
        for sp in ordered:
            checked = " checked" if sp in selected_spaces else ""
            if sp == prod and sp == stage:
                tag = ' <span style="opacity:0.6;">(prod / stage)</span>'
            elif sp == prod:
                tag = ' <span style="opacity:0.6;">(prod)</span>'
            elif sp == stage:
                tag = ' <span style="opacity:0.6;">(stage)</span>'
            else:
                tag = ""
            checkbox_rows.append(
                '<label style="display:flex;align-items:center;gap:0.4rem;'
                'padding:0.2rem 0.5rem;cursor:pointer;font-size:0.8rem;">'
                f'<input type="checkbox" name="target_space" value="{escape(sp)}"{checked}>'
                f'<span>{escape(sp)}{tag}</span>'
                '</label>'
            )
        space_picker = (
            '<details class="space-picker" style="position:relative;">'
            '<summary style="list-style:none;cursor:pointer;'
            'background:var(--color-bg-input, #0d1117);'
            'border:1px solid var(--color-border, #30363d);'
            'border-radius:4px;padding:0.25rem 0.5rem;font-size:0.8rem;'
            'display:flex;align-items:center;justify-content:space-between;gap:0.4rem;" '
            f'title="Click to pick one or more spaces. Empty selection = log every space.">'
            f'<span>{escape(summary_text)}</span>'
            '<span style="opacity:0.6;font-size:0.7rem;">&#9662;</span>'
            '</summary>'
            '<div style="position:absolute;z-index:50;margin-top:0.2rem;'
            'min-width:100%;max-height:220px;overflow:auto;'
            'background:var(--color-bg-elevated, #161b22);'
            'border:1px solid var(--color-border, #30363d);'
            'border-radius:4px;padding:0.25rem 0;'
            'box-shadow:0 4px 12px rgba(0,0,0,0.4);">'
            + "".join(checkbox_rows)
            + '</div></details>'
        )

    summary_pill = (
        '<span class="status-pill status-pill--ok" title="Logging enabled">'
        '<span class="status-dot"></span>Logging On</span>'
        if enabled else
        '<span class="status-pill status-pill--unknown" title="Logging disabled">'
        '<span class="status-dot"></span>Logging Off</span>'
    )

    safe_label = "".join(
        c if c.isalnum() or c in ("-", "_", ".") else "_" for c in (s.get("label") or "siem")
    ) or "siem"
    dest_hint = f"/app/data/log/rules/{escape(safe_label)}/&lt;YYYY-MM-DD&gt;-&lt;space&gt;-rules.log"

    return f'''
            <details class="mgmt-subsection" style="margin:0.5rem 0 0;">
                <summary class="mgmt-subsection__summary" style="padding:0.45rem 0.6rem;">
                    <span class="mgmt-subsection__title">Rule Logging</span>
                    <span class="mgmt-subsection__hint">{summary_pill}</span>
                </summary>
                <div class="mgmt-subsection__body" style="padding:0.6rem;">
                    <form hx-post="/api/management/siems/{sid}/logging"
                          hx-target="#mgmt-sub-siems" hx-swap="innerHTML"
                          style="display:grid;grid-template-columns:auto 1fr;gap:0.4rem 0.6rem;align-items:center;font-size:0.8125rem;">
                        <label style="display:flex;align-items:center;gap:0.4rem;">
                            <input type="checkbox" name="enabled" value="on" {"checked" if enabled else ""}>
                            <span>Enabled</span>
                        </label>
                        <span class="text-secondary" style="font-size:0.75rem;">Toggle daily rule-score export for this SIEM.</span>
                        <span class="text-secondary">Target space(s)</span>
                        {space_picker}
                        <span class="text-secondary">Schedule (HH:MM)</span>
                        <input type="time" name="schedule" class="form-input" value="{escape(schedule)}"
                               style="font-size:0.8rem;padding:0.25rem 0.4rem;width:130px;">
                        <span class="text-secondary">Retention (days)</span>
                        <input type="number" name="retention_days" min="1" max="365" value="{int(retention)}"
                               class="form-input" style="font-size:0.8rem;padding:0.25rem 0.4rem;width:80px;">
                        <span class="text-secondary">Logs</span>
                        <div style="font-size:0.75rem;line-height:1.3;">
                            <span style="opacity:0.75;">written to</span>
                            <code style="background:transparent;padding:0;font-size:0.75rem;color:var(--color-accent, #58a6ff);">{dest_hint}</code>
                        </div>
                        <div style="grid-column:1 / -1;display:flex;gap:0.4rem;justify-content:flex-end;margin-top:0.3rem;">
                            <button type="submit" class="btn btn-primary btn-sm">Save</button>
                        </div>
                    </form>
                </div>
            </details>'''


def _render_siems_tab(siems: list) -> str:
    """Render the SIEMs tab content as cards (matching systems.html pattern)."""
    from html import escape
    count = len(siems)
    cards = ""
    for s in siems:
        sid = s["id"]
        lbl_esc = escape(s["label"])
        stype_esc = escape(s["siem_type"])
        es_url = escape(s.get("elasticsearch_url") or "-")
        kb_url = escape(s.get("kibana_url") or "-")
        status_pill = _status_pill_html(s, target_id=f"siem-status-{sid}")
        tenant_chips = _tenant_chips_html(s.get("_clients", []))
        test_btn = _test_button_html("siems", sid, f"siem-status-{sid}")
        logging_block = _siem_logging_block_html(s)

        cards += f'''
        <div class="system-card" style="display:flex;flex-direction:column;">
            <div class="system-card__title" style="display:flex;align-items:center;justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
                    <span style="font-weight:600;">{lbl_esc}</span>
                    <span class="badge badge-muted">{stype_esc}</span>
                    {status_pill}
                </div>
                <div style="display:flex;gap:0.25rem;">
                    {test_btn}
                    <button class="btn btn-ghost btn-sm"
                            onclick="editSiem('{sid}', '{lbl_esc}', '{stype_esc}', '{escape(s.get("elasticsearch_url") or "")}', '{escape(s.get("kibana_url") or "")}')"
                            title="Edit">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
                    </button>
                    <button class="btn btn-ghost btn-sm text-danger"
                            hx-delete="/api/management/siems/{sid}"
                            hx-target="#mgmt-sub-siems" hx-swap="innerHTML"
                            hx-confirm="Delete SIEM '{lbl_esc}'? This will unlink it from all clients."
                            title="Delete">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
                            <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                    </button>
                </div>
            </div>
            <div class="system-card__desc" style="margin-top:0.5rem;">
                <div style="display:grid;grid-template-columns:auto 1fr;gap:0.25rem 0.75rem;font-size:0.8125rem;">
                    <span class="text-secondary">Elasticsearch</span>
                    <span style="font-family:var(--font-mono,monospace);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{es_url}</span>
                    <span class="text-secondary">Kibana</span>
                    <span style="font-family:var(--font-mono,monospace);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{kb_url}</span>
                </div>
            </div>
            {logging_block}
            <div class="system-card__footer" style="margin-top:auto;padding-top:0.75rem;flex-wrap:wrap;">
                {tenant_chips}
            </div>
        </div>'''

    return f'''
    <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:1.5rem;">
        <span class="text-secondary">{count} SIEM{"s" if count != 1 else ""} in inventory</span>
        <button class="btn btn-primary" onclick="showCreateSiemModal()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            New SIEM
        </button>
    </div>
    <div class="systems-grid">{cards}</div>
    {_siem_empty_state() if not siems else ""}'''


def _siem_empty_state() -> str:
    return '''
    <div style="text-align:center;padding:2rem;color:var(--color-text-secondary);">
        <p>No SIEMs configured yet. Create one to get started.</p>
    </div>'''


def _render_users_tab(users: list, all_roles: list, clients: list) -> str:
    """Render the Users tab content with Manage Clients action.

    The Roles column has moved to the Client Detail page — this tab is now
    a global directory only (username, source, active, last login, clients).
    """
    if not users:
        return '<p class="text-muted" style="font-size:0.85rem;">No users found.</p>'

    rows = ""
    for u in users:
        provider = (u.get("auth_provider") or "local").lower()
        if provider == "keycloak":
            source_badge = '<span class="badge badge-info">SSO</span>'
        elif provider == "hybrid":
            source_badge = '<span class="badge badge-primary">Hybrid</span>'
        else:
            source_badge = '<span class="badge badge-secondary">Local</span>'

        active_checked = "checked" if u.get("is_active") else ""
        last_login = str(u["last_login"])[:19] if u.get("last_login") else "Never"

        # Client assignment checklist
        user_client_ids = set(u.get("_client_ids", []))
        client_count = len(user_client_ids)
        client_checkboxes = ""
        for cl in clients:
            checked = "checked" if cl["id"] in user_client_ids else ""
            client_checkboxes += (
                f'<label class="role-checkbox" style="display:block;margin:0.25rem 0;">'
                f'<input type="checkbox" name="client_ids" value="{cl["id"]}" {checked}> '
                f'{cl["name"]}</label>'
            )

        rows += f'''<tr id="user-row-{u['id']}">
            <td>{u['username']}</td>
            <td>{u.get('email') or '-'}</td>
            <td>{source_badge}</td>
            <td>
                <label class="toggle-switch toggle-sm">
                    <input type="checkbox" {active_checked}
                           hx-post="/api/management/users/{u['id']}/toggle-active"
                           hx-target="#management-content"
                           hx-swap="innerHTML"
                           hx-trigger="change">
                    <span class="toggle-slider"></span>
                </label>
            </td>
            <td>{last_login}</td>
            <td>
                <details class="mgmt-client-details">
                    <summary class="btn btn-sm btn-secondary" style="cursor:pointer;">
                        Clients ({client_count})
                    </summary>
                    <form class="mgmt-client-checklist"
                          hx-post="/api/management/users/{u['id']}/clients"
                          hx-target="#management-content"
                          hx-swap="innerHTML"
                          style="padding:0.75rem;background:var(--color-bg-base);border-radius:var(--radius-sm);margin-top:0.5rem;">
                        {client_checkboxes}
                        <button type="submit" class="btn btn-sm btn-primary" style="margin-top:0.5rem;">Save</button>
                    </form>
                </details>
            </td>
            <td>
                <button class="btn btn-danger btn-sm"
                        hx-delete="/api/management/users/{u['id']}"
                        hx-target="#management-content"
                        hx-swap="innerHTML"
                        hx-confirm="Delete user {_esc(u['username'])}?">Del</button>
            </td>
        </tr>'''

    add_form = '''
    <details class="add-user-details" style="margin-bottom:1.5rem;">
        <summary class="btn btn-secondary btn-sm" style="cursor:pointer;">+ Add Local User</summary>
        <p class="text-secondary" style="font-size:0.78rem;margin:0.5rem 0 0;">
            Roles are assigned per-tenant from the Client Detail page after creation.
        </p>
        <form hx-post="/api/management/users" hx-target="#management-content" hx-swap="innerHTML"
              style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;margin-top:0.75rem;padding:1rem;background:var(--color-bg-base);border-radius:var(--radius-md);">
            <div>
                <label class="form-label" style="font-size:0.8rem;">Username *</label>
                <input type="text" name="new_username" class="form-input" required placeholder="username" autocomplete="off">
            </div>
            <div>
                <label class="form-label" style="font-size:0.8rem;">Email</label>
                <input type="email" name="new_email" class="form-input" placeholder="user@example.com">
            </div>
            <div>
                <label class="form-label" style="font-size:0.8rem;">Full Name</label>
                <input type="text" name="new_full_name" class="form-input" placeholder="Full Name">
            </div>
            <div>
                <label class="form-label" style="font-size:0.8rem;">Password *</label>
                <input type="password" name="new_password" class="form-input" required minlength="8" placeholder="Min 8 chars" autocomplete="new-password">
            </div>
            <div style="grid-column:1/-1;">
                <button type="submit" class="btn btn-primary btn-sm">Create User</button>
            </div>
        </form>
    </details>'''

    return f'''
    {add_form}
    <table class="mapping-table">
        <thead><tr>
            <th>Username</th><th>Email</th><th>Source</th>
            <th>Active</th><th>Last Login</th>
            <th>Clients</th><th></th>
        </tr></thead>
        <tbody>{rows}</tbody>
    </table>'''


def _render_permissions_tab(db, client_id: Optional[str] = None) -> str:
    """Render the role permissions matrix.

    With ``client_id`` set the matrix is scoped to that tenant and the toggle
    POSTs to the per-client endpoint. With ``client_id=None`` the legacy
    global view is rendered (kept for back-compat with stale bookmarks).
    """
    roles = [r for r in db.get_all_roles() if r["name"] != "ADMIN"]
    resources = db.get_all_resources()
    matrix = db.get_permissions_matrix(client_id=client_id)

    lookup = {}
    for entry in matrix:
        lookup[(entry["role_name"], entry["resource"])] = {
            "can_read": entry["can_read"],
            "can_write": entry["can_write"],
            "role_id": entry["role_id"],
        }

    if not roles or not resources:
        return '<p class="text-muted" style="font-size:0.85rem;">No permissions configured.</p>'

    page_resources = sorted([r for r in resources if r.startswith("page:")])
    tab_resources = [r for r in resources if r.startswith("tab:")]
    tab_order = [
        "tab:profile", "tab:classifications", "tab:integrations",
        "tab:logging", "tab:sigma", "tab:users",
    ]
    tab_resources = [res for res in tab_order if res in tab_resources] + \
                    [res for res in tab_resources if res not in tab_order]

    if client_id:
        post_url = f"/api/management/clients/{client_id}/permissions"
        target_id = f"permissions-matrix-{client_id}"
    else:
        post_url = "/api/settings/permissions"
        target_id = "permissions-matrix"

    def _label(res):
        parts = res.split(":", 1)
        name = parts[1] if len(parts) > 1 else res
        return name.replace("_", " ").title()

    def _type_badge(res):
        if res.startswith("page:"):
            return '<span class="badge badge-info" style="font-size:0.65rem;">Page</span>'
        return '<span class="badge badge-secondary" style="font-size:0.65rem;">Tab</span>'

    def _rows(resource_list):
        html = ""
        for res in resource_list:
            html += f'<tr><td>{_type_badge(res)} {_label(res)}</td>'
            for role in roles:
                perm = lookup.get((role["name"], res), {"can_read": False, "can_write": False, "role_id": role["id"]})
                role_id = role["id"]
                r_chk = "checked" if perm["can_read"] else ""
                w_chk = "checked" if perm["can_write"] else ""
                html += f'''<td style="text-align:center;">
                    <div style="display:flex;gap:0.5rem;justify-content:center;align-items:center;">
                        <label class="role-checkbox" title="Read">
                            <input type="checkbox" name="perm" {r_chk}
                                hx-post="{post_url}"
                                hx-vals='{{"role_id":"{role_id}","resource":"{res}","access":"read","state":"{("off" if r_chk else "on")}"}}'
                                hx-target="#{target_id}"
                                hx-swap="innerHTML"> R
                        </label>
                        <label class="role-checkbox" title="Write">
                            <input type="checkbox" name="perm" {w_chk}
                                hx-post="{post_url}"
                                hx-vals='{{"role_id":"{role_id}","resource":"{res}","access":"write","state":"{("off" if w_chk else "on")}"}}'
                                hx-target="#{target_id}"
                                hx-swap="innerHTML"> W
                        </label>
                    </div>
                </td>'''
            html += '</tr>'
        return html

    role_headers = "".join(f'<th style="text-align:center;">{r["name"]}</th>' for r in roles)

    blurb = (
        "Control which roles can <strong>Read</strong> (view) or <strong>Write</strong> (modify) "
        "each page and settings tab <em>for this tenant</em>. The ADMIN role always has full access "
        "and is not shown below. Changes take effect on next login."
        if client_id else
        "Control which roles can <strong>Read</strong> (view) or <strong>Write</strong> (modify) each page and settings tab. "
        "The ADMIN role always has full access and is not shown below. Changes take effect on next login."
    )

    return f'''
    <p style="font-size:0.8rem;color:var(--color-text-secondary);margin:0 0 1rem 0;">
        {blurb}
    </p>
    <div id="{target_id}">
        <table class="mapping-table">
            <thead><tr><th>Resource</th>{role_headers}</tr></thead>
            <tbody>
                <tr><td colspan="{len(roles) + 1}" style="font-weight:600;background:var(--color-bg-elevated);padding:0.5rem;">Pages</td></tr>
                {_rows(page_resources)}
                <tr><td colspan="{len(roles) + 1}" style="font-weight:600;background:var(--color-bg-elevated);padding:0.5rem;">Settings Tabs</td></tr>
                {_rows(tab_resources)}
            </tbody>
        </table>
    </div>'''


def _render_threat_intel_tab(instances: list) -> str:
    """Render the Threat Intel (OpenCTI) tab as system-card style cards."""
    from html import escape
    count = len(instances)
    cards = ""
    for i in instances:
        iid = i["id"]
        lbl_esc = escape(i["label"])
        url_esc = escape(i["url"])
        status_pill = _status_pill_html(i, target_id=f"opencti-status-{iid}")
        tenant_chips = _tenant_chips_html(i.get("_clients", []))
        test_btn = _test_button_html("opencti", iid, f"opencti-status-{iid}")

        cards += f'''
        <div class="system-card" style="display:flex;flex-direction:column;">
            <div class="system-card__title" style="display:flex;align-items:center;justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
                    <span style="font-weight:600;">{lbl_esc}</span>
                    {status_pill}
                </div>
                <div style="display:flex;gap:0.25rem;">
                    {test_btn}
                    <button class="btn btn-ghost btn-sm"
                            onclick="editOpenCTI('{iid}', '{lbl_esc}', '{url_esc}')"
                            title="Edit">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
                    </button>
                    <button class="btn btn-ghost btn-sm text-danger"
                            hx-delete="/api/management/opencti/{iid}"
                            hx-target="#mgmt-sub-opencti" hx-swap="innerHTML"
                            hx-confirm="Delete OpenCTI instance '{lbl_esc}'? This will unlink it from all clients."
                            title="Delete">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
                            <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                    </button>
                </div>
            </div>
            <div class="system-card__desc" style="margin-top:0.5rem;">
                <div style="display:grid;grid-template-columns:auto 1fr;gap:0.25rem 0.75rem;font-size:0.8125rem;">
                    <span class="text-secondary">URL</span>
                    <span style="font-family:var(--font-mono,monospace);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{url_esc}">{url_esc}</span>
                    <span class="text-secondary">Token</span>
                    <span class="text-secondary" style="font-size:0.75rem;">{'&#x2713; configured' if i.get('token_enc') else '&#x2717; not set'}</span>
                </div>
            </div>
            <div class="system-card__footer" style="flex-wrap:wrap;margin-top:auto;padding-top:0.75rem;">
                {tenant_chips}
            </div>
        </div>'''

    empty = ""
    if not instances:
        empty = '''
        <div class="empty-output" style="padding:4rem 2rem;text-align:center;">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.3;">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <p style="margin-top:1rem;color:var(--color-text-muted);">No Threat Intel sources configured yet.</p>
        </div>'''

    return f'''
    <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:1.5rem;">
        <span class="text-secondary">{count} OpenCTI instance{"s" if count != 1 else ""} configured</span>
        <button class="btn btn-primary" onclick="showCreateOpenCTIModal()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            New OpenCTI
        </button>
    </div>
    <div class="systems-grid">{cards}</div>
    {empty}'''


def _render_gitlab_tab(instances: list) -> str:
    """Render the GitLab tab as system-card style cards."""
    from html import escape
    count = len(instances)
    cards = ""
    for i in instances:
        iid = i["id"]
        lbl_esc = escape(i["label"])
        url_esc = escape(i["url"])
        grp_esc = escape(i.get("default_group") or "—")
        status_pill = _status_pill_html(i, target_id=f"gitlab-status-{iid}")
        tenant_chips = _tenant_chips_html(i.get("_clients", []))
        test_btn = _test_button_html("gitlab", iid, f"gitlab-status-{iid}")

        cards += f'''
        <div class="system-card" style="display:flex;flex-direction:column;">
            <div class="system-card__title" style="display:flex;align-items:center;justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
                    <span style="font-weight:600;">{lbl_esc}</span>
                    {status_pill}
                </div>
                <div style="display:flex;gap:0.25rem;">
                    {test_btn}
                    <button class="btn btn-ghost btn-sm"
                            onclick="editGitLab('{iid}', '{lbl_esc}', '{url_esc}', '{grp_esc}')"
                            title="Edit">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
                    </button>
                    <button class="btn btn-ghost btn-sm text-danger"
                            hx-delete="/api/management/gitlab/{iid}"
                            hx-target="#mgmt-sub-gitlab" hx-swap="innerHTML"
                            hx-confirm="Delete GitLab instance '{lbl_esc}'?"
                            title="Delete">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
                            <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                    </button>
                </div>
            </div>
            <div class="system-card__desc" style="margin-top:0.5rem;">
                <div style="display:grid;grid-template-columns:auto 1fr;gap:0.25rem 0.75rem;font-size:0.8125rem;">
                    <span class="text-secondary">URL</span>
                    <span style="font-family:var(--font-mono,monospace);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{url_esc}">{url_esc}</span>
                    <span class="text-secondary">Group</span>
                    <span style="font-family:var(--font-mono,monospace);font-size:0.8rem;">{grp_esc}</span>
                    <span class="text-secondary">Token</span>
                    <span class="text-secondary" style="font-size:0.75rem;">{'&#x2713; configured' if i.get('token_enc') else '&#x2717; not set'}</span>
                </div>
            </div>
            <div class="system-card__footer" style="flex-wrap:wrap;margin-top:auto;padding-top:0.75rem;">
                {tenant_chips}
            </div>
        </div>'''

    empty = ""
    if not instances:
        empty = '''
        <div class="empty-output" style="padding:4rem 2rem;text-align:center;">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.3;">
                <path d="m22 16.92-.02.02-2.71 1.6a1 1 0 0 1-1.02-.06l-2.09-1.41a1 1 0 0 0-1.16.08L13 19"/>
                <path d="M22 22H2"/><path d="M2 12 12 2l10 10"/>
            </svg>
            <p style="margin-top:1rem;color:var(--color-text-muted);">No GitLab instances configured yet.</p>
            <p style="color:var(--color-text-muted);font-size:0.85rem;margin-top:0.5rem;">GitLab integration is reserved for future report publishing workflows.</p>
        </div>'''

    return f'''
    <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:1.5rem;">
        <div>
            <span class="text-secondary">{count} GitLab instance{"s" if count != 1 else ""} configured</span>
            <span class="badge badge-secondary" style="margin-left:0.5rem;font-size:0.7rem;">Planned</span>
        </div>
        <button class="btn btn-primary" onclick="showCreateGitLabModal()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            New GitLab
        </button>
    </div>
    <div style="padding:0.75rem 1rem;background:var(--color-bg-elevated);border-radius:var(--radius-md);
                border-left:3px solid var(--color-primary);margin-bottom:1.25rem;font-size:0.85rem;
                color:var(--color-text-secondary);">
        GitLab integration will allow TIDE to push generated reports to a configured repository.
        Register your instance now and it will be available when the feature ships.
    </div>
    <div class="systems-grid">{cards}</div>
    {empty}'''


def _render_keycloak_tab(instances: list) -> str:
    """Render the Keycloak tab as system-card style cards."""
    from html import escape
    count = len(instances)
    cards = ""
    for i in instances:
        iid = i["id"]
        lbl_esc = escape(i["label"])
        url_esc = escape(i["url"])
        realm_esc = escape(i.get("realm") or "master")
        has_client_id = bool(i.get("client_id_enc"))
        has_secret = bool(i.get("client_secret_enc"))
        status_pill = _status_pill_html(i, target_id=f"keycloak-status-{iid}")
        tenant_chips = _tenant_chips_html([], all_tenants=True)
        test_btn = _test_button_html("keycloak", iid, f"keycloak-status-{iid}")

        cards += f'''
        <div class="system-card" style="display:flex;flex-direction:column;">
            <div class="system-card__title" style="display:flex;align-items:center;justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
                    <span style="font-weight:600;">{lbl_esc}</span>
                    {status_pill}
                </div>
                <div style="display:flex;gap:0.25rem;">
                    {test_btn}
                    <button class="btn btn-ghost btn-sm"
                            onclick="editKeycloak('{iid}', '{lbl_esc}', '{url_esc}', '{realm_esc}')"
                            title="Edit">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
                    </button>
                    <button class="btn btn-ghost btn-sm text-danger"
                            hx-delete="/api/management/keycloak/{iid}"
                            hx-target="#mgmt-sub-keycloak" hx-swap="innerHTML"
                            hx-confirm="Delete Keycloak instance &#39;{lbl_esc}&#39;?"
                            title="Delete">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
                            <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                    </button>
                </div>
            </div>
            <div class="system-card__desc" style="margin-top:0.5rem;">
                <div style="display:grid;grid-template-columns:auto 1fr;gap:0.25rem 0.75rem;font-size:0.8125rem;">
                    <span class="text-secondary">URL</span>
                    <span style="font-family:var(--font-mono,monospace);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{url_esc}">{url_esc}</span>
                    <span class="text-secondary">Realm</span>
                    <span style="font-family:var(--font-mono,monospace);font-size:0.8rem;">{realm_esc}</span>
                    <span class="text-secondary">Client ID</span>
                    <span class="text-secondary" style="font-size:0.75rem;">{'&#x2713; configured' if has_client_id else '&#x2717; not set'}</span>
                    <span class="text-secondary">Secret</span>
                    <span class="text-secondary" style="font-size:0.75rem;">{'&#x2713; configured' if has_secret else '&#x2717; not set'}</span>
                </div>
            </div>
            <div class="system-card__footer" style="flex-wrap:wrap;margin-top:auto;padding-top:0.75rem;">
                {tenant_chips}
            </div>
        </div>'''

    empty = ""
    if not instances:
        empty = '''
        <div class="empty-output" style="padding:4rem 2rem;text-align:center;">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.3;">
                <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <p style="margin-top:1rem;color:var(--color-text-muted);">No Keycloak instances configured yet.</p>
            <p style="color:var(--color-text-muted);font-size:0.85rem;margin-top:0.5rem;">Register Keycloak to centralise SSO configuration across clients.</p>
        </div>'''

    return f'''
    <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:1.5rem;">
        <span class="text-secondary">{count} Keycloak instance{"s" if count != 1 else ""} configured</span>
        <button class="btn btn-primary" onclick="showCreateKeycloakModal()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            New Keycloak
        </button>
    </div>
    <div class="systems-grid">{cards}</div>
    {empty}'''


# ---------------------------------------------------------------------------
# Client detail page partial helpers
# ---------------------------------------------------------------------------

def _render_client_siems_partial(client_id: str, db, toast: str = None) -> HTMLResponse:
    """Re-render the client SIEMs section using Jinja2 partial."""
    from html import escape
    import os
    from jinja2 import Environment, FileSystemLoader

    client = db.get_client(client_id)
    client_siems = db.get_client_siems(client_id)
    all_siems = db.list_siem_inventory()
    available_siems = all_siems

    # SIEM rule counts by space
    siem_rule_counts = {}
    try:
        import duckdb
        conn = duckdb.connect(str(db.db_path), read_only=False)  # 4.1.0 P3: pool conflict
        rows = conn.execute(
            "SELECT space, COUNT(*) as total, SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) as enabled "
            "FROM detection_rules WHERE space IS NOT NULL GROUP BY space"
        ).fetchall()
        conn.close()
        for space, total, enabled in rows:
            siem_rule_counts[str(space)] = {"total": int(total), "enabled": int(enabled)}
    except Exception:
        pass

    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("partials/client_siems.html")
    html = template.render(
        client=client, client_siems=client_siems,
        available_siems=available_siems, siem_rule_counts=siem_rule_counts,
    )

    toast_html = ""
    if toast:
        toast_html = (
            f'<div hx-swap-oob="afterbegin:#toast-container">'
            f'<div class="toast toast-success">{escape(toast)}</div></div>'
        )

    return HTMLResponse(f"{html}{toast_html}")


def _render_client_opencti_partial(client_id: str, db, toast: str = None) -> HTMLResponse:
    """Re-render the client OpenCTI section using Jinja2 partial."""
    from html import escape
    import os
    from jinja2 import Environment, FileSystemLoader

    client = db.get_client(client_id)
    client_opencti = db.get_client_opencti_instances(client_id)
    all_opencti = db.list_opencti_inventory()
    linked_ids = {o["id"] for o in client_opencti}
    available_opencti = [o for o in all_opencti if o["id"] not in linked_ids]

    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("partials/client_opencti.html")
    html = template.render(
        client=client,
        client_opencti=client_opencti,
        available_opencti=available_opencti,
    )

    toast_html = ""
    if toast:
        toast_html = (
            f'<div hx-swap-oob="afterbegin:#toast-container">'
            f'<div class="toast toast-success">{escape(toast)}</div></div>'
        )

    return HTMLResponse(f"{html}{toast_html}")


def _render_client_users_partial(client_id: str, db, toast: str = None) -> HTMLResponse:
    """Re-render the client users section using Jinja2 partial."""
    from html import escape
    import os
    from jinja2 import Environment, FileSystemLoader

    client = db.get_client(client_id)
    client_users = db.get_client_users(client_id)
    all_users = db.get_all_users()
    all_roles = db.get_all_roles()
    # Decorate each assigned user with their current role for THIS tenant so
    # the template can pre-select the dropdown without doing N queries itself.
    for u in client_users:
        roles = db.get_user_roles(u["id"], client_id=client_id)
        u["_current_role"] = roles[0] if roles else ""
    assigned_ids = {u["id"] for u in client_users}
    available_users = [u for u in all_users if u["id"] not in assigned_ids]

    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("partials/client_users.html")
    html = template.render(
        client=client, client_users=client_users,
        available_users=available_users,
        all_roles=all_roles,
    )

    toast_html = ""
    if toast:
        toast_html = (
            f'<div hx-swap-oob="afterbegin:#toast-container">'
            f'<div class="toast toast-success">{escape(toast)}</div></div>'
        )

    return HTMLResponse(f"{html}{toast_html}")


def _render_client_systems_partial(client_id: str, db, toast: str = None) -> HTMLResponse:
    """Re-render the client systems section using Jinja2 partial."""
    from html import escape
    import os
    from jinja2 import Environment, FileSystemLoader
    from app.inventory_engine import list_systems, list_playbooks, get_system_summaries
    from app.services.tenant_manager import tenant_context_for

    client = db.get_client(client_id)
    with tenant_context_for(client_id):
        client_systems = list_systems(client_id=client_id)
        all_systems = list_systems()
        system_summaries = get_system_summaries(client_id=client_id)
    assigned_ids = {s.id for s in client_systems}
    available_systems = [s for s in all_systems if s.id not in assigned_ids]
    all_clients = [c for c in db.list_clients() if c["id"] != client_id]

    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("partials/client_systems.html")
    html = template.render(
        client=client, client_systems=client_systems,
        system_summaries=system_summaries,
        available_systems=available_systems,
        all_clients=all_clients,
    )

    # OOB update the edit-systems-modal in client_detail.html
    sys_options = "".join(
        f'<option value="{s.id}">{escape(s.name)}'
        f'{" (" + escape(s.classification) + ")" if s.classification else ""}'
        f'</option>'
        for s in available_systems
    )
    client_opts = "".join(
        f'<option value="{c["id"]}">{escape(c["name"])}</option>'
        for c in all_clients
    )

    # Rebuild the edit-systems-modal OOB
    sys_list_items = ""
    for s in client_systems:
        cls_badge = f' <span class="badge badge-muted" style="font-size:0.6rem;">{escape(s.classification)}</span>' if s.classification else ""
        sys_list_items += (
            f'<div style="display:flex;align-items:center;justify-content:space-between;padding:0.35rem 0.5rem;background:var(--color-bg-surface);border-radius:var(--radius-sm);font-size:0.85rem;">'
            f'<span>{escape(s.name)}{cls_badge}</span>'
            f'<div style="display:flex;gap:0.25rem;">'
            f'<button class="btn btn-ghost btn-sm" onclick="document.getElementById(\'edit-systems-modal\').style.display=\'none\';openMoveSystemModal(\'{s.id}\', \'{escape(s.name)}\')" style="padding:0.15rem 0.35rem;font-size:0.75rem;">'
            f'<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m16 3 4 4-4 4"/><path d="M20 7H4"/><path d="m8 21-4-4 4-4"/><path d="M4 17h16"/></svg> Move</button>'
            f'<button class="btn btn-ghost btn-sm text-danger" hx-delete="/api/management/clients/{client_id}/systems/{s.id}" hx-target="#client-systems-section" hx-swap="innerHTML" hx-confirm="Remove \'{escape(s.name)}\' from this client?" style="padding:0.15rem 0.35rem;font-size:0.75rem;">'
            f'<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Remove</button>'
            f'</div></div>'
        )

    modal_body = '<div style="display:flex;flex-direction:column;gap:1rem;">'
    if client_systems:
        modal_body += f'<div><label class="form-label">Current Systems</label><div style="display:flex;flex-direction:column;gap:0.35rem;">{sys_list_items}</div></div>'
    if available_systems:
        modal_body += (
            f'<hr style="border:none;border-top:1px solid var(--color-border);margin:0;">'
            f'<form hx-post="/api/management/clients/{client_id}/systems" hx-target="#client-systems-section" hx-swap="innerHTML" style="display:flex;flex-direction:column;gap:0.75rem;" hx-on::before-request="if(event.detail.elt===this) document.getElementById(\'edit-systems-modal\').style.display=\'none\'">'
            f'<label class="form-label">Add System</label>'
            f'<select name="system_id" class="form-input" required><option value="" disabled selected>Select a system&hellip;</option>{sys_options}</select>'
            f'<button type="submit" class="btn btn-primary btn-sm"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/><path d="M12 5v14"/></svg> Add System</button></form>'
        )
    if all_clients:
        modal_body += (
            f'<hr style="border:none;border-top:1px solid var(--color-border);margin:0;">'
            f'<form hx-post="/api/management/clients/{client_id}/move-from" hx-target="#client-systems-section" hx-swap="innerHTML" style="display:flex;flex-direction:column;gap:0.75rem;" hx-on::before-request="if(event.detail.elt===this) document.getElementById(\'edit-systems-modal\').style.display=\'none\'">'
            f'<label class="form-label">Move from Another Client</label>'
            f'<select name="source_client_id" class="form-input" required hx-get="/api/management/clients/{client_id}/move-from/systems" hx-target="#edit-move-from-system-select" hx-trigger="change" hx-include="this" hx-swap="innerHTML">'
            f'<option value="" disabled selected>Select source client&hellip;</option>{client_opts}</select>'
            f'<select name="system_id" id="edit-move-from-system-select" class="form-input" required><option value="" disabled selected>Select a source client first&hellip;</option></select>'
            f'<label style="display:flex;align-items:center;gap:0.5rem;font-size:0.85rem;cursor:pointer;"><input type="checkbox" name="move_baselines" checked style="accent-color:var(--color-primary);"> Also move associated baselines</label>'
            f'<button type="submit" class="btn btn-primary btn-sm"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m16 3 4 4-4 4"/><path d="M20 7H4"/><path d="m8 21-4-4 4-4"/><path d="M4 17h16"/></svg> Move Here</button></form>'
        )
    modal_body += (
        f'<div style="display:flex;justify-content:flex-end;">'
        f'<button type="button" class="btn btn-secondary btn-sm" onclick="document.getElementById(\'edit-systems-modal\').style.display=\'none\'">Close</button></div></div>'
    )

    edit_modal_oob = (
        f'<div id="edit-systems-modal" class="modal-overlay" style="display:none;" hx-swap-oob="true" '
        f'onclick="if(event.target===this) this.style.display=\'none\'">'
        f'<div class="modal-content modal-sm"><div class="modal-header">'
        f'<h3 class="modal-title">Manage Systems — {escape(client["name"])}</h3>'
        f'<button style="background:none;border:none;cursor:pointer;color:var(--color-muted);font-size:1.3rem;line-height:1;" '
        f'onclick="document.getElementById(\'edit-systems-modal\').style.display=\'none\'">&#x2715;</button></div>'
        f'{modal_body}</div></div>'
    )

    toast_html = ""
    if toast:
        toast_html = (
            f'<div hx-swap-oob="afterbegin:#toast-container">'
            f'<div class="toast toast-success">{escape(toast)}</div></div>'
        )

    return HTMLResponse(f"{html}{edit_modal_oob}{toast_html}")


def _render_client_baselines_partial(client_id: str, db, toast: str = None) -> HTMLResponse:
    """Re-render the client baselines section using Jinja2 partial."""
    from html import escape
    import os
    from jinja2 import Environment, FileSystemLoader
    from app.inventory_engine import list_playbooks
    from app.services.tenant_manager import tenant_context_for

    client = db.get_client(client_id)
    with tenant_context_for(client_id):
        client_baselines = list_playbooks(client_id=client_id)
        all_baselines = list_playbooks()
    assigned_ids = {b.id for b in client_baselines}
    available_baselines = [b for b in all_baselines if b.id not in assigned_ids]
    other_clients = [c for c in db.list_clients() if c["id"] != client_id]

    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("partials/client_baselines.html")
    html = template.render(
        client=client, client_baselines=client_baselines,
        available_baselines=available_baselines,
        all_clients=other_clients,
    )

    # OOB update the edit-baselines-modal
    bl_list_items = ""
    for b in client_baselines:
        bl_list_items += (
            f'<div style="display:flex;align-items:center;justify-content:space-between;padding:0.35rem 0.5rem;background:var(--color-bg-surface);border-radius:var(--radius-sm);font-size:0.85rem;">'
            f'<span>{escape(b.name)}</span>'
            f'<button class="btn btn-ghost btn-sm text-danger" hx-delete="/api/management/clients/{client_id}/baselines/{b.id}" hx-target="#client-baselines-section" hx-swap="innerHTML" hx-confirm="Remove \'{escape(b.name)}\' from this client?" style="padding:0.15rem 0.35rem;font-size:0.75rem;">'
            f'<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Remove</button></div>'
        )

    bl_options = "".join(
        f'<option value="{b.id}">{escape(b.name)}</option>'
        for b in available_baselines
    )
    client_opts = "".join(
        f'<option value="{c["id"]}">{escape(c["name"])}</option>'
        for c in other_clients
    )

    modal_body = '<div style="display:flex;flex-direction:column;gap:1rem;">'
    if client_baselines:
        modal_body += f'<div><label class="form-label">Current Baselines</label><div style="display:flex;flex-direction:column;gap:0.35rem;">{bl_list_items}</div></div>'
    if available_baselines:
        modal_body += (
            f'<hr style="border:none;border-top:1px solid var(--color-border);margin:0;">'
            f'<form hx-post="/api/management/clients/{client_id}/baselines" hx-target="#client-baselines-section" hx-swap="innerHTML" style="display:flex;flex-direction:column;gap:0.75rem;" hx-on::before-request="if(event.detail.elt===this) document.getElementById(\'edit-baselines-modal\').style.display=\'none\'">'
            f'<label class="form-label">Add Baseline</label>'
            f'<select name="baseline_id" class="form-input" required><option value="" disabled selected>Select a baseline&hellip;</option>{bl_options}</select>'
            f'<button type="submit" class="btn btn-primary btn-sm"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/><path d="M12 5v14"/></svg> Add Baseline</button></form>'
        )
    if other_clients:
        modal_body += (
            f'<hr style="border:none;border-top:1px solid var(--color-border);margin:0;">'
            f'<form hx-post="/api/management/clients/{client_id}/clone-baseline" hx-target="#client-baselines-section" hx-swap="innerHTML" style="display:flex;flex-direction:column;gap:0.75rem;" hx-on::before-request="if(event.detail.elt===this) document.getElementById(\'edit-baselines-modal\').style.display=\'none\'">'
            f'<label class="form-label">Clone from Another Client</label>'
            f'<select name="source_client_id" class="form-input" required hx-get="/api/management/clients/{client_id}/clone-baseline/baselines" hx-target="#edit-clone-baseline-select" hx-trigger="change" hx-include="this" hx-swap="innerHTML">'
            f'<option value="" disabled selected>Select source client&hellip;</option>{client_opts}</select>'
            f'<select name="baseline_id" id="edit-clone-baseline-select" class="form-input" required><option value="" disabled selected>Select a source client first&hellip;</option></select>'
            f'<button type="submit" class="btn btn-primary btn-sm"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg> Clone Baseline</button></form>'
        )
    modal_body += (
        f'<div style="display:flex;justify-content:flex-end;">'
        f'<button type="button" class="btn btn-secondary btn-sm" onclick="document.getElementById(\'edit-baselines-modal\').style.display=\'none\'">Close</button></div></div>'
    )

    edit_modal_oob = (
        f'<div id="edit-baselines-modal" class="modal-overlay" style="display:none;" hx-swap-oob="true" '
        f'onclick="if(event.target===this) this.style.display=\'none\'">'
        f'<div class="modal-content modal-sm"><div class="modal-header">'
        f'<h3 class="modal-title">Manage Baselines — {escape(client["name"])}</h3>'
        f'<button style="background:none;border:none;cursor:pointer;color:var(--color-muted);font-size:1.3rem;line-height:1;" '
        f'onclick="document.getElementById(\'edit-baselines-modal\').style.display=\'none\'">&#x2715;</button></div>'
        f'{modal_body}</div></div>'
    )

    toast_html = ""
    if toast:
        toast_html = (
            f'<div hx-swap-oob="afterbegin:#toast-container">'
            f'<div class="toast toast-success">{escape(toast)}</div></div>'
        )

    return HTMLResponse(f"{html}{edit_modal_oob}{toast_html}")
