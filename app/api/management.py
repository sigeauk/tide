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

from app.api.deps import DbDep, RequireAdmin, RequireSuperadmin, ActiveClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory move-task tracker (async move system)
# ---------------------------------------------------------------------------
_move_tasks: dict = {}   # task_id -> { status, message, client_id, result }

router = APIRouter(prefix="/api/management", tags=["management"])


# ---------------------------------------------------------------------------
# Live Kibana space lookup, cached. Used to validate operator input on the
# Add-SIEM-to-tenant form so a typo'd space name (e.g. "production" vs the
# actual "default" or "one") is rejected before it lands in client_siem_map
# and silently breaks every subsequent sync. 60-second TTL is plenty short
# for operator workflows and stops a flapping Kibana from slowing the UI.
# ---------------------------------------------------------------------------
_KIBANA_SPACES_CACHE: dict = {}  # siem_id -> (expiry_epoch, set[str] | None)
_KIBANA_SPACES_TTL = 60.0


# ---------------------------------------------------------------------------
# API token normalisation. Operator-visible failure mode: pasting the API key
# from Kibana sometimes brings along the literal ``ApiKey `` prefix, a
# trailing newline from a wrapped terminal, or whitespace from a copy-paste
# out of a JSON viewer. Any of those silently 401s every request because the
# Authorization header becomes ``ApiKey ApiKey <token>`` or ``ApiKey <token>\n``.
# Normalise on every read of the form so the column always holds the bare
# base64 string. Returns ``(token, error_message_or_None)``.
# ---------------------------------------------------------------------------
def _normalize_api_token(raw: str) -> tuple[Optional[str], Optional[str]]:
    if raw is None:
        return None, None
    t = str(raw).strip()
    if not t:
        return None, None
    # Strip an accidentally-pasted ``ApiKey `` / ``Bearer `` prefix.
    low = t.lower()
    for prefix in ("apikey ", "bearer "):
        if low.startswith(prefix):
            t = t[len(prefix):].strip()
            low = t.lower()
    # Reject if there's any internal whitespace — that means the paste split
    # mid-token, or the operator pasted a JSON object instead of the encoded
    # field. Either way Kibana will 401, so fail loudly at save time.
    if any(ch.isspace() for ch in t):
        return None, (
            "API key contains internal whitespace. Paste only the single "
            "base64 'Encoded' value from Kibana → Stack Management → API keys, "
            "not the full JSON object or a wrapped multi-line string."
        )
    return t, None


def _list_kibana_spaces(db, siem_id: str) -> Optional[set]:
    """Return the set of space ids on this SIEM's Kibana, or ``None`` when
    discovery has nothing to offer (no creds, no persisted cache, and live
    lookup failed) -- caller should fail open and not block the operator.

    Thin wrapper around
    :func:`app.services.space_resolver.resolve_discoverable_spaces`
    that adds an in-memory TTL cache so chatty UI calls (the link-to-tenant
    form re-renders on every keystroke via HTMX) don't hit Kibana on every
    request. The resolver itself owns the persistent cache and the live
    lookup, keeping this code path in lock-step with what the sync
    orchestrator does (4.1.7 Phase B -- see
    ``app/services/space_resolver.py``).
    """
    import time as _time
    from app.services.space_resolver import (
        resolve_discoverable_spaces,
        REASON_NO_CREDS,
        REASON_LIVE_FAILED,
        REASON_NO_SPACES,
    )
    now = _time.time()
    cached = _KIBANA_SPACES_CACHE.get(siem_id)
    if cached and cached[0] > now:
        return cached[1]
    try:
        spaces, reason = resolve_discoverable_spaces(db, siem_id, allow_live=True)
    except Exception as exc:
        logger.warning(
            f"_list_kibana_spaces({siem_id}): resolver raised: {exc!r}"
        )
        spaces, reason = set(), "resolver_error"
    if not spaces and reason in (REASON_NO_CREDS, REASON_LIVE_FAILED, REASON_NO_SPACES):
        # Distinguish "we tried and Kibana said nothing" from "we never
        # tried" -- surfaces in logs only; callers see None either way.
        logger.info(
            f"_list_kibana_spaces({siem_id}): no spaces resolved (reason={reason})"
        )
    result: Optional[set] = spaces if spaces else None
    _KIBANA_SPACES_CACHE[siem_id] = (now + _KIBANA_SPACES_TTL, result)
    return result


def _match_space_id(candidate: str, available: set) -> Optional[str]:
    """Return canonical space id from ``available`` matching ``candidate``.

    Accept exact matches first. If none, accept a single case-insensitive
    match so operators aren't blocked by accidental capitalization.
    """
    c = (candidate or "").strip()
    if not c:
        return None
    if c in available:
        return c
    c_l = c.lower()
    folded = [s for s in available if str(s).strip().lower() == c_l]
    if len(folded) == 1:
        return folded[0]
    return None


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
def tab_siems(request: Request, db: DbDep, user: RequireSuperadmin, client_id: ActiveClient):
    """SIEMs tab partial for the management hub.

    Restricted to platform super-admins (4.1.6). Tenant admins manage which
    SIEMs are linked to their tenants from the Settings → Clients → tenant
    detail page; the global inventory (where API tokens live) is no longer
    visible to them. Closes the cross-tenant credential-leak path where any
    tenant admin could read every other tenant's stored API keys.
    """
    siems = db.list_siem_inventory()
    for s in siems:
        s["_clients"] = db.get_siem_clients(s["id"])
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
    return _render_users_tab(users, all_roles, clients, current_user=user)


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
    return _render_users_tab(users, all_roles, clients, current_user=user)


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


@router.post("/users/{user_id}/superadmin", response_class=HTMLResponse)
def mgmt_toggle_user_superadmin(request: Request, user_id: str, db: DbDep,
                                 user: RequireSuperadmin, client_id: ActiveClient):
    """Grant or revoke the platform-admin (superadmin) flag on a user.

    Only an existing super-admin may call this. Self-revoke is blocked so an
    operator cannot accidentally lock themselves out of the only platform-admin
    account. The flag is the platform-wide bypass — it grants visibility into
    every tenant and the SIEMs management tab — so changes are audit-logged.
    Added in 4.1.6.
    """
    from app.services.log_context import audit_log
    target = db.get_user_by_id(user_id)
    if not target:
        return HTMLResponse(
            '<div hx-swap-oob="afterbegin:#toast-container">'
            '<div class="toast toast-warning">User not found.</div></div>'
        )
    if user_id == user.id:
        return HTMLResponse(
            '<div hx-swap-oob="afterbegin:#toast-container">'
            '<div class="toast toast-warning">You cannot change your own platform-admin flag.</div></div>'
            + _refresh_users_tab(db, user=user, client_id=client_id)
        )
    new_value = not bool(target.get("is_superadmin"))
    db.set_user_superadmin(user_id, new_value)
    audit_log(
        "superadmin_grant" if new_value else "superadmin_revoke",
        actor_id=user.id, actor_username=user.username,
        target_id=user_id, target_username=target.get("username"),
    )
    logger.warning(
        f"Platform-admin {'granted to' if new_value else 'revoked from'} "
        f"{target.get('username')} ({user_id}) by {user.username}"
    )
    toast = (
        '<div hx-swap-oob="afterbegin:#toast-container">'
        f'<div class="toast toast-success">Platform-admin '
        f'{"granted to" if new_value else "revoked from"} '
        f'{_esc(target.get("username") or user_id)}.</div></div>'
    )
    return HTMLResponse(toast + _refresh_users_tab(db, user=user, client_id=client_id))


@router.get("/tab/permissions", response_class=HTMLResponse)
def tab_permissions(request: Request, db: DbDep, user: RequireAdmin):
    """Permissions tab partial for the management hub."""
    return _render_permissions_tab(db)


@router.get("/tab/threat-intel", response_class=HTMLResponse)
def tab_threat_intel(request: Request, db: DbDep, user: RequireAdmin):
    """Retired in 5.0.0 — see Management → Connectors instead.

    Kept only so a legacy bookmark / HTMX poll renders a stable
    explanatory message instead of a 404. Migration 50 dropped the
    underlying ``opencti_inventory`` table.
    """
    return HTMLResponse(
        '<div class="text-secondary" style="padding:1rem;">'
        'Threat Intel (legacy OpenCTI GraphQL) was retired in 5.0.0. '
        'Add OpenCTI as an <code>opencti_taxii</code> connector under '
        '<a href="/management#mgmt-sub-connectors" '
        'style="color:var(--color-primary);">Management → Connectors</a> '
        'instead.</div>'
    )


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



# ---------------------------------------------------------------------------
# Legacy OpenCTI GraphQL endpoints (retired in 5.0.0).
#
# Every /opencti/* route below has been removed:
#   * POST /opencti/test-connection          (GraphQL probe)
#   * POST /opencti                          (create instance)
#   * PUT  /opencti/{id}                     (update instance)
#   * DELETE /opencti/{id}                   (delete instance)
#   * POST /opencti/{id}/sync-cti            (GraphQL bundle pull)
#   * POST /clients/{cid}/opencti            (link to client)
#   * DELETE /clients/{cid}/opencti/{id}     (unlink from client)
# Migration 50 drops the backing tables (``opencti_inventory`` and
# ``client_opencti_map``); the corresponding section in the Management
# UI was already removed in 4.1.20. The new path is
# ``/api/management/connectors[/{id}[/test|/sync]]`` driven by the
# multi-vendor framework in ``app.services.cti_connectors``.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# CTI Egress Targets CRUD  (Phase 1 §4 — per-tenant)
#
# An egress target tells TIDE *where* to ship a tenant's CTI indicators.
# It lives in the tenant's CTI DuckDB (``cti_<slug>_<short>.duckdb``)
# rather than the shared ``tide.duckdb``, so a tenant's Elastic key
# never leaves their database. ``siem_id`` is a soft reference to the
# shared ``siem_inventory`` row — validated at this layer, not via FK.
# ---------------------------------------------------------------------------

def _validate_siem_id(db, siem_id: Optional[str]) -> Optional[str]:
    """Return error message if siem_id is set but doesn't exist."""
    if not siem_id:
        return None
    try:
        with db.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM siem_inventory WHERE id = ?", [siem_id],
            ).fetchone()
    except Exception:
        return "Could not verify siem_id against inventory."
    if not row:
        return f"SIEM id {siem_id!r} not found in inventory."
    return None


def _validate_client_id(db, client_id: str) -> bool:
    try:
        with db.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM clients WHERE id = ?", [client_id],
            ).fetchone()
    except Exception:
        return False
    return bool(row)


def _render_client_cti_egress_partial(client_id: str, db,
                                      toast: Optional[str] = None,
                                      ) -> HTMLResponse:
    """Re-render the client CTI egress section using the Jinja2 partial.

    Mirrors :func:`_render_client_opencti_partial` so create / update /
    delete endpoints can return a single OOB-aware payload that swaps the
    full section in place.
    """
    from html import escape
    import os
    from jinja2 import Environment, FileSystemLoader
    from app.services import cti_database

    client = db.get_client(client_id)
    try:
        cti_targets = cti_database.list_egress_targets(client_id)
    except Exception as exc:
        logger.warning(
            f"cti_targets read for client {client_id} failed: {exc}"
        )
        cti_targets = []
    siems = db.list_siem_inventory()

    templates_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "templates",
    )
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("partials/client_cti_egress.html")
    html = template.render(
        client=client,
        cti_targets=cti_targets,
        siems=siems,
    )

    toast_html = ""
    if toast:
        toast_html = (
            f'<div hx-swap-oob="afterbegin:#toast-container">'
            f'<div class="toast toast-success">{escape(toast)}</div></div>'
        )
    return HTMLResponse(f"{html}{toast_html}")


@router.get("/clients/{client_id}/cti-egress", response_class=HTMLResponse)
def list_cti_egress_targets(request: Request, client_id: str,
                            db: DbDep, user: RequireAdmin):
    """Render the CTI egress targets section for ``client_id``.

    Returns the same partial used inside the client detail page, so HTMX
    callers can swap it into ``#client-cti-egress-section``.
    """
    if not _validate_client_id(db, client_id):
        return HTMLResponse(
            '<span class="badge badge-warning">Client not found</span>',
            status_code=404,
        )
    return _render_client_cti_egress_partial(client_id, db)


@router.post("/clients/{client_id}/cti-egress", response_class=HTMLResponse)
async def create_cti_egress_target(request: Request, client_id: str,
                                   db: DbDep, user: RequireAdmin):
    """Create a CTI egress target for ``client_id``."""
    from app.services import cti_database

    if not _validate_client_id(db, client_id):
        return HTMLResponse(
            '<span class="badge badge-warning">Client not found</span>',
            status_code=404,
        )
    form = await request.form()
    label = str(form.get("label", "")).strip()
    kind = (str(form.get("kind", "")).strip().lower() or "elastic")
    siem_id = (str(form.get("siem_id", "")).strip() or None)
    index_pattern = str(form.get("index_pattern", "")).strip() \
        or "logs-ti_tide.indicator-*"
    latest_index = str(form.get("latest_index", "")).strip() \
        or "logs-ti_tide_latest"
    api_key = (str(form.get("api_key", "")).strip() or None)
    folder_path = (str(form.get("folder_path", "")).strip() or None)
    diode_endpoint = (str(form.get("diode_endpoint", "")).strip() or None)
    tlp_ceiling = (str(form.get("tlp_ceiling", "")).strip() or "amber")
    is_active_raw = str(form.get("is_active", "true")).strip().lower()
    is_active = is_active_raw not in ("false", "0", "no", "off")

    if not label:
        return HTMLResponse(
            '<span class="badge badge-warning">label is required</span>',
            status_code=400,
        )
    # Per-kind validation: elastic needs a SIEM; file-drop kinds need a path.
    if kind == "elastic":
        err = _validate_siem_id(db, siem_id)
        if err:
            return HTMLResponse(
                f'<span class="badge badge-warning">{_esc(err)}</span>',
                status_code=400,
            )
    elif kind == "stix_folder":
        if not folder_path:
            return HTMLResponse(
                '<span class="badge badge-warning">folder_path is required for stix_folder targets</span>',
                status_code=400,
            )
        siem_id = None  # not used by file-drop drivers
    elif kind == "diode":
        # diode_endpoint is optional — driver falls back to the per-client
        # data/diode_outbox/<client_id>/ outbox when blank.
        siem_id = None
    else:
        return HTMLResponse(
            f'<span class="badge badge-warning">unknown egress kind {_esc(kind)!r}</span>',
            status_code=400,
        )

    created = cti_database.create_egress_target(
        client_id,
        label=label, kind=kind, siem_id=siem_id,
        index_pattern=index_pattern, latest_index=latest_index,
        api_key_enc=api_key,
        folder_path=folder_path, diode_endpoint=diode_endpoint,
        tlp_ceiling=tlp_ceiling,
        is_active=is_active,
    )
    logger.info(
        f"CTI egress target created: client={client_id} label={label!r} "
        f"siem_id={siem_id} id={created['id']} by {user.username}"
    )
    return _render_client_cti_egress_partial(
        client_id, db, toast=f"Egress target '{label}' created.",
    )


@router.put("/clients/{client_id}/cti-egress/{target_id}",
            response_class=HTMLResponse)
async def update_cti_egress_target(request: Request, client_id: str,
                                   target_id: str, db: DbDep,
                                   user: RequireAdmin):
    """Patch a CTI egress target. Only supplied form fields are updated."""
    from app.services import cti_database

    if not _validate_client_id(db, client_id):
        return HTMLResponse(
            '<span class="badge badge-warning">Client not found</span>',
            status_code=404,
        )
    form = await request.form()
    updates: dict = {}
    for key in ("label", "kind", "siem_id", "index_pattern", "latest_index",
                "api_key", "folder_path", "diode_endpoint",
                "tlp_ceiling", "is_active"):
        if key in form:
            raw = str(form.get(key, "")).strip()
            if key == "is_active":
                updates[key] = raw.lower() not in ("false", "0", "no", "off")
            elif key == "api_key":
                updates["api_key_enc"] = raw or None
            elif key == "kind":
                updates[key] = raw.lower() or "elastic"
            else:
                updates[key] = raw or None

    # Only validate siem_id when the (possibly updated) effective kind is
    # elastic. For stix_folder/diode the SIEM is optional/ignored.
    eff_kind = updates.get("kind")
    if eff_kind is None:
        existing = cti_database.get_egress_target(client_id, target_id)
        eff_kind = (existing or {}).get("kind", "elastic")
    if eff_kind == "elastic" and "siem_id" in updates:
        err = _validate_siem_id(db, updates["siem_id"])
        if err:
            return HTMLResponse(
                f'<span class="badge badge-warning">{_esc(err)}</span>',
                status_code=400,
            )

    updated = cti_database.update_egress_target(
        client_id, target_id, **updates,
    )
    if updated is None:
        return HTMLResponse(
            '<span class="badge badge-warning">Target not found</span>',
            status_code=404,
        )
    logger.info(
        f"CTI egress target updated: client={client_id} id={target_id} "
        f"keys={sorted(updates)} by {user.username}"
    )
    return _render_client_cti_egress_partial(
        client_id, db, toast="Egress target updated.",
    )


@router.delete("/clients/{client_id}/cti-egress/{target_id}",
               response_class=HTMLResponse)
def delete_cti_egress_target(request: Request, client_id: str, target_id: str,
                             db: DbDep, user: RequireAdmin):
    """Delete a CTI egress target."""
    from app.services import cti_database

    if not _validate_client_id(db, client_id):
        return HTMLResponse(
            '<span class="badge badge-warning">Client not found</span>',
            status_code=404,
        )
    removed = cti_database.delete_egress_target(client_id, target_id)
    if not removed:
        return HTMLResponse(
            '<span class="badge badge-warning">Target not found</span>',
            status_code=404,
        )
    logger.info(
        f"CTI egress target deleted: client={client_id} id={target_id} "
        f"by {user.username}"
    )
    return _render_client_cti_egress_partial(
        client_id, db, toast="Egress target deleted.",
    )


@router.post("/clients/{client_id}/cti-egress/{target_id}/run",
             response_class=HTMLResponse)
def run_cti_egress_target(request: Request, client_id: str, target_id: str,
                          db: DbDep, user: RequireAdmin):
    """Trigger an immediate export of indicators to one egress target.

    Returns an HTML badge summarising the result (read / batches /
    latest_indexed / history_created / failures), in the same shape as
    the step 6b ``/opencti/.../sync-cti`` button.
    """
    from app.services import cti_egress

    if not _validate_client_id(db, client_id):
        return HTMLResponse(
            '<span class="badge badge-warning">Client not found</span>',
            status_code=404,
        )
    try:
        summary = cti_egress.export_cti_for_client(
            client_id, target_id=target_id,
        )
    except Exception as exc:
        logger.error(
            f"CTI egress run failed: client={client_id} target={target_id}: "
            f"{exc}", exc_info=True,
        )
        return HTMLResponse(
            f'<span class="badge badge-danger">Egress failed &mdash; '
            f"{_esc(str(exc)[:120])}</span>"
        )

    if summary.get("targets", 0) == 0:
        return HTMLResponse(
            '<span class="badge badge-warning">Target not found '
            "or inactive</span>"
        )

    read = summary.get("read", 0)
    batches = summary.get("batches", 0)
    latest = summary.get("latest_indexed", 0)
    hist = summary.get("history_created", 0)
    dup = summary.get("history_duplicates", 0)
    fails = summary.get("failures", 0)
    errors = summary.get("errors", [])
    cls = "badge-success" if not errors and not fails else "badge-warning"
    err_suffix = f" &middot; {len(errors)} error(s)" if errors else ""
    fail_suffix = f" &middot; {fails} failed" if fails else ""
    logger.info(
        f"CTI egress run: client={client_id} target={target_id} "
        f"read={read} batches={batches} latest={latest} "
        f"hist={hist} dup={dup} fails={fails}"
    )
    return HTMLResponse(
        f'<span class="badge {cls}">'
        f"{read} read &middot; {batches} batch(es) &middot; "
        f"{latest} latest &middot; {hist} hist (+{dup} dup)"
        f"{fail_suffix}{err_suffix}</span>"
    )


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
async def create_siem(request: Request, db: DbDep, user: RequireSuperadmin):
    """Create a SIEM in the centralized inventory."""
    form = await request.form()
    siem_type = str(form.get("siem_type", "elastic")).strip()
    label = str(form.get("label", "")).strip()
    elasticsearch_url = str(form.get("elasticsearch_url", "")).strip() or None
    kibana_url = str(form.get("kibana_url", "")).strip() or None
    api_token, tok_err = _normalize_api_token(form.get("api_token"))
    if tok_err:
        return HTMLResponse(
            '<div hx-swap-oob="afterbegin:#toast-container">'
            f'<div class="toast toast-warning">{_esc(tok_err)}</div></div>'
        )

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
async def update_siem(request: Request, siem_id: str, db: DbDep, user: RequireSuperadmin):
    """Update a SIEM in the inventory."""
    form = await request.form()
    updates = {}
    for field in ("label", "elasticsearch_url", "kibana_url"):
        val = form.get(field)
        if val is not None:
            updates[field] = str(val).strip() or None
    # Token field: form input is named ``api_token`` (see management.html);
    # column is ``api_token_enc``. Only update the token when the operator
    # actually typed something — empty string means "keep existing", per the
    # form placeholder. Run through the shared normaliser to strip an
    # accidental ``ApiKey `` prefix and reject embedded whitespace before it
    # reaches the DB.
    raw_token = form.get("api_token")
    if raw_token is not None and str(raw_token).strip():
        norm, err = _normalize_api_token(raw_token)
        if err:
            return HTMLResponse(
                '<div hx-swap-oob="afterbegin:#toast-container">'
                f'<div class="toast toast-warning">{_esc(err)}</div></div>'
            )
        if norm:
            updates["api_token_enc"] = norm
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
def delete_siem(request: Request, siem_id: str, db: DbDep, user: RequireSuperadmin):
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

def _format_test_result_panel(result: dict, *, panel_id: str = "siem-test-result") -> str:
    """Render a three-row breakdown of a Kibana test result. Returned as an
    OOB-swap fragment so the per-card pill stays in place and a separate
    persistent panel below the form / card shows the full diagnostic.
    """
    rows = []
    for chk in result.get("checks", []):
        icon = "✓" if chk["ok"] else "✗"
        cls = "status-pill--ok" if chk["ok"] else "status-pill--fail"
        sc = chk.get("status_code")
        sc_str = f" [HTTP {sc}]" if sc is not None else ""
        body = chk.get("body_excerpt")
        body_html = (
            f'<div style="font-family:var(--font-mono,monospace);font-size:0.75rem;'
            f'color:var(--color-text-secondary);margin-left:1.5rem;'
            f'word-break:break-all;">{_esc(body)}</div>'
        ) if body else ""
        rows.append(
            f'<div style="padding:0.4rem 0;border-top:1px solid var(--color-border);">'
            f'<div style="display:flex;gap:0.5rem;align-items:center;">'
            f'<span class="status-pill {cls}" style="min-width:1.25rem;text-align:center;">{icon}</span>'
            f'<strong>{_esc(chk["name"])}</strong>'
            f'<code style="font-size:0.75rem;color:var(--color-text-secondary);">{_esc(chk["endpoint"])}{sc_str}</code>'
            f'</div>'
            f'<div style="margin-left:1.5rem;font-size:0.8125rem;">{_esc(chk["detail"])}</div>'
            f'{body_html}'
            f'</div>'
        )
    overall_cls = "status-pill--ok" if result.get("ok") else "status-pill--fail"
    overall_label = "All checks passed" if result.get("ok") else "One or more checks failed"
    spaces = result.get("spaces") or []
    spaces_hint = (
        f'<div style="margin-top:0.5rem;font-size:0.8125rem;color:var(--color-text-secondary);">'
        f'Discovered spaces: <code>{_esc(", ".join(spaces))}</code></div>'
    ) if spaces else ""
    return (
        f'<div id="{panel_id}" hx-swap-oob="true" '
        f'style="margin-top:0.75rem;padding:0.75rem;border:1px solid var(--color-border);'
        f'border-radius:0.375rem;background:var(--color-bg-subtle);">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;">'
        f'<strong>Test Connection result</strong>'
        f'<span class="status-pill {overall_cls}">{overall_label}</span>'
        f'</div>'
        + "".join(rows)
        + spaces_hint
        + '</div>'
    )


@router.post("/siems/test-connection", response_class=HTMLResponse)
async def test_siem_connection(request: Request, db: DbDep, user: RequireSuperadmin):
    """Test connectivity to a SIEM with a three-tier privilege check.

    Runs against /api/status (token format), /api/spaces/space (spaces:read),
    and /s/<space>/api/detection_engine/rules/_find (sync privilege). Returns
    a status badge for the inline form indicator AND an OOB-swap result panel
    keyed on ``#siem-test-result`` so the operator sees the full breakdown.
    Persists the rolled-up status to ``siem_inventory.last_test_status``.
    """
    form = await request.form()
    siem_id = str(form.get("siem_id", "")).strip()
    kibana_url = str(form.get("kibana_url", "")).strip()
    api_token, tok_err = _normalize_api_token(form.get("api_token"))
    siem_type = str(form.get("siem_type", "elastic")).strip()

    if siem_type != "elastic":
        return HTMLResponse(
            '<span class="badge badge-secondary">Test not available for this SIEM type</span>'
        )
    if not kibana_url:
        return HTMLResponse(
            '<span class="badge badge-warning">Kibana URL is required</span>'
        )
    if tok_err:
        return HTMLResponse(
            f'<span class="badge badge-warning">{_esc(tok_err)}</span>'
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
        from app.elastic_helper import test_elastic_connection_full
        result = test_elastic_connection_full(kibana_url, api_token)
        # Persist roll-up + per-check JSON so the SIEMs tab pill stays accurate
        # and the operator can revisit the result without re-testing.
        if siem_id:
            try:
                import json as _json
                msg = _json.dumps({
                    "summary": ("All checks passed" if result["ok"]
                                else "One or more checks failed"),
                    "checks": [
                        {"name": c["name"], "ok": c["ok"],
                         "status_code": c.get("status_code"),
                         "detail": c["detail"]}
                        for c in result["checks"]
                    ],
                })[:500]
                db.update_inventory_test_status(
                    "siems", siem_id, "pass" if result["ok"] else "fail", msg,
                )
            except Exception as exc:  # pragma: no cover - best effort
                logger.warning(f"persist test-status failed for {siem_id}: {exc}")
        # Refresh the cached spaces lookup so the link-form dropdown picks
        # them up immediately on the next render — no separate "Refresh" click
        # needed when the operator just proved Kibana is reachable. Also
        # persist to the DB (Migration 41) so the dropdown survives restarts
        # and is available before the first sync ever runs.
        if siem_id and result.get("spaces"):
            import time as _time
            _KIBANA_SPACES_CACHE[siem_id] = (
                _time.time() + _KIBANA_SPACES_TTL,
                set(result["spaces"]),
            )
            try:
                db.save_siem_spaces(siem_id, list(result["spaces"]))
            except Exception as exc:
                logger.warning(f"persist spaces failed for {siem_id}: {exc}")
        badge_cls = "badge-success" if result["ok"] else "badge-danger"
        badge_text = "Connected" if result["ok"] else "Failed"
        # Pull the first failing check's detail into the inline badge so the
        # operator sees the headline without scrolling to the panel.
        first_fail = next((c for c in result["checks"] if not c["ok"]), None)
        headline = first_fail["detail"] if first_fail else result["checks"][0]["detail"]
        badge_html = (
            f'<span class="badge {badge_cls}">{badge_text} — {_esc(headline)[:120]}</span>'
        )
        panel_html = _format_test_result_panel(result)
        return HTMLResponse(badge_html + panel_html)
    except Exception as exc:
        logger.warning(f"SIEM test-connection error: {exc}")
        return HTMLResponse(
            f'<span class="badge badge-danger">Error — {_esc(str(exc))[:120]}</span>'
        )


# ---------------------------------------------------------------------------
# Unified per-card Test Connection (persists last_test_status)
# ---------------------------------------------------------------------------

def _run_inventory_test(kind: str, item: dict) -> tuple[bool, str]:
    """Dispatch to the appropriate live test for a stored inventory item.

    Returns ``(ok, short_message)``. The message is bounded to ~140 chars so
    it fits cleanly inside the status-pill tooltip. For SIEMs the message is
    a JSON document (per-check breakdown) so the SIEMs tab can render the
    full diagnostic in the per-card result panel.
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
            from app.elastic_helper import test_elastic_connection_full
            result = test_elastic_connection_full(kibana_url, api_token)
            import json as _json
            msg = _json.dumps({
                "summary": ("All checks passed" if result["ok"]
                            else "One or more checks failed"),
                "checks": [
                    {"name": c["name"], "ok": c["ok"],
                     "status_code": c.get("status_code"),
                     "detail": c["detail"]}
                    for c in result["checks"]
                ],
                "spaces": result.get("spaces", []),
            })[:500]
            return result["ok"], msg

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
    # The CTI connectors test route (`/connectors/{id}/test`) is defined
    # later in this module, so FastAPI's registration order means this
    # generic ``/{kind}/{item_id}/test`` would otherwise shadow it and
    # return a fast "Unknown kind 'connectors'" fail pill. Delegate so the
    # real vendor probe actually runs. ``test_connector`` is a sync
    # function whose tester uses ``asyncio.run`` internally, so we MUST
    # bounce it through a worker thread — calling it inline from this
    # async handler would trip ``asyncio.run() cannot be called from a
    # running event loop`` and stamp every Test click as failed.
    if kind == "connectors":
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(test_connector, item_id, db, user)
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
        f"{kind} test-connection on {item_id} by {user.username}: {status} ({msg[:120]})"
    )
    pill_html = _status_pill_html(refreshed, target_id=f"{kind}-status-{item_id}")

    # SIEM tests carry a structured result; render the breakdown panel as an
    # OOB swap into the per-card result slot, refresh the spaces cache, and
    # also fire a toast so the operator sees pass/fail without scrolling.
    if kind == "siems":
        try:
            import json as _json
            parsed = _json.loads(msg) if msg.startswith("{") else None
        except Exception:
            parsed = None
        if parsed:
            # Reconstruct the result shape the panel formatter expects.
            result_for_panel = {
                "ok": ok,
                "spaces": parsed.get("spaces", []),
                "checks": [
                    {**c, "endpoint": _SIEM_CHECK_ENDPOINT.get(c["name"], ""),
                     "body_excerpt": None}
                    for c in parsed.get("checks", [])
                ],
            }
            panel = _format_test_result_panel(
                result_for_panel, panel_id=f"siem-test-result-{item_id}"
            )
            # Refresh cached spaces so the link form sees them next render.
            spaces = parsed.get("spaces") or []
            if spaces:
                import time as _time
                _KIBANA_SPACES_CACHE[item_id] = (
                    _time.time() + _KIBANA_SPACES_TTL, set(spaces),
                )
                try:
                    db.save_siem_spaces(item_id, list(spaces))
                except Exception as exc:
                    logger.warning(f"persist spaces failed for {item_id}: {exc}")
            toast_cls = "toast-success" if ok else "toast-error"
            toast_msg = parsed.get("summary", "Test complete")
            toast = (
                '<div hx-swap-oob="afterbegin:#toast-container">'
                f'<div class="toast {toast_cls}">{_esc(toast_msg)}</div></div>'
            )
            return HTMLResponse(pill_html + panel + toast)
    return HTMLResponse(pill_html)


# Endpoint paths for the three SIEM checks; used to reconstruct the result
# panel from the persisted JSON message without re-running the live calls.
_SIEM_CHECK_ENDPOINT = {
    "kibana_status": "/api/status",
    "spaces": "/api/spaces/space",
    "detection_rules": "/s/<space>/api/detection_engine/rules/_find",
}


@router.post("/siems/{siem_id}/logging", response_class=HTMLResponse)
async def update_siem_logging(
    request: Request,
    siem_id: str,
    db: DbDep,
    user: RequireSuperadmin,
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

    # NOTE: prior releases (4.1.5–4.1.7) hard-rejected the literal values
    # ``'production'`` / ``'staging'`` here on the assumption they were
    # always operator confusion between the *environment role* dropdown and
    # the *Kibana space* input. That assumption is wrong — Kibana permits
    # space ids named ``production`` or ``staging``, and at least one
    # standalone deployment uses exactly those names. The blanket block
    # made those legitimate spaces unselectable. The live-Kibana validator
    # immediately below is the correct gate: it rejects only when the
    # SIEM's actual ``GET /api/spaces/space`` response proves the space
    # does not exist, which catches the original footgun without false
    # positives.

    # Validate the space exists on the SIEM's Kibana before storing the row.
    # The most common 4.1.x sync failure was an operator typing the role name
    # into the space field ("production" / "staging") instead of an actual
    # Kibana space id. Without this guard the bad row sat in
    # ``client_siem_map`` and every sync logged "Sync drift 0/0" against
    # ``/s/production/api/...`` until someone read the diag script output.
    real_spaces = _list_kibana_spaces(db, siem_id)
    if real_spaces is not None:
        matched = _match_space_id(space, real_spaces)
        if not matched:
            from html import escape
            avail = ", ".join(escape(s) for s in sorted(real_spaces)) or "(none)"
            msg = (
                f"Kibana space '{escape(space)}' does not exist on this SIEM. "
                f"Available: {avail}. The role label (Production/Staging) is "
                f"separate from the Kibana space id \u2014 they're rarely the same value."
            )
            return HTMLResponse(
                '<div hx-swap-oob="afterbegin:#toast-container">'
                f'<div class="toast toast-warning">{msg}</div></div>'
            )
        # Persist the canonical id to keep client_siem_map normalized.
        space = matched

    db.link_client_siem(client_id, siem_id, environment_role=environment_role, space=space)
    logger.info(f"SIEM {siem_id} linked to client {client_id} as {environment_role} by {user.username}")
    # Push existing rules from the shared cache into this tenant's DB.
    # Without this the tenant's ``detection_rules`` table stays empty until
    # the next scheduled global Elastic sync runs \u2014 which made the common
    # "remove + re-add a SIEM mapping to fix sync" workflow look broken.
    # The distributor is idempotent (DELETE+INSERT scoped per tenant) and
    # only touches tenants whose ``client_siem_map`` is non-empty, so calling
    # it here is safe and cheap.
    try:
        from app.services.sync import _distribute_rules_to_tenants
        _distribute_rules_to_tenants()
    except Exception as exc:
        logger.warning(f"rule redistribution after SIEM link failed: {exc}")
    return _render_client_siems_partial(client_id, db, toast="SIEM linked successfully.")


@router.delete("/clients/{client_id}/siems/{siem_id}", response_class=HTMLResponse)
def unlink_siem_from_client(request: Request, client_id: str, siem_id: str,
                            db: DbDep, user: RequireAdmin):
    """Unlink a SIEM from a client.

    Ghost-rule prevention (4.1.16): after the ``client_siem_map`` row(s) are
    deleted, the tenant's ``detection_rules`` rows for the unlinked
    ``(siem_id, space)`` pairs are purged INSIDE ``tenant_context_for(client_id)``.
    Without this, the rows lingered indefinitely — sync only iterates
    currently-mapped pairs (AGENTS.md §8.2 g2), so an unlinked pair is never
    revisited and the now-orphan rules stayed visible on the Rule Health page.
    The previous "redistributor" call here was a no-op stub since 4.1.13 and
    has been removed.

    Partial-unlink contract (AGENTS.md §8.1 dual-role config): when
    ``environment_role`` is supplied, we MUST only purge the specific
    ``(siem_id, space)`` pair removed — the same ``siem_id`` may still be
    mapped under the other role with a different space, and a blanket
    ``DELETE WHERE siem_id = ?`` would destroy rules belonging to that
    still-valid mapping. Pairs are captured BEFORE the map delete so the
    purge is exact.
    """
    env_role = request.query_params.get("environment_role")

    # 1. Capture the (siem_id, space) pairs about to be removed, BEFORE the
    #    map delete (otherwise the rows are gone and we can't know what to
    #    purge). Space is lowercased + 'default'-normalised to match the
    #    same shape ``get_client_siem_scopes`` uses, so the DELETE predicate
    #    against detection_rules below is symmetric with the rest of the
    #    tenant-isolation surface.
    pairs_to_purge: list = []
    try:
        with db.get_shared_connection() as _sconn:
            _q = (
                "SELECT DISTINCT siem_id, "
                "LOWER(COALESCE(NULLIF(TRIM(space), ''), 'default')) "
                "FROM client_siem_map "
                "WHERE client_id = ? AND siem_id = ?"
            )
            _params: list = [client_id, siem_id]
            if env_role:
                _q += " AND environment_role = ?"
                _params.append(env_role)
            pairs_to_purge = [(sid, sp) for sid, sp in _sconn.execute(_q, _params).fetchall() if sid and sp]
    except Exception as exc:
        logger.warning(f"could not enumerate (siem_id, space) pairs prior to unlink: {exc}")

    # 2. Delete the client_siem_map row(s).
    db.unlink_client_siem(client_id, siem_id, environment_role=env_role)
    logger.info(f"SIEM {siem_id} ({env_role or 'all'}) unlinked from client {client_id} by {user.username}")

    # 3. Purge the orphaned detection_rules rows from the tenant DB. Wrapped
    #    so a missing/empty detection_rules table on a never-synced tenant
    #    cannot break the unlink response.
    if pairs_to_purge:
        try:
            from app.services.tenant_manager import tenant_context_for
            with tenant_context_for(client_id):
                with db.get_connection() as _tconn:
                    purged_total = 0
                    for _sid, _space in pairs_to_purge:
                        try:
                            _res = _tconn.execute(
                                "DELETE FROM detection_rules "
                                "WHERE siem_id = ? AND LOWER(space) = ?",
                                [_sid, _space],
                            )
                            # DuckDB returns affected-row count via .fetchall() on the result
                            try:
                                _affected = _res.fetchone()
                                _n = int(_affected[0]) if _affected and _affected[0] is not None else 0
                            except Exception:
                                _n = 0
                            purged_total += _n
                        except Exception as _row_exc:
                            # Likely "table does not exist" on a never-synced tenant
                            # — non-fatal, the rules can't be ghosts if the table
                            # itself isn't there.
                            logger.debug(
                                f"detection_rules purge skipped for client={client_id} "
                                f"siem={_sid} space={_space}: {_row_exc}"
                            )
                            break  # table absent → no point retrying other pairs
                    logger.info(
                        f"ghost-rule purge: removed {purged_total} detection_rules rows "
                        f"for client={client_id} pairs={pairs_to_purge}"
                    )
        except Exception as exc:
            logger.warning(
                f"ghost-rule purge after SIEM unlink failed for client={client_id} "
                f"siem={siem_id} role={env_role or 'all'}: {exc}"
            )

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
# Per-tenant rule validation thresholds (4.1.20)
# ---------------------------------------------------------------------------
# The amber/expired week thresholds that drive the rule validation badge
# used to be a single global env var pair, but different tenants run
# different review cadences. This endpoint persists per-tenant overrides
# on the ``clients`` row (NULL means "inherit the global default") and
# re-renders the Linked SIEMs partial so the form bounces back with the
# new values.

@router.post("/clients/{client_id}/validation-thresholds",
             response_class=HTMLResponse)
async def update_validation_thresholds(
    request: Request, client_id: str, db: DbDep, user: RequireAdmin
):
    """Update the per-tenant amber/expired validation week thresholds.

    Form fields ``amber_weeks`` and ``expired_weeks`` accept a positive
    integer or an empty value (= clear override, inherit the global
    setting). Rejects amber >= expired with a toast and leaves the row
    unchanged.
    """
    form = await request.form()

    def _parse(name: str):
        v = form.get(name)
        if v is None:
            return None, True  # untouched
        s = str(v).strip()
        if s == "":
            return None, True  # explicit clear
        try:
            iv = int(s)
        except ValueError:
            return None, False
        return (iv if iv > 0 else None), True

    amber, amber_ok = _parse("amber_weeks")
    expired, expired_ok = _parse("expired_weeks")
    if not amber_ok or not expired_ok:
        return _render_client_siems_partial(
            client_id, db,
            toast="Thresholds must be positive whole numbers.",
        )
    if amber is not None and expired is not None and amber >= expired:
        return _render_client_siems_partial(
            client_id, db,
            toast="Amber threshold must be less than expired threshold.",
        )
    db.update_client(
        client_id,
        rule_validation_amber_weeks=amber,
        rule_validation_expired_weeks=expired,
    )
    logger.info(
        f"Client {client_id} validation thresholds updated by "
        f"{user.username}: amber={amber}, expired={expired}"
    )
    return _render_client_siems_partial(
        client_id, db, toast="Validation thresholds saved.",
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
    with db.get_shared_connection() as conn:
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
    return HTMLResponse(_render_users_tab(users, all_roles, clients, current_user=user))


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
    raw_msg = (item.get("last_test_message") or "").strip()
    # SIEM tests persist a JSON breakdown; render the summary in the tooltip
    # rather than dumping raw JSON. Other inventory kinds keep plain strings.
    msg = raw_msg
    if raw_msg.startswith("{"):
        try:
            import json as _json
            parsed = _json.loads(raw_msg)
            summary = parsed.get("summary") or ""
            failed = [c for c in parsed.get("checks", []) if not c.get("ok")]
            if failed:
                msg = (summary + " — " + "; ".join(
                    f"{c.get('name')}: {c.get('detail', '')}" for c in failed
                ))[:200]
            else:
                msg = summary or raw_msg
        except Exception:
            msg = raw_msg
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

    # Pull the *actual* set of spaces this SIEM has rules in (from
    # detection_rules + client_siem_map). Since Migration 38 the SIEM no
    # longer carries production_space/staging_space fields \u2014 client_siem_map
    # is the sole source of (siem, role, space).
    discovered_spaces: list[str] = []
    prod_spaces: set[str] = set()
    stage_spaces: set[str] = set()
    try:
        from app.services.database import get_database_service
        _db = get_database_service()
        discovered_spaces = _db.get_siem_spaces(sid) or []
        with _db.get_shared_connection() as _conn:
            for _sp, _role in _conn.execute(
                "SELECT COALESCE(NULLIF(TRIM(space), ''), 'default'), environment_role "
                "FROM client_siem_map WHERE siem_id = ?",
                [sid],
            ).fetchall():
                if _role == "production":
                    prod_spaces.add(_sp)
                elif _role == "staging":
                    stage_spaces.add(_sp)
        # 4.1.5 — also union live spaces from this SIEM's Kibana so freshly
        # created spaces appear in the logging picker without waiting for a
        # client mapping to be saved first.
        try:
            _live = _list_kibana_spaces(_db, sid) or set()
            _seen_lc = {s.lower() for s in discovered_spaces}
            for _sp in sorted(_live):
                if _sp and _sp.lower() not in _seen_lc:
                    discovered_spaces.append(_sp)
                    _seen_lc.add(_sp.lower())
        except Exception as exc:
            logger.warning(
                f"_siem_logging_block_html({sid}): live Kibana space lookup failed: {exc!r}"
            )
    except Exception as exc:
        logger.warning(
            f"_siem_logging_block_html({sid}): space discovery failed: {exc!r}"
        )
        discovered_spaces = []
    logger.info(
        f"_siem_logging_block_html({sid}) discovered_spaces={discovered_spaces} "
        f"saved={sorted(selected_spaces)}"
    )
    # Build the union: discovered \u222a already-saved selections, preserving
    # discovery order then adding anything missing alphabetically.
    ordered: list[str] = []
    seen: set[str] = set()
    for sp in discovered_spaces:
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
            in_prod = sp in prod_spaces
            in_stage = sp in stage_spaces
            if in_prod and in_stage:
                tag = ' <span style="opacity:0.6;">(prod / stage)</span>'
            elif in_prod:
                tag = ' <span style="opacity:0.6;">(prod)</span>'
            elif in_stage:
                tag = ' <span style="opacity:0.6;">(stage)</span>'
            else:
                tag = ""
            checkbox_rows.append(
                '<label style="display:flex;align-items:center;gap:0.4rem;'
                'padding:0.2rem 0.5rem;cursor:pointer;font-size:0.8rem;">'
                f'<input type="checkbox" name="target_space" value="{escape(sp)}"{checked}>'
                f'<span>{escape(sp)}</span>'
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
            <div id="siem-test-result-{sid}"></div>
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


def _render_users_tab(users: list, all_roles: list, clients: list,
                      current_user=None) -> str:
    """Render the Users tab content with Manage Clients action.

    The Roles column has moved to the Client Detail page — this tab is now
    a global directory only (username, source, active, last login, clients).
    A "Platform Admin" toggle column is rendered only when ``current_user``
    is a platform super-admin (so tenant admins cannot grant themselves
    cross-tenant powers). 4.1.6.
    """
    if not users:
        return '<p class="text-muted" style="font-size:0.85rem;">No users found.</p>'

    show_super = bool(current_user and getattr(current_user, "is_superadmin", False))
    self_id = getattr(current_user, "id", None) if current_user else None

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

        # Platform Admin toggle (super-admin viewers only). Self-revoke is
        # blocked at the endpoint AND disabled in the UI so the operator
        # cannot accidentally lock themselves out.
        super_cell = ""
        if show_super:
            sa_checked = "checked" if u.get("is_superadmin") else ""
            disabled = "disabled" if (self_id and u["id"] == self_id) else ""
            title = (
                "You cannot change your own platform-admin flag"
                if disabled else "Grant or revoke platform-admin (cross-tenant)"
            )
            super_cell = f'''<td title="{title}">
                <label class="toggle-switch toggle-sm">
                    <input type="checkbox" {sa_checked} {disabled}
                           hx-post="/api/management/users/{u['id']}/superadmin"
                           hx-target="#management-content"
                           hx-swap="innerHTML"
                           hx-trigger="change"
                           hx-confirm="{'Revoke' if u.get('is_superadmin') else 'Grant'} platform-admin for {_esc(u['username'])}?">
                    <span class="toggle-slider"></span>
                </label>
            </td>'''

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
            {super_cell}
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

    super_th = "<th>Platform Admin</th>" if show_super else ""
    return f'''
    {add_form}
    <table class="mapping-table">
        <thead><tr>
            <th>Username</th><th>Email</th><th>Source</th>
            <th>Active</th>{super_th}<th>Last Login</th>
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
        kind = (i.get("kind") or "actors").lower()
        kind_label = {"actors": "actors", "cti": "CTI", "both": "actors + CTI"}.get(kind, kind)
        kind_cls = {"actors": "badge-secondary", "cti": "badge-info", "both": "badge-success"}.get(kind, "badge-secondary")
        kind_badge = (
            f'<span class="badge {kind_cls}" title="kind={escape(kind)}">'
            f'{escape(kind_label)}</span>'
        )
        status_pill = _status_pill_html(i, target_id=f"opencti-status-{iid}")
        tenant_chips = _tenant_chips_html(i.get("_clients", []))
        test_btn = _test_button_html("opencti", iid, f"opencti-status-{iid}")

        # Sync CTI button is only meaningful when this row participates in
        # the new fetcher. Otherwise we omit it to keep the legacy actor
        # cards unchanged.
        sync_cti_btn = ""
        if kind in ("cti", "both"):
            sync_cti_btn = (
                f'<button class="btn btn-ghost btn-sm" '
                f'hx-post="/api/management/opencti/{iid}/sync-cti" '
                f'hx-target="#opencti-cti-status-{iid}" hx-swap="innerHTML" '
                f'title="Pull STIX bundle into every linked tenant\'s CTI DB">'
                f'Sync CTI</button>'
            )

        cards += f'''
        <div class="system-card" style="display:flex;flex-direction:column;">
            <div class="system-card__title" style="display:flex;align-items:center;justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
                    <span style="font-weight:600;">{lbl_esc}</span>
                    {kind_badge}
                    {status_pill}
                </div>
                <div style="display:flex;gap:0.25rem;">
                    {sync_cti_btn}
                    {test_btn}
                    <button class="btn btn-ghost btn-sm"
                            onclick="editOpenCTI('{iid}', '{lbl_esc}', '{url_esc}', '{escape(kind)}')"
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
                <div id="opencti-cti-status-{iid}" style="margin-top:0.5rem;font-size:0.8125rem;"></div>
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
    <div class="info-box info-box--warning" style="margin-bottom:1rem;font-size:0.85rem;display:flex;align-items:flex-start;gap:0.5rem;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;margin-top:0.15rem;">
            <path d="M12 9v4"/><path d="M12 17h.01"/>
            <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/>
        </svg>
        <div>
            <strong>Deprecated.</strong> Manage OpenCTI sources on the new <strong>Connectors</strong> tab below — it covers OpenCTI, Mandiant, CrowdStrike and any vendor added in future releases under one consistent surface. Existing instances were copied over automatically; this tab is kept for one release and will be removed in <code>5.0.0</code>.
        </div>
    </div>
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

    # SIEM rule counts keyed by (siem_id, space). Keying by space alone
    # collapses two SIEMs that share a Kibana space-name into one bucket and
    # mis-labels rules in the grid (AGENTS.md §8.2 guarantee 4). The legacy
    # space-only ``siem_rule_counts`` dict is kept (last-writer-wins) only
    # for templates that have not been migrated to the per-SIEM map yet.
    siem_rule_counts: dict = {}
    siem_rule_counts_by_pair: dict = {}
    siem_space_counts: dict = {}
    try:
        # Detection rules are per-tenant since 4.1.13 — read this client's
        # tenant DB directly, not the shared cache (which no longer holds
        # detection_rules).
        from app.services.tenant_manager import resolve_tenant_db_path
        from app.config import get_settings
        import duckdb, os
        tenant_path = resolve_tenant_db_path(client_id, get_settings().data_dir)
        if tenant_path and os.path.exists(tenant_path):
            conn = duckdb.connect(tenant_path, read_only=False)
            try:
                rows = conn.execute(
                    "SELECT siem_id, space, COUNT(*) AS total, "
                    "SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) AS enabled "
                    "FROM detection_rules "
                    "WHERE space IS NOT NULL AND siem_id IS NOT NULL "
                    "GROUP BY siem_id, space"
                ).fetchall()
            finally:
                conn.close()
            for sid, space, total, enabled in rows:
                entry = {"total": int(total), "enabled": int(enabled or 0)}
                siem_space_counts.setdefault(str(sid), {})[str(space)] = entry
                siem_rule_counts_by_pair[f'{sid}|{str(space).lower()}'] = entry
                siem_rule_counts[str(space)] = entry  # legacy fallback only
    except Exception:
        pass

    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("partials/client_siems.html")
    from app.config import get_settings as _get_settings
    _settings = _get_settings()
    # Build a per-SIEM map of Kibana spaces so the Add-SIEM picker can show
    # ONLY the spaces that exist on the SIEM the operator selected. AGENTS.md
    # §8.2 guarantee 1: a flat union across SIEMs leaks SIEM B's spaces into
    # SIEM A's picker, then the live-Kibana validator 404s the submission.
    # 4.1.5 → 4.1.9 used a flat ``known_kibana_spaces`` union; that is the
    # bug. Per-SIEM map below; flat list retained as a defensive fallback for
    # any partial template that still references it.
    siem_spaces_by_id: dict = {}
    known_kibana_spaces: list[str] = []
    try:
        for _si in (available_siems or []):
            _sid = _si.get("id") if isinstance(_si, dict) else getattr(_si, "id", None)
            if not _sid:
                continue
            collected: set = set()
            # 1. Persisted cache (siem_kibana_spaces, populated on Test
            # Connection success and on sync). Survives Kibana outages.
            try:
                for sp in (db.get_persisted_kibana_spaces(_sid) or []):
                    if sp:
                        collected.add(str(sp))
            except AttributeError:
                # Older db service without the helper — fall back to a
                # direct SELECT so we don't regress.
                try:
                    with db.get_shared_connection() as _c:
                        for (sp,) in _c.execute(
                            "SELECT DISTINCT space FROM siem_kibana_spaces "
                            "WHERE siem_id = ? AND space IS NOT NULL", [_sid]
                        ).fetchall():
                            if sp:
                                collected.add(str(sp))
                except Exception:
                    pass
            except Exception:
                pass
            # 2. Live discovery via the cached resolver (60s TTL).
            try:
                _live = _list_kibana_spaces(db, _sid)
                for sp in (_live or set()):
                    if sp:
                        collected.add(str(sp))
            except Exception as exc:
                logger.debug(
                    f"_render_client_siems_partial: live spaces for {_sid} failed: {exc!r}"
                )
            # 3. Spaces this SIEM has rules in (always trustworthy).
            for sp in (siem_space_counts.get(str(_sid), {}) or {}):
                collected.add(str(sp))
            siem_spaces_by_id[str(_sid)] = sorted(collected, key=str.lower)
            for sp in siem_spaces_by_id[str(_sid)]:
                if sp not in known_kibana_spaces:
                    known_kibana_spaces.append(sp)
    except Exception as exc:
        logger.warning(f"_render_client_siems_partial: per-SIEM space build failed: {exc!r}")

    html = template.render(
        client=client, client_siems=client_siems,
        available_siems=available_siems, siem_rule_counts=siem_rule_counts,
        siem_rule_counts_by_pair=siem_rule_counts_by_pair,
        siem_space_counts=siem_space_counts,
        siem_spaces_by_id=siem_spaces_by_id,
        known_kibana_spaces=known_kibana_spaces,
        settings=_settings,
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


def _client_connector_rows(client_id: str, db) -> tuple[list, list]:
    """Return ``(linked, available)`` connector dicts for ``client_id``.

    Each entry carries the vendor label (resolved against the connector
    registry) so the partial doesn't have to know how vendors are
    registered. Used by both the client detail page renderer in
    :mod:`app.main` and :func:`_render_client_connectors_partial` below
    so the two surfaces stay in sync after every link / unlink.
    """
    from app.services.cti_connectors import all_vendors
    vendor_by_name = {v.name: v.label for v in all_vendors()}
    all_connectors = db.list_cti_connectors()
    linked_ids: set[str] = set()
    linked: list = []
    for c in all_connectors:
        members = db.get_cti_connector_clients(c["id"])
        if any((m.get("id") == client_id) for m in members):
            linked_ids.add(c["id"])
            linked.append({
                "id": c["id"],
                "vendor": c.get("vendor"),
                "vendor_label": vendor_by_name.get(c.get("vendor")) or c.get("vendor"),
                "label": c.get("label"),
                "is_active": c.get("is_active", True),
                "last_status": c.get("last_status"),
                "last_run_at": c.get("last_run_at"),
            })
    available = [
        {
            "id": c["id"],
            "vendor": c.get("vendor"),
            "vendor_label": vendor_by_name.get(c.get("vendor")) or c.get("vendor"),
            "label": c.get("label"),
        }
        for c in all_connectors if c["id"] not in linked_ids
    ]
    return linked, available


def _render_client_connectors_partial(client_id: str, db, toast: str = None) -> HTMLResponse:
    """Re-render the per-tenant ``Linked CTI Connectors`` section.

    Mirrors :func:`_render_client_opencti_partial` so the link / unlink
    endpoints can swap just the affected section instead of repainting
    the full client detail page.
    """
    from html import escape
    import os
    from jinja2 import Environment, FileSystemLoader

    client = db.get_client(client_id)
    linked, available = _client_connector_rows(client_id, db)

    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("partials/client_connectors.html")
    html = template.render(
        client=client,
        client_connectors=linked,
        available_connectors=available,
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



# ===========================================================================
# Phase E (4.1.7): Read-only Query tab
# ---------------------------------------------------------------------------
# Super-admin diagnostic surface for inspecting the shared TIDE catalog and
# any per-tenant DuckDB file. All execution paths are read-only:
#   - DuckDB is opened with read_only=True on a snapshot copy (live writer
#     holds an exclusive file lock, so we never contend with it)
#   - SQL is single-statement and the leading keyword must be allow-listed
#   - Results are capped at MAX_ROWS to keep the UI responsive
#   - Target databases are resolved against the on-disk data dir; arbitrary
#     filesystem paths are rejected
# ===========================================================================

import os as _os_q
import re as _re_q
import time as _time_q

try:
    import duckdb as _duckdb_q
except Exception:  # pragma: no cover - duckdb is a hard dep at runtime
    _duckdb_q = None

_QUERY_MAX_ROWS = 500
_QUERY_ALLOWED_KEYWORDS = {
    "SELECT", "WITH", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "SUMMARIZE",
}
_QUERY_FORBIDDEN_TOKENS = (
    "ATTACH", "COPY", "EXPORT", "IMPORT", "INSTALL", "LOAD",
    "PRAGMA", "CALL", "CREATE", "DROP", "INSERT", "UPDATE",
    "DELETE", "ALTER", "TRUNCATE", "VACUUM", "CHECKPOINT",
)

_QUERY_PRESETS = [
    {"id": "schema_version", "label": "Schema version (current)", "target": "shared",
     "sql": "SELECT MAX(version) AS schema_version FROM schema_version"},
    {"id": "schema_history", "label": "Schema migration history", "target": "shared",
     "sql": "SELECT version, applied_at FROM schema_version ORDER BY version DESC LIMIT 50"},
    {"id": "tenants", "label": "Tenants and their DuckDB files", "target": "shared",
     "sql": ("SELECT id, name, slug, db_filename, is_default, created_at "
             "FROM clients ORDER BY is_default DESC, name")},
    {"id": "siem_inventory", "label": "SIEM inventory", "target": "shared",
         "sql": ("SELECT id, label, siem_type, base_url, kibana_url, "
             "(api_token_enc IS NOT NULL AND LENGTH(TRIM(api_token_enc)) > 0) "
             "AS has_token, created_at "
             "FROM siem_inventory ORDER BY label")},
    {"id": "client_siem_map", "label": "Tenant - SIEM - space mappings", "target": "shared",
     "sql": ("SELECT csm.client_id, c.name AS client_name, csm.siem_id, "
             "s.label AS siem_name, csm.environment_role, csm.space "
             "FROM client_siem_map csm "
             "LEFT JOIN clients c ON c.id = csm.client_id "
             "LEFT JOIN siem_inventory s ON s.id = csm.siem_id "
             "ORDER BY c.name, s.label, csm.environment_role")},
    {"id": "siem_kibana_spaces", "label": "Persisted Kibana space cache (Migration 41)",
     "target": "shared",
     "sql": ("SELECT siem_id, space, discovered_at "
             "FROM siem_kibana_spaces ORDER BY siem_id, space")},
    {"id": "sync_history_recent", "label": "Recent sync runs (Migration 42)",
     "target": "shared",
     "sql": ("SELECT started_at, sync_kind, status, total_count, duration_ms, "
             "substr(coalesce(error,''), 1, 200) AS error_preview "
             "FROM sync_history ORDER BY started_at DESC LIMIT 50")},
    {"id": "sync_history_failures", "label": "Sync failures and partials (last 50)",
     "target": "shared",
     "sql": ("SELECT started_at, sync_kind, status, total_count, duration_ms, "
             "substr(coalesce(error,''), 1, 500) AS error_preview "
             "FROM sync_history WHERE status IN ('failed','partial') "
             "ORDER BY started_at DESC LIMIT 50")},
    {"id": "users_overview", "label": "Users and superadmin flag", "target": "shared",
     "sql": ("SELECT id, username, email, is_superadmin, created_at "
             "FROM users ORDER BY username")},
    {"id": "tenant_tables", "label": "Tables in selected tenant DB", "target": "tenant",
     "sql": ("SELECT table_name FROM information_schema.tables "
             "WHERE table_schema = 'main' ORDER BY table_name")},
    {"id": "tenant_systems", "label": "Systems in selected tenant DB", "target": "tenant",
     "sql": "SELECT id, name, classification_id, created_at FROM systems ORDER BY name"},
    {"id": "tenant_threat_actors", "label": "Threat actors in selected tenant DB",
     "target": "tenant",
     "sql": ("SELECT id, name, source, updated_at FROM threat_actors "
             "ORDER BY updated_at DESC NULLS LAST LIMIT 100")},
    # 4.1.14: SIEM/space introspection presets. Pinned to target='tenant'
    # because since 4.1.13 (Migration 45) `detection_rules` lives in each
    # tenant DB, not the shared DB. Running these in shared scope would
    # error with `Table does not exist`.
    {"id": "rules_per_siem_space_role",
     "label": "Rule count per SIEM/space/role",
     "target": "tenant",
     "sql": ("SELECT m.siem_id, m.space, m.environment_role, "
             "COUNT(r.rule_id) AS rule_count "
             "FROM client_siem_map m "
             "LEFT JOIN detection_rules r "
             "ON m.siem_id = r.siem_id AND m.space = r.space "
             "GROUP BY m.siem_id, m.space, m.environment_role;")},
    {"id": "top10_rules_prod_vs_staging",
     "label": "Top 10 rules for production vs staging",
     "target": "tenant",
     "sql": ("SELECT m.environment_role, m.siem_id, m.space, r.name "
             "FROM client_siem_map m "
             "JOIN detection_rules r "
             "ON m.siem_id = r.siem_id AND m.space = r.space "
             "ORDER BY m.environment_role, r.name LIMIT 10;")},
]


def _query_toast(message: str, level: str = "success") -> str:
    css = {
        "success": "toast-success",
        "warning": "toast-warning",
        "error": "toast-error",
    }.get(level, "toast-success")
    return (
        '<div hx-swap-oob="afterbegin:#toast-container">'
        f'<div class="toast {css}">{_esc(message)}</div>'
        '</div>'
    )


def _all_query_presets(db) -> list:
    """Built-ins + saved templates as a single preset payload."""
    presets = [dict(p) for p in _QUERY_PRESETS]
    for row in db.list_query_templates():
        presets.append({
            "id": f"custom:{row['id']}",
            "label": row.get("name") or "(unnamed)",
            "target": row.get("target_key") or "shared",
            "sql": row.get("sql_text") or "",
            "kind": "custom",
            "template_id": row.get("id"),
            "name": row.get("name") or "",
        })
    return presets


def _resolve_query_targets(db) -> list:
    """Enumerate the DuckDB files we are willing to query."""
    targets: list = []
    shared_path = db.db_path
    targets.append({
        "key": "shared",
        "label": f"Shared catalog ({_os_q.path.basename(shared_path)})",
        "path": shared_path,
        "kind": "shared",
    })
    data_dir = _os_q.path.dirname(shared_path)
    try:
        clients = db.list_clients()
    except Exception:
        clients = []
    for c in clients:
        fname = c.get("db_filename")
        if not fname:
            continue
        if "/" in fname or "\\" in fname or fname.startswith("."):
            continue
        path = _os_q.path.join(data_dir, fname)
        if not _os_q.path.exists(path):
            continue
        targets.append({
            "key": f"tenant:{c['id']}",
            "label": f"{c['name']} ({fname})",
            "path": path,
            "kind": "tenant",
            "client_id": c["id"],
            "client_name": c["name"],
        })
    return targets


def _target_path(db, key: str):
    for t in _resolve_query_targets(db):
        if t["key"] == key:
            return t["path"]
    return None


def _validate_sql(sql: str):
    """Return (cleaned_sql, error). Read-only, single-statement only."""
    if not sql or not sql.strip():
        return None, "SQL is empty."
    s = sql.strip()
    if s.endswith(";"):
        s = s[:-1].rstrip()
    if ";" in s:
        return None, "Only a single statement is allowed (no ';' in body)."
    head = s
    while head.startswith("--"):
        nl = head.find("\n")
        if nl < 0:
            return None, "SQL is empty after comments."
        head = head[nl + 1:].lstrip()
    m = _re_q.match(r"\s*([A-Za-z]+)", head)
    if not m:
        return None, "Could not parse a leading keyword."
    kw = m.group(1).upper()
    if kw not in _QUERY_ALLOWED_KEYWORDS:
        return None, f"Statement type '{kw}' is not allowed (read-only mode)."
    upper = s.upper()
    for tok in _QUERY_FORBIDDEN_TOKENS:
        if _re_q.search(r"(^|[^A-Z_])" + _re_q.escape(tok) + r"([^A-Z_]|$)", upper):
            return None, f"Forbidden token '{tok}' present."
    return s, None


def _render_query_results(rows, cols, elapsed_ms, truncated):
    if not rows:
        return (
            f'<div class="text-secondary" style="padding:0.75rem;">'
            f'No rows. ({elapsed_ms} ms)</div>'
        )
    head = "".join(f"<th>{_esc(c)}</th>" for c in cols)
    body_rows = []
    for r in rows:
        cells = []
        for v in r:
            if v is None:
                cells.append('<td class="text-secondary"><em>null</em></td>')
            else:
                txt = str(v)
                if len(txt) > 500:
                    txt = txt[:500] + "..."
                cells.append(f"<td>{_esc(txt)}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    note = ""
    if truncated:
        note = (
            f'<div class="text-secondary" style="padding:0.5rem 0;font-size:0.8rem;">'
            f'Truncated to {_QUERY_MAX_ROWS} rows.</div>'
        )
    return (
        f'<div class="text-secondary" style="font-size:0.8rem;margin:0 0 0.5rem;">'
        f'{len(rows)} row(s) - {elapsed_ms} ms</div>'
        f'<div style="overflow:auto;max-height:60vh;border:var(--border-card);'
        f'border-radius:var(--radius-sm);">'
        f'<table class="data-table" style="width:100%;font-size:0.8rem;">'
        f'<thead><tr>{head}</tr></thead><tbody>{"".join(body_rows)}</tbody></table>'
        f'</div>{note}'
    )


def _render_query_tab(
    targets,
    presets,
    *,
    selected_preset: str = "",
    target_value: str = "shared",
    sql_value: str = "",
    query_name: str = "",
):
    selected_preset = (selected_preset or "").strip()
    target_value = (target_value or "shared").strip() or "shared"
    sql_value = sql_value or ""
    query_name = query_name or ""

    target_options = "".join(
        f'<option value="{_esc(t["key"])}"'
        f'{" selected" if t["key"] == target_value else ""}>'
        f'{_esc(t["label"])}</option>'
        for t in targets
    )

    builtins = [p for p in presets if p.get("kind") != "custom"]
    custom = [p for p in presets if p.get("kind") == "custom"]

    def _opts(rows):
        return "".join(
            f'<option value="{_esc(p["id"])}"'
            f'{" selected" if p["id"] == selected_preset else ""}>'
            f'{_esc(p["label"])}</option>'
            for p in rows
        )

    preset_options = '<option value="">-- pick a preset --</option>'
    if builtins:
        preset_options += f'<optgroup label="Built-in">{_opts(builtins)}</optgroup>'
    if custom:
        preset_options += f'<optgroup label="Saved">{_opts(custom)}</optgroup>'

    import json as _json_q
    presets_json = _json_q.dumps({p["id"]: p for p in presets})
    is_custom_selected = selected_preset.startswith("custom:")
    return f"""
<div id="mgmt-query-root">
<div class="text-secondary" style="font-size:0.85rem;margin:0 0 1rem;max-width:80ch;">
  Read-only DuckDB query manager. Save reusable SQL snippets, run them against
  shared or tenant DuckDB targets, and delete saved templates when obsolete.
  Only <code>SELECT / WITH / SHOW / DESCRIBE /
  EXPLAIN / SUMMARIZE</code> statements are allowed and results are capped at
  {_QUERY_MAX_ROWS} rows. Targets are resolved from the on-disk data directory;
  arbitrary file paths are rejected. Queries run against a point-in-time
  snapshot copy so the live writer is never blocked.
</div>
<form id="mgmt-query-form"
      hx-post="/api/management/query/exec"
      hx-target="#mgmt-query-results"
      hx-swap="innerHTML"
      style="display:flex;flex-direction:column;gap:0.5rem;">
  <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:flex-end;">
    <label style="display:flex;flex-direction:column;gap:0.25rem;flex:1;min-width:240px;">
      <span class="form-label" style="margin:0;">Database</span>
            <select id="mgmt-query-target" name="target" class="form-input" required>{target_options}</select>
    </label>
    <label style="display:flex;flex-direction:column;gap:0.25rem;flex:1;min-width:240px;">
      <span class="form-label" style="margin:0;">Predefined query</span>
            <select id="mgmt-query-preset" name="preset_id" class="form-input"
              onchange="mgmtQueryApplyPreset(this.value)">{preset_options}</select>
    </label>
  </div>
    <label style="display:flex;flex-direction:column;gap:0.25rem;max-width:520px;">
        <span class="form-label" style="margin:0;">Template name</span>
        <input id="mgmt-query-name" name="query_name" type="text" class="form-input"
                     maxlength="120" placeholder="e.g. Recent failed syncs"
                     value="{_esc(query_name)}">
    </label>
  <label style="display:flex;flex-direction:column;gap:0.25rem;">
    <span class="form-label" style="margin:0;">SQL</span>
    <textarea id="mgmt-query-sql" name="sql" class="form-input" rows="6" required
              placeholder="SELECT * FROM clients LIMIT 10"
                            style="font-family:var(--font-mono,monospace);font-size:0.8rem;">{_esc(sql_value)}</textarea>
  </label>
  <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
    <button type="submit" class="btn btn-primary btn-sm">Run query</button>
        <button type="button" class="btn btn-secondary btn-sm"
                        hx-post="/api/management/query/save"
                        hx-include="#mgmt-query-form"
                        hx-target="#mgmt-query-root"
                        hx-swap="outerHTML">Save</button>
        <button id="mgmt-query-delete" type="button" class="btn btn-secondary btn-sm"
                        hx-post="/api/management/query/delete"
                        hx-include="#mgmt-query-form"
                        hx-target="#mgmt-query-root"
                        hx-swap="outerHTML"
                        {"" if is_custom_selected else "disabled"}>Delete</button>
    <button type="button" class="btn btn-secondary btn-sm"
            onclick="document.getElementById('mgmt-query-sql').value='';
                                         document.getElementById('mgmt-query-name').value='';
                     document.getElementById('mgmt-query-results').innerHTML='';
                                         document.getElementById('mgmt-query-preset').value='';
                                         if(window.mgmtQueryUpdateActions){{ window.mgmtQueryUpdateActions(); }};">Add / New</button>
    <span class="text-secondary" style="font-size:0.75rem;">
      Read-only - {_QUERY_MAX_ROWS}-row cap
    </span>
  </div>
</form>
<div id="mgmt-query-results" style="margin-top:1rem;"></div>
<script>
(function(){{
  window.__MGMT_QUERY_PRESETS = {presets_json};
    window.mgmtQueryUpdateActions = function(){{
        var sel = document.getElementById('mgmt-query-preset');
        var del = document.getElementById('mgmt-query-delete');
        if(!sel || !del){{ return; }}
        del.disabled = !(sel.value && sel.value.indexOf('custom:') === 0);
    }};
  window.mgmtQueryApplyPreset = function(id){{
        var targetEl = document.getElementById('mgmt-query-target');
        var sqlEl = document.getElementById('mgmt-query-sql');
        var nameEl = document.getElementById('mgmt-query-name');
        if(!id){{
            if(window.mgmtQueryUpdateActions){{ window.mgmtQueryUpdateActions(); }}
            return;
        }}
    var p = window.__MGMT_QUERY_PRESETS[id];
        if(!p){{
            if(window.mgmtQueryUpdateActions){{ window.mgmtQueryUpdateActions(); }}
            return;
        }}
        if(sqlEl){{ sqlEl.value = p.sql || ''; }}
        if(targetEl && p.target){{ targetEl.value = p.target; }}
        if(nameEl && (p.kind || '') === 'custom'){{
            nameEl.value = p.name || p.label || '';
        }}
        if(window.mgmtQueryUpdateActions){{ window.mgmtQueryUpdateActions(); }}
  }};
    if(window.mgmtQueryUpdateActions){{ window.mgmtQueryUpdateActions(); }}
}})();
</script>
</div>
"""


@router.get("/tab/query", response_class=HTMLResponse)
def tab_query(request: Request, db: DbDep, user: RequireSuperadmin):
    """Read-only Query tab partial with template CRUD. Super-admin only."""
    targets = _resolve_query_targets(db)
    presets = _all_query_presets(db)
    return HTMLResponse(_render_query_tab(targets, presets))


@router.post("/query/save", response_class=HTMLResponse)
async def query_save(request: Request, db: DbDep, user: RequireSuperadmin):
    """Create/update a saved query template, then re-render the query tab."""
    form = await request.form()
    query_name = str(form.get("query_name", "")).strip()
    target_key = str(form.get("target", "shared")).strip() or "shared"
    selected_preset = str(form.get("preset_id", "")).strip()
    sql_raw = str(form.get("sql", ""))

    targets = _resolve_query_targets(db)
    presets = _all_query_presets(db)

    if not _target_path(db, target_key):
        body = _render_query_tab(
            targets,
            presets,
            selected_preset=selected_preset,
            target_value=target_key,
            sql_value=sql_raw,
            query_name=query_name,
        )
        return HTMLResponse(_query_toast("Unknown or unavailable database target.", "warning") + body)

    cleaned, err = _validate_sql(sql_raw)
    if err:
        body = _render_query_tab(
            targets,
            presets,
            selected_preset=selected_preset,
            target_value=target_key,
            sql_value=sql_raw,
            query_name=query_name,
        )
        return HTMLResponse(_query_toast(err, "warning") + body)

    if not query_name:
        body = _render_query_tab(
            targets,
            presets,
            selected_preset=selected_preset,
            target_value=target_key,
            sql_value=cleaned,
            query_name=query_name,
        )
        return HTMLResponse(_query_toast("Template name is required to save.", "warning") + body)

    try:
        row, created = db.save_query_template(
            query_name,
            cleaned,
            target_key=target_key,
            created_by_user_id=user.id,
        )
    except ValueError as exc:
        body = _render_query_tab(
            targets,
            presets,
            selected_preset=selected_preset,
            target_value=target_key,
            sql_value=cleaned,
            query_name=query_name,
        )
        return HTMLResponse(_query_toast(str(exc), "warning") + body)

    presets = _all_query_presets(db)
    selected = f"custom:{row['id']}"
    body = _render_query_tab(
        targets,
        presets,
        selected_preset=selected,
        target_value=row.get("target_key") or target_key,
        sql_value=row.get("sql_text") or cleaned,
        query_name=row.get("name") or query_name,
    )
    action = "saved" if created else "updated"
    return HTMLResponse(_query_toast(f"Query template '{row.get('name')}' {action}.") + body)


@router.post("/query/delete", response_class=HTMLResponse)
async def query_delete(request: Request, db: DbDep, user: RequireSuperadmin):
    """Delete a saved query template, then re-render the query tab."""
    form = await request.form()
    selected_preset = str(form.get("preset_id", "")).strip()
    target_key = str(form.get("target", "shared")).strip() or "shared"
    sql_raw = str(form.get("sql", ""))
    query_name = str(form.get("query_name", "")).strip()

    targets = _resolve_query_targets(db)
    presets = _all_query_presets(db)

    if not selected_preset.startswith("custom:"):
        body = _render_query_tab(
            targets,
            presets,
            selected_preset=selected_preset,
            target_value=target_key,
            sql_value=sql_raw,
            query_name=query_name,
        )
        return HTMLResponse(_query_toast("Pick a saved query in the dropdown before deleting.", "warning") + body)

    template_id = selected_preset.split(":", 1)[1].strip()
    deleted = db.delete_query_template(template_id)
    presets = _all_query_presets(db)
    body = _render_query_tab(targets, presets)
    if deleted:
        return HTMLResponse(_query_toast("Saved query deleted.") + body)
    return HTMLResponse(_query_toast("Saved query not found (it may already be deleted).", "warning") + body)


@router.post("/query/exec", response_class=HTMLResponse)
async def query_exec(request: Request, db: DbDep, user: RequireSuperadmin):
    """Execute a single read-only SQL statement against a known DuckDB file."""
    if _duckdb_q is None:
        return HTMLResponse(
            '<div class="alert alert-error">DuckDB driver not available.</div>'
        )
    form = await request.form()
    target_key = str(form.get("target", "")).strip()
    sql_raw = str(form.get("sql", ""))
    path = _target_path(db, target_key)
    if not path:
        return HTMLResponse(
            '<div class="alert alert-error">Unknown or unavailable database target.</div>'
        )
    cleaned, err = _validate_sql(sql_raw)
    if err:
        return HTMLResponse(f'<div class="alert alert-error">{_esc(err)}</div>')
    upper = cleaned.upper()
    if "LIMIT" not in upper and (upper.startswith("SELECT") or upper.startswith("WITH")):
        wrapped = f"SELECT * FROM ({cleaned}) AS _q LIMIT {_QUERY_MAX_ROWS + 1}"
    else:
        wrapped = cleaned
    started = _time_q.monotonic()
    conn = None
    try:
        # Snapshot-copy the DB so we never contend with the live writer.
        # DuckDB enforces a single-process file lock, so a direct read_only
        # open against the live file fails with a Conflicting lock error.
        import shutil as _shutil_q
        import tempfile as _tempfile_q
        with _tempfile_q.TemporaryDirectory(prefix="tide_q_") as tmpd:
            snap = _os_q.path.join(tmpd, _os_q.path.basename(path))
            _shutil_q.copy2(path, snap)
            wal = path + ".wal"
            if _os_q.path.exists(wal):
                try:
                    _shutil_q.copy2(wal, snap + ".wal")
                except Exception:
                    pass
            conn = _duckdb_q.connect(snap, read_only=True)
            cur = conn.execute(wrapped)
            cols = [d[0] for d in (cur.description or [])]
            rows = cur.fetchall()
        elapsed_ms = int((_time_q.monotonic() - started) * 1000)
        truncated = False
        if (upper.startswith("SELECT") or upper.startswith("WITH")) and len(rows) > _QUERY_MAX_ROWS:
            rows = rows[:_QUERY_MAX_ROWS]
            truncated = True
        return HTMLResponse(_render_query_results(rows, cols, elapsed_ms, truncated))
    except Exception as exc:
        logger.warning("query_exec failed on %s: %s", target_key, exc)
        return HTMLResponse(
            f'<div class="alert alert-error">Query failed: {_esc(str(exc))}</div>'
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ===========================================================================
# CTI Connectors (multi-vendor framework — F5)
# ---------------------------------------------------------------------------
# Lives alongside the legacy ``/opencti/*`` endpoints. The connectors framework
# uses the vendor registry in ``app/services/cti_connectors/`` (FieldSpec +
# ConnectorVendor) and the shared ``cti_connectors`` / ``cti_connector_clients``
# tables (Migration 47). Storage CRUD already lives in ``app/services/database``.
# ===========================================================================

import json as _cn_json
from datetime import datetime as _cn_datetime


def _connector_status_pill(connector: dict, *, target_id: str | None = None) -> str:
    """Adapter: connectors persist ``last_status`` / ``last_run_at`` /
    ``last_message`` instead of the inventory ``last_test_*`` triplet. Wrap
    so we can reuse :func:`_status_pill_html` verbatim.
    """
    adapted = {
        "last_test_status": connector.get("last_status"),
        "last_test_at": connector.get("last_run_at"),
        "last_test_message": connector.get("last_message"),
    }
    return _status_pill_html(adapted, target_id=target_id)


def _render_vendor_fields_html(vendor, current_cfg: dict | None = None) -> str:
    """Render a vendor's :class:`FieldSpec` list as a stack of form inputs.

    Inputs are named ``cfg_<key>`` so the form-submit JS can scoop them up
    without knowing the schema. Secret fields render as ``<input type=password>``
    with a placeholder reminder so operators don't accidentally blank stored
    credentials.
    """
    current_cfg = current_cfg or {}
    rows: list[str] = []
    for spec in vendor.fields:
        key = spec.key
        name = f"cfg_{key}"
        label = _esc(spec.label or key)
        required = ' <span style="color:var(--color-danger)">*</span>' if spec.required else ""
        help_html = (
            f'<span class="text-secondary" style="font-size:0.75rem;">{_esc(spec.help)}</span>'
            if spec.help else ""
        )
        existing = current_cfg.get(key)
        if spec.type == "bool":
            checked = "checked" if (existing if existing is not None else spec.default) else ""
            field = (
                f'<label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;">'
                f'<input type="checkbox" name="{name}" {checked}> {label}</label>'
            )
            rows.append(f'<div>{field}{help_html}</div>')
            continue
        if spec.type == "select":
            opts_html = "".join(
                f'<option value="{_esc(str(o))}"'
                f'{" selected" if str(existing) == str(o) else ""}>{_esc(str(o))}</option>'
                for o in (spec.options or [])
            )
            field = (
                f'<select name="{name}" class="form-input"'
                f'{" required" if spec.required else ""}>{opts_html}</select>'
            )
        elif spec.type == "textarea":
            field = (
                f'<textarea name="{name}" class="form-input" rows="3"'
                f'{" required" if spec.required else ""}>{_esc(str(existing or spec.default or ""))}</textarea>'
            )
        else:
            input_type = {
                "password": "password",
                "url": "url",
                "number": "number",
            }.get(spec.type, "text")
            placeholder = ""
            value_attr = ""
            if spec.secret:
                placeholder = ' placeholder="Leave blank to keep existing"'
            else:
                v = existing if existing is not None else spec.default
                if v is not None:
                    value_attr = f' value="{_esc(str(v))}"'
            field = (
                f'<input type="{input_type}" name="{name}" class="form-input"'
                f'{value_attr}{placeholder}'
                f'{" required" if (spec.required and not spec.secret) else ""}>'
            )
        rows.append(
            f'<div><label class="form-label" for="{name}">{label}{required}</label>'
            f'{field}{help_html}</div>'
        )
    if not rows:
        return '<div class="text-secondary" style="font-size:0.8125rem;">This vendor has no configuration fields.</div>'
    return "".join(rows)


def _render_connectors_tab(connectors: list, vendors: list, all_clients: list | None = None) -> str:
    """Render the Connectors subsection: per-vendor cards + New button.

    Mirrors :func:`_render_threat_intel_tab` (system-card grid) so the look
    is consistent across Management subsections.
    """
    from html import escape as _e
    all_clients = all_clients or []
    vendor_by_name = {v.name: v for v in vendors}
    count = len(connectors)
    cards = ""
    for c in connectors:
        cid = c["id"]
        vendor = vendor_by_name.get(c.get("vendor"))
        vendor_label = _e(vendor.label if vendor else (c.get("vendor") or "Unknown"))
        lbl_esc = _e(c.get("label") or "(unnamed)")
        # 4.1.20 — the kind chip (CTI / actors / actors + CTI) was
        # dropped from the card header to keep the row aligned with
        # the SIEM cards; the kind is still editable from the modal.
        vendor_badge = f'<span class="badge badge-muted">{vendor_label}</span>'
        # 4.1.20 — drop the standalone "Active/Disabled" badge. It
        # duplicated the live status pill (operators were seeing two
        # green chips on every card), and the SIEM cards next door
        # surface availability through the status pill alone. The
        # disabled state is still reachable from the Edit modal's
        # ``is_active`` toggle.
        status_pill = _connector_status_pill(c, target_id=f"connector-status-{cid}")
        # 5.0.x — auto-sync interval chip. Quiet "manual only" muted
        # chip when interval is NULL/0 so operators can tell at a
        # glance which connectors are on the scheduler.
        iv = c.get("sync_interval_minutes")
        if iv and int(iv) > 0:
            iv_int = int(iv)
            if iv_int % 1440 == 0:
                iv_text = f"every {iv_int // 1440}d"
            elif iv_int % 60 == 0:
                iv_text = f"every {iv_int // 60}h"
            else:
                iv_text = f"every {iv_int}m"
            auto_chip = f'<span class="badge badge-info" title="Auto-sync runs in the background through the CTI scheduler">auto &middot; {_e(iv_text)}</span>'
        else:
            auto_chip = '<span class="badge badge-muted" title="This connector only syncs when an operator clicks Sync">manual only</span>'
        tenant_chips = _tenant_chips_html(c.get("_clients", []))
        cfg = c.get("config") or {}
        # Config summary line — non-secret keys only
        summary_pairs = []
        if vendor:
            for spec in vendor.fields:
                if spec.secret:
                    has = bool(cfg.get(spec.key))
                    summary_pairs.append(
                        (spec.label, '<span class="text-secondary">&#x2713; set</span>' if has else '<span class="text-secondary">&#x2717; missing</span>')
                    )
                else:
                    v = cfg.get(spec.key)
                    if v is None or v == "":
                        continue
                    summary_pairs.append((spec.label, _e(str(v))))
        summary_html = "".join(
            f'<span class="text-secondary">{_e(k)}</span>'
            f'<span style="font-family:var(--font-mono,monospace);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{_e(str(v))}">{v}</span>'
            for k, v in summary_pairs
        )
        # Test connection button — mirrors the SIEM card layout. The
        # standalone "Sync" button was removed in 4.1.20 (the
        # per-connector sync now runs from the connector's edit modal
        # / the per-page Check-connection action; the management hub
        # card just confirms reachability and surfaces CRUD).
        test_btn = (
            f'<button class="btn btn-ghost btn-sm" '
            f'hx-post="/api/management/connectors/{cid}/test" '
            f'hx-target="#connector-status-{cid}" hx-swap="outerHTML" '
            f'title="Test connection now" aria-label="Test connection">'
            f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            f'<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg></button>'
        )
        edit_btn = (
            f'<button class="btn btn-ghost btn-sm" '
            f'onclick="editConnector(\'{cid}\')" title="Edit">'
            f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
            f'<path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg></button>'
        )
        del_btn = (
            f'<button class="btn btn-ghost btn-sm text-danger" '
            f'hx-delete="/api/management/connectors/{cid}" '
            f'hx-target="#mgmt-sub-connectors" hx-swap="innerHTML" '
            f'hx-confirm="Delete connector \'{lbl_esc}\'? This will unlink it from all clients." '
            f'title="Delete">'
            f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
            f'<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>'
            f'<path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg></button>'
        )
        cards += f'''
        <div class="system-card" style="display:flex;flex-direction:column;">
            <div class="system-card__title" style="display:flex;align-items:center;justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
                    <span style="font-weight:600;">{lbl_esc}</span>
                    {vendor_badge}
                    {status_pill}
                    {auto_chip}
                </div>
                <div style="display:flex;gap:0.25rem;">
                    {test_btn}
                    {edit_btn}
                    {del_btn}
                </div>
            </div>
            <div class="system-card__desc" style="margin-top:0.5rem;">
                <div style="display:grid;grid-template-columns:auto 1fr;gap:0.25rem 0.75rem;font-size:0.8125rem;">
                    {summary_html}
                </div>
            </div>
            <div class="system-card__footer" style="flex-wrap:wrap;margin-top:auto;padding-top:0.75rem;">
                {tenant_chips}
            </div>
        </div>'''

    empty = ""
    if not connectors:
        empty = '''
        <div class="empty-output" style="padding:4rem 2rem;text-align:center;">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.3;">
                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
            </svg>
            <p style="margin-top:1rem;color:var(--color-text-muted);">No connectors configured yet.</p>
        </div>'''

    # Embed vendor list + connector rows for the modal JS to consume.
    vendors_payload = _cn_json.dumps([
        {"name": v.name, "label": v.label} for v in vendors
    ])
    rows_payload = _cn_json.dumps([
        {
            "id": c["id"],
            "vendor": c.get("vendor"),
            "label": c.get("label"),
            "kind": c.get("kind"),
            "sync_interval_minutes": c.get("sync_interval_minutes"),
            "config": c.get("config") or {},
        } for c in connectors
    ])

    return f'''
    <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:1.5rem;">
        <span class="text-secondary">{count} connector{"s" if count != 1 else ""} configured &middot; {len(vendors)} vendor{"s" if len(vendors) != 1 else ""} available</span>
        <div style="display:flex;gap:0.5rem;">
            <button class="btn btn-secondary" onclick="showImportConnectorModal()" title="Import a connector from JSON exported elsewhere">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Import
            </button>
            <button class="btn btn-primary" onclick="showCreateConnectorModal()">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                New Connector
            </button>
        </div>
    </div>
    <div class="systems-grid">{cards}</div>
    {empty}
    <script>
        window._connectorVendors = {vendors_payload};
        window._connectorRows = {rows_payload};
    </script>'''


def _connectors_tab_response(db) -> HTMLResponse:
    """Shared helper so every CRUD endpoint can return the refreshed tab."""
    from app.services.cti_connectors import all_vendors
    connectors = db.list_cti_connectors()
    for c in connectors:
        c["_clients"] = db.get_cti_connector_clients(c["id"])
    all_clients = db.list_clients()
    return HTMLResponse(_render_connectors_tab(connectors, all_vendors(), all_clients))


def _parse_connector_form(form, vendor, *, existing_cfg: dict | None = None) -> tuple[dict, dict, list[str]]:
    """Extract generic + per-vendor config from a form submission.

    Returns ``(generic_fields, config_dict, errors)``. Secret fields left
    blank fall back to ``existing_cfg`` so editing without re-entering the
    password works as operators expect.
    """
    existing_cfg = existing_cfg or {}
    errors: list[str] = []
    generic = {
        "label": str(form.get("label", "")).strip(),
        "kind": str(form.get("kind", "cti")).strip().lower() or "cti",
    }
    # 5.0.x — optional auto-sync interval (minutes). Blank/0/missing
    # means "off"; the CTI scheduler skips connectors whose interval
    # is NULL. Capped at 7 days (10 080 min) so a typo can't park a
    # connector for years; min 5 min so the scheduler tick isn't
    # outrun by the interval.
    interval_raw = str(form.get("sync_interval_minutes", "")).strip()
    interval_val: Optional[int] = None
    if interval_raw:
        try:
            iv = int(interval_raw)
            if iv > 0:
                if iv < 5:
                    errors.append("Auto-sync interval must be at least 5 minutes.")
                elif iv > 10080:
                    errors.append("Auto-sync interval cannot exceed 7 days (10080 minutes).")
                else:
                    interval_val = iv
        except ValueError:
            errors.append("Auto-sync interval must be a whole number of minutes.")
    generic["sync_interval_minutes"] = interval_val
    if not generic["label"]:
        errors.append("Label is required.")
    if generic["kind"] not in ("cti", "actors", "both"):
        errors.append("Kind must be one of: cti, actors, both.")
    cfg: dict = {}
    for spec in vendor.fields:
        raw = form.get(f"cfg_{spec.key}")
        if spec.type == "bool":
            cfg[spec.key] = (str(raw).lower() == "true") if raw is not None else bool(spec.default)
            continue
        s = "" if raw is None else str(raw).strip()
        if not s:
            if spec.secret and spec.key in existing_cfg:
                cfg[spec.key] = existing_cfg[spec.key]  # preserve
                continue
            if spec.required and (spec.default is None):
                errors.append(f"{spec.label} is required.")
                continue
            cfg[spec.key] = spec.default
            continue
        if spec.type == "number":
            try:
                cfg[spec.key] = int(s) if s.isdigit() else float(s)
            except Exception:
                errors.append(f"{spec.label} must be numeric.")
                cfg[spec.key] = s
        else:
            cfg[spec.key] = s
    return generic, cfg, errors


@router.get("/tab/connectors", response_class=HTMLResponse)
def tab_connectors(request: Request, db: DbDep, user: RequireAdmin):
    """Connectors tab partial for the management hub."""
    return _connectors_tab_response(db)


@router.get("/connectors/vendor-fields/{vendor_name}", response_class=HTMLResponse)
def connector_vendor_fields(vendor_name: str, user: RequireAdmin):
    """Return the FieldSpec form-fragment for the chosen vendor.

    Fired by the vendor ``<select onchange>`` in the connector modal so the
    form can render the right inputs without a page reload.
    """
    from app.services.cti_connectors import get as get_vendor
    vendor = get_vendor(vendor_name)
    if vendor is None:
        return HTMLResponse(
            f'<span class="badge badge-danger">Unknown vendor: {_esc(vendor_name)}</span>',
            status_code=404,
        )
    return HTMLResponse(_render_vendor_fields_html(vendor))


@router.post("/connectors", response_class=HTMLResponse)
async def create_connector(request: Request, db: DbDep, user: RequireAdmin):
    """Create a new connector. Vendor + label + per-vendor cfg required."""
    from app.services.cti_connectors import get as get_vendor
    form = await request.form()
    vendor_name = str(form.get("vendor", "")).strip()
    vendor = get_vendor(vendor_name)
    if vendor is None:
        return HTMLResponse(
            f'<span class="badge badge-danger">Unknown vendor: {_esc(vendor_name)}</span>',
            status_code=400,
        )
    generic, cfg, errors = _parse_connector_form(form, vendor)
    if errors:
        return HTMLResponse(
            '<div class="alert alert-error">' + "; ".join(_esc(e) for e in errors) + '</div>',
            status_code=400,
        )
    try:
        created = db.create_cti_connector(
            vendor=vendor_name,
            label=generic["label"],
            kind=generic["kind"],
            is_active=True,
            config=cfg,
        )
        cid = (created or {}).get("id", "?")
        # Apply interval as an update (create_cti_connector signature
        # is a stable wire contract we don't want to change just for
        # this optional field).
        if cid and generic.get("sync_interval_minutes") is not None:
            try:
                db.update_cti_connector(
                    cid, sync_interval_minutes=generic["sync_interval_minutes"],
                )
            except Exception:
                logger.warning("create_connector: could not set interval on %s", cid)
    except Exception as exc:
        logger.error("create_cti_connector failed: %s", exc, exc_info=True)
        return HTMLResponse(
            f'<div class="alert alert-error">Create failed: {_esc(str(exc))}</div>',
            status_code=500,
        )
    logger.info("Connector created: %s (%s) by %s", cid, vendor_name, user.username)
    return _connectors_tab_response(db)


@router.post("/connectors/import", response_class=HTMLResponse)
async def import_connectors(request: Request, db: DbDep, user: RequireAdmin):
    """Bulk-create connectors from a pasted JSON payload.

    Accepts either a single connector object or ``{"connectors": [...]}``.
    Each entry must specify ``vendor`` + ``label``; ``kind`` defaults to the
    vendor's ``kind_default``; ``config`` is validated against the vendor's
    FieldSpec list using the same parser as the create form.
    """
    from app.services.cti_connectors import get as get_vendor
    form = await request.form()
    raw = str(form.get("payload", "")).strip()
    if not raw:
        return HTMLResponse(
            '<div class="alert alert-error">Paste a JSON payload to import.</div>',
            status_code=400,
        )
    try:
        data = _cn_json.loads(raw)
    except Exception as exc:
        return HTMLResponse(
            f'<div class="alert alert-error">Invalid JSON: {_esc(str(exc))}</div>',
            status_code=400,
        )
    entries = data.get("connectors") if isinstance(data, dict) and "connectors" in data else data
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list) or not entries:
        return HTMLResponse(
            '<div class="alert alert-error">Payload must be a connector object or a list of connectors.</div>',
            status_code=400,
        )
    created_ids: list[str] = []
    errors: list[str] = []
    for idx, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            errors.append(f"Entry {idx}: must be an object.")
            continue
        vendor_name = str(entry.get("vendor", "")).strip().lower()
        try:
            vendor = get_vendor(vendor_name) if vendor_name else None
        except KeyError:
            vendor = None
        if vendor is None:
            errors.append(f"Entry {idx}: unknown vendor '{vendor_name}'.")
            continue
        label = str(entry.get("label", "")).strip()
        if not label:
            errors.append(f"Entry {idx} ({vendor_name}): label is required.")
            continue
        kind = str(entry.get("kind", vendor.kind_default) or vendor.kind_default).strip().lower()
        if kind not in ("cti", "actors", "both"):
            errors.append(f"Entry {idx} ({label}): kind must be cti, actors, or both.")
            continue
        cfg_in = entry.get("config") or {}
        if not isinstance(cfg_in, dict):
            errors.append(f"Entry {idx} ({label}): config must be an object.")
            continue
        cfg: dict = {}
        missing: list[str] = []
        for spec in vendor.fields:
            if spec.key in cfg_in:
                cfg[spec.key] = cfg_in[spec.key]
            elif spec.required and spec.default is None:
                missing.append(spec.label)
            else:
                cfg[spec.key] = spec.default
        if missing:
            errors.append(f"Entry {idx} ({label}): missing required field(s): {', '.join(missing)}.")
            continue
        try:
            created = db.create_cti_connector(
                vendor=vendor_name,
                label=label,
                kind=kind,
                is_active=bool(entry.get("is_active", True)),
                config=cfg,
            )
            created_ids.append((created or {}).get("id", "?"))
        except Exception as exc:
            logger.error("import create_cti_connector failed: %s", exc, exc_info=True)
            errors.append(f"Entry {idx} ({label}): {exc}")
    logger.info(
        "Connector import by %s: %d created, %d errors", user.username, len(created_ids), len(errors)
    )
    if errors and not created_ids:
        return HTMLResponse(
            '<div class="alert alert-error"><strong>Import failed.</strong><ul style="margin:0.5rem 0 0 1rem;">'
            + "".join(f"<li>{_esc(e)}</li>" for e in errors)
            + "</ul></div>",
            status_code=400,
        )
    # Partial or full success: refresh tab, with a banner about errors if any.
    refreshed = _render_connectors_tab(
        [dict(c, _clients=db.get_cti_connector_clients(c["id"])) for c in db.list_cti_connectors()],
        __import__("app.services.cti_connectors", fromlist=["all_vendors"]).all_vendors(),
        db.list_clients(),
    )
    banner = (
        f'<div class="alert alert-success" style="margin-bottom:1rem;">Imported {len(created_ids)} connector(s).</div>'
    )
    if errors:
        banner += (
            '<div class="alert alert-warning" style="margin-bottom:1rem;"><strong>Some entries skipped:</strong>'
            '<ul style="margin:0.5rem 0 0 1rem;">'
            + "".join(f"<li>{_esc(e)}</li>" for e in errors)
            + "</ul></div>"
        )
    return HTMLResponse(banner + refreshed)


@router.put("/connectors/{connector_id}", response_class=HTMLResponse)
async def update_connector(request: Request, connector_id: str, db: DbDep, user: RequireAdmin):
    """Update generic + vendor-specific fields on an existing connector."""
    from app.services.cti_connectors import get as get_vendor
    existing = db.get_cti_connector(connector_id)
    if not existing:
        return HTMLResponse(
            '<div class="alert alert-error">Connector not found</div>',
            status_code=404,
        )
    vendor = get_vendor(existing.get("vendor") or "")
    if vendor is None:
        return HTMLResponse(
            f'<div class="alert alert-error">Vendor {_esc(existing.get("vendor") or "?")} is no longer registered</div>',
            status_code=400,
        )
    form = await request.form()
    generic, cfg, errors = _parse_connector_form(
        form, vendor, existing_cfg=(existing.get("config") or {}),
    )
    if errors:
        return HTMLResponse(
            '<div class="alert alert-error">' + "; ".join(_esc(e) for e in errors) + '</div>',
            status_code=400,
        )
    try:
        db.update_cti_connector(
            connector_id,
            label=generic["label"],
            kind=generic["kind"],
            config=cfg,
            sync_interval_minutes=generic.get("sync_interval_minutes"),
        )
    except Exception as exc:
        logger.error("update_cti_connector failed: %s", exc, exc_info=True)
        return HTMLResponse(
            f'<div class="alert alert-error">Update failed: {_esc(str(exc))}</div>',
            status_code=500,
        )
    logger.info("Connector updated: %s by %s", connector_id, user.username)
    return _connectors_tab_response(db)


@router.delete("/connectors/{connector_id}", response_class=HTMLResponse)
def delete_connector(connector_id: str, db: DbDep, user: RequireAdmin):
    """Delete a connector and all its client links."""
    existing = db.get_cti_connector(connector_id)
    if not existing:
        return _connectors_tab_response(db)
    try:
        db.delete_cti_connector(connector_id)
    except Exception as exc:
        logger.error("delete_cti_connector failed: %s", exc, exc_info=True)
        return HTMLResponse(
            f'<div class="alert alert-error">Delete failed: {_esc(str(exc))}</div>',
            status_code=500,
        )
    logger.info("Connector deleted: %s by %s", connector_id, user.username)
    return _connectors_tab_response(db)


@router.post("/connectors/{connector_id}/test", response_class=HTMLResponse)
def test_connector(connector_id: str, db: DbDep, user: RequireAdmin):
    """Run a lightweight connectivity probe and persist the result.

    Every supported vendor wires a ``tester=`` callable on its
    :class:`ConnectorVendor`; this endpoint dispatches to that probe
    and persists ``last_status`` / ``last_run_at`` / ``last_message``
    so the per-card pill reflects the most recent attempt. Vendors
    without a probe registered surface that fact instead of silently
    flashing fail.
    """
    from app.services.cti_connectors import get as get_vendor
    connector = db.get_cti_connector(connector_id)
    if not connector:
        return HTMLResponse(
            '<span class="status-pill status-pill--fail">Not found</span>',
            status_code=404,
        )
    vendor_name = connector.get("vendor") or ""
    try:
        vendor = get_vendor(vendor_name)
    except KeyError:
        vendor = None
    status = "fail"
    message = ""
    try:
        if vendor is None:
            message = (
                f"Vendor '{vendor_name}' is not registered. "
                f"This usually means a legacy connector row survived a "
                f"vendor cutover; delete the connector and recreate it "
                f"under the current vendor list."
            )
        elif vendor.tester is not None:
            result = vendor.tester(connector) or {}
            ok = bool(result.get("ok"))
            err = (result.get("error") or "").strip()
            cols = result.get("collections")
            if ok:
                status = "pass"
                if isinstance(cols, list):
                    message = f"collections={len(cols)}" + (
                        f" ({', '.join(cols[:3])}{'…' if len(cols) > 3 else ''})"
                        if cols else ""
                    )
                else:
                    message = "connection ok"
            else:
                status = "fail"
                message = err or "connection probe returned ok=false"
        else:
            message = "No test probe registered for this vendor yet"
            status = "fail"
    except Exception as exc:
        message = str(exc)[:200]
        status = "fail"
    try:
        db.update_cti_connector(
            connector_id,
            last_status=status,
            last_message=message[:500],
            last_run_at=_cn_datetime.utcnow(),
        )
        logger.info(
            "connector test %s (%s) -> %s: %s",
            connector_id[:8], connector.get("vendor"), status, message[:200],
        )
    except Exception as exc:
        logger.warning(
            "Failed to persist test status for connector %s: %s",
            connector_id, exc,
        )
    refreshed = db.get_cti_connector(connector_id) or connector
    return HTMLResponse(_connector_status_pill(refreshed, target_id=f"connector-status-{connector_id}"))


@router.post("/connectors/{connector_id}/sync", response_class=HTMLResponse)
def sync_connector(connector_id: str, db: DbDep, user: RequireAdmin):
    """Kick off a background sync job and return the polling badge.

    The pre-5.0.x synchronous implementation held the worker thread
    through the entire vendor fetch, so the operator's HTMX click
    timed out on populous OpenCTI / Mandiant tenants before the data
    landed (nginx 504 → no visible state → row count silently caught
    up minutes later if the work finished at all). We now submit the
    work to :mod:`app.services.cti_jobs` and return a polling fragment
    that swaps itself out for the terminal badge when the job ends.
    """
    from app.services.cti_connectors import get as get_vendor
    from app.services import cti_jobs

    connector = db.get_cti_connector(connector_id)
    if not connector:
        return HTMLResponse('<span class="badge badge-warning">Connector not found</span>')
    vendor = get_vendor(connector.get("vendor") or "")
    if vendor is None:
        return HTMLResponse(
            f'<span class="badge badge-danger">Vendor &lsquo;{_esc(connector.get("vendor") or "?")}&rsquo; is no longer registered</span>'
        )
    linked = db.get_cti_connector_clients(connector_id)
    if not linked:
        return HTMLResponse(
            '<span class="badge badge-warning">No linked tenants &mdash; link this connector to at least one client first.</span>'
        )

    def _runner():
        # Re-resolve at run-time so an operator who links/unlinks a
        # tenant between submit and start still gets the current fan-out.
        connector_now = db.get_cti_connector(connector_id) or connector
        linked_now = db.get_cti_connector_clients(connector_id) or linked
        try:
            result = vendor.fetcher(connector_now, linked_now)
        except Exception as exc:
            msg = str(exc)[:200]
            try:
                db.update_cti_connector(
                    connector_id,
                    last_status="fail",
                    last_message=msg,
                    last_run_at=_cn_datetime.utcnow(),
                )
            except Exception:
                pass
            raise
        summary = result.as_dict() if hasattr(result, "as_dict") else (result or {})
        errors = summary.get("errors") or []
        tenants = summary.get("tenants", 0)
        new = summary.get("indicators_new", 0)
        merged = summary.get("indicators_merged", 0)
        review = summary.get("indicators_review", 0)
        actors = summary.get("actors", 0) + summary.get("intrusion_sets", 0)
        reports = summary.get("reports", 0)
        rels = summary.get("relationships", 0)
        badge_msg = (
            f"{tenants} tenant(s) · +{new} new / ~{merged} merged / ?{review} review"
            f" · {actors} actors / {reports} reports / {rels} links"
        )
        try:
            db.update_cti_connector(
                connector_id,
                last_status="pass" if not errors else "fail",
                last_message=badge_msg[:500],
                last_run_at=_cn_datetime.utcnow(),
            )
        except Exception:
            logger.warning("Failed to persist sync status for connector %s", connector_id)
        return summary

    job_id = cti_jobs.submit(
        kind="connector",
        runner=_runner,
        label=connector.get("label") or connector.get("vendor") or connector_id,
    )
    # Inline polling fragment — re-uses the same render shape as the
    # /cti/sync/jobs/{id} endpoint so the badge swap is identical.
    target_id = f"connector-sync-job-{job_id}"
    return HTMLResponse(
        f'<span id="{target_id}" class="badge badge-info" '
        f'hx-get="/api/management/connectors/sync/jobs/{job_id}" '
        f'hx-trigger="every 2s" '
        f'hx-swap="outerHTML">… syncing {_esc(connector.get("label") or "")}</span>'
    )


@router.get("/connectors/sync/jobs/{job_id}", response_class=HTMLResponse)
def sync_connector_job_status(job_id: str, user: RequireAdmin):
    """HTMX polling target for a connector sync job."""
    from app.services import cti_jobs
    job = cti_jobs.get(job_id)
    target_id = f"connector-sync-job-{_esc(job_id)}"
    if job is None:
        return HTMLResponse(
            f'<span id="{target_id}" class="badge badge-warning">'
            f'Job no longer tracked &mdash; refresh to see status.</span>'
        )
    status = job.get("status")
    label = job.get("label") or ""
    if status in ("pending", "running"):
        return HTMLResponse(
            f'<span id="{target_id}" class="badge badge-info" '
            f'hx-get="/api/management/connectors/sync/jobs/{_esc(job_id)}" '
            f'hx-trigger="every 2s" '
            f'hx-swap="outerHTML">… syncing {_esc(label)}</span>'
        )
    if status == "failed":
        err = job.get("error") or "unknown error"
        return HTMLResponse(
            f'<span id="{target_id}" class="badge badge-danger">'
            f'Sync failed &mdash; {_esc(err[:200])}</span>'
        )
    summary = job.get("summary") or {}
    if not isinstance(summary, dict):
        summary = {}
    errors = summary.get("errors") or []
    cls = "badge-success" if not errors else "badge-warning"
    tenants = summary.get("tenants", 0)
    new = summary.get("indicators_new", 0)
    merged = summary.get("indicators_merged", 0)
    review = summary.get("indicators_review", 0)
    actors = summary.get("actors", 0) + summary.get("intrusion_sets", 0)
    reports = summary.get("reports", 0)
    rels = summary.get("relationships", 0)
    err_suffix = f" &middot; {len(errors)} error(s)" if errors else ""
    badge_msg = (
        f"{tenants} tenant(s) &middot; +{new} new / ~{merged} merged / ?{review} review"
        f" &middot; {actors} actors / {reports} reports / {rels} links{err_suffix}"
    )
    return HTMLResponse(
        f'<span id="{target_id}" class="badge {cls}">{badge_msg}</span>'
    )


@router.post("/clients/{client_id}/connectors/{connector_id}", response_class=HTMLResponse)
def link_connector_to_client(client_id: str, connector_id: str, db: DbDep, user: RequireAdmin):
    """Link a connector to a client (positional path variant)."""
    try:
        db.link_cti_connector_client(connector_id, client_id)
    except Exception as exc:
        logger.error("link_cti_connector_client failed: %s", exc, exc_info=True)
        return HTMLResponse(
            f'<div class="alert alert-error">Link failed: {_esc(str(exc))}</div>',
            status_code=500,
        )
    logger.info("Connector %s linked to client %s by %s", connector_id, client_id, user.username)
    return _render_client_connectors_partial(client_id, db, toast="Connector linked.")


@router.post("/clients/{client_id}/connectors", response_class=HTMLResponse)
async def add_connector_to_client(request: Request, client_id: str,
                                  db: DbDep, user: RequireAdmin):
    """Link a connector via form body (mirrors the SIEM/OpenCTI add pattern).

    Used by the per-tenant ``Linked Connectors`` modal on the client
    detail page; the dropdown posts ``connector_id`` here so the same
    surface adds and removes connectors via the same partial swap.
    """
    form = await request.form()
    connector_id = (form.get("connector_id") or "").strip()
    if not connector_id:
        return HTMLResponse("")
    try:
        db.link_cti_connector_client(connector_id, client_id)
    except Exception as exc:
        logger.error("link_cti_connector_client failed: %s", exc, exc_info=True)
        return HTMLResponse(
            f'<div class="alert alert-error">Link failed: {_esc(str(exc))}</div>',
            status_code=500,
        )
    logger.info(
        "Connector %s linked to client %s by %s (form)",
        connector_id, client_id, user.username,
    )
    return _render_client_connectors_partial(client_id, db, toast="Connector linked.")


@router.delete("/clients/{client_id}/connectors/{connector_id}", response_class=HTMLResponse)
def unlink_connector_from_client(client_id: str, connector_id: str, db: DbDep, user: RequireAdmin):
    """Unlink a connector from a client."""
    try:
        db.unlink_cti_connector_client(connector_id, client_id)
    except Exception as exc:
        logger.error("unlink_cti_connector_client failed: %s", exc, exc_info=True)
        return HTMLResponse(
            f'<div class="alert alert-error">Unlink failed: {_esc(str(exc))}</div>',
            status_code=500,
        )
    logger.info("Connector %s unlinked from client %s by %s", connector_id, client_id, user.username)
    return _render_client_connectors_partial(client_id, db, toast="Connector unlinked.")
