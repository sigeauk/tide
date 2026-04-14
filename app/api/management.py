"""
Management Hub API endpoints for TIDE v4.0.0.
Centralized admin area for Clients, SIEM Inventory, Users, and Permissions.
All endpoints require ADMIN role.
"""

import logging
import threading
import uuid as _uuid
from html import escape as _esc

import requests as http_requests
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from app.api.deps import DbDep, RequireAdmin

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
def tab_clients(request: Request, db: DbDep, user: RequireAdmin):
    """Clients tab partial for the management hub."""
    from app.inventory_engine import list_systems, list_playbooks
    from app.services.tenant_manager import tenant_context_for
    clients = db.list_clients()
    for c in clients:
        c["_siem_count"] = len(db.get_client_siems(c["id"]))
        c["_user_count"] = len(db.get_client_users(c["id"]))
        with tenant_context_for(c["id"]):
            c["_system_count"] = len(list_systems(client_id=c["id"]))
            c["_baseline_count"] = len(list_playbooks(client_id=c["id"]))
    return _render_clients_tab(clients)


@router.get("/tab/siems", response_class=HTMLResponse)
def tab_siems(request: Request, db: DbDep, user: RequireAdmin):
    """SIEMs tab partial for the management hub."""
    siems = db.list_siem_inventory()
    for s in siems:
        s["_clients"] = db.get_siem_clients(s["id"])
    return _render_siems_tab(siems)


@router.get("/tab/users", response_class=HTMLResponse)
def tab_users(request: Request, db: DbDep, user: RequireAdmin):
    """Users tab partial for the management hub."""
    users = db.get_all_users()
    all_roles = db.get_all_roles()
    for u in users:
        u["_roles"] = db.get_user_roles(u["id"])
        u["_client_ids"] = db.get_user_client_ids(u["id"])
    clients = db.list_clients()
    return _render_users_tab(users, all_roles, clients)


@router.get("/tab/permissions", response_class=HTMLResponse)
def tab_permissions(request: Request, db: DbDep, user: RequireAdmin):
    """Permissions tab partial for the management hub."""
    return _render_permissions_tab(db)


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
    kibana_url = str(form.get("kibana_url", "")).strip()
    api_token = str(form.get("api_token", "")).strip()
    siem_type = str(form.get("siem_type", "elastic")).strip()

    if siem_type != "elastic":
        return HTMLResponse(
            '<span class="badge badge-secondary">Test not available for this SIEM type</span>'
        )
    if not kibana_url or not api_token:
        return HTMLResponse(
            '<span class="badge badge-warning">Kibana URL and API key are required</span>'
        )

    try:
        from app.elastic_helper import test_elastic_connection
        ok, detail = test_elastic_connection(kibana_url, api_token)
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
# Client-SIEM linking (returns partial for client detail page)
# ---------------------------------------------------------------------------

@router.post("/clients/{client_id}/siems", response_class=HTMLResponse)
async def link_siem_to_client(request: Request, client_id: str, db: DbDep, user: RequireAdmin):
    """Link a SIEM to a client with an environment role and space."""
    form = await request.form()
    siem_id = str(form.get("siem_id", "")).strip()
    environment_role = str(form.get("environment_role", "production")).strip()
    space = str(form.get("space", "")).strip() or None
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
    """Assign a user to a client."""
    form = await request.form()
    user_id = str(form.get("user_id", "")).strip()
    if not user_id:
        return HTMLResponse("")
    db.assign_user_to_client(user_id, client_id)
    logger.info(f"User {user_id} assigned to client {client_id} by {user.username}")
    return _render_client_users_partial(client_id, db, toast="User assigned.")


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


def _render_siems_tab(siems: list) -> str:
    """Render the SIEMs tab content as cards (matching systems.html pattern)."""
    from html import escape
    count = len(siems)
    cards = ""
    for s in siems:
        client_badges = ""
        for cl in s.get("_clients", []):
            client_badges += f'<span class="badge badge-muted">{escape(cl["name"])}</span> '
        if not s.get("_clients"):
            client_badges = '<span class="text-secondary" style="font-size:0.8125rem;">No clients linked</span>'

        active_badge = '<span class="badge badge-success">active</span>' if s.get("is_active") else '<span class="badge badge-secondary">inactive</span>'
        created = s["created_at"].strftime('%Y-%m-%d') if s.get("created_at") else "N/A"

        es_url = escape(s.get("elasticsearch_url") or "-")
        kb_url = escape(s.get("kibana_url") or "-")
        lbl_esc = escape(s["label"])
        stype_esc = escape(s["siem_type"])
        sid = s["id"]

        cards += f'''
        <div class="system-card" style="display:flex;flex-direction:column;">
            <div class="system-card__title" style="display:flex;align-items:center;justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:0.5rem;">
                    <span style="font-weight:600;">{lbl_esc}</span>
                    <span class="badge badge-muted">{stype_esc}</span>
                    {active_badge}
                </div>
                <div style="display:flex;gap:0.25rem;">
                    <button class="btn btn-ghost btn-sm"
                            onclick="editSiem('{sid}', '{lbl_esc}', '{stype_esc}', '{escape(s.get("elasticsearch_url") or "")}', '{escape(s.get("kibana_url") or "")}')"
                            title="Edit">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
                    </button>
                    <button class="btn btn-ghost btn-sm text-danger"
                            hx-delete="/api/management/siems/{sid}"
                            hx-target="#management-content" hx-swap="innerHTML"
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
            <div class="system-card__footer" style="margin-top:auto;padding-top:0.75rem;">
                <div style="display:flex;align-items:center;justify-content:space-between;">
                    <div>{client_badges}</div>
                    <span class="text-secondary" style="font-size:0.75rem;">{created}</span>
                </div>
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
    """Render the Users tab content with Manage Clients action."""
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

        # Roles
        role_checkboxes = ""
        user_roles = u.get("_roles", [])
        for r in all_roles:
            checked = "checked" if r["name"] in user_roles else ""
            role_checkboxes += (
                f'<label class="role-checkbox"><input type="checkbox" name="roles" '
                f'value="{r["name"]}" {checked}> {r["name"]}</label> '
            )

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
                <form class="inline-role-form"
                      hx-post="/api/settings/users/{u['id']}/roles"
                      hx-target="#management-content"
                      hx-swap="innerHTML"
                      hx-get="/api/management/tab/users"
                      hx-trigger="submit">
                    {role_checkboxes}
                    <button type="submit" class="btn btn-sm btn-secondary">Save</button>
                </form>
            </td>
            <td>
                <label class="toggle-switch toggle-sm">
                    <input type="checkbox" {active_checked}
                           hx-post="/api/settings/users/{u['id']}/toggle-active"
                           hx-target="#management-content"
                           hx-swap="innerHTML"
                           hx-get="/api/management/tab/users"
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
                        hx-delete="/api/settings/users/{u['id']}"
                        hx-target="#management-content"
                        hx-swap="innerHTML"
                        hx-get="/api/management/tab/users"
                        hx-confirm="Delete user {u['username']}?">Del</button>
            </td>
        </tr>'''

    # Add user form
    role_options = ""
    for r in all_roles:
        checked = "checked" if r["name"] == "ANALYST" else ""
        role_options += f'<label class="role-checkbox"><input type="checkbox" name="new_roles" value="{r["name"]}" {checked}> {r["name"]}</label> '

    add_form = f'''
    <details class="add-user-details" style="margin-bottom:1.5rem;">
        <summary class="btn btn-secondary btn-sm" style="cursor:pointer;">+ Add Local User</summary>
        <form hx-post="/api/settings/users" hx-target="#management-content" hx-swap="innerHTML"
              hx-get="/api/management/tab/users" hx-trigger="submit"
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
                <label class="form-label" style="font-size:0.8rem;">Roles</label>
                <div style="display:flex;gap:1rem;">{role_options}</div>
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
            <th>Roles</th><th>Active</th><th>Last Login</th>
            <th>Clients</th><th></th>
        </tr></thead>
        <tbody>{rows}</tbody>
    </table>'''


def _render_permissions_tab(db) -> str:
    """Render the permissions matrix (reuses settings logic)."""
    roles = [r for r in db.get_all_roles() if r["name"] != "ADMIN"]
    resources = db.get_all_resources()
    matrix = db.get_permissions_matrix()

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
                                hx-post="/api/settings/permissions"
                                hx-vals='{{"role_id":"{role_id}","resource":"{res}","access":"read","state":"{("off" if r_chk else "on")}"}}'
                                hx-target="#permissions-matrix"
                                hx-swap="innerHTML"> R
                        </label>
                        <label class="role-checkbox" title="Write">
                            <input type="checkbox" name="perm" {w_chk}
                                hx-post="/api/settings/permissions"
                                hx-vals='{{"role_id":"{role_id}","resource":"{res}","access":"write","state":"{("off" if w_chk else "on")}"}}'
                                hx-target="#permissions-matrix"
                                hx-swap="innerHTML"> W
                        </label>
                    </div>
                </td>'''
            html += '</tr>'
        return html

    role_headers = "".join(f'<th style="text-align:center;">{r["name"]}</th>' for r in roles)

    return f'''
    <p style="font-size:0.8rem;color:var(--color-text-secondary);margin:0 0 1rem 0;">
        Control which roles can <strong>Read</strong> (view) or <strong>Write</strong> (modify) each page and settings tab.
        The ADMIN role always has full access and is not shown below. Changes take effect on next login.
    </p>
    <div id="permissions-matrix">
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
        conn = duckdb.connect(str(db.db_path), read_only=True)
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

    # OOB update the edit-systems-modal and edit-baselines-modal in client_detail.html
    return HTMLResponse(f"{html}{toast_html}")


def _render_client_users_partial(client_id: str, db, toast: str = None) -> HTMLResponse:
    """Re-render the client users section using Jinja2 partial."""
    from html import escape
    import os
    from jinja2 import Environment, FileSystemLoader

    client = db.get_client(client_id)
    client_users = db.get_client_users(client_id)
    all_users = db.get_all_users()
    assigned_ids = {u["id"] for u in client_users}
    available_users = [u for u in all_users if u["id"] not in assigned_ids]

    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("partials/client_users.html")
    html = template.render(
        client=client, client_users=client_users,
        available_users=available_users,
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
