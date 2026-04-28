"""
Client (tenant) management API endpoints for TIDE multi-tenant MSSP.
Handles CRUD for clients, user-client assignments, SIEM configs, and client switching.
"""

import logging
from fastapi import APIRouter, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse

from app.api.deps import DbDep, RequireUser, RequireAdmin, RequireSuperadmin, ActiveClient
from app.models.client import (
    ClientCreate, ClientUpdate,
    SIEMConfigCreate, SIEMConfigUpdate,
    UserClientAssignment,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/clients", tags=["clients"])


# ---------------------------------------------------------------------------
# Client CRUD (admin only)
# ---------------------------------------------------------------------------

@router.get("", response_class=JSONResponse)
def list_clients(db: DbDep, user: RequireUser):
    """List clients the user has access to. Super-admins see all tenants."""
    if user.is_superadmin:
        clients = db.list_clients()
    else:
        client_ids = db.get_user_client_ids(user.id)
        clients = [db.get_client(cid) for cid in client_ids]
        clients = [c for c in clients if c is not None]
    return [c for c in clients]


@router.post("", response_class=JSONResponse, status_code=201)
def create_client(data: ClientCreate, db: DbDep, user: RequireSuperadmin):
    """Create a new client (super-admin only)."""
    client = db.create_client(data.name, data.slug, data.description)
    logger.info(f"Client created: {client['name']} (slug={client['slug']}) by {user.username}")
    return client


@router.get("/{client_id}", response_class=JSONResponse)
def get_client(client_id: str, db: DbDep, user: RequireUser):
    """Get a single client by ID."""
    if not user.is_superadmin:
        allowed = client_id in db.get_user_client_ids(user.id)
        if not allowed:
            raise HTTPException(status_code=403, detail="Access denied to this client")
    client = db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@router.put("/{client_id}", response_class=JSONResponse)
def update_client(client_id: str, data: ClientUpdate, db: DbDep, user: RequireUser):
    """Update a client. Super-admins or the tenant's own ADMIN may edit it."""
    if not user.is_superadmin and not user.is_admin(client_id=client_id):
        raise HTTPException(status_code=403, detail="Admin access for this client required")
    client = db.update_client(client_id, name=data.name, description=data.description)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@router.delete("/{client_id}", response_class=JSONResponse)
def delete_client(client_id: str, db: DbDep, user: RequireSuperadmin):
    """Delete a client (super-admin only). Cannot delete the default client."""
    existing = db.get_client(client_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Client not found")
    if existing.get("is_default"):
        raise HTTPException(status_code=400, detail="Cannot delete the default client")
    ok = db.delete_client(client_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Delete failed")
    logger.info(f"Client deleted: {client_id} by {user.username}")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Switch active client
# ---------------------------------------------------------------------------

@router.post("/switch", response_class=JSONResponse)
def switch_client(
    request: Request,
    db: DbDep,
    user: RequireUser,
    client_id: str = Form(...),
):
    """Switch the user's active client. Sets a cookie and returns client info."""
    # Validate access — super-admins can hop between any client; everyone else
    # must be a member of the target tenant.
    if not user.is_superadmin:
        if client_id not in db.get_user_client_ids(user.id):
            raise HTTPException(status_code=403, detail="Access denied to this client")

    client = db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    response = JSONResponse({"client_id": client_id, "client_name": client["name"]})
    response.set_cookie(
        key="active_client_id",
        value=client_id,
        httponly=True,
        samesite="lax",
        max_age=86400 * 365,  # 1 year
    )
    logger.info(f"User {user.username} switched to client {client['name']}")
    return response


# ---------------------------------------------------------------------------
# User-client assignments (admin only)
# ---------------------------------------------------------------------------

@router.get("/{client_id}/users", response_class=JSONResponse)
def get_client_users(client_id: str, db: DbDep, user: RequireAdmin):
    """List users assigned to a client."""
    return db.get_client_users(client_id)


@router.post("/{client_id}/users", response_class=JSONResponse)
def assign_user(client_id: str, data: UserClientAssignment, db: DbDep, user: RequireAdmin):
    """Assign a user to a client."""
    db.assign_user_to_client(data.user_id, client_id, is_default=data.is_default)
    logger.info(f"User {data.user_id} assigned to client {client_id} by {user.username}")
    return {"ok": True}


@router.delete("/{client_id}/users/{user_id}", response_class=JSONResponse)
def remove_user(client_id: str, user_id: str, db: DbDep, user: RequireAdmin):
    """Remove a user from a client."""
    db.remove_user_from_client(user_id, client_id)
    logger.info(f"User {user_id} removed from client {client_id} by {user.username}")
    return {"ok": True}


# ---------------------------------------------------------------------------
# SIEM configs per client (admin only)
# ---------------------------------------------------------------------------

@router.get("/{client_id}/siem", response_class=JSONResponse)
def list_siem_configs(client_id: str, db: DbDep, user: RequireAdmin):
    """List SIEM configurations for a client."""
    return db.list_siem_configs(client_id)


@router.post("/{client_id}/siem", response_class=JSONResponse, status_code=201)
def create_siem_config(client_id: str, data: SIEMConfigCreate, db: DbDep, user: RequireAdmin):
    """Create a SIEM config for a client."""
    config = db.create_siem_config(
        client_id=client_id,
        siem_type=data.siem_type,
        label=data.label,
        base_url=data.base_url,
        space_list=data.space_list,
        extra_config=data.extra_config,
    )
    logger.info(f"SIEM config created for client {client_id}: {data.label} by {user.username}")
    return config


@router.put("/{client_id}/siem/{config_id}", response_class=JSONResponse)
def update_siem_config(
    client_id: str, config_id: str,
    data: SIEMConfigUpdate, db: DbDep, user: RequireAdmin,
):
    """Update a SIEM config."""
    config = db.update_siem_config(
        config_id=config_id,
        label=data.label,
        base_url=data.base_url,
        space_list=data.space_list,
        extra_config=data.extra_config,
        is_active=data.is_active,
    )
    if not config:
        raise HTTPException(status_code=404, detail="SIEM config not found")
    return config


@router.delete("/{client_id}/siem/{config_id}", response_class=JSONResponse)
def delete_siem_config(client_id: str, config_id: str, db: DbDep, user: RequireAdmin):
    """Delete a SIEM config."""
    ok = db.delete_siem_config(config_id)
    if not ok:
        raise HTTPException(status_code=404, detail="SIEM config not found")
    return {"ok": True}
