"""
FastAPI dependency injection for TIDE.
Provides database, authentication, and other dependencies.
"""

from typing import Optional, Annotated
from fastapi import Depends, HTTPException, Request, status, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.config import Settings, get_settings
from app.services.database import DatabaseService, get_database_service
from app.services.auth import AuthService, get_auth_service
from app.services.tenant_manager import (
    resolve_tenant_db_path, set_tenant_context, clear_tenant_context,
)
from app.models.auth import User

import logging

logger = logging.getLogger(__name__)

# Security scheme for Bearer tokens
bearer_scheme = HTTPBearer(auto_error=False)


async def get_db() -> DatabaseService:
    """Dependency: Get database service."""
    return get_database_service()


async def get_auth() -> AuthService:
    """Dependency: Get auth service."""
    return get_auth_service()


async def get_current_user(
    request: Request,
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(bearer_scheme)] = None,
    access_token: Annotated[Optional[str], Cookie()] = None,
    session_token: Annotated[Optional[str], Cookie()] = None,
    settings: Settings = Depends(get_settings),
    auth_service: AuthService = Depends(get_auth),
) -> Optional[User]:
    """
    Dependency: Get current authenticated user.
    
    Checks for JWT/session in:
    1. Authorization header (Bearer token) — Keycloak JWT
    2. access_token cookie — Keycloak JWT
    3. session_token cookie — Local auth signed session
    
    Returns None if auth is disabled or no valid token found.
    """
    # Dev mode bypass
    if settings.auth_disabled:
        return auth_service.get_dev_user()
    
    # Try Authorization header first (Keycloak JWT)
    token = None
    if credentials:
        token = credentials.credentials
    
    # Fall back to Keycloak cookie
    if not token and access_token:
        token = access_token
    
    # Validate Keycloak JWT
    if token:
        user = auth_service.get_user_from_token(token)
        if user:
            return user
    
    # Fall back to local session cookie
    if session_token:
        user = auth_service.get_user_from_session(session_token)
        if user:
            return user
    
    return None


async def require_auth(
    user: Annotated[Optional[User], Depends(get_current_user)]
) -> User:
    """
    Dependency: Require authenticated user.
    Raises 401 if not authenticated.
    """
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def require_admin(
    user: Annotated[User, Depends(require_auth)]
) -> User:
    """
    Dependency: Require admin role.
    Raises 403 if not admin.
    """
    if not user.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


async def require_superadmin(
    user: Annotated[User, Depends(require_auth)]
) -> User:
    """Dependency: Require platform-wide super-admin (Keycloak `superadmin` group).

    A tenant ADMIN can manage their own client through the management panel,
    but operations that affect the *global* client list (create / delete) are
    restricted to super-admins.
    """
    if not user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super-admin access required",
        )
    return user


def require_role(role_name: str):
    """Factory: Create a dependency that requires a specific role."""
    async def _check(user: Annotated[User, Depends(require_auth)]) -> User:
        if not user.has_role(role_name):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role_name}' required",
            )
        return user
    return _check


def require_read(resource: str):
    """Factory: Create a dependency that requires read permission on a resource."""
    async def _check(user: Annotated[User, Depends(require_auth)]) -> User:
        if not user.can_read(resource):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Read access to '{resource}' required",
            )
        return user
    return _check


def require_write(resource: str):
    """Factory: Create a dependency that requires write permission on a resource."""
    async def _check(user: Annotated[User, Depends(require_auth)]) -> User:
        if not user.can_write(resource):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Write access to '{resource}' required",
            )
        return user
    return _check


# Type aliases for cleaner route signatures
DbDep = Annotated[DatabaseService, Depends(get_db)]
AuthDep = Annotated[AuthService, Depends(get_auth)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
CurrentUser = Annotated[Optional[User], Depends(get_current_user)]
RequireUser = Annotated[User, Depends(require_auth)]
RequireAdmin = Annotated[User, Depends(require_admin)]
RequireSuperadmin = Annotated[User, Depends(require_superadmin)]


async def get_active_client(
    request: Request,
    user: CurrentUser,
    db: Annotated[DatabaseService, Depends(get_db)],
) -> str:
    """
    Dependency: Resolve the active client (tenant) for this request.

    Resolution order:
    1. X-Client-ID request header (API consumers)
    2. active_client_id session cookie
    3. User's default client from user_clients table
    4. System default client (fallback for dev mode / auth-disabled)
    5. 400 if unresolvable

    Validates the user has access to the resolved client.
    Admins may access any client.
    """
    client_id: Optional[str] = None

    # 1. Explicit header
    header_val = request.headers.get("X-Client-ID")
    if header_val:
        client_id = header_val

    # 2. Cookie fallback
    if not client_id:
        client_id = request.cookies.get("active_client_id")

    # 3. Default client for user (when authenticated)
    if not client_id and user:
        with db.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                [user.id],
            ).fetchone()
            if row:
                client_id = row[0]

    # 4. System default client (dev mode / auth disabled)
    if not client_id:
        with db.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT id FROM clients WHERE is_default = true LIMIT 1",
            ).fetchone()
            if row:
                client_id = row[0]

    if not client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active client selected. Set X-Client-ID header or switch client.",
        )

    # Validate access:
    # - Superadmin (Keycloak `superadmin` group) bypasses everything.
    # - Otherwise the user must be a member of the resolved client. Per-tenant
    #   ADMIN no longer implies access to other tenants.
    if user and not user.is_superadmin:
        with db.get_shared_connection() as conn:
            allowed = conn.execute(
                "SELECT 1 FROM user_clients WHERE user_id = ? AND client_id = ?",
                [user.id, client_id],
            ).fetchone()
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You do not have access to this client.",
                )

    # Verify client exists
    with db.get_shared_connection() as conn:
        exists = conn.execute("SELECT 1 FROM clients WHERE id = ?", [client_id]).fetchone()
    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found.",
        )

    # Stash on request state for downstream use
    request.state.client_id = client_id

    # Set tenant DB context as early as possible so any DB calls made during
    # roles/permissions refresh below use the correct tenant connection.
    settings = get_settings()
    tenant_path = resolve_tenant_db_path(client_id, settings.data_dir)
    if tenant_path:
        set_tenant_context(tenant_path)

    # 4.1.0 P1: enrich the structured logging contextvar so every subsequent
    # log line for this request carries the resolved tenant + user. The
    # middleware seeded the dict with placeholders; we mutate it in-place so
    # the contextvar token reset still works.
    try:
        from app.services.log_context import set_context_fields
        set_context_fields(
            client_id=client_id,
            user_id=str(user.id) if user is not None else "-",
        )
    except Exception:  # pragma: no cover - logging must never break a request
        pass

    # Refresh the user's role list to reflect THIS tenant only. After this point
    # `user.roles` and `user.is_admin()` reason about the active tenant — the
    # full per-tenant map is preserved on `user.client_roles`.
    if user is not None:
        user.active_client_id = client_id
        if user.is_superadmin:
            user.roles = ["ADMIN"]
        else:
            user.roles = list(user.client_roles.get(client_id, []))
        # Refresh the permissions map so sidebar / page gating reflects the
        # roles held in the active tenant only. Superadmins keep an empty map
        # because their bypass lives in `can_read` / `can_write`.
        try:
            if user.is_superadmin:
                user.permissions = {}
            else:
                user.permissions = db.get_user_permissions(user.id, client_id=client_id)
        except Exception:  # pragma: no cover - permissions optional
            user.permissions = {}

    return client_id


# Active tenant type alias
ActiveClient = Annotated[str, Depends(get_active_client)]
