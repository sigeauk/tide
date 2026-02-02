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
    settings: Settings = Depends(get_settings),
    auth_service: AuthService = Depends(get_auth),
) -> Optional[User]:
    """
    Dependency: Get current authenticated user.
    
    Checks for JWT in:
    1. Authorization header (Bearer token)
    2. access_token cookie
    
    Returns None if auth is disabled or no valid token found.
    """
    # Dev mode bypass
    if settings.auth_disabled:
        return auth_service.get_dev_user()
    
    # Try Authorization header first
    token = None
    if credentials:
        token = credentials.credentials
    
    # Fall back to cookie
    if not token and access_token:
        token = access_token
    
    if not token:
        return None
    
    # Validate token and get user
    user = auth_service.get_user_from_token(token)
    return user


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


# Type aliases for cleaner route signatures
DbDep = Annotated[DatabaseService, Depends(get_db)]
AuthDep = Annotated[AuthService, Depends(get_auth)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
CurrentUser = Annotated[Optional[User], Depends(get_current_user)]
RequireUser = Annotated[User, Depends(require_auth)]
RequireAdmin = Annotated[User, Depends(require_admin)]
