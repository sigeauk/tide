"""
API routes for Authentication (Keycloak OIDC).
"""

from fastapi import APIRouter, Request, Response, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from typing import Optional

from app.api.deps import AuthDep, SettingsDep, CurrentUser
from app.config import get_settings

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/login", name="auth_login")
async def login(
    request: Request,
    auth: AuthDep,
    settings: SettingsDep,
    next: Optional[str] = Query("/"),
):
    """
    Redirect to Keycloak login page.
    """
    logger.info(f"Auth login called - auth_disabled={settings.auth_disabled}")
    
    if settings.auth_disabled:
        logger.info(f"Auth disabled, redirecting to {next}")
        return RedirectResponse(url=next, status_code=302)
    
    # Build redirect URI using the external APP_URL
    redirect_uri = f"{settings.app_url}/auth/callback"
    login_url = auth.get_login_url(redirect_uri, state=next)
    
    logger.info(f"Redirecting to Keycloak: {login_url}")
    return RedirectResponse(url=login_url, status_code=302)


@router.get("/callback", name="auth_callback")
async def auth_callback(
    request: Request,
    auth: AuthDep,
    settings: SettingsDep,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query("/"),
    error: Optional[str] = Query(None),
):
    """
    Handle Keycloak callback after authentication.
    """
    if error:
        logger.error(f"Auth callback error: {error}")
        return HTMLResponse(f"<h1>Authentication Error</h1><p>{error}</p>", status_code=400)
    
    if not code:
        return HTMLResponse("<h1>Missing authorization code</h1>", status_code=400)
    
    # Exchange code for tokens - must use same redirect_uri as login
    redirect_uri = f"{settings.app_url}/auth/callback"
    tokens = await auth.exchange_code(code, redirect_uri)
    
    if not tokens:
        return HTMLResponse("<h1>Failed to exchange authorization code</h1>", status_code=400)
    
    # Set tokens in cookies
    response = RedirectResponse(url=state or "/", status_code=302)
    
    response.set_cookie(
        key="access_token",
        value=tokens["access_token"],
        httponly=True,
        secure=not settings.debug,
        samesite="lax",
        max_age=tokens.get("expires_in", 3600),
    )
    
    if "refresh_token" in tokens:
        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh_token"],
            httponly=True,
            secure=not settings.debug,
            samesite="lax",
            max_age=tokens.get("refresh_expires_in", 86400),
        )
    
    return response


@router.get("/logout", name="auth_logout")
async def logout(
    request: Request,
    auth: AuthDep,
    settings: SettingsDep,
):
    """
    Logout - clear cookies and redirect to login page.
    """
    # Clear cookies and redirect to login
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    
    return response


@router.get("/me", response_class=HTMLResponse)
async def get_current_user_info(
    request: Request,
    user: CurrentUser,
):
    """
    Get current user info (for debugging).
    """
    if not user:
        return HTMLResponse("<p>Not authenticated</p>")
    
    return HTMLResponse(f"""
    <div>
        <p><strong>Username:</strong> {user.username}</p>
        <p><strong>Email:</strong> {user.email or 'N/A'}</p>
        <p><strong>Name:</strong> {user.name or 'N/A'}</p>
        <p><strong>Roles:</strong> {', '.join(user.roles)}</p>
    </div>
    """)
