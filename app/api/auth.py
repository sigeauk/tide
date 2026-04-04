"""
API routes for Authentication (Keycloak OIDC + Local DB).
"""

from fastapi import APIRouter, Request, Response, Query, Form
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


@router.post("/local-login", name="auth_local_login")
async def local_login(
    request: Request,
    auth: AuthDep,
    settings: SettingsDep,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
):
    """
    Authenticate with local username/password against the DB.
    Sets a signed session cookie on success.
    """
    result = auth.authenticate_local(username, password)
    if not result:
        # Return login page with error
        return HTMLResponse(
            content='<div class="login-error" id="login-error">'
                    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
                    '<circle cx="12" cy="12" r="10"/><line x1="15" x2="9" y1="9" y2="15"/>'
                    '<line x1="9" x2="15" y1="9" y2="15"/></svg>'
                    ' Invalid username or password</div>',
            status_code=200,
        )
    
    user = result
    # Create session token and set cookie
    session_token = auth.create_session_token(user.id)
    
    response = HTMLResponse(content="", status_code=200)
    response.headers["HX-Redirect"] = next
    
    use_secure = settings.app_url.startswith("https://")
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=use_secure,
        samesite="lax",
        max_age=86400,  # 24 hours
    )
    
    return response


@router.get("/callback", name="auth_callback")
async def auth_callback(
    request: Request,
    auth: AuthDep,
    settings: SettingsDep,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query("/"),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
):
    """
    Handle Keycloak callback after authentication.
    """
    logger.info(f"Auth callback received - code={'present' if code else 'missing'}, state={state}, error={error}")
    
    if error:
        logger.error(f"Auth callback error: {error} - {error_description}")
        return HTMLResponse(f"<h1>Authentication Error</h1><p>{error}: {error_description}</p>", status_code=400)
    
    if not code:
        logger.error("Auth callback missing authorization code")
        return HTMLResponse("<h1>Missing authorization code</h1>", status_code=400)
    
    # Exchange code for tokens - must use same redirect_uri as login
    redirect_uri = f"{settings.app_url}/auth/callback"
    logger.info(f"Exchanging code with redirect_uri: {redirect_uri}")
    
    tokens = await auth.exchange_code(code, redirect_uri)
    
    if not tokens:
        return HTMLResponse("<h1>Failed to exchange authorization code</h1>", status_code=400)
    
    # Set tokens in cookies
    response = RedirectResponse(url=state or "/", status_code=302)
    
    # Only set secure=True if using HTTPS (check APP_URL scheme)
    use_secure = settings.app_url.startswith("https://")
    
    logger.info(f"Setting auth cookies - secure={use_secure}, samesite=lax")
    
    response.set_cookie(
        key="access_token",
        value=tokens["access_token"],
        httponly=True,
        secure=use_secure,
        samesite="lax",
        max_age=tokens.get("expires_in", 3600),
    )
    
    if "refresh_token" in tokens:
        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh_token"],
            httponly=True,
            secure=use_secure,
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
    Logout - clear all auth cookies.
    If user had a Keycloak session, redirect through Keycloak logout.
    If local-only, redirect straight to login page.
    """
    use_secure = settings.app_url.startswith("https://")
    had_keycloak = request.cookies.get("access_token") is not None
    
    if had_keycloak:
        post_logout_uri = f"{settings.app_url}/login?logout=1"
        keycloak_logout_url = auth.get_logout_url(post_logout_uri)
        response = RedirectResponse(url=keycloak_logout_url, status_code=302)
    else:
        response = RedirectResponse(url="/login?logout=1", status_code=302)
    
    for cookie_name in ("access_token", "refresh_token", "session_token"):
        response.delete_cookie(
            key=cookie_name,
            path="/",
            httponly=True,
            secure=use_secure,
            samesite="lax",
        )
    
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
