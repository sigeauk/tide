"""
API routes for Authentication (Keycloak OIDC + Local DB).
"""

from fastapi import APIRouter, Request, Response, Query, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from html import escape
from itsdangerous import BadSignature, URLSafeTimedSerializer
from typing import Optional
from urllib.parse import urlencode, urlsplit
import secrets

from app.services.icons import icon as _icon
from app.api.deps import AuthDep, SettingsDep, CurrentUser, DbDep
from app.config import get_settings

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# The single sign-on a browser started (#100): a random state sent to Keycloak, kept with the page to
# return to in a signed cookie only /auth/* sees. The callback signs in only when Keycloak brings that
# state back, so another site can't sign someone in to an account of its choosing (login CSRF).
STATE_COOKIE = "tide_sso_state"
STATE_MAX_AGE = 600


def _state_signer(settings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_secret, salt="tide-sso-state")


def _started_sign_in(settings, cookie: Optional[str]) -> Optional[dict]:
    """The sign-in this browser started (``{state, next}``), or None: no cookie, a forged one, or older
    than STATE_MAX_AGE."""
    if not cookie:
        return None
    try:
        saved = _state_signer(settings).loads(cookie, max_age=STATE_MAX_AGE)
    except BadSignature:   # a bad signature or an expired one
        return None
    return saved if isinstance(saved, dict) and saved.get("state") else None


def _same_origin(request: Request, settings) -> bool:
    """Whether a POST comes from TIDE's own pages. Browsers send Origin with every POST, so one from
    another site is refused; none at all is not a browser's cross-site request. Hosts are compared
    without the port, as nginx passes the host on without it."""
    origin = request.headers.get("origin")
    if not origin:
        return True
    host = (urlsplit(origin).hostname or "").lower()
    ours = {(request.headers.get("host") or "").split(":")[0].lower(), (urlsplit(settings.app_url).hostname or "").lower()}
    return bool(host) and host in ours


def _sign_in_failed(why: str) -> HTMLResponse:
    response = HTMLResponse(f"<h1>Could not sign in</h1><p>{escape(why)}</p><p><a href=\"/login\">Sign in again</a></p>",
                            status_code=400)
    response.delete_cookie(STATE_COOKIE, path="/auth")
    return response


def local_path(target: Optional[str]) -> str:
    """Where to send someone after signing in: a path on TIDE itself, else the home page. ``next``
    and the OIDC ``state`` arrive in the URL, so anything else would let a link send a person who
    has just signed in to another site."""
    t = target or ""
    if (not t.startswith("/") or t.startswith("//") or "\\" in t
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in t)):
        return "/"
    return t


@router.get("/login", name="auth_login")
async def login(
    request: Request,
    auth: AuthDep,
    settings: SettingsDep,
    next: Optional[str] = Query("/"),
    moved: bool = Query(False),
):
    """
    Redirect to Keycloak login page.
    """
    logger.info(f"Auth login called - auth_disabled={settings.auth_disabled}")
    next = local_path(next)

    if settings.auth_disabled:
        logger.info(f"Auth disabled, redirecting to {next}")
        return RedirectResponse(url=next, status_code=302)

    # Keycloak sends the browser back to APP_URL, and the state cookie belongs to the host it is set
    # on, so a sign-in must start at APP_URL too. Opened under another name (an IP address, an alias),
    # go to APP_URL's /auth/login first. Only once (``moved``): a proxy that renames the host can't
    # make it loop. Hosts are compared without the port, as nginx passes the host on without it.
    app_host = (urlsplit(settings.app_url).hostname or "").lower()
    here = (urlsplit("//" + (request.headers.get("host") or "")).hostname or "").lower()
    if app_host and here and here != app_host and not moved:
        logger.info("Sign-in opened at %s: starting it at APP_URL (%s) instead", here, app_host)
        return RedirectResponse(url=f"{settings.app_url.rstrip('/')}/auth/login?{urlencode({'next': next, 'moved': 1})}",
                                status_code=302)

    # Build redirect URI using the external APP_URL
    redirect_uri = f"{settings.app_url}/auth/callback"
    state = secrets.token_urlsafe(24)
    login_url = auth.get_login_url(redirect_uri, state=state)

    logger.info("Redirecting to Keycloak to sign in")
    response = RedirectResponse(url=login_url, status_code=302)
    response.set_cookie(STATE_COOKIE, _state_signer(settings).dumps({"state": state, "next": next}),
                        max_age=STATE_MAX_AGE, path="/auth", httponly=True,
                        secure=settings.app_url.startswith("https://"), samesite="lax")
    return response


@router.post("/local-login", name="auth_local_login")
async def local_login(
    request: Request,
    auth: AuthDep,
    settings: SettingsDep,
    db: DbDep,
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
            content='<div class="login-error" id="login-error">' + _icon("circle-x", "16")
                    + ' Invalid username or password</div>',
            status_code=200,
        )
    
    user = result
    # 4.1.0 P1: structured login audit (success path).
    try:
        from app.services.log_context import audit_log
        audit_log(
            "login_success",
            user_id=str(user.id),
            username=user.username,
            method="local",
        )
    except Exception:
        pass
    # Create session token and set cookie
    session_token = auth.create_session_token(user.id)
    
    response = HTMLResponse(content="", status_code=200)
    response.headers["HX-Redirect"] = local_path(next)   # htmx follows it with location.href
    
    use_secure = settings.app_url.startswith("https://")
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=use_secure,
        samesite="lax",
        max_age=86400,  # 24 hours
    )

    # Set active_client_id cookie so the user lands on their assigned tenant.
    # Priority: user's is_default client → first assigned client → system default.
    _cid = None
    try:
        with db.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                [user.id],
            ).fetchone()
            if row:
                _cid = row[0]
            else:
                row = conn.execute(
                    "SELECT client_id FROM user_clients WHERE user_id = ? LIMIT 1",
                    [user.id],
                ).fetchone()
                if row:
                    _cid = row[0]
        if _cid:
            response.set_cookie(
                key="active_client_id",
                value=_cid,
                httponly=True,
                secure=use_secure,
                samesite="lax",
                max_age=86400,
            )
    except Exception as e:
        logger.warning(f"Could not resolve default client for user {user.id}: {e}")

    # Clear Keycloak cookies to prevent stale SSO tokens from shadowing local sessions.
    response.delete_cookie(
        key="access_token",
        path="/",
        httponly=True,
        secure=use_secure,
        samesite="lax",
    )
    response.delete_cookie(
        key="refresh_token",
        path="/",
        httponly=True,
        secure=use_secure,
        samesite="lax",
    )
    
    return response


@router.get("/callback", name="auth_callback")
async def auth_callback(
    request: Request,
    auth: AuthDep,
    settings: SettingsDep,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
):
    """
    Handle Keycloak callback after authentication: only for the sign-in this browser started (its
    state, from STATE_COOKIE), checked before the code is used.
    """
    logger.info(f"Auth callback received - code={'present' if code else 'missing'}, error={error}")

    if error:
        logger.error(f"Auth callback error: {error} - {error_description}")
        # Both come from the URL, so they're shown as text: a link could otherwise run a script on TIDE.
        response = HTMLResponse(f"<h1>Authentication Error</h1><p>{escape(error)}: {escape(error_description or '')}</p>",
                                status_code=400)
        response.delete_cookie(STATE_COOKIE, path="/auth")
        return response

    if not code:
        logger.error("Auth callback missing authorization code")
        return HTMLResponse("<h1>Missing authorization code</h1>", status_code=400)

    started = _started_sign_in(settings, request.cookies.get(STATE_COOKIE))
    if not started or not state or not secrets.compare_digest(str(started["state"]), state):
        logger.warning("Auth callback refused: it isn't the sign-in this browser started")
        return _sign_in_failed("This sign-in wasn't started in this browser, or took more than 10 minutes.")

    # Exchange code for tokens - must use same redirect_uri as login
    redirect_uri = f"{settings.app_url}/auth/callback"
    logger.info(f"Exchanging code with redirect_uri: {redirect_uri}")
    
    tokens = await auth.exchange_code(code, redirect_uri)
    
    if not tokens:
        return HTMLResponse("<h1>Could not complete sign-in. Go back and sign in again.</h1>", status_code=400)

    # The one place an SSO sign-in is recorded (provisions a first-time user, sets last_login);
    # later requests with the cookie only read the user.
    auth.get_user_from_token(tokens["access_token"], login=True)

    # Set tokens in cookies
    response = RedirectResponse(url=local_path(started.get("next")), status_code=302)
    response.delete_cookie(STATE_COOKIE, path="/auth")
    
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


@router.get("/logout", response_class=HTMLResponse, name="auth_logout")
async def logout_page(request: Request, user: CurrentUser):
    """Sign out asks first (#100): a GET (a link, or another site's image or page) never signs anyone
    out. The page's Log Out button POSTs, as the sidebar's does."""
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return request.app.state.render_template("pages/auth/logout.html", request, {"user": user})


@router.post("/logout", name="auth_logout_post")
async def logout(
    request: Request,
    auth: AuthDep,
    settings: SettingsDep,
):
    """
    Logout - clear all auth cookies.
    If user had a Keycloak session, redirect through Keycloak logout.
    If local-only, redirect straight to login page.
    Only from TIDE's own pages: another site's POST signs no one out (_same_origin).
    """
    if not _same_origin(request, settings):
        logger.warning("Sign-out refused: the request came from another site (Origin %s)", request.headers.get("origin"))
        return RedirectResponse(url="/", status_code=303)
    use_secure = settings.app_url.startswith("https://")
    had_keycloak = request.cookies.get("access_token") is not None

    # End this user's local sessions, not just this browser's cookie: a copy of the cookie would
    # otherwise keep working until it expired (#30).
    signed_out = auth.session_user_id(request.cookies.get("session_token") or "")
    if signed_out:
        try:
            from app.services.database import get_database_service
            get_database_service().end_user_sessions(signed_out)
        except Exception as exc:  # pragma: no cover - signing out must never fail
            logger.warning(f"Could not end the sessions of {signed_out} at sign-out: {exc}")
    
    if had_keycloak:
        post_logout_uri = f"{settings.app_url}/login?logout=1"
        keycloak_logout_url = auth.get_logout_url(post_logout_uri)
        response = RedirectResponse(url=keycloak_logout_url, status_code=303)
    else:
        response = RedirectResponse(url="/login?logout=1", status_code=303)
    
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
    
    # Names and emails come from Keycloak or a form: shown as text.
    return HTMLResponse(f"""
    <div>
        <p><strong>Username:</strong> {escape(user.username or '')}</p>
        <p><strong>Email:</strong> {escape(user.email or 'N/A')}</p>
        <p><strong>Name:</strong> {escape(user.name or 'N/A')}</p>
        <p><strong>Roles:</strong> {escape(', '.join(user.roles))}</p>
    </div>
    """)
