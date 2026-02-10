"""
TIDE - Threat Intelligence Detection Engineering

FastAPI Application Entry Point.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, BackgroundTasks, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import logging
import os
import time

from app.config import get_settings
from app.api.deps import get_db, get_current_user, CurrentUser, RequireUser, DbDep
from app.api import auth, rules, heatmap, threats, promotion, sigma, settings as settings_api

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# Background task scheduler
scheduler = AsyncIOScheduler()


async def scheduled_sync():
    """Background task: Sync detection rules from Elastic every 60 minutes."""
    settings = get_settings()
    logger.info(f"⏰ Scheduled sync triggered (interval: {settings.sync_interval_minutes}m)")
    
    # Import here to avoid circular imports
    from app.services.database import get_database_service
    from app.services.sync import trigger_sync
    
    db = get_database_service()
    
    # Check for manual trigger
    if db.check_and_clear_trigger("sync_elastic"):
        logger.info("🔄 Manual sync trigger detected")
    
    # Run the actual sync
    await trigger_sync()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    import asyncio
    settings = get_settings()
    
    # Startup
    logger.info(f"🌊 Starting TIDE v{settings.tide_version}")
    
    # Initialize database
    from app.services.database import get_database_service
    db = get_database_service()
    logger.info("🦆 Database initialized")
    
    # Pre-load Sigma rules cache to avoid slow first page load
    # This takes ~6 seconds but happens during startup, not during user request
    try:
        from app import sigma_helper
        rules_count = len(sigma_helper.load_all_rules())
        logger.info(f"📜 Sigma rules pre-loaded: {rules_count} rules cached")
    except Exception as e:
        logger.warning(f"⚠️ Failed to pre-load Sigma rules: {e}")
    
    # Run initial sync on startup (in background to not block startup)
    asyncio.create_task(scheduled_sync())
    
    # Start background scheduler
    scheduler.add_job(
        scheduled_sync,
        "interval",
        minutes=settings.sync_interval_minutes,
        id="elastic_sync",
        replace_existing=True,
    )
    
    # Schedule rule log export job
    _schedule_rule_log_job(db)
    
    scheduler.start()
    logger.info(f"⏰ Scheduler started (sync every {settings.sync_interval_minutes}m)")
    
    yield
    
    # Shutdown
    scheduler.shutdown()
    logger.info("🛑 TIDE shutdown complete")


def _schedule_rule_log_job(db=None):
    """Schedule or reschedule the daily rule log export based on app_settings."""
    try:
        if db is None:
            from app.services.database import get_database_service
            db = get_database_service()
        
        app_settings = db.get_all_settings()
        enabled = app_settings.get("rule_log_enabled", "false").lower() == "true"
        schedule_time = app_settings.get("rule_log_schedule", "00:00")
        
        # Remove existing job if present
        try:
            scheduler.remove_job("rule_log_export")
        except Exception:
            pass
        
        if enabled:
            parts = schedule_time.split(":")
            hour = int(parts[0]) if len(parts) > 0 else 0
            minute = int(parts[1]) if len(parts) > 1 else 0
            
            scheduler.add_job(
                _run_rule_log_export,
                "cron",
                hour=hour,
                minute=minute,
                id="rule_log_export",
                replace_existing=True,
            )
            logger.info(f"📝 Rule log export scheduled at {schedule_time}")
        else:
            logger.info("📝 Rule log export disabled")
    except Exception as e:
        logger.warning(f"Could not schedule rule log job: {e}")


def _run_rule_log_export():
    """Synchronous wrapper for rule log export (called by scheduler)."""
    try:
        from app.services.database import get_database_service
        from app.services.rule_logger import run_rule_log_export
        db = get_database_service()
        run_rule_log_export(db)
    except Exception as e:
        logger.error(f"Rule log export failed: {e}")


def reschedule_rule_log_job():
    """Public function to reschedule rule log job (called from settings API)."""
    _schedule_rule_log_job()


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce authentication on protected routes.
    Redirects to /login if not authenticated.
    Also adds cache-control headers for HTML pages.
    
    For HTMX requests:
    - Uses HX-Trigger to signal auth state changes
    - Avoids full page redirects that break partial swaps
    """
    
    # Routes that don't require authentication
    PUBLIC_PATHS = {
        "/health",
        "/login",
        "/logout",
        "/auth/login",
        "/auth/callback",
        "/auth/logout",
        "/auth/refresh",
        "/static",
        "/api/docs",
        "/api/redoc",
        "/openapi.json",
    }
    
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        path = request.url.path
        is_htmx = request.headers.get("HX-Request") == "true"
        
        # Helper to add cache headers for HTML responses
        async def add_cache_headers(response):
            content_type = response.headers.get("content-type", "")
            if "text/html" in content_type and not path.startswith("/static"):
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
            return response
        
        # Skip auth check if disabled (but still add cache headers)
        if settings.auth_disabled:
            response = await call_next(request)
            return await add_cache_headers(response)
        
        # Check if path is public
        if any(path.startswith(p) for p in self.PUBLIC_PATHS):
            response = await call_next(request)
            return await add_cache_headers(response)
        
        # Check for access token in cookie
        access_token = request.cookies.get("access_token")
        refresh_token = request.cookies.get("refresh_token")
        
        # Build login URL for redirects
        return_url = str(request.url.path)
        if request.url.query:
            return_url += f"?{request.url.query}"
        login_url = f"/login?next={return_url}"
        
        if not access_token:
            # No access_token cookie — try refresh before redirecting to login
            if refresh_token:
                logger.info(f"No access token but refresh token exists for path: {path}, attempting refresh...")
                from app.services.auth import get_auth_service
                auth_service = get_auth_service()
                new_tokens = await auth_service.refresh_token(refresh_token)
                if new_tokens:
                    new_access_token = new_tokens.get("access_token")
                    user = auth_service.get_user_from_token(new_access_token)
                    if user:
                        logger.info(f"Silent refresh successful for {user.username}, continuing to {path}")
                        response = await call_next(request)
                        response = await add_cache_headers(response)
                        use_secure = settings.app_url.startswith("https://")
                        response.set_cookie(
                            key="access_token",
                            value=new_tokens["access_token"],
                            httponly=True,
                            secure=use_secure,
                            samesite="lax",
                            max_age=new_tokens.get("expires_in", 3600),
                        )
                        if "refresh_token" in new_tokens:
                            response.set_cookie(
                                key="refresh_token",
                                value=new_tokens["refresh_token"],
                                httponly=True,
                                secure=use_secure,
                                samesite="lax",
                                max_age=new_tokens.get("refresh_expires_in", 86400),
                            )
                        return response
                    else:
                        logger.warning("Refresh succeeded but new token failed validation")
                else:
                    logger.warning(f"Refresh token also failed for path: {path}")
            
            # No token and no valid refresh - redirect to login
            logger.info(f"No valid tokens for path: {path}, redirecting to login (is_htmx={is_htmx})")
            if is_htmx:
                from fastapi.responses import Response
                response = Response(content="", status_code=200)
                response.headers["HX-Redirect"] = login_url
                return response
            
            return RedirectResponse(url=login_url, status_code=302)
        
        # Token exists - validate it
        from app.services.auth import get_auth_service
        auth_service = get_auth_service()
        
        logger.debug(f"Validating token for path: {path}, is_htmx: {is_htmx}")
        user = auth_service.get_user_from_token(access_token)
        
        # If token is invalid/expired, or about to expire soon, try to refresh
        new_tokens = None
        should_refresh = (user is None) or (user and refresh_token and auth_service.token_expires_soon(access_token, 60))
        
        if should_refresh and refresh_token:
            reason = "expired/invalid" if user is None else "expiring soon"
            logger.info(f"Access token {reason} for path: {path}, attempting refresh...")
            new_tokens = await auth_service.refresh_token(refresh_token)
            
            if new_tokens:
                # Validate the new access token
                new_access_token = new_tokens.get("access_token")
                user = auth_service.get_user_from_token(new_access_token)
                if user:
                    logger.info(f"Token refresh successful for user: {user.username}")
                else:
                    logger.warning("Refreshed token also failed validation")
                    new_tokens = None
        
        if user is None:
            logger.warning(f"Token validation FAILED for path: {path}, is_htmx: {is_htmx}, redirecting to login")
            
            # Token invalid - redirect to login
            # Must use same attributes as when setting the cookies for proper deletion
            use_secure = settings.app_url.startswith("https://")
            
            if is_htmx:
                from fastapi.responses import Response
                response = Response(content="", status_code=200)
                # Use HX-Redirect for clean navigation
                response.headers["HX-Redirect"] = login_url
                # Clear invalid cookies with proper attributes
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
            
            response = RedirectResponse(url=login_url, status_code=302)
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
        
        logger.debug(f"Token valid for user: {user.username}, path: {path}")
        
        # Token is valid, proceed
        response = await call_next(request)
        response = await add_cache_headers(response)
        
        # If we refreshed the token, update cookies on the response
        if new_tokens:
            use_secure = settings.app_url.startswith("https://")
            response.set_cookie(
                key="access_token",
                value=new_tokens["access_token"],
                httponly=True,
                secure=use_secure,
                samesite="lax",
                max_age=new_tokens.get("expires_in", 3600),
            )
            if "refresh_token" in new_tokens:
                response.set_cookie(
                    key="refresh_token",
                    value=new_tokens["refresh_token"],
                    httponly=True,
                    secure=use_secure,
                    samesite="lax",
                    max_age=new_tokens.get("refresh_expires_in", 86400),
                )
            logger.info(f"Updated cookies with refreshed tokens for {user.username}")
        
        return response


def create_app() -> FastAPI:
    """Application factory."""
    settings = get_settings()
    
    app = FastAPI(
        title="TIDE",
        description="Threat Intelligence Detection Engineering",
        version=settings.tide_version,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.debug else None,
        redoc_url="/api/redoc" if settings.debug else None,
    )
    
    # Add authentication middleware
    app.add_middleware(AuthMiddleware)
    
    # Exception handler for 401 errors (handle HTMX requests)
    from fastapi import HTTPException as FastAPIHTTPException
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException
    
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 401:
            login_url = f"/login?next={request.url.path}"
            if request.headers.get("HX-Request"):
                response = HTMLResponse(content="", status_code=200)
                response.headers["HX-Redirect"] = login_url
                return response
            return RedirectResponse(url=login_url, status_code=302)
        
        # Default handling for other errors
        return HTMLResponse(
            content=f"<h1>Error {exc.status_code}</h1><p>{exc.detail}</p>",
            status_code=exc.status_code
        )
    
    # Mount static files
    static_path = os.path.join(os.path.dirname(__file__), "static")
    app.mount("/static", StaticFiles(directory=static_path), name="static")
    
    # Setup templates
    templates_path = os.path.join(os.path.dirname(__file__), "templates")
    templates = Jinja2Templates(directory=templates_path)
    app.state.templates = templates
    
    # --- Custom Jinja2 filter for query syntax highlighting ---
    import re
    from markupsafe import Markup, escape
    
    def highlight_query(query: str, language: str = "kuery") -> Markup:
        """Syntax highlight a detection query based on language."""
        if not query:
            return Markup("")
        
        # Escape HTML first
        text = str(escape(query))
        lang = (language or "kuery").lower()
        
        # Define patterns based on language
        if lang in ("esql", "sql"):
            keywords = r'\b(FROM|WHERE|AND|OR|NOT|IN|LIKE|BETWEEN|ORDER|GROUP|BY|HAVING|JOIN|LEFT|RIGHT|INNER|OUTER|ON|AS|DISTINCT|LIMIT|OFFSET|UNION|NULL|IS|TRUE|FALSE|CASE|WHEN|THEN|ELSE|END|STATS|METADATA|ROW|KEEP|EVAL|SORT|RENAME|DISSECT|GROK|ENRICH|MV_EXPAND)\b'
        elif lang == "eql":
            keywords = r'\b(sequence|join|until|maxspan|by|with|where|and|or|not|in|like|regex|true|false|null|any|process|file|registry|network|library|driver|pipe|dns)\b'
        else:  # kuery, lucene
            keywords = r'\b(and|or|not|AND|OR|NOT)\b'
        
        # Apply highlighting
        text = re.sub(keywords, r'<span class="hl-kw">\1</span>', text, flags=re.IGNORECASE)
        
        # Highlight strings
        text = re.sub(r'(&quot;[^&]*&quot;)', r'<span class="hl-str">\1</span>', text)
        text = re.sub(r"('[^']*')", r'<span class="hl-str">\1</span>', text)
        
        # Highlight field names (word.word:)
        text = re.sub(r'([a-zA-Z_][a-zA-Z0-9_\.]*)(\s*:)', r'<span class="hl-field">\1</span><span class="hl-op">\2</span>', text)
        
        return Markup(text)
    
    templates.env.filters["highlight_query"] = highlight_query
    
    # --- Helper function to render templates with global context ---
    def render_template(name: str, request: Request, context: dict = None):
        """Render template with global context variables (brand_hue, cache_bust)."""
        ctx = {
            "request": request,
            "brand_hue": settings.brand_hue,
            "cache_bust": str(int(time.time())),
            "settings": settings,
        }
        if context:
            ctx.update(context)
        return templates.TemplateResponse(name, ctx)
    
    # Include API routers
    app.include_router(auth.router)
    app.include_router(rules.router)
    app.include_router(heatmap.router)
    app.include_router(threats.router)
    app.include_router(promotion.router)
    app.include_router(sigma.router)
    app.include_router(settings_api.router)
    
    # --- HEALTH CHECK ---
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint for container orchestration."""
        return {"status": "healthy", "version": settings.tide_version}
    
    # --- LOGIN PAGE (public) ---
    
    @app.get("/login", response_class=HTMLResponse, name="login_page")
    async def login_page(request: Request, next: str = "/", logout: bool = False):
        """
        Login page - shows login button that redirects to Keycloak.
        This is a public route (no auth required).
        """
        # If auth is disabled, redirect to home
        if settings.auth_disabled:
            return RedirectResponse(url=next, status_code=302)
        
        # If coming from logout, force clear cookies and show login page
        # This handles the race condition where cookies aren't deleted yet
        if logout:
            use_secure = settings.app_url.startswith("https://")
            response = render_template(
                "pages/login.html",
                request,
                {
                    "next": next,
                    "user": None,
                }
            )
            # Ensure cookies are deleted on this response too
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
        
        # Check if user is already logged in with a valid token
        access_token = request.cookies.get("access_token")
        if access_token:
            from app.services.auth import get_auth_service
            auth_service = get_auth_service()
            user = auth_service.get_user_from_token(access_token)
            if user is not None:
                # Valid token, redirect to destination
                return RedirectResponse(url=next, status_code=302)
            # else: token exists but invalid/expired - show login page
        
        return render_template(
            "pages/login.html",
            request,
            {
                "next": next,
                "user": None,
            }
        )
    
    # --- LOGOUT REDIRECT (to clear session properly) ---
    
    @app.get("/logout", response_class=HTMLResponse, name="logout")
    async def logout_redirect(request: Request):
        """Redirect to auth logout endpoint."""
        return RedirectResponse(url="/auth/logout", status_code=302)
    
    # --- PAGE ROUTES ---
    
    @app.get("/", response_class=HTMLResponse, name="home")
    async def home(request: Request, user: CurrentUser):
        """Home page - redirect to dashboard or show landing."""
        return render_template(
            "pages/home.html",
            request,
            {
                "user": user,
                "active_page": "home",
            }
        )
    
    @app.get("/rules", response_class=HTMLResponse, name="rule_health")
    async def rule_health_page(request: Request, user: CurrentUser):
        """Rule Health page."""
        from app.services.database import get_database_service
        db = get_database_service()
        
        metrics = db.get_rule_health_metrics()
        spaces = db.get_unique_spaces()
        
        return render_template(
            "pages/rule_health.html",
            request,
            {
                "user": user,
                "active_page": "rules",
                "metrics": metrics,
                "spaces": spaces,
            }
        )
    
    @app.get("/heatmap", response_class=HTMLResponse, name="heatmap")
    async def heatmap_page(request: Request, user: CurrentUser):
        """Heatmap page."""
        from app.services.database import get_database_service
        from app.models.threats import HeatmapData
        
        db = get_database_service()
        actors = db.get_threat_actors()
        
        # Empty initial data
        empty_data = HeatmapData(
            tactics=[],
            matrix={},
            selected_actors=[],
            total_ttps=0,
            gap_count=0,
            covered_count=0,
            defense_count=0,
            coverage_pct=0,
        )
        
        return render_template(
            "pages/heatmap.html",
            request,
            {
                "user": user,
                "active_page": "heatmap",
                "actors": actors,
                "data": empty_data,
            }
        )
    
    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard_page(request: Request, user: CurrentUser):
        """Dashboard page - Aggregated overview of detection engineering posture."""
        from app.services.database import get_database_service
        db = get_database_service()
        
        # Aggregate metrics from all sources
        rule_metrics = db.get_rule_health_metrics()
        promotion_metrics = db.get_promotion_metrics()
        threat_metrics = db.get_threat_landscape_metrics()
        
        dashboard_data = {
            # Rule Health highlights (RuleHealthMetrics is a Pydantic model)
            "total_rules": rule_metrics.total_rules,
            "avg_quality_score": rule_metrics.avg_score,
            "low_quality_count": rule_metrics.low_quality_count,
            # Promotion highlights (dict)
            "staging_rules": promotion_metrics.get("staging_total", 0),
            "production_rules": promotion_metrics.get("production_total", 0),
            # Threat highlights (ThreatLandscapeMetrics is a Pydantic model)
            "threat_actors": threat_metrics.total_actors,
            "total_ttps": threat_metrics.unique_ttps,
            "coverage_pct": threat_metrics.global_coverage_pct,
        }
        
        return render_template(
            "pages/dashboard.html",
            request,
            {
                "user": user,
                "active_page": "dashboard",
                "metrics": dashboard_data,
            }
        )
    
    @app.get("/threats", response_class=HTMLResponse)
    async def threats_page(request: Request, user: CurrentUser):
        """Threat Landscape page."""
        from app.services.database import get_database_service
        db = get_database_service()
        
        metrics = db.get_threat_landscape_metrics()
        
        # Get unique origins and sources for filters
        actors = db.get_threat_actors()
        origins = sorted(set(a.origin for a in actors if a.origin))
        sources = sorted(set(src for a in actors for src in a.source if src))
        
        return render_template(
            "pages/threat_landscape.html",
            request,
            {
                "user": user,
                "active_page": "threats",
                "metrics": metrics,
                "origins": origins,
                "sources": sources,
            }
        )
    
    @app.get("/promotion", response_class=HTMLResponse)
    async def promotion_page(request: Request, user: CurrentUser):
        """Promotion page - Promote staging rules to production."""
        from app.services.database import get_database_service
        db = get_database_service()
        
        metrics = db.get_promotion_metrics()
        
        return render_template(
            "pages/promotion.html",
            request,
            {
                "user": user,
                "active_page": "promotion",
                "metrics": metrics,
            }
        )
    
    @app.get("/sigma", response_class=HTMLResponse)
    async def sigma_page(request: Request, user: CurrentUser, technique: str = ""):
        """Sigma Convert page."""
        from app import sigma_helper as sigma_mod
        
        # Load initial data
        all_rules = sigma_mod.load_all_rules()
        categories = sigma_mod.get_rule_categories()
        backends = sigma_mod.get_available_backends()
        pipelines = sigma_mod.get_available_pipelines()
        
        # Get formats for default backend (elasticsearch)
        formats = sigma_mod.get_output_formats('elasticsearch')
        
        # Initial rule search (optionally filtered by technique from URL)
        initial_rules = sigma_mod.search_rules(
            technique_filter=technique,
            limit=100
        )
        
        return render_template(
            "pages/sigma.html",
            request,
            {
                "user": user,
                "active_page": "sigma",
                "rules": initial_rules,
                "total_count": len(all_rules),
                "filtered_count": len(initial_rules),
                "categories": categories,
                "backends": backends,
                "pipelines": pipelines,
                "formats": formats,
                "technique_filter": technique,
            }
        )
    
    @app.get("/attack-tree", response_class=HTMLResponse)
    async def attack_tree_page(request: Request, user: CurrentUser):
        """Attack Tree page (placeholder)."""
        return render_template(
            "pages/placeholder.html",
            request,
            {
                "user": user,
                "active_page": "attack_tree",
                "page_title": "Attack Tree",
                "page_subtitle": "Visualize attack paths and detection coverage.",
            }
        )
    
    @app.get("/presentation", response_class=HTMLResponse)
    async def presentation_page(request: Request, user: CurrentUser):
        """Presentation page (placeholder)."""
        return render_template(
            "pages/placeholder.html",
            request,
            {
                "user": user,
                "active_page": "presentation",
                "page_title": "Presentation",
                "page_subtitle": "Generate executive reports and presentations.",
            }
        )
    
    @app.get("/preferences", response_class=HTMLResponse)
    async def preferences_page(request: Request, user: CurrentUser):
        """User preferences page."""
        return render_template(
            "pages/preferences.html",
            request,
            {
                "user": user,
                "active_page": "preferences",
                "page_title": "User Preferences",
                "page_subtitle": "Customize your TIDE experience.",
            }
        )
    
    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request, user: CurrentUser, db: DbDep):
        """Settings page - configure integrations and logging."""
        app_settings = db.get_all_settings()
        env_settings = get_settings()
        return render_template(
            "pages/settings.html",
            request,
            {
                "user": user,
                "active_page": "settings",
                "app_settings": app_settings,
                "env": env_settings,
            }
        )
    
    # --- SYNC API ---
    
    @app.post("/api/sync/elastic", response_class=HTMLResponse)
    async def trigger_elastic_sync(request: Request, user: CurrentUser, background_tasks: BackgroundTasks):
        """Trigger manual Elastic sync."""
        import asyncio
        
        # Run sync in background
        asyncio.create_task(scheduled_sync())
        
        # Return toast notification
        return HTMLResponse("""
        <div class="toast toast-success">
            🔄 Sync started. Rules will refresh shortly.
        </div>
        """)
    
    return app


# Create app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
