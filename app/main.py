"""
TIDE - Threat Intelligence Detection Engineering

FastAPI Application Entry Point.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import logging
import os
import time

from app.config import get_settings
from app.api.deps import CurrentUser, DbDep
from app.api import auth, rules, heatmap, threats, promotion, sigma, settings as settings_api, inventory, external_sharing, clients as clients_api, management as management_api, quest as quest_api

# 4.1.0 P1: structured JSON logging with per-request context. Replaces the
# old basicConfig() call. Format selected by TIDE_LOG_FORMAT env (default
# "json" — set to anything else for human-readable lines in dev).
from app.services.log_context import (
    configure_logging,
    RequestContextMiddleware,
    audit_log,
    error_log,
)
configure_logging(level=logging.INFO)
logger = logging.getLogger(__name__)


# Background task scheduler
scheduler = AsyncIOScheduler()

# ── Migration 37 (4.0.13) re-sync advisory ──
# Surfaced both as a Jinja global (for the in-app banner) and as a response
# header (X-TIDE-Resync-Required) so JSON / external API consumers see the
# same notice. The check is one COUNT query, cached for one minute to avoid
# hammering DuckDB on every htmx fragment render.
#
# Cache is keyed by the active tenant DB path (or ``__shared__``) so each
# tenant gets an independent verdict \u2014 since 4.1.2 every tenant has its
# own ``detection_rules`` table and the answer differs per-tenant.
_migration37_cache: dict = {}


def migration37_resync_required() -> bool:
    """Return True if Migration 37 left the rule cache empty and a sync hasn't
    repopulated it yet. False on any error (fail-closed for the banner so a
    transient DB hiccup doesn't spam every page with a warning)."""
    from app.services.tenant_manager import get_tenant_db_path
    cache_key = get_tenant_db_path() or "__shared__"
    now = time.time()
    cached = _migration37_cache.get(cache_key)
    if cached and now - cached["ts"] < 60:
        return cached["needed"]
    needed = False
    try:
        from app.services.database import get_database_service
        _db = get_database_service()
        # The advisory must reflect the user's *active* DB. Per-tenant
        # routing means an authenticated request reads from the tenant
        # DB; ``siem_inventory`` is replicated into every tenant via the
        # reference-data sync, so the legacy "rules == 0 AND active SIEMs
        # exist" heuristic raises a false positive for any tenant that
        # has no ``client_siem_map`` rows yet (the distributor skips
        # them, leaving ``detection_rules`` empty even after a global
        # sync). Scope the SIEM count to the active tenant via
        # ``client_siem_map`` so the banner only fires when the tenant
        # has at least one SIEM mapped AND its rule cache is empty.
        with _db.get_connection() as _conn:
            ver_row = _conn.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()
            ver = int(ver_row[0]) if ver_row and ver_row[0] is not None else 0
            if ver >= 37:
                rules = int(_conn.execute(
                    "SELECT COUNT(*) FROM detection_rules"
                ).fetchone()[0])
                if cache_key != "__shared__":
                    # Tenant DB context: count only SIEMs mapped to *this*
                    # tenant. ``client_siem_map`` is replicated into the
                    # tenant DB by ``sync_shared_data`` and already
                    # filtered to this client by Migration 29, so a
                    # COUNT(*) here is the per-tenant scope.
                    siems = int(_conn.execute(
                        "SELECT COUNT(DISTINCT siem_id) FROM client_siem_map"
                    ).fetchone()[0])
                else:
                    siems = int(_conn.execute(
                        "SELECT COUNT(*) FROM siem_inventory WHERE is_active"
                    ).fetchone()[0])
                # Banner only fires when the table is empty AND at least one
                # mapped SIEM exists \u2014 the wipe only matters if there were
                # rules to repopulate. Fresh installs / unmapped tenants
                # would otherwise see a misleading "resync required"
                # warning when the real action is "map a SIEM first".
                needed = rules == 0 and siems > 0
    except Exception:
        needed = False
    _migration37_cache[cache_key] = {"ts": now, "needed": needed}
    return needed


# ── Sync status tracking ──
_sync_status = {
    "state": "idle",       # idle | running | complete | error
    "message": "",
    "started_at": None,
    "finished_at": None,
    "rule_count": 0,
}


def _update_sync_status(state: str, message: str = "", rule_count: int = 0):
    """Update the global sync status dict."""
    _sync_status["state"] = state
    _sync_status["message"] = message
    if state == "running" and _sync_status["started_at"] is None:
        _sync_status["started_at"] = time.time()
    if state in ("complete", "error"):
        _sync_status["finished_at"] = time.time()
        _sync_status["rule_count"] = rule_count


def get_last_sync_time() -> str:
    """Return human-readable last sync time, or 'Never' if no sync completed."""
    ts = _sync_status.get("finished_at")
    if ts is None:
        return "Never"
    from datetime import datetime
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%d %b %H:%M")


async def scheduled_sync(force_mapping=False):
    """Background task: Sync detection rules from Elastic every 60 minutes."""
    settings = get_settings()
    logger.info(f"Scheduled sync triggered (interval: {settings.sync_interval_minutes}m)")
    
    _update_sync_status("running", "Connecting to Elastic...")
    
    try:
        # Import here to avoid circular imports
        from app.services.database import get_database_service
        from app.services.sync import trigger_sync
        
        db = get_database_service()
        
        # Check for manual trigger
        if db.check_and_clear_trigger("sync_elastic"):
            logger.info("Manual sync trigger detected")
        
        _update_sync_status("running", "Fetching detection rules...")
        
        # Run the actual sync
        result = await trigger_sync(force_mapping=force_mapping)
        
        count = result if isinstance(result, int) else 0
        _update_sync_status("complete", f"Synced {count} rules from Elastic", rule_count=count)
    except Exception as e:
        logger.warning(f"Scheduled sync failed (Elastic may be unreachable): {e}")
        logger.info("TIDE will continue running — sync will retry on next interval")
        _update_sync_status("error", str(e))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    import asyncio
    settings = get_settings()
    
    # Startup
    logger.info(f"Starting TIDE v{settings.tide_version}")
    
    # Initialize database
    from app.services.database import get_database_service
    db = get_database_service()
    logger.info("Database initialized")

    # Initialize multi-tenant DB routing.
    # Per design (Migration 29), every client owns a physical DB file so that
    # tenant data (rules, baselines, systems, ...) is physically isolated
    # from every other tenant. ``clients.db_filename`` records the file name.
    # Backfill any client with NULL ``db_filename`` so existing installs that
    # predate auto-provisioning catch up on startup, then distribute rules
    # from the shared DB into each tenant DB so the views are populated.
    try:
        from app.services.tenant_manager import (
            refresh_tenant_cache, sync_shared_data, create_tenant_db,
        )
        # Backfill missing tenant DBs (run BEFORE refresh_tenant_cache so the
        # cache picks up the freshly-registered db_filename rows).
        try:
            with db.get_shared_connection() as _conn:
                _missing = _conn.execute(
                    "SELECT id, slug FROM clients WHERE db_filename IS NULL"
                ).fetchall()
            for _cid, _slug in _missing:
                try:
                    create_tenant_db(_cid, _slug, settings.data_dir, settings.db_path)
                except Exception as _e:
                    logger.error(f"Failed to provision tenant DB for {_slug} ({_cid}): {_e}")
            if _missing:
                logger.info(f"Provisioned {len(_missing)} missing tenant DB(s) on startup")
        except Exception as _e:
            logger.warning(f"Tenant DB backfill skipped: {_e}")

        refresh_tenant_cache(settings.data_dir, settings.db_path)
        sync_shared_data(settings.data_dir, settings.db_path)

        # 4.1.2 — recover per-client rows that were written into the
        # *shared* DB before per-tenant routing was wired up. Idempotent:
        # only copies rows for tables that are currently empty in the
        # tenant DB, so subsequent edits made post-backfill are never
        # duplicated. See tenant_manager.backfill_legacy_tenant_data.
        try:
            from app.services.tenant_manager import backfill_legacy_tenant_data
            backfill_legacy_tenant_data(settings.data_dir)
        except Exception as _e:
            logger.warning(f"Legacy data backfill skipped: {_e}")

        # Distribute rules from shared DB into each tenant DB. Without this
        # step a fresh-provisioned tenant has empty detection_rules until the
        # next elastic sync runs.
        try:
            from app.services.sync import _distribute_rules_to_tenants
            _distribute_rules_to_tenants()
        except Exception as _e:
            logger.warning(f"Initial rule distribution skipped: {_e}")

        # 4.1.3 \u2014 startup auth-source banner. Logs (in plain English) what
        # TIDE will use to talk to Kibana on the next sync. Saves operators
        # hours of "is it the env var, the DB record, or the per-tenant
        # mapping?" debugging when a sync 401s in production.
        try:
            from app.services.database import get_database_service as _gdb
            _db_b = _gdb()
            with _db_b.get_shared_connection() as _cb:
                try:
                    _siems = _cb.execute(
                        "SELECT label, kibana_url, "
                        "CASE WHEN api_token_enc IS NULL OR api_token_enc='' "
                        "THEN 0 ELSE 1 END, is_active "
                        "FROM siem_inventory"
                    ).fetchall()
                except Exception:
                    _siems = []
                try:
                    _maps = _cb.execute(
                        "SELECT siem_id, COUNT(DISTINCT client_id) "
                        "FROM client_siem_map GROUP BY siem_id"
                    ).fetchall()
                except Exception:
                    _maps = []
                try:
                    _rules = _cb.execute(
                        "SELECT COUNT(*) FROM detection_rules"
                    ).fetchone()[0]
                except Exception:
                    _rules = 0
            _env_url = bool(os.environ.get("ELASTIC_URL"))
            _env_key = bool(os.environ.get("ELASTIC_API_KEY"))
            logger.info(
                "[auth-banner] sync auth source: siem_inventory rows=%d "
                "(active+token+url=%d), env ELASTIC_URL=%s ELASTIC_API_KEY=%s, "
                "shared detection_rules=%d, client_siem_map siems=%d",
                len(_siems),
                sum(1 for _l, _u, _t, _a in _siems if _u and _t and _a),
                _env_url, _env_key, _rules, len(_maps),
            )
            for _l, _u, _t, _a in _siems:
                logger.info(
                    "[auth-banner]   SIEM '%s' active=%s url=%s token_present=%s",
                    _l, bool(_a), _u, bool(_t),
                )
            if not _siems and not (_env_url and _env_key):
                logger.warning(
                    "[auth-banner] NO sync credentials configured. Add a SIEM "
                    "via Management UI, or set ELASTIC_URL+ELASTIC_API_KEY env "
                    "vars (legacy <=4.0.9 only). Run "
                    "`docker exec tide-app python -m app.scripts.diag_sync` "
                    "for a full diagnostic."
                )

            # 4.1.4 \u2014 walk every client_siem_map row and verify the configured
            # ``space`` actually exists on the SIEM's Kibana. The single most
            # common 4.1.x outage cause was an operator typing the role
            # ('production'/'staging') into the space field, producing
            # ``/s/production/api/...`` URLs that 404'd silently. Caught here
            # at startup the operator sees the bad row before they ever click
            # Sync. Cached per-SIEM so a 50-mapping deployment makes one HTTP
            # call per unique Kibana, not one per mapping.
            try:
                from app.api.management import _list_kibana_spaces as _lks
                with _db_b.get_shared_connection() as _cb2:
                    _all_maps = _cb2.execute(
                        "SELECT m.client_id, m.siem_id, m.environment_role, "
                        "m.space, c.name "
                        "FROM client_siem_map m "
                        "LEFT JOIN clients c ON c.id = m.client_id"
                    ).fetchall()
                _bad = 0
                for _cid, _sid, _role, _sp, _cname in _all_maps:
                    _real = _lks(_db_b, _sid)
                    if _real is None:
                        continue  # unreachable Kibana \u2014 don't double-warn
                    if (_sp or "default") not in _real:
                        _bad += 1
                        logger.warning(
                            "[auth-banner] BAD MAPPING client='%s' (%s) "
                            "siem=%s role=%r space=%r is NOT a Kibana space "
                            "on this instance. Real spaces: %s. Sync will "
                            "404 against /s/%s/api/...",
                            _cname or "?", str(_cid)[:8], str(_sid)[:8],
                            _role, _sp, sorted(_real), _sp,
                        )
                if _all_maps and _bad == 0:
                    logger.info(
                        "[auth-banner] all %d client_siem_map rows reference "
                        "real Kibana spaces.", len(_all_maps),
                    )
            except Exception as _e:
                logger.warning(f"[auth-banner] space-validity check skipped: {_e}")
        except Exception as _e:
            logger.warning(f"Auth-source banner skipped: {_e}")
    except Exception as e:
        logger.warning(f"Tenant cache init failed (legacy single-DB mode): {e}")

    # Seed default baselines if not already present
    try:
        from app.inventory_engine import seed_default_playbooks as seed_default_baselines
        seed_default_baselines()
    except Exception as e:
        logger.warning(f"Failed to seed default baselines: {e}")
    
    # Pre-load Sigma rules cache to avoid slow first page load
    # This takes ~6 seconds but happens during startup, not during user request
    try:
        from app import sigma_helper
        rules_count = len(sigma_helper.load_all_rules())
        logger.info(f"Sigma rules pre-loaded: {rules_count} rules cached")
    except Exception as e:
        logger.warning(f"Failed to pre-load Sigma rules: {e}")

    # Index Sigma rule metadata into the shared DB for fast SQL queries
    try:
        indexed = sigma_helper.index_sigma_rules()
        logger.info(f"Sigma rules indexed: {indexed} rows in sigma_rules_index")
    except Exception as e:
        logger.warning(f"Sigma index build failed (non-fatal): {e}")
    
    # Warm up Sigma backends / pipelines so first conversion is instant
    try:
        sigma_helper.warm_up_backends()
    except Exception as e:
        logger.warning(f"Sigma backend warm-up failed (non-fatal): {e}")
    
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
    logger.info(f"Scheduler started (sync every {settings.sync_interval_minutes}m)")
    
    yield
    
    # Shutdown
    scheduler.shutdown()
    # 4.1.0 P3 — close all pooled DuckDB connections so the file locks
    # are released cleanly before uvicorn exits.
    try:
        from app.services.connection_pool import get_pool
        get_pool().close_all()
    except Exception as exc:  # pragma: no cover
        logger.warning(f"ConnectionPool close_all failed: {exc}")
    logger.info("TIDE shutdown complete")


def _schedule_rule_log_job(db=None):
    """Schedule (or reschedule) the daily rule-log export jobs.

    v4.0.8+ model: configuration lives on ``siem_inventory`` rows. We register
    one cron job per logging-enabled SIEM, each firing at its own ``log_schedule``
    HH:MM with its ``id`` bound so the export only writes that SIEM's directory.
    Falls back to the legacy global (``app_settings.rule_log_enabled`` /
    ``rule_log_schedule``) only when no SIEM has logging turned on, so existing
    pre-migration deployments keep working.
    """
    try:
        if db is None:
            from app.services.database import get_database_service
            db = get_database_service()

        # Tear down every previously-registered rule-log job (per-SIEM and
        # legacy) so a stale schedule can't survive a config change.
        for job in list(scheduler.get_jobs()):
            if job.id == "rule_log_export" or job.id.startswith("rule_log_export_"):
                try:
                    scheduler.remove_job(job.id)
                except Exception:
                    pass

        # ---- Per-SIEM scheduling (preferred) ----
        per_siem = []
        try:
            per_siem = db.list_logging_enabled_siems() or []
        except Exception as exc:
            logger.warning(f"list_logging_enabled_siems failed, scheduler falling back to legacy: {exc}")

        if per_siem:
            scheduled = 0
            for siem in per_siem:
                sid = siem.get("id")
                label = siem.get("label") or sid or "siem"
                schedule_time = (siem.get("log_schedule") or "00:00").strip() or "00:00"
                parts = schedule_time.split(":")
                try:
                    hour = int(parts[0]) if len(parts) > 0 else 0
                    minute = int(parts[1]) if len(parts) > 1 else 0
                except ValueError:
                    logger.warning(
                        f"SIEM '{label}' has invalid log_schedule '{schedule_time}', defaulting to 00:00"
                    )
                    hour, minute = 0, 0

                job_id = f"rule_log_export_{sid}"
                scheduler.add_job(
                    _run_rule_log_export,
                    "cron",
                    hour=hour,
                    minute=minute,
                    id=job_id,
                    replace_existing=True,
                    kwargs={"siem_id": sid},
                )
                scheduled += 1
                logger.info(
                    f"Rule log export scheduled for SIEM '{label}' at {hour:02d}:{minute:02d}"
                )
            logger.info(f"Rule log scheduler installed {scheduled} per-SIEM job(s)")
            return

        # ---- Legacy global path (back-compat) ----
        app_settings = db.get_all_settings()
        enabled = app_settings.get("rule_log_enabled", "false").lower() == "true"
        schedule_time = app_settings.get("rule_log_schedule", "00:00")

        if enabled:
            parts = schedule_time.split(":")
            try:
                hour = int(parts[0]) if len(parts) > 0 else 0
                minute = int(parts[1]) if len(parts) > 1 else 0
            except ValueError:
                hour, minute = 0, 0

            scheduler.add_job(
                _run_rule_log_export,
                "cron",
                hour=hour,
                minute=minute,
                id="rule_log_export",
                replace_existing=True,
            )
            logger.info(f"Rule log export scheduled at {schedule_time} (legacy global mode)")
        else:
            logger.info("Rule log export disabled (no per-SIEM config and global flag is off)")
    except Exception as e:
        logger.warning(f"Could not schedule rule log job: {e}")


def _run_rule_log_export(siem_id=None):
    """Synchronous wrapper for rule log export (called by scheduler).

    ``siem_id`` is bound by ``_schedule_rule_log_job`` for per-SIEM jobs so the
    export only writes that SIEM's directory; left ``None`` for the legacy
    global job.
    """
    try:
        from app.services.database import get_database_service
        from app.services.rule_logger import run_rule_log_export
        db = get_database_service()
        run_rule_log_export(db, siem_id=siem_id)
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
    Enforces page-level RBAC permissions.
    
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
        "/auth/local-login",
        "/static",
        "/api/docs",
        "/api/redoc",
        "/openapi.json",
        "/api/external",
    }
    
    # URL path → resource name mapping for permission checks
    PATH_RESOURCE_MAP = {
        "/": "page:home",
        "/dashboard": "page:dashboard",
        "/systems": "page:systems",
        "/cve-overview": "page:cve_overview",
        "/baselines": "page:baselines",
        "/rules": "page:rules",
        "/promotion": "page:promotion",
        "/sigma": "page:sigma",
        "/threats": "page:threats",
        "/heatmap": "page:heatmap",
        "/settings": "page:settings",
        "/clients": "page:clients",
        "/management": "page:management",
    }
    
    # API prefix → resource mapping for write checks
    API_WRITE_RESOURCE_MAP = {
        "/api/settings/profile": "tab:profile",
        "/api/settings/api-keys": "tab:profile",
        "/api/rules": "page:rules",
        "/api/heatmap": "page:heatmap",
        "/api/threats": "page:threats",
        "/api/promotion": "page:promotion",
        "/api/sigma": "page:sigma",
        "/api/inventory": "page:systems",
        "/api/settings": "page:settings",
        "/api/clients": "page:clients",
        "/api/management": "page:management",
    }
    
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        path = request.url.path
        is_htmx = request.headers.get("HX-Request") == "true"
        is_api = path.startswith("/api/")
        
        # Helper to add cache headers for HTML responses
        async def add_cache_headers(response):
            content_type = response.headers.get("content-type", "")
            if "text/html" in content_type and not path.startswith("/static"):
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
            return response
        
        def _check_page_permission(user):
            """Check if user has permission to access this path. Returns 403 response or None."""
            if not user or user.is_admin():
                return None
            # Page-level read check
            resource = self.PATH_RESOURCE_MAP.get(path)
            if not resource:
                # Check for sub-paths (e.g. /systems/123 → page:systems)
                for prefix, res in self.PATH_RESOURCE_MAP.items():
                    if prefix != "/" and path.startswith(prefix):
                        resource = res
                        break
            if resource and not user.can_read(resource):
                if is_htmx:
                    from fastapi.responses import Response
                    resp = Response(content="", status_code=200)
                    resp.headers["HX-Redirect"] = "/"
                    return resp
                if is_api:
                    return JSONResponse({"detail": "Insufficient permissions"}, status_code=403)
                return JSONResponse(
                    content="<h1>403 Forbidden</h1><p>You don't have access to this page.</p>",
                    status_code=403,
                    media_type="text/html",
                )
            # API write check (POST/PUT/DELETE)
            if is_api and request.method in ("POST", "PUT", "DELETE", "PATCH"):
                for prefix, res in sorted(self.API_WRITE_RESOURCE_MAP.items(), key=lambda x: len(x[0]), reverse=True):
                    if path.startswith(prefix):
                        if not user.can_write(res):
                            return JSONResponse({"detail": "Write access denied"}, status_code=403)
                        break
            return None
        
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
        session_token = request.cookies.get("session_token")
        
        # Build login URL for redirects
        return_url = str(request.url.path)
        if request.url.query:
            return_url += f"?{request.url.query}"
        login_url = f"/login?next={return_url}"

        def _unauthorized_response(reason: str):
            if is_api:
                return JSONResponse(
                    {"detail": "Authentication required", "reason": reason, "login": login_url},
                    status_code=401,
                )
            if is_htmx:
                from fastapi.responses import Response
                response = Response(content="", status_code=200)
                response.headers["HX-Redirect"] = login_url
                return response
            return RedirectResponse(url=login_url, status_code=302)
        
        if not access_token:
            # Prefer a valid local session before attempting any SSO token refresh.
            if session_token:
                from app.services.auth import get_auth_service
                auth_service = get_auth_service()
                user = auth_service.get_user_from_session(session_token)
                if user:
                    logger.debug(f"Local session valid for user: {user.username}, path: {path}")
                    perm_resp = _check_page_permission(user)
                    if perm_resp:
                        return perm_resp
                    response = await call_next(request)
                    return await add_cache_headers(response)

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
                        perm_resp = _check_page_permission(user)
                        if perm_resp:
                            return perm_resp
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
            return _unauthorized_response("missing_or_invalid_tokens")
        
        # Token exists - validate it
        from app.services.auth import get_auth_service
        auth_service = get_auth_service()
        
        logger.debug(f"Validating token for path: {path}, is_htmx: {is_htmx}")
        user = auth_service.get_user_from_token(access_token)

        local_session_user = None
        if session_token:
            local_session_user = auth_service.get_user_from_session(session_token)

        if user is None and local_session_user:
            logger.info(
                f"Access token invalid for path: {path}; preferring local session for user: {local_session_user.username}"
            )
            perm_resp = _check_page_permission(local_session_user)
            if perm_resp:
                return perm_resp
            response = await call_next(request)
            return await add_cache_headers(response)
        
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
            # If Keycloak token is stale but a local session is valid, allow local auth to continue.
            if local_session_user:
                logger.info(f"Falling back to local session for user: {local_session_user.username}, path: {path}")
                perm_resp = _check_page_permission(local_session_user)
                if perm_resp:
                    return perm_resp
                response = await call_next(request)
                return await add_cache_headers(response)

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

            if is_api:
                response = JSONResponse(
                    {
                        "detail": "Authentication required",
                        "reason": "token_validation_failed",
                        "login": login_url,
                    },
                    status_code=401,
                )
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
        
        # Check page-level permissions
        perm_resp = _check_page_permission(user)
        if perm_resp:
            return perm_resp
        
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

    # 4.1.0 P1: RequestContextMiddleware allocates the request_id, populates
    # the structured-logging contextvar, sets X-Request-ID, and emits one
    # tide.perf JSON line per request. Added LAST so it wraps the rest
    # outermost (Starlette middleware order: last-added = outermost). All
    # subsequent log records — including those emitted by AuthMiddleware and
    # the route handler — automatically inherit the request id, route, method,
    # plus the user_id / client_id that get_active_client backfills.
    app.add_middleware(RequestContextMiddleware)

    # Header-only middleware: the perf logging itself moved to
    # RequestContextMiddleware (above). This pass remains so DevTools still
    # sees Server-Timing and the Migration 37 advisory header continues to be
    # surfaced on every non-static response.
    @app.middleware("http")
    async def timing_middleware(request: Request, call_next):
        import time as _time
        path = request.url.path
        start = _time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (_time.perf_counter() - start) * 1000
        if not path.startswith("/static"):
            response.headers["Server-Timing"] = f"total;dur={elapsed_ms:.1f}"
            if elapsed_ms > 500:
                logger.warning(f"Slow request: {request.method} {path} took {elapsed_ms:.0f}ms")
            # 4.0.13 Migration 37 advisory header: surfaces the same "resync
            # required after upgrade" notice that the UI banner shows, so
            # external API consumers (sync_to_sigea, custom integrations,
            # CLI scripts, future SDK) can detect the empty post-migration
            # state without scraping HTML. The header is omitted entirely
            # when no resync is required so legacy clients don't see noise.
            try:
                if migration37_resync_required():
                    response.headers["X-TIDE-Resync-Required"] = "1"
                    response.headers["X-TIDE-Resync-Reason"] = (
                        "migration-37: detection_rules wiped on upgrade to "
                        "4.0.13; trigger POST /api/admin/sync to repopulate"
                    )
            except Exception:
                pass
        return response
    
    # Exception handler for 401 errors (handle HTMX requests)
    from fastapi import HTTPException as FastAPIHTTPException
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    # 4.1.0 P1: catch-all unhandled-exception handler emits one structured
    # tide.error log line (with traceback) and echoes the request id back to
    # the caller via X-TIDE-Error-Id so support bundles can correlate the
    # response with the JSON log entry.
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        if isinstance(exc, StarletteHTTPException):
            # Let the dedicated handler below take it (auth redirects etc.).
            raise exc
        request_id = getattr(request.state, "request_id", "-")
        error_log(
            "unhandled_exception",
            exc=exc,
            path=request.url.path,
            method=request.method,
        )
        from fastapi.responses import JSONResponse
        if request.url.path.startswith("/api/"):
            resp = JSONResponse(
                status_code=500,
                content={"detail": "Internal server error.", "request_id": request_id},
            )
        else:
            resp = HTMLResponse(
                content=(
                    f"<h1>Internal server error</h1>"
                    f"<p>Reference: <code>{request_id}</code></p>"
                ),
                status_code=500,
            )
        resp.headers["X-TIDE-Error-Id"] = request_id
        return resp

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        # JSON API endpoints should return JSON errors, not HTML redirects
        if request.url.path.startswith("/api/external"):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
            )

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

    # 4.1.0 P4 — Immutable-cache header for content-hashed bundles. Only
    # paths under /static/css/dist/ or /static/js/dist/ are eligible (those
    # filenames embed a 12-char content hash; safe to cache for a year).
    # All other /static/* assets keep whatever the StaticFiles app emitted.
    # Done in FastAPI rather than nginx because the nginx container does
    # not bind-mount the app static dir, so every /static request proxies
    # to uvicorn anyway — adding the header here is the only place it can
    # actually take effect.
    @app.middleware("http")
    async def _immutable_dist_cache(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.startswith("/static/css/dist/") or path.startswith("/static/js/dist/"):
            response.headers["Cache-Control"] = "public, immutable, max-age=31536000"
        return response
    
    # Setup templates
    templates_path = os.path.join(os.path.dirname(__file__), "templates")
    templates = Jinja2Templates(directory=templates_path)
    # Disable Jinja2 LRUCache — template globals contain dicts which are unhashable
    class _NoCache:
        def get(self, key, default=None): return default
        def __setitem__(self, key, value): pass
        def __delitem__(self, key): pass
        def __contains__(self, key): return False
        def clear(self): pass
    templates.env.cache = _NoCache()
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

    # --- Markdown filter for description fields ---
    import markdown as _md_lib

    def md_filter(text: str) -> Markup:
        """Convert Markdown text to safe HTML."""
        if not text:
            return Markup("")
        html = _md_lib.markdown(str(text), extensions=["extra", "nl2br", "sane_lists"])
        return Markup(html)

    templates.env.filters["md"] = md_filter

    # --- Add global template variables so all templates have access ---
    templates.env.globals["env"] = settings

    # Re-export the module-level helper as a Jinja global so every page can
    # render the Migration 37 banner without each route plumbing the flag
    # through context.
    templates.env.globals["migration37_resync_required"] = migration37_resync_required

    # 4.1.0 P4 — content-hashed asset bundles. Reads app/static/manifest.json
    # produced by `python -m app.scripts.build_assets` (run at container
    # build time). Templates use `{{ asset('styles.css') }}` and get back
    # the immutable hashed URL `/static/css/dist/styles-<hash>.css`.
    # In dev (no manifest) we fall back to the un-hashed source path with
    # a version-based query string so the hot-reload workflow keeps working.
    import json as _json
    _manifest_path = os.path.join(static_path, "manifest.json")
    _asset_manifest: dict = {}
    try:
        with open(_manifest_path, "r", encoding="utf-8") as _mf:
            _asset_manifest = _json.load(_mf)
        logger.info(f"Asset manifest loaded: {len(_asset_manifest)} bundle(s)")
    except FileNotFoundError:
        logger.warning(
            "Asset manifest missing at %s — falling back to un-hashed source paths. "
            "Run `python -m app.scripts.build_assets` to produce it.",
            _manifest_path,
        )
    except Exception as _exc:
        logger.warning(f"Asset manifest unreadable ({_exc}); using fallback paths")

    _ASSET_FALLBACK = {
        "styles.css": f"/static/css/style.css?v={settings.tide_version}",
        "app.js": f"/static/js/app.js?v={settings.tide_version}",
    }

    def asset(name: str) -> str:
        """Resolve a logical asset name to its URL.

        Order of resolution:
          1. manifest.json (production / post-build)
          2. _ASSET_FALLBACK with ?v=<version> (dev hot-reload, missing build)
          3. /static/<name> as a last resort
        """
        if name in _asset_manifest:
            return _asset_manifest[name]
        if name in _ASSET_FALLBACK:
            return _ASSET_FALLBACK[name]
        return f"/static/{name}"

    templates.env.globals["asset"] = asset

    # 4.1.0 P5 — route-metadata-driven breadcrumbs. Templates use
    # `{{ crumbs(request) }}` (or implicitly via the breadcrumb macro)
    # to fetch the trail. Resolution order in route_metadata.get_crumbs:
    # handler override (request.state.crumbs) → static registry → empty.
    from app.services.route_metadata import get_crumbs as _get_crumbs

    templates.env.globals["crumbs"] = _get_crumbs

    # 4.1.0 P6 — active coverage quest exposed to every template so the
    # quest tray can render above the breadcrumb when one is in flight.
    # Resolves silently to None on any error (unauth, no tenant, etc.).
    def _active_quest(request):
        try:
            from app.services.quest import get_quest_id_from_request, get_quest
            qid = get_quest_id_from_request(request)
            if not qid:
                return None
            q = get_quest(qid)
            if q and q.get("status") == "active":
                from app.services.quest import quest_summary
                return quest_summary(q)
        except Exception:
            return None
        return None

    templates.env.globals["active_quest"] = _active_quest

    # --- Helper function to render templates with global context ---
    def render_template(name: str, request: Request, context: dict = None):
        """Render template with global context variables (brand_hue, cache_bust, active_client)."""
        ctx = {
            "brand_hue": settings.brand_hue,
            "cache_bust": settings.tide_version,
            "settings": settings,
        }
        if context:
            ctx.update(context)

        # Inject active client info for the client switcher component
        if "active_client" not in ctx:
            try:
                from app.services.database import get_database_service
                _db = get_database_service()
                _user = ctx.get("user")

                # Resolve active client id (cookie → user default → system default)
                _cid = request.cookies.get("active_client_id")
                if not _cid and _user:
                    with _db.get_connection() as conn:
                        row = conn.execute(
                            "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                            [_user.id],
                        ).fetchone()
                        if row:
                            _cid = row[0]
                if not _cid:
                    with _db.get_connection() as conn:
                        row = conn.execute(
                            "SELECT id FROM clients WHERE is_default = true LIMIT 1",
                        ).fetchone()
                        if row:
                            _cid = row[0]

                # Fetch client record
                ctx["active_client"] = _db.get_client(_cid) if _cid else None

                # Fetch user's available clients (admin sees all)
                if _user and hasattr(_user, "is_admin") and _user.is_admin():
                    ctx["user_clients"] = _db.list_clients()
                elif _user:
                    _ids = _db.get_user_client_ids(_user.id)
                    ctx["user_clients"] = [c for c in (_db.get_client(i) for i in _ids) if c]
                else:
                    ctx["user_clients"] = []

                # Build space → environment-role label mapping for the active client
                if _cid and "space_labels" not in ctx:
                    try:
                        _siems = _db.get_client_siems(_cid)
                        ctx["space_labels"] = {
                            s["space"]: f'{s["label"]} ({s["environment_role"].title()})'
                            for s in _siems if s.get("space")
                        }
                    except Exception:
                        ctx["space_labels"] = {}
                elif "space_labels" not in ctx:
                    ctx["space_labels"] = {}
            except Exception:
                ctx["active_client"] = None
                ctx["user_clients"] = []
                ctx.setdefault("space_labels", {})

        return templates.TemplateResponse(request, name, ctx)
    
    # Include API routers
    app.include_router(auth.router)
    app.include_router(rules.router)
    app.include_router(heatmap.router)
    app.include_router(threats.router)
    app.include_router(promotion.router)
    app.include_router(sigma.router)
    app.include_router(settings_api.router)
    app.include_router(inventory.router)
    app.include_router(external_sharing.router)
    app.include_router(clients_api.router)
    app.include_router(management_api.router)
    app.include_router(quest_api.router)
    
    # --- HEALTH CHECK ---
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint for container orchestration."""
        body = {"status": "healthy", "version": settings.tide_version}
        # 4.1.0 P3 — surface pool counters so ops can watch hit-rate without
        # scraping logs. Cheap (one OrderedDict snapshot under a Lock).
        try:
            from app.services.connection_pool import get_pool
            body["db_pool"] = get_pool().stats()
        except Exception:  # pragma: no cover
            pass
        # Surface the Migration 37 advisory in the JSON body too so monitoring
        # tooling that polls /health can alert on it without parsing headers.
        if migration37_resync_required():
            body["resync_required"] = True
            body["resync_reason"] = (
                "migration-37: detection_rules wiped on upgrade to 4.0.13; "
                "POST /api/admin/sync to repopulate"
            )
        return body

    @app.get("/api/system/migration-status")
    async def migration_status():
        """Machine-readable migration / resync state for external API consumers.

        Returned regardless of auth state \u2014 contains no tenant data, only the
        global advisory flag set by Migration 37 (4.0.13). Lets sync_to_sigea,
        CLI scripts, and integration tests check post-upgrade state without
        scraping the HTML banner or relying on the response header.
        """
        return {
            "schema_version_expected": __import__(
                "app.services.database", fromlist=["SCHEMA_VERSION"]
            ).SCHEMA_VERSION,
            "resync_required": migration37_resync_required(),
            "resync_reason": (
                "migration-37"
                if migration37_resync_required() else None
            ),
        }
    
    # --- LOGIN PAGE (public) ---
    
    @app.get("/login", response_class=HTMLResponse, name="login_page")
    def login_page(request: Request, next: str = "/", logout: bool = False):
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
            response.delete_cookie(
                key="session_token",
                path="/",
                httponly=True,
                secure=use_secure,
                samesite="lax",
            )
            return response
        
        # Check if user is already logged in with a valid token
        access_token = request.cookies.get("access_token")
        session_token = request.cookies.get("session_token")
        from app.services.auth import get_auth_service
        auth_service = get_auth_service()
        
        if access_token:
            user = auth_service.get_user_from_token(access_token)
            if user is not None:
                return RedirectResponse(url=next, status_code=302)
        
        if session_token:
            user = auth_service.get_user_from_session(session_token)
            if user is not None:
                return RedirectResponse(url=next, status_code=302)
        
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
    def logout_redirect(request: Request):
        """Redirect to auth logout endpoint."""
        return RedirectResponse(url="/auth/logout", status_code=302)
    
    # --- PAGE ROUTES ---
    
    @app.get("/", response_class=HTMLResponse, name="home")
    def home(request: Request, user: CurrentUser):
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
    def rule_health_page(request: Request, user: CurrentUser):
        """Rule Health page."""
        from app.services.database import get_database_service
        db = get_database_service()
        
        # Resolve active client for tenant-scoped rule visibility
        # (mirrors the resolution chain in deps.get_active_client)
        _cid = request.cookies.get("active_client_id")
        if not _cid and user:
            with db.get_connection() as conn:
                row = conn.execute(
                    "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                    [user.id],
                ).fetchone()
                if row:
                    _cid = row[0]
        if not _cid:
            _cid = db.get_default_client_id()
        
        allowed_spaces = db.get_client_siem_spaces(_cid) if _cid else None
        
        metrics = db.get_rule_health_metrics(allowed_spaces=allowed_spaces)
        # Derive spaces from metrics (avoids a second DB connection)
        spaces = sorted(metrics.rules_by_space.keys()) if metrics.rules_by_space else []

        # Build space → label mapping from client's SIEM inventory
        client_siems = db.get_client_siems(_cid) if _cid else []
        space_labels = {}
        for s in client_siems:
            sp = s.get("space")
            if sp:
                space_labels[sp] = f'{s["label"]} ({s["environment_role"].title()})'
        
        return render_template(
            "pages/rule_health.html",
            request,
            {
                "user": user,
                "active_page": "rules",
                "metrics": metrics,
                "spaces": spaces,
                "space_labels": space_labels,
                "last_sync_time": get_last_sync_time(),
            }
        )
    
    @app.get("/heatmap", response_class=HTMLResponse, name="heatmap")
    def heatmap_page(request: Request, user: CurrentUser):
        """Heatmap page."""
        from app.services.database import get_database_service
        from app.models.threats import HeatmapData
        from app.services.report_generator import CLASSIFICATION_OPTIONS

        db = get_database_service()

        # Resolve the active tenant so OpenCTI-only actors are filtered out for
        # tenants without an OpenCTI link (mirrors the chain in /threats).
        _cid = request.cookies.get("active_client_id")
        if not _cid and user:
            with db.get_connection() as conn:
                row = conn.execute(
                    "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                    [user.id],
                ).fetchone()
                if row:
                    _cid = row[0]
        if not _cid:
            _cid = db.get_default_client_id()

        actors = db.get_threat_actors(client_id=_cid)

        # Derive distinct sources from loaded actors for the source filter
        # Normalise raw DB values to human-friendly display names
        _SOURCE_DISPLAY = {
            "enterprise": "Enterprise",
            "mitre:enterprise": "Enterprise",
            "mitre-enterprise": "Enterprise",
            "mobile": "Mobile",
            "mitre:mobile": "Mobile",
            "ics": "ICS",
            "mitre:ics": "ICS",
            "opencti": "OpenCTI",
            "open-cti": "OpenCTI",
            "octi": "OpenCTI",
        }
        # Build unique normalised names (preserving sort order, deduplicating)
        _seen = set()
        sources = []
        for actor in actors:
            for s in (actor.source or []):
                if not s:
                    continue
                display = _SOURCE_DISPLAY.get(s.lower().strip(), s.title())
                if display not in _seen:
                    _seen.add(display)
                    sources.append(display)
        sources = sorted(sources)

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
                "classification_options": CLASSIFICATION_OPTIONS,
                "sources": sources,
            }
        )
    
    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard_page(request: Request, user: CurrentUser):
        """Dashboard page - Aggregated overview of detection engineering posture."""
        import os
        from app.services.database import get_database_service
        from app.inventory_engine import get_inventory_stats, get_cve_overview_stats, get_baselines_overview
        db = get_database_service()
        
        # Resolve active client for tenant-scoped metrics
        # (mirrors the resolution chain in deps.get_active_client)
        _cid = request.cookies.get("active_client_id")
        if not _cid and user:
            with db.get_connection() as conn:
                row = conn.execute(
                    "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                    [user.id],
                ).fetchone()
                if row:
                    _cid = row[0]
        if not _cid:
            _cid = db.get_default_client_id()
        
        # Single combined query for all metrics (1 connection, 1 validation load)
        # 4.1.0 P7 — cache rollup per tenant for ~60s. The dashboard is the
        # single most-hit page after login, and the metric set is an aggregate
        # of aggregates (rule scores, validation freshness, threat counts) that
        # changes much slower than the rule-edit pulse. Cache is per
        # client_id so tenants never see each other's roll-ups.
        from app.services.ttl_cache import dashboard_cache
        rule_metrics, promotion_metrics, threat_metrics = dashboard_cache.get_or_compute(
            ("dashboard-metrics", _cid or "__global__"),
            lambda: db.get_dashboard_metrics(client_id=_cid),
        )
        
        # Integration / repo status (same as settings page)
        env_settings = get_settings()
        app_settings = db.get_all_settings()
        repo_status = {
            "mitre_enterprise": os.path.isfile(os.path.join(env_settings.mitre_repo_path, "enterprise-attack.json")),
            "mitre_mobile": os.path.isfile(os.path.join(env_settings.mitre_repo_path, "mobile-attack.json")),
            "mitre_ics": os.path.isfile(os.path.join(env_settings.mitre_repo_path, "ics-attack.json")),
            "mitre_pre": os.path.isfile(os.path.join(env_settings.mitre_repo_path, "pre-attack.json")),
            "sigma": os.path.isdir(os.path.join(env_settings.sigma_repo_path, "rules")),
            "elastic_detection": os.path.isdir(env_settings.elastic_repo_path),
        }

        # Inventory / CVE stats (best-effort — won't crash dashboard if engine unavailable)
        try:
            inventory_stats = get_inventory_stats()
            cve_stats = get_cve_overview_stats()
            baselines_overview = get_baselines_overview()
        except Exception:
            inventory_stats = None
            cve_stats = None
            baselines_overview = []
        
        return render_template(
            "pages/dashboard.html",
            request,
            {
                "user": user,
                "active_page": "dashboard",
                "rule_metrics": rule_metrics,
                "promotion_metrics": promotion_metrics,
                "threat_metrics": threat_metrics,
                "last_sync_time": get_last_sync_time(),
                "env": env_settings,
                "app_settings": app_settings,
                "repo_status": repo_status,
                "inventory_stats": inventory_stats,
                "cve_stats": cve_stats,
                "baselines_overview": baselines_overview,
            }
        )
    
    @app.get("/threats", response_class=HTMLResponse)
    def threats_page(request: Request, user: CurrentUser):
        """Threat Landscape page."""
        from app.services.database import get_database_service
        db = get_database_service()
        
        # Resolve active client for tenant-scoped coverage
        # (mirrors the resolution chain in deps.get_active_client)
        _cid = request.cookies.get("active_client_id")
        if not _cid and user:
            with db.get_connection() as conn:
                row = conn.execute(
                    "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                    [user.id],
                ).fetchone()
                if row:
                    _cid = row[0]
        if not _cid:
            _cid = db.get_default_client_id()

        # Resilience guard (4.1.7 Phase C): a concurrent threat sync can
        # leave ``threat_actors`` in a transiently inconsistent shape (the
        # MITRE phase calls ``clear_threat_actors`` mid-run) which made
        # ``get_threat_landscape_metrics`` raise and the page 500. Render an
        # empty landscape with a banner instead so the user can come back in
        # a moment without seeing a stack trace.
        from app.models.threats import ThreatLandscapeMetrics
        metrics_error = None
        try:
            metrics = db.get_threat_landscape_metrics(client_id=_cid)
        except Exception as exc:
            logger.exception(
                "threats_page: get_threat_landscape_metrics failed for "
                "client=%s: %r", _cid, exc,
            )
            metrics = ThreatLandscapeMetrics()
            metrics_error = (
                "Threat landscape metrics are temporarily unavailable. "
                "Reload in a few seconds. "
                "If this persists, run `docker exec tide-app python -m "
                "app.scripts.diag_sync` and check section 6 for the "
                "underlying error."
            )

        # Derive filter options from metrics (avoids a second DB connection)
        origins = sorted(metrics.origin_breakdown.keys()) if metrics.origin_breakdown else []
        sources = sorted(metrics.source_breakdown.keys()) if metrics.source_breakdown else []

        return render_template(
            "pages/threat_landscape.html",
            request,
            {
                "user": user,
                "active_page": "threats",
                "metrics": metrics,
                "metrics_error": metrics_error,
                "origins": origins,
                "sources": sources,
                "last_sync_time": get_last_sync_time(),
            }
        )
    
    @app.get("/promotion", response_class=HTMLResponse)
    def promotion_page(request: Request, user: CurrentUser):
        """Promotion page - Promote staging rules to production."""
        from app.services.database import get_database_service
        db = get_database_service()
        
        # Resolve active client (same pattern as sigma_page / rule_health_page)
        _cid = request.cookies.get("active_client_id")
        if not _cid and user:
            with db.get_connection() as conn:
                row = conn.execute(
                    "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                    [user.id],
                ).fetchone()
                if row:
                    _cid = row[0]
        if not _cid:
            _cid = db.get_default_client_id()

        staging_spaces = db.get_client_siem_spaces(_cid, environment_role="staging") if _cid else []
        production_spaces = db.get_client_siem_spaces(_cid, environment_role="production") if _cid else []
        
        metrics = db.get_promotion_metrics(
            staging_spaces=staging_spaces or None,
            production_spaces=production_spaces or None,
        )
        
        return render_template(
            "pages/promotion.html",
            request,
            {
                "user": user,
                "active_page": "promotion",
                "metrics": metrics,
                "staging_spaces": staging_spaces,
                "production_spaces": production_spaces,
                "last_sync_time": get_last_sync_time(),
            }
        )
    
    @app.get("/sigma", response_class=HTMLResponse)
    def sigma_page(request: Request, user: CurrentUser, db: DbDep, technique: str = ""):
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
        
        # Coverage data for MITRE pills (single DB connection)
        covered_ttps, ttp_rule_counts = db.get_sigma_coverage_data()

        # Dynamic env-driven dropdowns — scoped to active client's SIEMs
        # Resolve active client (mirrors deps.get_active_client)
        _cid = request.cookies.get("active_client_id")
        if not _cid and user:
            with db.get_connection() as conn:
                row = conn.execute(
                    "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                    [user.id],
                ).fetchone()
                if row:
                    _cid = row[0]
        if not _cid:
            _cid = db.get_default_client_id()

        # Build deploy targets from client's linked SIEMs
        client_siems = db.get_client_siems(_cid) if _cid else []
        deploy_targets = []
        for s in client_siems:
            if s.get("space"):
                deploy_targets.append({
                    "space": s["space"],
                    "label": f'{s["label"]} ({s["environment_role"].title()})',
                    "environment_role": s["environment_role"],
                })

        indices = sigma_mod.get_elastic_indices()
        pipeline_files = sigma_mod.list_saved_pipelines()
        template_files = sigma_mod.list_saved_templates()
        
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
                "covered_ttps": covered_ttps,
                "ttp_rule_counts": ttp_rule_counts,
                "deploy_targets": deploy_targets,
                "indices": indices,
                "pipeline_files": pipeline_files,
                "template_files": template_files,
            }
        )
    
    @app.get("/attack-tree", response_class=HTMLResponse)
    def attack_tree_page(request: Request, user: CurrentUser):
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
    def presentation_page(request: Request, user: CurrentUser):
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
    def preferences_page(request: Request, user: CurrentUser):
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
    def settings_page(request: Request, user: CurrentUser, db: DbDep):
        """Settings page - configure integrations, logging, and system health."""
        import os
        from app import sigma_helper as sigma_mod
        from app.inventory_engine import list_classifications
        app_settings = db.get_all_settings()
        env_settings = get_settings()

        # Check actual repo/data connectivity on disk
        repo_status = {
            "mitre_enterprise": os.path.isfile(os.path.join(env_settings.mitre_repo_path, "enterprise-attack.json")),
            "mitre_mobile": os.path.isfile(os.path.join(env_settings.mitre_repo_path, "mobile-attack.json")),
            "mitre_ics": os.path.isfile(os.path.join(env_settings.mitre_repo_path, "ics-attack.json")),
            "mitre_pre": os.path.isfile(os.path.join(env_settings.mitre_repo_path, "pre-attack.json")),
            "sigma": os.path.isdir(os.path.join(env_settings.sigma_repo_path, "rules")),
            "elastic_detection": os.path.isdir(env_settings.elastic_repo_path),
        }

        return render_template(
            "pages/settings.html",
            request,
            {
                "user": user,
                "active_page": "settings",
                "app_settings": app_settings,
                "env": env_settings,
                "repo_status": repo_status,
                "sigma_indices": sigma_mod.get_elastic_indices(),
                "classifications": list_classifications(),
            }
        )
    
    @app.get("/clients", response_class=HTMLResponse)
    def clients_page(request: Request, user: CurrentUser, db: DbDep):
        """Client management page (admin only)."""
        if user and not user.is_admin():
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url="/", status_code=302)
        clients = db.list_clients()
        # Enrich each client dict with SIEM configs and users for the template
        for c in clients:
            c["_siem_configs"] = db.list_siem_configs(c["id"])
            c["_users"] = db.get_client_users(c["id"])
        return render_template(
            "pages/clients.html",
            request,
            {
                "user": user,
                "active_page": "clients",
                "clients": clients,
            }
        )

    @app.get("/clients/{client_id}", response_class=HTMLResponse)
    def client_detail_page(request: Request, client_id: str, user: CurrentUser, db: DbDep):
        """Client detail page with SIEM linking and user assignment."""
        if user and not user.is_admin():
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url="/", status_code=302)
        client = db.get_client(client_id)
        if not client:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Client not found")
        client_siems = db.get_client_siems(client_id)
        client_users = db.get_client_users(client_id)
        # Available SIEMs — show all so same SIEM can be linked as production + staging
        all_siems = db.list_siem_inventory()
        available_siems = all_siems
        # OpenCTI instances linked to this client
        client_opencti = db.get_client_opencti_instances(client_id)
        all_opencti = db.list_opencti_inventory()
        linked_opencti_ids = {o["id"] for o in client_opencti}
        available_opencti = [o for o in all_opencti if o["id"] not in linked_opencti_ids]
        # Available users not yet assigned
        all_users = db.get_all_users()
        assigned_user_ids = {u["id"] for u in client_users}
        available_users = [u for u in all_users if u["id"] not in assigned_user_ids]
        # Roles available for tenant assignment + each assigned user's current role.
        all_roles = db.get_all_roles()
        for u in client_users:
            roles_in_tenant = db.get_user_roles(u["id"], client_id=client_id)
            u["_current_role"] = roles_in_tenant[0] if roles_in_tenant else ""
        # Systems and baselines assigned to this client
        from app.inventory_engine import list_systems, list_playbooks, get_system_summaries
        from app.services.tenant_manager import tenant_context_for
        with tenant_context_for(client_id):
            client_systems = list_systems(client_id=client_id)
            client_baselines = list_playbooks(client_id=client_id)
            all_systems = list_systems()
            all_baselines = list_playbooks()
            system_summaries = get_system_summaries(client_id=client_id)
        # Available systems/baselines not already assigned to this client
        assigned_sys_ids = {s.id for s in client_systems}
        available_systems = [s for s in all_systems if s.id not in assigned_sys_ids]
        assigned_bl_ids = {b.id for b in client_baselines}
        available_baselines = [b for b in all_baselines if b.id not in assigned_bl_ids]
        # SIEM rule counts by space (total + enabled)
        siem_rule_counts = {}
        try:
            import duckdb
            conn = duckdb.connect(str(db.db_path), read_only=False)  # 4.1.0 P3: pool conflict
            rows = conn.execute(
                "SELECT space, COUNT(*) as total, SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) as enabled FROM detection_rules WHERE space IS NOT NULL GROUP BY space"
            ).fetchall()
            conn.close()
            for space, total, enabled in rows:
                siem_rule_counts[str(space)] = {"total": int(total), "enabled": int(enabled)}
        except Exception:
            pass
        return render_template(
            "pages/client_detail.html",
            request,
            {
                "user": user,
                "active_page": "management",
                "client": client,
                "client_siems": client_siems,
                "client_users": client_users,
                "available_siems": available_siems,
                "available_users": available_users,
                "all_roles": all_roles,
                "known_kibana_spaces": (db.get_all_kibana_spaces() or []),
                "client_opencti": client_opencti,
                "available_opencti": available_opencti,
                "client_systems": client_systems,
                "client_baselines": client_baselines,
                "available_systems": available_systems,
                "available_baselines": available_baselines,
                "system_summaries": system_summaries,
                "siem_rule_counts": siem_rule_counts,
                "all_clients": [c for c in db.list_clients() if c["id"] != client_id],
            }
        )
    
    @app.get("/management", response_class=HTMLResponse)
    def management_page(request: Request, user: CurrentUser, db: DbDep):
        """Management hub — admin-only area for Clients, SIEMs, Users, Permissions."""
        if user and not user.is_admin():
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url="/", status_code=302)
        tab = request.query_params.get("tab", "clients")
        # The Management page now uses collapsible sections; only the
        # Tenants & Users sub-tabs (clients/users) honour ?tab=. Legacy
        # values (incl. the retired "permissions" sub-tab, now the
        # top-level Role Templates section) fall back to the default.
        if tab not in ("clients", "users"):
            tab = "clients"
        return render_template(
            "pages/management.html",
            request,
            {
                "user": user,
                "active_page": "management",
                "active_tab": tab,
            }
        )
    
    # --- SYNC API ---
    
    @app.post("/api/sync/elastic", response_class=HTMLResponse)
    async def trigger_elastic_sync(request: Request, user: CurrentUser, background_tasks: BackgroundTasks):
        """Trigger manual Elastic sync."""
        import asyncio
        
        # Reset status and start sync
        _sync_status["started_at"] = None
        _sync_status["finished_at"] = None
        _sync_status["rule_count"] = 0
        _update_sync_status("running", "Initialising sync...")
        
        asyncio.create_task(scheduled_sync())
        
        # Return a live sync tracker that polls for status
        return HTMLResponse("""
        <div id="sync-status"
             hx-get="/api/sync/status"
             hx-trigger="load, every 1s"
             hx-swap="outerHTML"
             class="sync-tracker sync-running">
            <span class="sync-spinner"></span>
            <span>Sync starting...</span>
        </div>
        """)
    
    @app.get("/api/sync/status", response_class=HTMLResponse)
    def get_sync_status(request: Request, user: CurrentUser):
        """Return current sync status as an HTMX partial."""
        state = _sync_status["state"]
        message = _sync_status["message"]
        
        if state == "running":
            elapsed = ""
            if _sync_status["started_at"]:
                secs = int(time.time() - _sync_status["started_at"])
                elapsed = f" ({secs}s)"
            return HTMLResponse(f"""
            <div id="sync-status"
                 hx-get="/api/sync/status"
                 hx-trigger="every 1s"
                 hx-swap="outerHTML"
                 class="sync-tracker sync-running">
                <span class="sync-spinner"></span>
                <span>{message}{elapsed}</span>
            </div>
            """)
        elif state == "complete":
            return HTMLResponse(f"""
            <div id="sync-status" class="sync-tracker sync-complete">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                <span>Sync complete</span>
            </div>
            <script>
            document.body.dispatchEvent(new Event('refreshRules'));
            setTimeout(function(){{ var el=document.getElementById('sync-status'); if(el) el.outerHTML='<div id="sync-status"></div>'; }}, 4000);
            </script>
            """)
        elif state == "error":
            return HTMLResponse(f"""
            <div id="sync-status" class="sync-tracker sync-error">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="15" y1="9" x2="9" y2="15"/>
                    <line x1="9" y1="9" x2="15" y2="15"/>
                </svg>
                <span>Sync failed: {message}</span>
            </div>
            <script>setTimeout(function(){{ var el=document.getElementById('sync-status'); if(el) el.outerHTML='<div id="sync-status"></div>'; }}, 6000);</script>
            """)
        else:
            # idle
            return HTMLResponse('<div id="sync-status"></div>')
    
    return app


# Create app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
