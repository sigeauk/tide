"""Structured logging foundation for TIDE (4.1.0 P1).

Provides:
- ``request_context`` ContextVar holding ``request_id``, ``user_id``, ``client_id``,
  ``route``, ``method``.
- ``ContextFilter`` — logging.Filter that copies the contextvar fields onto every
  LogRecord so any ``logger.info(...)`` call automatically inherits them.
- ``JsonFormatter`` — zero-dependency JSON line formatter (air-gap safe; we cannot
  rely on python-json-logger being in the image).
- ``configure_logging(format)`` — installs the filter + formatter on the root
  logger. Called once from the FastAPI lifespan.
- ``RequestContextMiddleware`` — Starlette middleware that allocates
  ``request_id`` per request, populates the contextvar, and emits the
  ``X-Request-ID`` response header.
- ``audit_log(event, **fields)`` — convenience emitter on the ``tide.audit``
  logger so call sites don't have to remember the channel name.

Format selection: env ``TIDE_LOG_FORMAT=json`` (default in container) → JSON
lines; anything else → human readable. JSON shape is the contract documented in
``.github/plan.md`` §3.1.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
import time
import traceback
import uuid
from typing import Any, Dict, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# ── Contextvar carrying per-request metadata ────────────────────────────────
# Stored as a plain dict so the middleware can mutate fields after auth has
# resolved the user/client without needing a second contextvar.
_EMPTY: Dict[str, Any] = {}
request_context: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    "tide_request_context", default=_EMPTY
)


# ── Tenant scope enforcement (Plan §2.1.1) ──────────────────────────────────
# Routes that legitimately do NOT require a tenant context. Anything else
# under /api/* or a server-rendered page route MUST resolve a tenant via
# get_active_client before touching the DB. The middleware classifies the
# inbound path and stamps `tenant_required` on the request_context dict;
# DatabaseService.get_connection() reads it to decide whether to enforce.
_TENANT_OPTIONAL_PREFIXES = (
    "/static/",
    "/auth/",
    "/login",
    "/logout",
    "/health",
    "/api/system/",       # /api/system/migration-status
    "/api/external/",     # external sharing API resolves tenant from API key
    "/api/clients",       # listing + switching tenants is pre-tenant
    "/api/management/",   # super-admin scoped, may operate cross-tenant
)


def path_requires_tenant(path: str) -> bool:
    """Return True if a request to *path* must resolve a tenant before
    reading from the DB. Conservative: defaults to True for unknown paths."""
    for prefix in _TENANT_OPTIONAL_PREFIXES:
        if path.startswith(prefix):
            return False
    return True


def get_context() -> Dict[str, Any]:
    """Return the active request context dict (read-only view)."""
    return request_context.get()


def set_context_fields(**fields: Any) -> None:
    """Update fields on the active request context. No-op outside a request."""
    ctx = request_context.get()
    if ctx is _EMPTY:
        return
    ctx.update({k: v for k, v in fields.items() if v is not None})


# ── logging.Filter that injects context fields into every record ─────────────
class ContextFilter(logging.Filter):
    """Copies contextvar fields onto each LogRecord.

    We assign with ``setattr`` so the JsonFormatter (or any %()s formatter) can
    pull them by name. Missing fields default to ``-`` to keep the human format
    aligned without conditional logic.
    """

    _FIELDS = ("request_id", "user_id", "client_id", "route", "method")

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        ctx = request_context.get()
        for field in self._FIELDS:
            if not hasattr(record, field):
                setattr(record, field, ctx.get(field, "-"))
        return True


# ── JSON line formatter (no third-party dep) ────────────────────────────────
_RESERVED_LOGRECORD_KEYS = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "message", "module",
    "msecs", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName", "taskName",
}


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record.

    Standard fields: ``ts``, ``level``, ``logger``, ``msg``, ``request_id``,
    ``user_id``, ``client_id``, ``route``, ``method``. Any extra kwargs passed
    via ``logger.info("msg", extra={...})`` are merged at the top level
    (collision with reserved fields is avoided by skipping LogRecord standard
    keys). Exceptions are serialised as a single ``exc_info`` string so the
    line stays grep-friendly.
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
                  + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
            "user_id": getattr(record, "user_id", "-"),
            "client_id": getattr(record, "client_id", "-"),
            "route": getattr(record, "route", "-"),
            "method": getattr(record, "method", "-"),
        }
        # Merge any extra=... fields the caller attached.
        for key, value in record.__dict__.items():
            if key in _RESERVED_LOGRECORD_KEYS or key in payload:
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)
        if record.exc_info:
            payload["exc_info"] = "".join(
                traceback.format_exception(*record.exc_info)
            ).strip()
        return json.dumps(payload, default=str, ensure_ascii=False)


_HUMAN_FORMAT = (
    "%(asctime)s | %(levelname)-7s | req=%(request_id)s "
    "client=%(client_id)s user=%(user_id)s | %(name)s | %(message)s"
)


def configure_logging(level: int = logging.INFO, fmt: Optional[str] = None) -> None:
    """Install the structured logging stack on the root logger.

    Idempotent: a sentinel attribute on the root logger stops repeated wiring
    when ``configure_logging`` is called multiple times (e.g. uvicorn --reload).
    """
    root = logging.getLogger()
    if getattr(root, "_tide_configured", False):
        return

    fmt = (fmt or os.getenv("TIDE_LOG_FORMAT", "json")).lower()

    # Drop any handlers basicConfig may have attached so we don't double-emit.
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(ContextFilter())
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            _HUMAN_FORMAT, datefmt="%Y-%m-%d %H:%M:%S"
        ))
    root.addHandler(handler)
    root.setLevel(level)

    # Quiet down noisy third-party libraries that would otherwise drown out
    # tide.* events at INFO. They stay reachable at DEBUG.
    for noisy in ("uvicorn.access", "apscheduler", "duckdb"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    root._tide_configured = True  # type: ignore[attr-defined]


# ── Convenience emitters for the documented event taxonomy ──────────────────
_audit_logger = logging.getLogger("tide.audit")
_perf_logger = logging.getLogger("tide.perf")
_error_logger = logging.getLogger("tide.error")


def audit_log(event: str, **fields: Any) -> None:
    """Emit a ``tide.audit`` INFO record. ``event`` is the taxonomy key
    (login, client_switch, role_change, rule_promote, baseline_create, …)."""
    _audit_logger.info(event, extra={"event": event, **fields})


def perf_log(route: str, status: int, elapsed_ms: float, **fields: Any) -> None:
    """One ``tide.perf`` line per HTTP request. Called by the timing
    middleware; not normally invoked from app code."""
    _perf_logger.info(
        "request",
        extra={"route": route, "status": status, "elapsed_ms": round(elapsed_ms, 1), **fields},
    )


def error_log(msg: str, *, exc: Optional[BaseException] = None, **fields: Any) -> None:
    """Emit a ``tide.error`` ERROR record with optional exception context.
    Prefer this over ``logger.exception`` at top-level handlers so the JSON
    line carries the standard taxonomy."""
    _error_logger.error(
        msg,
        exc_info=(type(exc), exc, exc.__traceback__) if exc else None,
        extra=fields,
    )


# ── Starlette middleware ────────────────────────────────────────────────────
class RequestContextMiddleware(BaseHTTPMiddleware):
    """Allocate a request id, populate the request_context contextvar, set the
    ``X-Request-ID`` response header, and emit one ``tide.perf`` line per
    request.

    Skips static asset paths (no perf line, no header) so the noise floor stays
    sane on pages that fan out to dozens of /static fetches.
    """

    _STATIC_PREFIXES = ("/static/",)

    async def dispatch(self, request: Request, call_next):  # noqa: D401
        path = request.url.path
        is_static = any(path.startswith(p) for p in self._STATIC_PREFIXES)

        # Honour an upstream X-Request-ID if the caller (nginx, sync_to_sigea,
        # external API consumer) supplied one — keeps trace continuity across
        # the proxy boundary. Fall back to a fresh uuid prefix.
        incoming = request.headers.get("X-Request-ID", "").strip()
        request_id = incoming[:32] if incoming else uuid.uuid4().hex[:12]

        ctx: Dict[str, Any] = {
            "request_id": request_id,
            "user_id": "-",
            "client_id": "-",
            "route": path,
            "method": request.method,
            # 4.1.0 P2: tenant-scope guard. The DB layer reads this flag to
            # decide whether get_connection() without a tenant context should
            # be treated as a leak attempt. Static + auth + system + external
            # API + management routes are exempt.
            "tenant_required": path_requires_tenant(path),
        }
        token = request_context.set(ctx)
        # Stash on request.state so downstream deps (get_active_client) can
        # update user_id / client_id without re-importing the contextvar.
        request.state.tide_log_ctx = ctx
        request.state.request_id = request_id

        start = time.perf_counter()
        status = 500
        try:
            response: Response = await call_next(request)
            status = response.status_code
            if not is_static:
                response.headers["X-Request-ID"] = request_id
            return response
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if not is_static:
                # Re-read the dict in case auth populated user_id / client_id.
                final_ctx = request_context.get()
                perf_log(
                    route=path,
                    status=status,
                    elapsed_ms=elapsed_ms,
                    user_id=final_ctx.get("user_id", "-"),
                    client_id=final_ctx.get("client_id", "-"),
                    method=request.method,
                )
            request_context.reset(token)
