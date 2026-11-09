"""The out-of-hours maintenance window (#82, app.services.maintenance).

Every signed-in page shows the restart it announces (``/notice``), and anyone signed in can delay it
(``/delay``). Super admins set the window up in Management -> Maintenance window (``/panel``,
``/schedule``), run it now (``/run``), and restart now or postpone an announced restart.
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.api.deps import RequireSuperadmin, RequireUser
from app.services import maintenance

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/maintenance", tags=["maintenance"])


def _notice(request: Request, message: str = "") -> HTMLResponse:
    return request.app.state.templates.TemplateResponse(request, "partials/maintenance_notice.html",
                                                        {"message": message})


@router.get("/notice", response_class=HTMLResponse)
def notice(request: Request, user: RequireUser):
    """The banner (every signed-in page checks it while the window is on)."""
    return _notice(request)


@router.post("/delay", response_class=HTMLResponse)
def delay(request: Request, user: RequireUser):
    """Delay the announced restart, or past the most it can be delayed, postpone it to the next window."""
    from app.main import schedule_maintenance_restart
    from app.services.log_context import audit_admin
    got = maintenance.delay(user.username)
    if got["ok"]:
        schedule_maintenance_restart(got["restart_at"])
        audit_admin("maintenance_restart_delay", user, restart_at=str(got["restart_at"] or "postponed"))
    return _notice(request, got["message"])


def _panel(request: Request, message: str = "", ok: bool = True) -> HTMLResponse:
    return request.app.state.templates.TemplateResponse(request, "partials/maintenance_panel.html", {
        "schedule": maintenance.get_schedule(), "summary": maintenance.summary(), "days": maintenance.DAY_NAMES,
        "steps": maintenance.STEPS, "last": maintenance.last_run(), "running": maintenance.running(),
        "pending": maintenance.pending(), "reclaim_pct": maintenance.RECLAIM_PCT,
        "reclaim_min_mb": maintenance.RECLAIM_MIN_FILE // (1024 * 1024), "message": message, "ok": ok,
    })


@router.get("/panel", response_class=HTMLResponse)
def panel(request: Request, user: RequireSuperadmin):
    return _panel(request)


@router.post("/schedule", response_class=HTMLResponse)
async def save_schedule(request: Request, user: RequireSuperadmin):
    from app.main import reschedule_maintenance_job
    from app.services.log_context import audit_admin
    form = await request.form()
    try:
        schedule = maintenance.save_schedule(
            form.get("enabled") == "on", form.getlist("days"), str(form.get("time", "")).strip(),
            {k: form.get(f"step_{k}") == "on" for k, _label in maintenance.STEPS})
    except ValueError as exc:
        return _panel(request, str(exc), ok=False)
    reschedule_maintenance_job()
    audit_admin("maintenance_window", user, **schedule)
    return _panel(request, f"The maintenance window runs {maintenance.summary(schedule).lower()}."
                  if schedule["enabled"] else "The maintenance window is off.")


@router.post("/run", response_class=HTMLResponse)
async def run_now(request: Request, user: RequireSuperadmin):
    """Run the window now, in the background, with the steps it has."""
    from app.main import _run_maintenance_window
    if maintenance.running():
        return _panel(request, "The maintenance window is already running.", ok=False)
    asyncio.get_running_loop().create_task(_run_maintenance_window(trigger="manual", by=user.username))
    await asyncio.sleep(0.2)
    return _panel(request, "Started.")


@router.post("/restart-now", response_class=HTMLResponse)
async def restart_now(request: Request, user: RequireSuperadmin):
    """Restart now to compact the files an announced restart is for (a moment after answering)."""
    from app.main import _maintenance_restart, schedule_maintenance_restart
    from app.services.log_context import audit_admin
    if not maintenance.pending():
        return _panel(request, "No restart is waiting.", ok=False)
    audit_admin("maintenance_restart_now", user)
    schedule_maintenance_restart(None)
    asyncio.get_running_loop().call_later(1.0, _maintenance_restart)
    return _panel(request, "TIDE is restarting to compact the files: it is back in a few minutes.")


@router.post("/postpone", response_class=HTMLResponse)
def postpone(request: Request, user: RequireSuperadmin):
    """Drop an announced restart: the next window measures the files again."""
    from app.main import schedule_maintenance_restart
    from app.services.log_context import audit_admin
    maintenance.postpone(user.username)
    schedule_maintenance_restart(None)
    audit_admin("maintenance_restart_postpone", user)
    return _panel(request, "Postponed to the next maintenance window.")
