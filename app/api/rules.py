"""
API routes for Detection Rules (Rule Health page).
"""

from fastapi import APIRouter, Request, Query, BackgroundTasks
from fastapi.responses import HTMLResponse
from typing import Optional

from app.api.deps import DbDep, CurrentUser, RequireUser, SettingsDep
from app.models.rules import RuleFilters

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("", response_class=HTMLResponse)
async def list_rules(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    search: Optional[str] = Query(None),
    space: Optional[str] = Query(None),
    enabled: Optional[str] = Query(None),
    sort_by: str = Query("score_asc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(24, ge=1, le=100),
):
    """List detection rules with filtering and pagination."""
    filters = RuleFilters(
        search=search if search else None,
        space=space if space else None,
        enabled=None if not enabled else (enabled.lower() == 'true'),
        sort_by=sort_by,
        page=page,
        page_size=page_size,
    )
    
    rules, total, last_sync = db.get_rules(filters=filters)
    total_pages = max(1, (total + page_size - 1) // page_size)
    
    logger.info(f"Fetched {len(rules)} rules (total: {total}, page: {page}/{total_pages})")
    
    templates = request.app.state.templates
    context = {
        "request": request,
        "rules": rules,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "search": search or "",
        "space": space or "",
        "enabled": enabled or "",
        "sort_by": sort_by,
    }
    return templates.TemplateResponse("partials/rules_grid.html", context)


@router.get("/metrics", response_class=HTMLResponse)
async def get_metrics(
    request: Request,
    db: DbDep,
    user: CurrentUser,
):
    """Get rule health metrics."""
    metrics = db.get_rule_health_metrics()
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "partials/metrics_row.html",
        {"request": request, "metrics": metrics}
    )


@router.get("/{rule_id}/detail", response_class=HTMLResponse)
async def get_rule_detail(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: CurrentUser,
    space: str = Query("default"),
):
    """Get full rule details for modal display."""
    rule = db.get_rule_by_id(rule_id, space)
    
    if not rule:
        return HTMLResponse(
            '<div class="modal-overlay" onclick="this.remove()">'
            '<div class="modal-content" onclick="event.stopPropagation()">'
            '<p style="color: var(--color-danger);">Rule not found</p>'
            '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Close</button>'
            '</div></div>',
            status_code=404
        )
    
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "components/rule_detail_modal.html",
        {"request": request, "rule": rule}
    )


@router.post("/{rule_id}/validate", response_class=HTMLResponse)
async def validate_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    space: str = Query("default"),
):
    """Mark a rule as validated by the current user."""
    rule = db.get_rule_by_id(rule_id, space)
    
    if not rule:
        return HTMLResponse('<div class="empty-state">Rule not found</div>', status_code=404)
    
    username = user.name or user.username if user else "Unknown"
    db.save_validation(rule.name, username)
    rule = db.get_rule_by_id(rule_id, space)
    
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "components/rule_card.html",
        {"request": request, "rule": rule}
    )


@router.post("/sync", response_class=HTMLResponse)
async def sync_rules(
    request: Request,
    db: DbDep,
    user: RequireUser,
    background_tasks: BackgroundTasks,
    settings: SettingsDep,
):
    """Trigger an immediate sync of rules from Elastic."""
    import asyncio
    from app.services.sync import trigger_sync
    
    # Run the sync in background to not block the response
    asyncio.create_task(trigger_sync())
    
    # Return toast with auto-refresh trigger after 10 seconds
    # Increased delay to ensure sync completes before UI refresh
    response = HTMLResponse(
        '<div class="toast toast-success" onclick="this.remove()">'
        '🔄 Sync started. Page will refresh in 10 seconds...'
        '</div>'
        '<script>setTimeout(function(){ htmx.trigger(document.body, "refreshRules"); }, 10000);</script>'
    )
    return response
