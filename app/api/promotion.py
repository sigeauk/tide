"""
API routes for Rule Promotion (Staging → Production).
"""

from fastapi import APIRouter, Request, Query, BackgroundTasks, Form
from fastapi.responses import HTMLResponse
from typing import Optional

from app.api.deps import DbDep, CurrentUser, RequireUser, SettingsDep
from app.models.rules import RuleFilters

import logging
import json

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/promotion", tags=["promotion"])


@router.get("", response_class=HTMLResponse)
def list_staging_rules(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    search: Optional[str] = Query(None),
    enabled: Optional[str] = Query(None),
    sort_by: str = Query("score_asc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
):
    """List detection rules from Staging space only."""
    filters = RuleFilters(
        search=search if search else None,
        space="staging",  # Always filter to staging
        enabled=None if not enabled else (enabled.lower() == 'true'),
        sort_by=sort_by,
        page=page,
        page_size=page_size,
    )
    
    rules, total, last_sync = db.get_rules(filters=filters)
    total_pages = max(1, (total + page_size - 1) // page_size)
    
    logger.info(f"Fetched {len(rules)} staging rules (total: {total}, page: {page}/{total_pages})")
    
    templates = request.app.state.templates
    context = {
        "request": request,
        "rules": rules,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "search": search or "",
        "enabled": enabled or "",
        "sort_by": sort_by,
    }
    return templates.TemplateResponse("partials/promotion_grid.html", context)


@router.get("/metrics", response_class=HTMLResponse)
def get_promotion_metrics(
    request: Request,
    db: DbDep,
    user: CurrentUser,
):
    """Get metrics for staging rules only."""
    from app.main import get_last_sync_time
    metrics = db.get_promotion_metrics()
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "partials/promotion_metrics.html",
        {"request": request, "metrics": metrics, "last_sync_time": get_last_sync_time()}
    )


@router.get("/{rule_id}/detail", response_class=HTMLResponse)
def get_promotion_rule_detail(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: CurrentUser,
):
    """Get full rule details for modal display."""
    rule = db.get_rule_by_id(rule_id, "staging")
    
    if not rule:
        return HTMLResponse(
            '<div class="modal-overlay" onclick="this.remove()">'
            '<div class="modal-content" onclick="event.stopPropagation()">'
            '<p style="color: var(--color-danger);">Rule not found in staging</p>'
            '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Close</button>'
            '</div></div>',
            status_code=404
        )
    
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "components/rule_detail_modal.html",
        {"request": request, "rule": rule}
    )


@router.post("/{rule_id}/promote", response_class=HTMLResponse)
async def promote_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
):
    """
    Promote a rule from Staging to Production.
    Uses elastic_helper.promote_rule_to_production function.
    """
    import asyncio
    from app.elastic_helper import promote_rule_to_production
    
    # Get the rule from staging
    rule = db.get_rule_by_id(rule_id, "staging")
    
    if not rule:
        return HTMLResponse(
            '<div class="toast toast-danger" onclick="this.remove()">'
            'Rule not found in staging space.'
            '</div>',
            status_code=404
        )
    
    # Get the raw_data for promotion
    if not rule.raw_data:
        return HTMLResponse(
            '<div class="toast toast-danger" onclick="this.remove()">'
            'Rule data not available for promotion.'
            '</div>',
            status_code=400
        )
    
    # Get username for validation record
    username = user.name or user.username if user else "Unknown"
    
    try:
        # Run the promotion (blocking call)
        loop = asyncio.get_event_loop()
        success, message = await loop.run_in_executor(
            None,
            lambda: promote_rule_to_production(
                rule_data=rule.raw_data,
                source_space="staging",
                target_space="production"
            )
        )
        
        if success:
            # Save validation record
            db.save_validation(rule.name, username)
            
            logger.info(f"Promoted rule '{rule.name}' to production by {username}")
            
            # Return success toast with trigger to refresh
            response = HTMLResponse(
                f'<div class="toast toast-success" onclick="this.remove()">'
                f'Successfully promoted "{rule.name}" to Production'
                f'</div>'
            )
            response.headers["HX-Trigger"] = "refreshPromotion"
            return response
        else:
            logger.error(f"Failed to promote rule '{rule.name}': {message}")
            return HTMLResponse(
                f'<div class="toast toast-danger" onclick="this.remove()">'
                f'Promotion failed: {message}'
                f'</div>',
                status_code=400
            )
    except Exception as e:
        logger.exception(f"Exception promoting rule '{rule.name}'")
        return HTMLResponse(
            f'<div class="toast toast-danger" onclick="this.remove()">'
            f'Error: {str(e)}'
            f'</div>',
            status_code=500
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
    from app.main import scheduled_sync, _sync_status, _update_sync_status
    
    # Reset status and start sync
    _sync_status["started_at"] = None
    _sync_status["finished_at"] = None
    _sync_status["rule_count"] = 0
    _update_sync_status("running", "Initialising sync...")
    
    asyncio.create_task(scheduled_sync())
    
    # Return live sync tracker that polls for status and refreshes grid on completion
    return HTMLResponse(
        '<div id="sync-status"'
        '     hx-get="/api/sync/status"'
        '     hx-trigger="load, every 1s"'
        '     hx-swap="outerHTML"'
        '     class="sync-tracker sync-running">'
        '    <span class="sync-spinner"></span>'
        '    <span>Sync starting...</span>'
        '</div>'
        '<script>'
        '(function poll(){'
        '  var iv=setInterval(function(){'
        '    var el=document.getElementById("sync-status");'
        '    if(el && el.classList.contains("sync-complete")){'
        '      clearInterval(iv);'
        '      htmx.trigger(document.body,"refreshPromotion");'
        '      htmx.ajax("GET","/api/promotion/metrics",{target:"#promotion-metrics",swap:"innerHTML"});'
        '    }'
        '  },1000);'
        '})();'
        '</script>'
    )
