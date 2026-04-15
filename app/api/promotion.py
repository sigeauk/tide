"""
API routes for Rule Promotion (environment-role aware).

The source/target Kibana spaces are resolved from the active client's
SIEM configuration via ``client_siem_map.environment_role``, not hardcoded.
"""

from fastapi import APIRouter, Request, Query, BackgroundTasks
from fastapi.responses import HTMLResponse
from typing import Optional, List

from app.api.deps import DbDep, CurrentUser, RequireUser, SettingsDep, ActiveClient
from app.models.rules import RuleFilters

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/promotion", tags=["promotion"])


@router.get("", response_class=HTMLResponse)
def list_staging_rules(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    search: Optional[str] = Query(None),
    enabled: Optional[str] = Query(None),
    sort_by: str = Query("score_asc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
):
    """List detection rules from the client's staging environment-role spaces."""
    staging_spaces = db.get_client_siem_spaces(client_id, environment_role="staging")

    filters = RuleFilters(
        search=search if search else None,
        space=None,
        enabled=None if not enabled else (enabled.lower() == 'true'),
        sort_by=sort_by,
        page=page,
        page_size=page_size,
        allowed_spaces=staging_spaces if staging_spaces else ["__none__"],
    )
    
    rules, total, last_sync = db.get_rules(filters=filters)
    total_pages = max(1, (total + page_size - 1) // page_size)
    
    logger.info(f"Fetched {len(rules)} staging rules (total: {total}, page: {page}/{total_pages})")
    
    templates = request.app.state.templates
    context = {
        "rules": rules,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "search": search or "",
        "enabled": enabled or "",
        "sort_by": sort_by,
    }
    return templates.TemplateResponse(request, "partials/promotion_grid.html", context)


@router.get("/metrics", response_class=HTMLResponse)
def get_promotion_metrics(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
):
    """Get metrics for staging rules only."""
    from app.main import get_last_sync_time
    staging_spaces = db.get_client_siem_spaces(client_id, environment_role="staging")
    production_spaces = db.get_client_siem_spaces(client_id, environment_role="production")
    metrics = db.get_promotion_metrics(
        staging_spaces=staging_spaces,
        production_spaces=production_spaces,
    )
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "partials/promotion_metrics.html",
        {"metrics": metrics, "last_sync_time": get_last_sync_time()}
    )


@router.get("/{rule_id}/detail", response_class=HTMLResponse)
def get_promotion_rule_detail(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: CurrentUser,
    settings: SettingsDep,
    client_id: ActiveClient,
):
    """Get full rule details for modal display."""
    staging_spaces = db.get_client_siem_spaces(client_id, environment_role="staging")

    # Try each staging space until the rule is found
    rule = None
    for sp in staging_spaces:
        rule = db.get_rule_by_id(rule_id, sp)
        if rule:
            break
    
    if not rule:
        return HTMLResponse(
            '<div class="modal-overlay" onclick="this.remove()">' 
            '<div class="modal-content" onclick="event.stopPropagation()">' 
            '<p style="color: var(--color-danger);">Rule not found in staging environment</p>'
            '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Close</button>'
            '</div></div>',
            status_code=404
        )
    
    templates = request.app.state.templates
    
    # Build space → env-role label mapping
    siems = db.get_client_siems(client_id)
    _sl = {s["space"]: f'{s["label"]} ({s["environment_role"].title()})' for s in siems if s.get("space")}
    
    return templates.TemplateResponse(
        request,
        "components/rule_detail_modal.html",
        {"rule": rule, "env": settings, "space_labels": _sl}
    )


@router.post("/{rule_id}/promote", response_class=HTMLResponse)
async def promote_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
):
    """
    Promote a rule from the client's staging space to their production space.
    Source/target Kibana spaces are resolved from client_siem_map.
    """
    import asyncio
    from app.elastic_helper import promote_rule_to_production
    
    staging_spaces = db.get_client_siem_spaces(client_id, environment_role="staging")
    production_spaces = db.get_client_siem_spaces(client_id, environment_role="production")

    if not staging_spaces:
        return HTMLResponse(
            '<div class="toast toast-danger" onclick="this.remove()">'
            'No staging SIEM configured for this client.'
            '</div>',
            status_code=400
        )
    if not production_spaces:
        return HTMLResponse(
            '<div class="toast toast-danger" onclick="this.remove()">'
            'No production SIEM configured for this client.'
            '</div>',
            status_code=400
        )

    # Find the rule in any staging space
    rule = None
    source_space = None
    for sp in staging_spaces:
        rule = db.get_rule_by_id(rule_id, sp)
        if rule:
            source_space = sp
            break
    
    if not rule:
        return HTMLResponse(
            '<div class="toast toast-danger" onclick="this.remove()">'
            'Rule not found in staging environment.'
            '</div>',
            status_code=404
        )

    target_space = production_spaces[0]
    
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
        _src, _tgt = source_space, target_space
        success, message = await loop.run_in_executor(
            None,
            lambda: promote_rule_to_production(
                rule_data=rule.raw_data,
                source_space=_src,
                target_space=_tgt
            )
        )
        
        if success:
            # Save validation record
            db.save_validation(rule.name, username)
            
            # Immediately update DuckDB: move the rule between spaces
            db.move_rule_space(rule_id, source_space, target_space)
            
            logger.info(f"Promoted rule '{rule.name}' from {source_space} to {target_space} by {username}")
            
            # Return success toast with trigger to refresh
            response = HTMLResponse(
                f'<div class="toast toast-success" onclick="this.remove()">' 
                f'Successfully promoted "{rule.name}" to production environment'
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
    force_mapping: bool = Query(False),
):
    """Trigger an immediate sync of rules from Elastic."""
    import asyncio
    from app.main import scheduled_sync, _sync_status, _update_sync_status
    
    # Reset status and start sync
    _sync_status["started_at"] = None
    _sync_status["finished_at"] = None
    _sync_status["rule_count"] = 0
    label = "Initialising full mapping sync..." if force_mapping else "Initialising sync..."
    _update_sync_status("running", label)
    
    asyncio.create_task(scheduled_sync(force_mapping=force_mapping))
    
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
