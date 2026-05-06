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
    staging_scopes = db.get_client_siem_scopes(client_id, environment_role="staging")

    filters = RuleFilters(
        search=search if search else None,
        space=None,
        enabled=None if not enabled else (enabled.lower() == 'true'),
        sort_by=sort_by,
        page=page,
        page_size=page_size,
        # Composite (siem_id, space) pairs — a space-only allow-list would
        # leak production-tagged rules into the staging view when two SIEMs
        # share a Kibana space name (AGENTS.md §8.2 g4).
        allowed_scopes=staging_scopes if staging_scopes else [],
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
    staging_scopes = db.get_client_siem_scopes(client_id, environment_role="staging")
    production_scopes = db.get_client_siem_scopes(client_id, environment_role="production")
    metrics = db.get_promotion_metrics(
        staging_scopes=staging_scopes,
        production_scopes=production_scopes,
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
    siem_id: Optional[str] = Query(None),
):
    """Get full rule details for modal display."""
    staging_siems = db.get_client_siems(client_id, environment_role="staging")

    # Try each staging (siem, space) until the rule is found. Scoped by
    # siem_id since 4.0.13 \u2014 multiple SIEMs may share a space name and the
    # rule we want to promote belongs to a specific one.
    candidate_siems = staging_siems
    if siem_id:
        candidate_siems = [s for s in staging_siems if s.get("id") == siem_id]
    rule = None
    matches = []
    for siem in candidate_siems:
        sp = siem.get("space")
        if not sp:
            continue
        _rule = db.get_rule_by_id(rule_id, sp, siem_id=siem.get("id"))
        if _rule:
            matches.append((siem, _rule))

    if len(matches) == 1:
        rule = matches[0][1]
    elif len(matches) > 1:
        return HTMLResponse(
            '<div class="modal-overlay" onclick="this.remove()">'
            '<div class="modal-content" onclick="event.stopPropagation()">'
            '<p style="color: var(--color-danger);">Rule exists in multiple staging SIEMs. Re-open details from the specific SIEM card.</p>'
            '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Close</button>'
            '</div></div>',
            status_code=409,
        )
    
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
    siem_id: Optional[str] = Query(None),
):
    """
    Promote a rule from the client's staging space to their production space.
    Source/target Kibana spaces AND SIEM connections are resolved from the inventory.
    """
    import asyncio
    from app.elastic_helper import promote_rule_to_production
    
    staging_siems = db.get_client_siems(client_id, environment_role="staging")
    production_siems = db.get_client_siems(client_id, environment_role="production")

    if not staging_siems:
        return HTMLResponse(
            '<div class="toast toast-danger" onclick="this.remove()">'
            'No staging SIEM configured for this client.'
            '</div>',
            status_code=400
        )
    if not production_siems:
        return HTMLResponse(
            '<div class="toast toast-danger" onclick="this.remove()">'
            'No production SIEM configured for this client.'
            '</div>',
            status_code=400
        )

    # Find the rule in any staging space. Each (siem, space) pair is checked
    # individually so the lookup is unambiguous: the same rule_id can legally
    # exist in multiple staging SIEMs, and we must promote from the SIEM the
    # rule was actually fetched from. ``get_rule_by_id`` is called with the
    # explicit ``siem_id`` since 4.0.13 \u2014 prior versions silently picked
    # the first row matching (rule_id, space).
    rule = None
    source_space = None
    source_siem = None
    matches = []
    candidate_siems = staging_siems
    if siem_id:
        candidate_siems = [s for s in staging_siems if s.get("id") == siem_id]
        if not candidate_siems:
            return HTMLResponse(
                '<div class="toast toast-danger" onclick="this.remove()">'
                'Selected source SIEM is not linked as staging for this client.'
                '</div>',
                status_code=400,
            )
    for siem in candidate_siems:
        sp = siem.get("space")
        if not sp:
            continue
        _rule = db.get_rule_by_id(rule_id, sp, siem_id=siem.get("id"))
        if _rule:
            matches.append((siem, sp, _rule))

    if len(matches) == 1:
        source_siem, source_space, rule = matches[0]
    elif len(matches) > 1:
        return HTMLResponse(
            '<div class="toast toast-danger" onclick="this.remove()">'
            'Promotion blocked: rule is present in multiple staging SIEMs. Retry from the specific SIEM context.'
            '</div>',
            status_code=409,
        )
    
    if not rule:
        return HTMLResponse(
            '<div class="toast toast-danger" onclick="this.remove()">'
            'Rule not found in staging environment.'
            '</div>',
            status_code=404
        )

    if len(production_siems) > 1:
        return HTMLResponse(
            '<div class="toast toast-danger" onclick="this.remove()">'
            'Promotion blocked: multiple production SIEMs are linked. Keep one production target per client to avoid ambiguous routing.'
            '</div>',
            status_code=409,
        )

    target_siem = production_siems[0]
    target_space = target_siem.get("space") or "default"
    
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
        _src_url = source_siem.get("kibana_url")
        _src_key = source_siem.get("api_token_enc")
        _tgt_url = target_siem.get("kibana_url")
        _tgt_key = target_siem.get("api_token_enc")
        success, message = await loop.run_in_executor(
            None,
            lambda: promote_rule_to_production(
                rule_data=rule.raw_data,
                source_space=_src,
                target_space=_tgt,
                source_kibana_url=_src_url,
                source_api_key=_src_key,
                target_kibana_url=_tgt_url,
                target_api_key=_tgt_key,
            )
        )
        
        if success:
            # Save validation record
            db.save_validation(rule.name, username)

            # Immediately update DuckDB: move the rule between spaces. Scoped
            # by source_siem.id since 4.0.13 so we don't accidentally rename
            # an identically-keyed row owned by a different SIEM. If staging
            # and production live in different SIEMs the next sync will remove
            # the stale row from source_siem and add the fresh one under
            # target_siem \u2014 the optimistic local move is still useful for
            # single-SIEM deployments (source==target) which is the common case.
            db.move_rule_space(
                rule_id, source_space, target_space,
                siem_id=source_siem.get("id"),
            )
            
            logger.info(f"Promoted rule '{rule.name}' from {source_space} to {target_space} by {username}")

            # Fire-and-forget per-tenant sync so any cross-SIEM promotion
            # (where staging and production live on different SIEMs) gets
            # the fresh row under target_siem on the next render. Safe to
            # run unawaited — errors are logged inside scheduled_sync and
            # the optimistic local ``move_rule_space`` above already gave
            # the operator instant UI feedback.
            try:
                import asyncio
                from app.main import scheduled_sync
                asyncio.create_task(scheduled_sync(client_id=client_id))
            except Exception as _exc:  # pragma: no cover - background hint only
                logger.warning(f"Post-promote sync schedule failed: {_exc}")
            
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
    client_id: ActiveClient,
    background_tasks: BackgroundTasks,
    settings: SettingsDep,
    force_mapping: bool = Query(False),
):
    """Trigger an immediate per-tenant sync of rules from Elastic.

    Always scoped to the active tenant. Cross-tenant ``scope=all`` was
    removed in 4.1.13 — detection rules are per-tenant.
    """
    import asyncio
    from app.main import scheduled_sync, _sync_status, _update_sync_status
    
    # Reset status and start sync
    _sync_status["started_at"] = None
    _sync_status["finished_at"] = None
    _sync_status["rule_count"] = 0
    label = "Initialising full mapping sync..." if force_mapping else "Initialising sync..."
    _update_sync_status("running", label)
    
    asyncio.create_task(scheduled_sync(force_mapping=force_mapping, client_id=client_id))
    
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
