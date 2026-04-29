"""
API routes for Detection Rules (Rule Health page).
"""

from fastapi import APIRouter, Request, Query, BackgroundTasks
from fastapi.responses import HTMLResponse
from typing import Optional

from app.api.deps import DbDep, CurrentUser, RequireUser, SettingsDep, ActiveClient
from app.models.rules import RuleFilters

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rules", tags=["rules"])


def _build_space_labels(db, client_id: str) -> dict:
    """Build space → environment-role label mapping for the active client."""
    try:
        siems = db.get_client_siems(client_id)
        return {s["space"]: f'{s["label"]} ({s["environment_role"].title()})' for s in siems if s.get("space")}
    except Exception:
        return {}


@router.get("", response_class=HTMLResponse)
def list_rules(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    search: Optional[str] = Query(None),
    space: Optional[str] = Query(None),
    enabled: Optional[str] = Query(None),
    sort_by: str = Query("score_asc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(24, ge=1, le=100),
):
    """List detection rules with filtering and pagination."""
    try:
        # Tenant isolation: restrict to spaces linked to the active client
        allowed_spaces = db.get_client_siem_spaces(client_id)
        
        filters = RuleFilters(
            search=search if search else None,
            space=space if space else None,
            enabled=None if not enabled else (enabled.lower() == 'true'),
            sort_by=sort_by,
            page=page,
            page_size=page_size,
            allowed_spaces=allowed_spaces,
        )
        
        rules, total, last_sync = db.get_rules(filters=filters)
        total_pages = max(1, (total + page_size - 1) // page_size)
        
        logger.info(f"Fetched {len(rules)} rules (total: {total}, page: {page}/{total_pages})")
        
        templates = request.app.state.templates
        context = {
            "rules": rules,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "search": search or "",
            "space": space or "",
            "enabled": enabled or "",
            "sort_by": sort_by,
            "space_labels": _build_space_labels(db, client_id),
        }
        return templates.TemplateResponse(request, "partials/rules_grid.html", context)
    except Exception as e:
        logger.exception(f"Failed to list rules (sort={sort_by}, space={space}): {e}")
        return HTMLResponse(
            '<div class="empty-state">'
            '<div class="empty-state-title">Error loading rules</div>'
            f'<p class="empty-state-text">An error occurred while loading rules. Check server logs for details.</p>'
            '</div>'
        )


@router.get("/metrics", response_class=HTMLResponse)
def get_metrics(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
):
    """Get rule health metrics."""
    from app.main import get_last_sync_time
    allowed_spaces = db.get_client_siem_spaces(client_id)
    metrics = db.get_rule_health_metrics(allowed_spaces=allowed_spaces)
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request, "partials/metrics_row.html",
        {"metrics": metrics, "last_sync_time": get_last_sync_time(), "space_labels": _build_space_labels(db, client_id)}
    )


@router.get("/{rule_id}/detail", response_class=HTMLResponse)
def get_rule_detail(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: CurrentUser,
    settings: SettingsDep,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(
        None,
        description="SIEM that owns this rule. Required for unambiguous "
                    "resolution when multiple SIEMs share a space name. "
                    "Falls back to first space-match (with WARN) if absent.",
    ),
):
    """Get full rule details for modal display."""
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id)
    
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
        request, "components/rule_detail_modal.html",
        {"rule": rule, "env": settings, "space_labels": _build_space_labels(db, client_id)}
    )


@router.post("/{rule_id}/validate", response_class=HTMLResponse)
def validate_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    settings: SettingsDep,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Mark a rule as validated by the current user."""
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id)
    
    if not rule:
        return HTMLResponse('<div class="empty-state">Rule not found</div>', status_code=404)
    
    username = user.name or user.username if user else "Unknown"
    db.save_validation(rule.name, username)
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id)
    
    templates = request.app.state.templates

    _sl = _build_space_labels(db, client_id) if client_id else {}

    # If called from the modal, re-render the modal instead of the card
    if request.headers.get("X-Return-Modal") == "true":
        return templates.TemplateResponse(
            request, "components/rule_detail_modal.html",
            {"rule": rule, "env": settings, "space_labels": _sl}
        )

    return templates.TemplateResponse(
        request, "components/rule_card.html",
        {"rule": rule, "space_labels": _sl}
    )


@router.post("/{rule_id}/test", response_class=HTMLResponse)
async def test_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    settings: SettingsDep,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(
        None,
        description="SIEM that owns this rule. Required since 4.0.13 for "
                    "unambiguous Kibana selection when multiple SIEMs are "
                    "mapped to the same space name. The legacy fallback "
                    "(first SIEM matching the space) is retained for one "
                    "release with a WARN log + UI banner.",
    ),
):
    """Test a detection rule against live Elasticsearch data via the Kibana Preview API."""
    import asyncio
    
    # Parse lookback from form body (sent via hx-include)
    form = await request.form()
    lookback = str(form.get("test-lookback", "24h"))
    allowed = {"1h", "6h", "24h", "7d", "30d"}
    if lookback not in allowed:
        lookback = "24h"
    
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id)
    if not rule:
        return HTMLResponse(
            '<div class="test-result test-error">Rule not found</div>',
            status_code=404
        )
    
    if not rule.raw_data:
        return HTMLResponse(
            '<div class="test-result test-error">Rule data not available for testing</div>',
            status_code=400
        )
    
    # Resolve the SIEM for this rule. The PREFERRED path (4.0.13+) is to use
    # the explicit siem_id query param — either passed by the rule_detail_modal
    # template (which knows rule.siem_id) or inferred from rule.siem_id below.
    # Falling back to space-only matching is ambiguous when two SIEMs share a
    # Kibana space name (e.g. both expose 'production') and was the root cause
    # of the 4.0.7→4.0.11 Test Rule 401 regression — the first SIEM matching
    # the space won, sending the request to the wrong Kibana with the wrong
    # API key. Until callers all pass siem_id we keep the fallback alive but
    # log loudly so it shows up in support bundles.
    resolved_siem_id = siem_id or getattr(rule, "siem_id", None)
    siem = None
    try:
        client_siems = db.get_client_siems(client_id)
    except Exception:
        client_siems = []
        logger.exception("Failed to load client SIEMs for client %s", client_id)

    if resolved_siem_id:
        for s in client_siems:
            if s.get("id") == resolved_siem_id:
                siem = s
                break
        if siem is None:
            logger.warning(
                "test_rule: rule siem_id=%s is not assigned to active client %s; "
                "refusing to fall back to space-match to avoid leaking across tenants",
                resolved_siem_id, client_id,
            )
            return HTMLResponse(
                '<div class="test-result test-error">'
                f"This rule was synced from a SIEM that is not assigned to the "
                f"current tenant. Re-assign the SIEM in Settings or run a sync "
                f"to refresh."
                '</div>',
                status_code=400,
            )
    else:
        # Legacy fallback: first SIEM whose space matches. Logged at WARN so
        # operators can see the deprecated path being exercised.
        logger.warning(
            "test_rule: siem_id missing for rule_id=%s space=%s client=%s — "
            "falling back to first space-match (DEPRECATED, ambiguous when "
            "multiple SIEMs share a space name; callers must pass siem_id)",
            rule_id, space, client_id,
        )
        for s in client_siems:
            if (s.get("space") or "default") == space:
                siem = s
                break

    if not siem or not siem.get("kibana_url") or not siem.get("api_token_enc"):
        return HTMLResponse(
            '<div class="test-result test-error">'
            f"No SIEM is assigned to this client for space '{space}'. "
            "Add a SIEM to this tenant in Settings and re-test."
            '</div>',
            status_code=400,
        )

    # Diagnostic context (4.0.13): customer upgraded 4.0.7 -> 4.0.11 and the
    # Test Rule popup started returning 401. The wire-format request is
    # byte-identical to 4.0.7 — only the source of kibana_url / api_key changed
    # (was .env, now siem_inventory). Log enough to compare without leaking
    # the secret: SIEM label, kibana_url, space, env role, key prefix + length.
    _key = siem.get("api_token_enc") or ""
    logger.info(
        "test_rule resolved SIEM client=%s space=%s siem_label=%s siem_id=%s "
        "kibana_url=%s env_role=%s api_key_prefix=%s api_key_len=%d es_url=%s",
        client_id, space, siem.get("label"), siem.get("id"),
        siem.get("kibana_url"), siem.get("environment_role"),
        _key[:8] + "..." if _key else "<empty>", len(_key),
        siem.get("elasticsearch_url"),
    )

    try:
        from app.elastic_helper import preview_detection_rule
        loop = asyncio.get_event_loop()
        hit_count, samples, error = await loop.run_in_executor(
            None,
            lambda: preview_detection_rule(
                rule.raw_data, space, lookback=lookback,
                kibana_url=siem["kibana_url"],
                api_key=siem["api_token_enc"],
                elasticsearch_url=siem.get("elasticsearch_url"),
            )
        )
        
        templates = request.app.state.templates
        return templates.TemplateResponse(
            request, "components/test_result_popup.html",
            {
                "rule": rule,
                "hit_count": hit_count,
                "samples": samples,
                "error": error,
                "lookback": lookback,
                "space_labels": _build_space_labels(db, client_id),
            }
        )
    except Exception as e:
        logger.exception(f"Test rule failed for {rule_id}")
        return HTMLResponse(
            f'<div class="test-result test-error">Error: {str(e)}</div>',
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
        '      htmx.trigger(document.body,"refreshRules");'
        '      htmx.ajax("GET","/api/rules/metrics",{target:"#metrics-row",swap:"innerHTML"});'
        '    }'
        '  },1000);'
        '})();'
        '</script>'
    )
