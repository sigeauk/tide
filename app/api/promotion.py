"""
API routes for Rule Promotion (environment-role aware).

The source/target Kibana spaces are resolved from the active client's
SIEM configuration via ``client_siem_map.environment_role``, not hardcoded.
"""

from fastapi import APIRouter, Request, Query, BackgroundTasks
from fastapi.responses import HTMLResponse
import json
from typing import Optional, List, Dict, Any

from app.api.deps import DbDep, CurrentUser, RequireUser, SettingsDep, ActiveClient
from app.models.rules import RuleFilters

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/promotion", tags=["promotion"])

_VOLATILE_DIFF_KEYS = {
    "execution_summary", "last_execution", "last_execution_at", "search_time",
    "updated_at", "created_at", "last_updated", "revision", "revision_id",
}


def _diff_rule_payloads(source: dict, target: dict) -> list[dict]:
    def clean(value):
        if isinstance(value, dict):
            return {
                key: clean(item) for key, item in value.items()
                if key not in _VOLATILE_DIFF_KEYS
            }
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value

    left = clean(source or {})
    right = clean(target or {})
    fields = sorted(set(left) | set(right))
    return [
        {"field": field, "source": left.get(field), "production": right.get(field)}
        for field in fields if left.get(field) != right.get(field)
    ]


def _build_promotion_filters(
    db,
    client_id: str,
    search: Optional[str] = None,
    enabled: Optional[str] = None,
    state: Optional[List[str]] = None,
    min_score: Optional[str] = None,
    max_score: Optional[str] = None,
    validated_from: Optional[str] = None,
    validated_to: Optional[str] = None,
    sort_by: str = "score_asc",
    sort_score: str = "",
    sort_validated: str = "",
    sort_name: str = "",
    page: int = 1,
    page_size: int = 10,
) -> RuleFilters:
    from app.api.rules import _parse_date_bound

    staging_scopes = db.get_client_siem_scopes(client_id, environment_role="staging")
    return RuleFilters(
        search=search or None,
        enabled=None if not enabled else (enabled.lower() == "true"),
        state=[value for value in (state or []) if value],
        min_score=int(min_score) if min_score and min_score.strip().lstrip("-").isdigit() else None,
        max_score=int(max_score) if max_score and max_score.strip().lstrip("-").isdigit() else None,
        validated_from=_parse_date_bound(validated_from, end_of_day=False),
        validated_to=_parse_date_bound(validated_to, end_of_day=True),
        sort_by=sort_by,
        sort_score=sort_score,
        sort_validated=sort_validated,
        sort_name=sort_name,
        page=page,
        page_size=page_size,
        allowed_scopes=staging_scopes if staging_scopes else [],
    )


def _promotion_metrics_from_rules(rules, production_total: int) -> Dict[str, Any]:
    scores = [int(rule.score or 0) for rule in rules]
    severity: Dict[str, int] = {}
    for rule in rules:
        value = str(getattr(rule.severity, "value", rule.severity) or "low").lower()
        severity[value] = severity.get(value, 0) + 1

    validated = sum(1 for rule in rules if rule.validation_status != "never")
    expired = sum(1 for rule in rules if rule.validation_status == "expired")
    total = len(rules)
    return {
        "staging_total": total,
        "staging_enabled": sum(1 for rule in rules if rule.enabled),
        "staging_avg_score": round(sum(scores) / total, 1) if total else 0,
        "staging_min_score": min(scores) if scores else 0,
        "staging_max_score": max(scores) if scores else 0,
        "staging_low_quality": sum(1 for score in scores if score < 50),
        "staging_high_quality": sum(1 for score in scores if score >= 80),
        "staging_quality_excellent": sum(1 for score in scores if score >= 80),
        "staging_quality_good": sum(1 for score in scores if 70 <= score < 80),
        "staging_quality_fair": sum(1 for score in scores if 50 <= score < 70),
        "staging_quality_poor": sum(1 for score in scores if score < 50),
        "staging_severity": severity,
        "staging_validated": validated,
        "staging_validation_expired": expired,
        "staging_never_validated": total - validated,
        "production_total": production_total,
    }


def _get_filtered_staging_rules(db, filters: RuleFilters, client_id: str):
    from app.api.rules import _resort_rules

    all_filters = filters.model_copy(update={"page": 1, "page_size": 1_000_000})
    rules, _, _ = db.get_rules(filters=all_filters, client_id=client_id)
    staging_scopes = {
        (str(siem_id), str(space).lower())
        for siem_id, space in (filters.allowed_scopes or [])
    }
    staging_rules = [
        rule for rule in rules
        if (str(rule.siem_id), str(rule.space).lower()) in staging_scopes
    ]
    return _resort_rules(
        staging_rules,
        filters.sort_score or "",
        filters.sort_validated or "",
        filters.sort_name or "",
        filters.sort_by or "score_asc",
    )


@router.get("", response_class=HTMLResponse)
def list_staging_rules(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    search: Optional[str] = Query(None),
    enabled: Optional[str] = Query(None),
    state: list[str] = Query([]),
    min_score: Optional[str] = Query(None),
    max_score: Optional[str] = Query(None),
    validated_from: Optional[str] = Query(None),
    validated_to: Optional[str] = Query(None),
    sort_by: str = Query("score_asc"),
    sort_score: str = Query(""),
    sort_validated: str = Query(""),
    sort_name: str = Query(""),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
    append: bool = Query(False),
):
    """List detection rules from the client's staging environment-role spaces."""
    staging_scopes = db.get_client_siem_scopes(client_id, environment_role="staging")
    filters = _build_promotion_filters(
        db, client_id, search, enabled, state, min_score, max_score,
        validated_from, validated_to, sort_by, sort_score, sort_validated,
        sort_name, page, page_size,
    )
    
    all_rules = _get_filtered_staging_rules(db, filters, client_id)
    total = len(all_rules)
    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size
    rules = all_rules[offset:offset + page_size]
    production_scopes = db.get_client_siem_scopes(client_id, environment_role="production")
    lifecycle_states = {
        f"{rule.rule_id}|{rule.siem_id}|{rule.space}": db.get_rule_lifecycle_state(
            rule.rule_id, staging_scopes, production_scopes
        )
        for rule in rules
    }
    
    logger.info(f"Fetched {len(rules)} staging rules (total: {total}, page: {page}/{total_pages})")
    
    templates = request.app.state.templates
    delete_source_default = bool(
        (db.get_client(client_id) or {}).get("delete_source_after_promotion", True)
    )
    logger.info(
        "Promotion source-delete default client_id=%s value=%s",
        client_id,
        delete_source_default,
    )
    context = {
        "rules": rules,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "search": search or "",
        "enabled": enabled or "",
        "state": [s for s in state if s],
        "min_score": min_score if min_score is not None else "",
        "max_score": max_score if max_score is not None else "",
        "validated_from": validated_from or "",
        "validated_to": validated_to or "",
        "sort_by": sort_by,
        "sort_score": sort_score,
        "sort_validated": sort_validated,
        "sort_name": sort_name,
        "lifecycle_states": lifecycle_states,
        "delete_source_default": delete_source_default,
        "append": append,
    }
    return templates.TemplateResponse(request, "partials/promotion_grid.html", context)


@router.get("/metrics", response_class=HTMLResponse)
def get_promotion_metrics(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    search: Optional[str] = Query(None),
    enabled: Optional[str] = Query(None),
    state: list[str] = Query([]),
    min_score: Optional[str] = Query(None),
    max_score: Optional[str] = Query(None),
    validated_from: Optional[str] = Query(None),
    validated_to: Optional[str] = Query(None),
):
    """Get metrics for the same filtered staging rules as the card list."""
    from app.main import get_last_sync_time
    staging_scopes = db.get_client_siem_scopes(client_id, environment_role="staging")
    production_scopes = db.get_client_siem_scopes(client_id, environment_role="production")
    base_metrics = db.get_promotion_metrics(
        staging_scopes=staging_scopes,
        production_scopes=production_scopes,
    )
    filters = _build_promotion_filters(
        db, client_id, search, enabled, state, min_score, max_score,
        validated_from, validated_to, page=1, page_size=1_000_000,
    )
    rules = _get_filtered_staging_rules(db, filters, client_id)
    metrics = _promotion_metrics_from_rules(rules, base_metrics["production_total"])
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


@router.get("/{rule_id}/diff", response_class=HTMLResponse)
def get_promotion_rule_diff(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    siem_id: Optional[str] = Query(None),
):
    migration = db.get_rule_migration_for_rule(rule_id)
    if not migration:
        return HTMLResponse('<div class="empty-state-text">No migrated counterpart is recorded.</div>', status_code=404)
    source = db.get_rule_by_id(
        migration["source_rule_id"], migration["source_space"],
        siem_id=migration["source_siem_id"], client_id=client_id,
    )
    target = db.get_rule_by_id(
        migration["target_rule_id"], migration["target_space"],
        siem_id=migration["target_siem_id"], client_id=client_id,
    )
    diffs = _diff_rule_payloads(
        getattr(source, "raw_data", None) if source else {},
        getattr(target, "raw_data", None) if target else {},
    )
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "components/rule_migration_diff.html",
        {"migration": migration, "source": source, "target": target, "diffs": diffs},
    )


@router.post("/{rule_id}/master", response_class=HTMLResponse)
async def set_promotion_master(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
):
    form = await request.form()
    side = str(form.get("master") or "production").lower()
    migration = db.get_rule_migration_for_rule(rule_id)
    if not migration or side not in {"staging", "production"}:
        return HTMLResponse('<div class="empty-state-text">Migration or master selection is invalid.</div>', status_code=400)
    if side == "staging":
        master_id = migration["source_rule_id"]
        master_siem = migration["source_siem_id"]
        master_space = migration["source_space"]
        old_id = migration["target_rule_id"]
    else:
        master_id = migration["target_rule_id"]
        master_siem = migration["target_siem_id"]
        master_space = migration["target_space"]
        old_id = migration["source_rule_id"]
    db.remap_rule_references(
        old_id, master_id, client_id,
        migration["source_siem_id"] if side == "production" else migration["target_siem_id"],
        migration["source_space"] if side == "production" else migration["target_space"],
        master_siem, master_space,
    )
    db.set_rule_migration_master(migration["id"], master_id, master_siem, master_space)
    db.record_rule_history(
        rule_id=master_id, siem_id=master_siem, space=master_space,
        client_id=client_id, action="master_selected", actor_user_id=user.id,
        actor_name=user.username,
        detail={"migration_id": migration["id"], "master": side, "previous_master": migration["master_rule_id"]},
    )
    return HTMLResponse('<div class="empty-state-text">Master rule updated and baseline references re-linked.</div>')


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
    form = await request.form()
    keep_source = str(form.get("keep_source") or "").lower() in {"1", "true", "on", "yes"}
    client = db.get_client(client_id) or {}
    explicit_delete = form.get("delete_source")
    if explicit_delete is not None:
        delete_source = str(explicit_delete).lower() in {"1", "true", "on", "yes"}
    else:
        delete_source = bool(client.get("delete_source_after_promotion", True)) and not keep_source
    logger.info(
        "Promotion decision client_id=%s rule_id=%s explicit_delete=%r "
        "client_default=%r keep_source=%r delete_source=%r",
        client_id,
        rule_id,
        explicit_delete,
        client.get("delete_source_after_promotion", True),
        keep_source,
        delete_source,
    )
    
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
        promotion_result = await loop.run_in_executor(
            None,
            lambda: promote_rule_to_production(
                rule_data=rule.raw_data,
                source_space=_src,
                target_space=_tgt,
                source_kibana_url=_src_url,
                source_api_key=_src_key,
                target_kibana_url=_tgt_url,
                target_api_key=_tgt_key,
                delete_source=delete_source,
            )
        )
        success, message = promotion_result[:2]
        target_rule_id = promotion_result[2] if len(promotion_result) > 2 else rule_id
        
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
            db.set_rule_deprecated(rule_id, source_siem.get("id"), source_space, delete_source)
            db.remap_rule_references(
                rule_id,
                target_rule_id,
                client_id,
                source_siem.get("id"),
                source_space,
                target_siem.get("id"),
                target_space,
            )
            db.record_rule_migration(
                source_rule_id=rule_id,
                source_siem_id=source_siem.get("id"),
                source_space=source_space,
                target_rule_id=target_rule_id,
                target_siem_id=target_siem.get("id"),
                target_space=target_space,
                source_retained=not delete_source,
                actor_user_id=user.id,
                actor_name=username,
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
                f' as {target_rule_id}'
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
