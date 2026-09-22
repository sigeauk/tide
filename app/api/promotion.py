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

from app.services.rule_diff import build_rule_diff

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/promotion", tags=["promotion"])

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
    diffs = None
    if source and target:
        diffs = build_rule_diff(
            getattr(source, "raw_data", None) or {},
            getattr(target, "raw_data", None) or {},
        )
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "components/rule_migration_diff.html",
        {"migration": migration, "source": source, "target": target, "diffs": diffs},
    )


def _push_master_to_counterpart(db, client_id: str, migration: Dict[str, Any], side: str,
                                user_id: str, username: str):
    """Make the other copy of a migrated rule match the master, in its SIEM (blocking).

    ``side`` is the copy being made master ("staging" or "production"). Its content is written over
    the counterpart. The counterpart keeps its own enabled state, so choosing a master never switches
    a detection on or off. Returns ``(status_code, message)``; 200 means the counterpart was updated.
    """
    import copy
    from app.elastic_helper import promote_rule_to_production

    m, o = ("source", "target") if side == "staging" else ("target", "source")
    m_id, m_siem, m_space = migration[f"{m}_rule_id"], migration[f"{m}_siem_id"], migration[f"{m}_space"]
    o_id, o_siem, o_space = migration[f"{o}_rule_id"], migration[f"{o}_siem_id"], migration[f"{o}_space"]
    other_side = "production" if side == "staging" else "staging"

    master = db.get_rule_by_id(m_id, m_space, siem_id=m_siem, client_id=client_id)
    other = db.get_rule_by_id(o_id, o_space, siem_id=o_siem, client_id=client_id)
    if not master or not master.raw_data:
        return 404, f"The {side} copy no longer exists, so it cannot be the master."
    if not other:
        return 404, f"The {other_side} copy no longer exists, so there is nothing to update."
    siems = {s.get("id"): s for s in (db.get_client_siems(client_id) or [])}
    m_siem_row, o_siem_row = siems.get(m_siem), siems.get(o_siem)
    if not m_siem_row or not o_siem_row:
        return 400, "Both SIEMs must still be linked to this client to update the other copy."

    payload = copy.deepcopy(master.raw_data)
    payload["enabled"] = bool((other.raw_data or {}).get("enabled", False))
    try:
        result = promote_rule_to_production(
            rule_data=payload,
            source_space=m_space,
            target_space=o_space,
            source_kibana_url=m_siem_row.get("kibana_url"),
            source_api_key=m_siem_row.get("api_token_enc"),
            target_kibana_url=o_siem_row.get("kibana_url"),
            target_api_key=o_siem_row.get("api_token_enc"),
            delete_source=False,
        )
    except Exception as exc:
        logger.exception("Updating the %s copy from the %s master failed", other_side, side)
        return 500, f"Error: {exc}"
    success, message = result[:2]
    if not success:
        return 400, f"Could not update the {other_side} copy: {message}"
    db.record_rule_history(
        rule_id=o_id, siem_id=o_siem, space=o_space, client_id=client_id, action="master_synced",
        actor_user_id=user_id, actor_name=username,
        detail={"message": f"Updated to match the {side} copy, now the master.", "master": side},
    )
    return 200, f"The {other_side} copy was updated to match the {side} copy."


@router.post("/{rule_id}/master", response_class=HTMLResponse)
async def set_promotion_master(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
):
    """Choose which copy of a migrated rule is the master.

    The master's content is written over the other copy in its SIEM, baseline links are pointed at the
    master, and the choice is recorded. If the other copy cannot be updated nothing else changes.
    """
    from html import escape
    form = await request.form()
    side = str(form.get("master") or "production").lower()
    migration = db.get_rule_migration_for_rule(rule_id)
    if not migration or side not in {"staging", "production"}:
        return HTMLResponse('<div class="empty-state-text">Migration or master selection is invalid.</div>', status_code=400)
    username = user.name or user.username if user else "Unknown"

    status, message = await _run_in_context(
        _push_master_to_counterpart, db, client_id, migration, side, user.id, username,
    )
    if status != 200:
        return HTMLResponse(f'<div class="empty-state-text text-danger">{escape(message)}</div>', status_code=status)

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
    _schedule_client_sync(client_id)
    return HTMLResponse(
        f'<div class="empty-state-text">{escape(message)} Baseline references now point at the {side} rule. '
        f'A sync is refreshing the rule cache.</div>'
    )


def _restore_rule_sync(db, user_id: str, username: str, client_id: str, rule_id: str, siem_id: str, space: str):
    """Recreate a deprecated rule in the SIEM it came from (blocking). Returns ``(status_code, message)``."""
    from app.elastic_helper import restore_detection_rule

    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return 404, "Rule not found."
    if not rule.deprecated:
        return 400, "This rule is not deprecated."
    siem = next(
        (s for s in (db.get_client_siems(client_id) or [])
         if s.get("id") == siem_id and str(s.get("space") or "default").lower() == str(space).lower()),
        None,
    )
    if not siem:
        return 400, "This rule's SIEM and space are no longer linked to the client, so it cannot be restored there."
    if not rule.raw_data:
        return 400, "TIDE has no stored copy of this rule to restore from."

    ok, message, saved_id = restore_detection_rule(
        rule.raw_data, space=space, kibana_url=siem.get("kibana_url"), api_key=siem.get("api_token_enc"),
    )
    if not ok:
        return 400, f"Restore failed: {message}"

    # TIDE's row is keyed by the id it last synced. If that is the rule's own Kibana rule_id it survives
    # the restore, so the row just becomes active again. If it was the saved-object id, Kibana has now
    # issued a new one: keep the old row for history and move baseline links to the new identity.
    kibana_rule_id = (rule.raw_data or {}).get("rule_id")
    if kibana_rule_id and kibana_rule_id == rule_id:
        db.set_rule_deprecated(rule_id, siem_id, space, False)
    elif saved_id and saved_id != rule_id:
        db.remap_rule_references(rule_id, saved_id, client_id, siem_id, space, siem_id, space)
    else:
        db.set_rule_deprecated(rule_id, siem_id, space, False)
    db.record_rule_history(
        rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id, action="restored",
        actor_user_id=user_id, actor_name=username,
        detail={"message": message, "restored_disabled": True},
    )
    logger.info("Restored deprecated rule '%s' in %s by %s", rule.name, space, username)
    return 200, f'Restored "{rule.name}". It was recreated disabled; enable it when you are ready.'


@router.post("/{rule_id}/restore", response_class=HTMLResponse)
async def restore_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    siem_id: str = Query(...),
    space: str = Query("default"),
):
    """Bring a deprecated rule back: recreate it (disabled) in the SIEM it was removed from."""
    username = user.name or user.username if user else "Unknown"
    status, message = await _run_in_context(
        _restore_rule_sync, db, user.id, username, client_id, rule_id, siem_id, space,
    )
    if status != 200:
        return _toast("danger", message, status)
    _schedule_client_sync(client_id)
    return _toast("success", message, 200, trigger="refreshRules")


def _toast(kind: str, message: str, status_code: int = 200, trigger: Optional[str] = None) -> HTMLResponse:
    from html import escape
    response = HTMLResponse(
        f'<div class="toast toast-{kind}" onclick="this.remove()">{escape(message)}</div>',
        status_code=status_code,
    )
    if trigger:
        response.headers["HX-Trigger"] = trigger
    return response


async def _run_in_context(fn, *args):
    """Run blocking work in a thread, keeping the request's tenant context."""
    import asyncio
    import contextvars
    ctx = contextvars.copy_context()
    return await asyncio.get_running_loop().run_in_executor(None, lambda: ctx.run(fn, *args))


def _promote_rule_sync(db, user_id: str, username: str, client_id: str, rule_id: str,
                       siem_id: Optional[str], delete_source: bool, validation_mode: str = "stamp"):
    """Promote one staging rule to the client's production SIEM (blocking).

    ``validation_mode``: ``stamp`` records the rule as validated now by ``username`` (a rule is
    promoted because it was reviewed); ``keep`` leaves its validation as it is (SIEM-to-SIEM
    migrations); ``new_only`` stamps only rules that have never been validated.

    Returns ``(status_code, message, rule_name, target_rule_id)``; 200 means promoted.
    """
    from app.elastic_helper import promote_rule_to_production
    from app.services.database import validation_for, validation_key

    staging_siems = db.get_client_siems(client_id, environment_role="staging")
    production_siems = db.get_client_siems(client_id, environment_role="production")
    if not staging_siems:
        return 400, "No staging SIEM configured for this client.", None, None
    if not production_siems:
        return 400, "No production SIEM configured for this client.", None, None

    # Find the rule in a staging space. Each (siem, space) pair is checked individually: the same
    # rule_id can exist in several staging SIEMs and must be promoted from the SIEM it came from.
    candidate_siems = staging_siems
    if siem_id:
        candidate_siems = [s for s in staging_siems if s.get("id") == siem_id]
        if not candidate_siems:
            return 400, "Selected source SIEM is not linked as staging for this client.", None, None
    matches = []
    for siem in candidate_siems:
        sp = siem.get("space")
        if not sp:
            continue
        found = db.get_rule_by_id(rule_id, sp, siem_id=siem.get("id"))
        if found:
            matches.append((siem, sp, found))
    if len(matches) > 1:
        return 409, "Promotion blocked: rule is present in multiple staging SIEMs. Retry from the specific SIEM context.", None, None
    if not matches:
        return 404, "Rule not found in staging environment.", None, None
    source_siem, source_space, rule = matches[0]

    if len(production_siems) > 1:
        return 409, ("Promotion blocked: multiple production SIEMs are linked. Keep one production "
                     "target per client to avoid ambiguous routing."), rule.name, None
    target_siem = production_siems[0]
    target_space = target_siem.get("space") or "default"
    if not rule.raw_data:
        return 400, "Rule data not available for promotion.", rule.name, None

    try:
        result = promote_rule_to_production(
            rule_data=rule.raw_data,
            source_space=source_space,
            target_space=target_space,
            source_kibana_url=source_siem.get("kibana_url"),
            source_api_key=source_siem.get("api_token_enc"),
            target_kibana_url=target_siem.get("kibana_url"),
            target_api_key=target_siem.get("api_token_enc"),
            delete_source=delete_source,
        )
    except Exception as e:
        logger.exception(f"Exception promoting rule '{rule.name}'")
        return 500, f"Error: {e}", rule.name, None

    success, message = result[:2]
    target_rule_id = result[2] if len(result) > 2 else rule_id
    if not success:
        logger.error(f"Failed to promote rule '{rule.name}': {message}")
        return 400, f"Promotion failed: {message}", rule.name, None

    # Validation is stored under Kibana's own rule id, which the promoted copy keeps, so "keep"
    # needs no work: the copy is already validated exactly like the source.
    key = validation_key(rule.rule_id, rule.raw_data)
    validated_before = bool(validation_for(db._load_validation_data(), key, rule.name))
    if validation_mode == "stamp" or (validation_mode == "new_only" and not validated_before):
        db.save_validation(key, rule.name, username)

    # Move the rule in the local cache straight away, scoped by source SIEM. For a cross-SIEM
    # promotion the next sync removes the stale row and adds the target copy.
    db.set_rule_deprecated(rule_id, source_siem.get("id"), source_space, delete_source)
    db.remap_rule_references(
        rule_id, target_rule_id, client_id,
        source_siem.get("id"), source_space,
        target_siem.get("id"), target_space,
    )
    db.record_rule_migration(
        source_rule_id=rule_id,
        source_siem_id=source_siem.get("id"),
        source_space=source_space,
        target_rule_id=target_rule_id,
        target_siem_id=target_siem.get("id"),
        target_space=target_space,
        source_retained=not delete_source,
        actor_user_id=user_id,
        actor_name=username,
    )
    logger.info(f"Promoted rule '{rule.name}' from {source_space} to {target_space} by {username}")
    return 200, f'Successfully promoted "{rule.name}" to production environment as {target_rule_id}', rule.name, target_rule_id


def _schedule_client_sync(client_id: str) -> None:
    """Reconcile the tenant's rule cache in the background after promotions."""
    try:
        import asyncio
        from app.main import scheduled_sync
        asyncio.create_task(scheduled_sync(client_id=client_id))
    except Exception as _exc:  # pragma: no cover - background hint only
        logger.warning(f"Post-promote sync schedule failed: {_exc}")


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
        client_id, rule_id, explicit_delete,
        client.get("delete_source_after_promotion", True), keep_source, delete_source,
    )
    username = user.name or user.username if user else "Unknown"
    validation_mode = str(form.get("validation") or "stamp")
    status, message, _name, _target = await _run_in_context(
        _promote_rule_sync, db, user.id, username, client_id, rule_id, siem_id, delete_source, validation_mode,
    )
    if status != 200:
        return _toast("danger", message, status)
    _schedule_client_sync(client_id)
    return _toast("success", message, 200, trigger="refreshPromotion")


def _toast_error(message: str, status_code: int) -> HTMLResponse:
    return HTMLResponse(
        f'<div class="toast toast-danger" onclick="this.remove()">{message}</div>',
        status_code=status_code,
    )


def _demote_rule_sync(db, user_id: str, username: str, client_id: str, rule_id: str,
                      siem_id: Optional[str], delete_source: bool):
    """Send one production rule back to the client's staging SIEM (blocking).

    Returns ``(status_code, message, rule_name)``; 200 means demoted.
    """
    from app.elastic_helper import promote_rule_to_production

    staging_siems = db.get_client_siems(client_id, environment_role="staging")
    production_siems = db.get_client_siems(client_id, environment_role="production")
    if not production_siems:
        return 400, "No production SIEM configured for this client.", None
    if not staging_siems:
        return 400, "No staging SIEM configured for this client.", None
    if len(staging_siems) > 1:
        return 409, ("Demotion blocked: multiple staging SIEMs are linked. Keep one staging target "
                     "per client to avoid ambiguous routing."), None

    candidates = production_siems
    if siem_id:
        candidates = [s for s in production_siems if s.get("id") == siem_id]
        if not candidates:
            return 400, "Selected source SIEM is not linked as production for this client.", None
    matches = []
    for siem in candidates:
        sp = siem.get("space")
        if not sp:
            continue
        found = db.get_rule_by_id(rule_id, sp, siem_id=siem.get("id"))
        if found:
            matches.append((siem, sp, found))
    if not matches:
        return 404, "Rule not found in production environment.", None
    if len(matches) > 1:
        return 409, ("Demotion blocked: rule is present in multiple production SIEMs. Retry from the "
                     "specific SIEM context."), None
    source_siem, source_space, rule = matches[0]
    if not rule.raw_data:
        return 400, "Rule data not available for demotion.", rule.name

    target_siem = staging_siems[0]
    target_space = target_siem.get("space") or "default"

    try:
        result = promote_rule_to_production(
            rule_data=rule.raw_data,
            source_space=source_space,
            target_space=target_space,
            source_kibana_url=source_siem.get("kibana_url"),
            source_api_key=source_siem.get("api_token_enc"),
            target_kibana_url=target_siem.get("kibana_url"),
            target_api_key=target_siem.get("api_token_enc"),
            delete_source=delete_source,
        )
    except Exception as e:
        logger.exception(f"Exception demoting rule '{rule.name}'")
        return 500, f"Error: {e}", rule.name

    success, message = result[:2]
    staging_rule_id = result[2] if len(result) > 2 else rule_id
    if not success:
        logger.error(f"Failed to demote rule '{rule.name}': {message}")
        return 400, f"Demotion failed: {message}", rule.name

    if delete_source:
        db.set_rule_deprecated(rule_id, source_siem.get("id"), source_space, True)
        db.remap_rule_references(
            rule_id, staging_rule_id, client_id,
            source_siem.get("id"), source_space,
            target_siem.get("id"), target_space,
        )
    else:
        # The staging copy is the "source" of the pair and production stays the master.
        db.record_rule_migration(
            source_rule_id=staging_rule_id,
            source_siem_id=target_siem.get("id"),
            source_space=target_space,
            target_rule_id=rule_id,
            target_siem_id=source_siem.get("id"),
            target_space=source_space,
            source_retained=True,
            actor_user_id=user_id,
            actor_name=username,
        )
    db.record_rule_history(
        rule_id=rule_id, siem_id=source_siem.get("id"), space=source_space,
        client_id=client_id, action="demoted", actor_user_id=user_id, actor_name=username,
        detail={
            "message": "Demoted to staging" + ("; production copy deleted." if delete_source else "; production copy kept."),
            "staging_rule_id": staging_rule_id,
            "delete_source": delete_source,
        },
    )
    logger.info(f"Demoted rule '{rule.name}' from {source_space} to {target_space} by {username}")
    return (200,
            f'Demoted "{rule.name}" to the staging environment'
            f'{"" if delete_source else "; the production copy was kept"}',
            rule.name)


@router.post("/{rule_id}/demote", response_class=HTMLResponse)
async def demote_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    siem_id: Optional[str] = Query(None),
):
    """Send a production rule back to the client's staging space (the reverse of promote).

    The production copy is kept unless ``delete_source`` is set, so a demote never
    removes a live detection by accident. Kept copies show as Migrated.
    """
    form = await request.form()
    delete_source = str(form.get("delete_source") or "").lower() in {"1", "true", "on", "yes"}
    username = user.name or user.username if user else "Unknown"
    status, message, _name = await _run_in_context(
        _demote_rule_sync, db, user.id, username, client_id, rule_id, siem_id, delete_source,
    )
    if status != 200:
        return _toast_error(message, status)
    _schedule_client_sync(client_id)
    from html import escape
    response = HTMLResponse(f'<div class="toast toast-success" onclick="this.remove()">{escape(message)}</div>')
    response.headers["HX-Trigger"] = "refreshPromotion"
    return response


# ---------------------------------------------------------------------------
# Bulk promote
# ---------------------------------------------------------------------------

# One job per client, kept in memory. A job is started by a click and ends on its own; it is
# not a scheduled task.
_BULK_JOBS: Dict[str, Dict[str, Any]] = {}


def _bulk_candidates(request: Request, db, client_id: str):
    """Staging-only rules matching the Rule Health filters on the request, as ``(rule, status)``."""
    from app.api.rules import _get_filtered_deduped_rules, _parse_date_bound
    qp = request.query_params

    def _int(name):
        v = (qp.get(name) or "").strip()
        return int(v) if v.lstrip("-").isdigit() else None

    enabled = qp.get("enabled") or ""
    filters = RuleFilters(
        search=qp.get("search") or None,
        space=qp.get("space") or None,
        enabled=None if not enabled else enabled.lower() == "true",
        min_score=_int("min_score"),
        max_score=_int("max_score"),
        validated_from=_parse_date_bound(qp.get("validated_from"), end_of_day=False),
        validated_to=_parse_date_bound(qp.get("validated_to"), end_of_day=True),
    )
    rules = _get_filtered_deduped_rules(db, filters, client_id)
    staging = db.get_client_siem_scopes(client_id, environment_role="staging")
    production = db.get_client_siem_scopes(client_id, environment_role="production")
    states = db.get_rule_lifecycle_states_bulk([r.rule_id for r in rules], staging, production)
    return [r for r in rules if states.get(r.rule_id) == "Staging" and not r.deprecated]


def _render(request: Request, template: str, ctx: Dict[str, Any]) -> HTMLResponse:
    return request.app.state.templates.TemplateResponse(request, template, ctx)


@router.get("/bulk", response_class=HTMLResponse)
def bulk_promote_dialog(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Options dialog for promoting every staging rule that matches the current filters."""
    from urllib.parse import urlencode
    job = _BULK_JOBS.get(client_id)
    if job and job["state"] == "running":
        return _render(request, "components/bulk_promote_dialog.html", {"job": job})
    candidates = _bulk_candidates(request, db, client_id)
    counts = {"valid": 0, "amber": 0, "expired": 0, "never": 0}
    for r in candidates:
        counts[r.validation_status if r.validation_status in counts else "never"] += 1
    client = db.get_client(client_id) or {}
    return _render(request, "components/bulk_promote_dialog.html", {
        "total": len(candidates), "counts": counts,
        "delete_default": bool(client.get("delete_source_after_promotion", True)),
        "qs": urlencode([(k, v) for k, v in request.query_params.multi_items() if k != "state" and v]),
        "has_production": bool(db.get_client_siems(client_id, environment_role="production")),
    })


async def _run_bulk(job: Dict[str, Any], db, user_id: str, username: str, client_id: str, rules) -> None:
    from html import escape
    try:
        for rule in rules:
            if job["cancel"]:
                break
            job["current"] = rule.name
            status, message, _name, _target = await _run_in_context(
                _promote_rule_sync, db, user_id, username, client_id, rule.rule_id, rule.siem_id,
                job["delete_source"], job["validation_mode"],
            )
            job["done"] += 1
            if status == 200:
                job["ok"] += 1
            else:
                job["failed"] += 1
                if len(job["errors"]) < 10:
                    job["errors"].append(f"{rule.name}: {message}")
        job["state"] = "cancelled" if job["cancel"] else "done"
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Bulk promote crashed")
        job["state"] = "error"
        job["errors"].append(escape(str(exc)))
    finally:
        job["current"] = ""
        if job["ok"]:
            _schedule_client_sync(client_id)


@router.post("/bulk/start", response_class=HTMLResponse)
async def bulk_promote_start(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Start promoting every matching staging rule; returns the progress view."""
    import asyncio
    import time
    job = _BULK_JOBS.get(client_id)
    if job and job["state"] == "running":
        return _render(request, "components/bulk_promote_status.html", {"job": job})
    form = await request.form()
    if not db.get_client_siems(client_id, environment_role="production"):
        return _toast("danger", "No production SIEM configured for this client.", 400)
    validation_mode = str(form.get("validation") or "keep")
    if validation_mode not in ("stamp", "keep", "new_only"):
        validation_mode = "keep"
    rules = await _run_in_context(_bulk_candidates, request, db, client_id)
    if str(form.get("only_validated") or "") in {"1", "true", "on"}:
        rules = [r for r in rules if r.validation_status == "valid"]
    username = user.name or user.username if user else "Unknown"
    job = {
        "state": "running", "total": len(rules), "done": 0, "ok": 0, "failed": 0, "errors": [],
        "current": "", "cancel": False, "started": time.time(),
        "delete_source": str(form.get("delete_source") or "") in {"1", "true", "on"},
        "validation_mode": validation_mode,
    }
    if not rules:
        job["state"] = "done"
    else:
        _BULK_JOBS[client_id] = job
        import contextvars
        asyncio.get_running_loop().create_task(
            _run_bulk(job, db, user.id, username, client_id, rules), context=contextvars.copy_context()
        )
    _BULK_JOBS[client_id] = job
    logger.info(
        f"Bulk promote started client_id={client_id} rules={len(rules)} validation={validation_mode} "
        f"delete_source={job['delete_source']} by {username}"
    )
    return _render(request, "components/bulk_promote_status.html", {"job": job})


@router.get("/bulk/status", response_class=HTMLResponse)
def bulk_promote_status(request: Request, user: RequireUser, client_id: ActiveClient):
    job = _BULK_JOBS.get(client_id)
    if not job:
        return HTMLResponse("")
    return _render(request, "components/bulk_promote_status.html", {"job": job})


@router.post("/bulk/cancel", response_class=HTMLResponse)
def bulk_promote_cancel(request: Request, user: RequireUser, client_id: ActiveClient):
    """Stop after the rule currently being promoted."""
    job = _BULK_JOBS.get(client_id)
    if job and job["state"] == "running":
        job["cancel"] = True
    return _render(request, "components/bulk_promote_status.html", {"job": job or {"state": "done", "total": 0, "done": 0, "ok": 0, "failed": 0, "errors": [], "current": ""}})


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
