"""
API routes for moving a rule between SIEM+space destinations, and pushing content between two
linked rules.

Destinations are named, not roles: a client can link any number of (siem_id, space) pairs, each
under a free-text name chosen when it was linked (``client_siem_map.name``). "Move" replaces the
old promote/demote pair -- it is the same operation (copy or relocate a rule to another
destination), just no longer restricted to exactly one "staging" and one "production" SIEM.
Leaving the source in place records a link (``rule_links``) between the two rows.
"""

from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse
from typing import Optional, Dict, Any

from app.api.deps import DbDep, CurrentUser, RequireUser, ActiveClient

import logging

from app.services.rule_diff import build_rule_diff

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/promotion", tags=["promotion"])


def _parse_scope_pair(value: str):
    """``"<siem_id>|<space>"`` -> ``(siem_id, space)``, or ``(None, None)`` if malformed."""
    if not value or "|" not in value:
        return None, None
    siem_id, _, space = value.partition("|")
    siem_id, space = siem_id.strip(), space.strip()
    return (siem_id, space) if siem_id and space else (None, None)


def _pick_link(db, rule_id: str, siem_id: str, space: str,
                target_rule_id: Optional[str], target_siem_id: Optional[str], target_space: Optional[str]):
    """The link to act on: the one explicitly chosen (when a rule has more than one), or the
    only one there is. Returns ``None`` if the rule has no links, or the chosen target isn't
    actually one of them."""
    links = db.get_rule_links_bulk([(rule_id, siem_id, space)]).get((rule_id, siem_id, space)) or []
    links = [l for l in links if not l.get("missing")]
    if not links:
        return None
    if target_rule_id and target_siem_id and target_space:
        for l in links:
            if l["rule_id"] == target_rule_id and l["siem_id"] == target_siem_id and l["space"] == target_space:
                return l
        return None
    return links[0]


@router.get("/{rule_id}/diff", response_class=HTMLResponse)
def get_promotion_rule_diff(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    siem_id: Optional[str] = Query(None),
    space: str = Query("default"),
    target_rule_id: Optional[str] = Query(None),
    target_siem_id: Optional[str] = Query(None),
    target_space: Optional[str] = Query(None),
):
    all_links = db.get_rule_links_bulk([(rule_id, siem_id, space)]).get((rule_id, siem_id, space), []) if siem_id else []
    all_links = [l for l in all_links if not l.get("missing")]
    link = _pick_link(db, rule_id, siem_id, space, target_rule_id, target_siem_id, target_space) if siem_id else None
    if not link:
        return HTMLResponse('<div class="empty-state-text">This rule has no linked counterpart.</div>', status_code=404)
    source = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    target = db.get_rule_by_id(link["rule_id"], link["space"], siem_id=link["siem_id"], client_id=client_id)
    diffs = None
    if source and target:
        diffs = build_rule_diff(
            getattr(source, "raw_data", None) or {},
            getattr(target, "raw_data", None) or {},
        )
    # Rules on either side commonly share a name (that's often *why* they're linked -- the same
    # detection in two places), so every label in the template names the destination too, not
    # just the rule name.
    source_dest_name = next(
        (s.get("name") for s in (db.get_client_siems(client_id) or [])
         if s.get("id") == siem_id and str(s.get("space") or "default").lower() == str(space).lower()),
        space,
    )
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "components/rule_migration_diff.html",
        {"link": link, "source": source, "target": target, "diffs": diffs, "all_links": all_links,
         "source_rule_id": rule_id, "source_siem_id": siem_id, "source_space": space,
         "source_dest_name": source_dest_name},
    )


def _merge_rule_sync(db, client_id: str, rule_id: str, siem_id: str, space: str,
                     user_id: str, username: str, direction: str, delete_which: str,
                     target_rule_id: Optional[str] = None, target_siem_id: Optional[str] = None,
                     target_space: Optional[str] = None):
    """Merge two linked rules: one side's content overwrites the other's, in the other's own
    SIEM (blocking). ``direction`` is ``"source_over_target"`` (this rule's content overwrites
    the linked rule) or ``"target_over_source"`` (the reverse) -- "source" always means this
    rule, "target" always means the linked rule, regardless of which way content flows.
    ``delete_which`` (``"none"`` / ``"source"`` / ``"target"``) is an independent choice of which
    row, if either, to remove from TIDE afterward -- deliberately not tied to which side donated
    content, so e.g. merging source over target and then deleting *target* is allowed even
    though it looks unusual; it's the caller's call, not this function's to second-guess.
    Merging never switches a detection on or off -- whichever side is overwritten keeps its own
    enabled state.

    Returns ``(status_code, message, refresh_scope)``; 200 means merged. ``refresh_scope`` is
    ``(siem_id, space, rule_id)`` for whichever row TIDE should re-sync -- the one that was
    overwritten, or None if that same row was then deleted.
    """
    import copy
    from app.elastic_helper import promote_rule_to_production, delete_detection_rule

    link = _pick_link(db, rule_id, siem_id, space, target_rule_id, target_siem_id, target_space)
    if not link:
        return 404, "This rule has no linked counterpart.", None

    source = (rule_id, siem_id, space)
    target = (link["rule_id"], link["siem_id"], link["space"])
    source_rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    target_rule = db.get_rule_by_id(link["rule_id"], link["space"], siem_id=link["siem_id"], client_id=client_id)
    if not source_rule:
        return 404, "This rule no longer exists.", None
    if not target_rule:
        return 404, "The linked rule no longer exists.", None

    if direction == "target_over_source":
        donor, dest, donor_rule, dest_rule = target, source, target_rule, source_rule
    else:
        donor, dest, donor_rule, dest_rule = source, target, source_rule, target_rule
    donor_id, donor_siem, donor_space = donor
    dest_id, dest_siem, dest_space = dest

    if not donor_rule.raw_data:
        return 400, f'"{donor_rule.name}" has no stored content to merge from.', None
    siems = {s.get("id"): s for s in (db.get_client_siems(client_id) or [])}
    donor_siem_row, dest_siem_row = siems.get(donor_siem), siems.get(dest_siem)
    if not donor_siem_row or not dest_siem_row:
        return 400, "Both destinations must still be linked to this client to merge.", None

    payload = copy.deepcopy(donor_rule.raw_data)
    payload["enabled"] = bool((dest_rule.raw_data or {}).get("enabled", False))
    try:
        result = promote_rule_to_production(
            rule_data=payload,
            source_space=donor_space,
            target_space=dest_space,
            source_kibana_url=donor_siem_row.get("kibana_url"),
            source_api_key=donor_siem_row.get("api_token_enc"),
            target_kibana_url=dest_siem_row.get("kibana_url"),
            target_api_key=dest_siem_row.get("api_token_enc"),
            delete_source=False,
        )
    except Exception as exc:
        logger.exception("Merging '%s' onto '%s' failed", donor_rule.name, dest_rule.name)
        return 500, f"Error: {exc}", None
    success, message = result[:2]
    if not success:
        return 400, f"Could not merge: {message}", None
    db.record_rule_history(
        rule_id=dest_id, siem_id=dest_siem, space=dest_space, client_id=client_id,
        action="link_synced", actor_user_id=user_id, actor_name=username,
        detail={"message": f'Merged: updated to match "{donor_rule.name}".', "source_rule_id": donor_id,
                "source_siem_id": donor_siem, "source_space": donor_space},
    )

    friendly = f'Merged — "{dest_rule.name}" now matches "{donor_rule.name}".'
    refresh_scope = (dest_siem, dest_space, dest_id)
    to_delete = source if delete_which == "source" else (target if delete_which == "target" else None)
    if to_delete:
        # A real removal, unlike "Delete from TIDE" elsewhere in the app: the whole point of
        # deleting after a merge is ending that copy's existence, and a TIDE-only delete doesn't
        # do that -- the rule is still live in Elastic, so the very next sync (which fires after
        # almost every action) pulls it straight back into TIDE. Delete from the SIEM first;
        # only remove TIDE's own row once that succeeds, so a failed Elastic delete never leaves
        # TIDE believing a still-live rule is gone.
        del_id, del_siem, del_space = to_delete
        del_name = source_rule.name if to_delete == source else target_rule.name
        del_siem_row = siems.get(del_siem)
        if not del_siem_row:
            friendly += f' Could not delete "{del_name}" -- its SIEM is no longer linked to this client.'
        else:
            elastic_ok, elastic_msg = delete_detection_rule(
                del_id, del_space, del_siem_row.get("kibana_url"), del_siem_row.get("api_token_enc"),
            )
            if not elastic_ok:
                friendly += f' Could not delete "{del_name}" from its SIEM ({elastic_msg}) -- left in place in both Elastic and TIDE.'
            elif db.delete_rule(del_id, del_siem, del_space, remove_links=True):
                friendly += f' "{del_name}" was deleted from its SIEM and TIDE.'
                if to_delete == dest:
                    refresh_scope = None  # nothing left there worth re-syncing
            else:
                friendly += f' "{del_name}" was removed from its SIEM; its TIDE row was already gone.'
    return 200, friendly, refresh_scope


@router.post("/{rule_id}/merge", response_class=HTMLResponse)
async def merge_linked_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    siem_id: str = Query(...),
    space: str = Query("default"),
    target_rule_id: Optional[str] = Query(None),
    target_siem_id: Optional[str] = Query(None),
    target_space: Optional[str] = Query(None),
):
    """Merge this rule with its linked counterpart -- from the Compare view. Not to be confused
    with Find duplicate rules (``POST /api/rules/duplicates/resolve``), which folds two TIDE rows
    that turned out to be the same rule into one; this merges two rules that are deliberately,
    temporarily, both live.

    ``target_*`` picks which linked rule when there is more than one; omitted, and there is
    exactly one link, that one is used.
    """
    from html import escape
    form = await request.form()
    direction = str(form.get("direction") or "source_over_target")
    delete_which = str(form.get("delete_which") or "none")
    if delete_which not in {"none", "source", "target"}:
        delete_which = "none"
    username = user.name or user.username if user else "Unknown"
    status, message, refresh_scope = await _run_in_context(
        _merge_rule_sync, db, client_id, rule_id, siem_id, space, user.id, username, direction, delete_which,
        target_rule_id, target_siem_id, target_space,
    )
    if status != 200:
        return HTMLResponse(f'<div class="empty-state-text text-danger">{escape(message)}</div>', status_code=status)
    if refresh_scope:
        from app.api.rules import sync_single_rule
        await _run_in_context(sync_single_rule, db, client_id, refresh_scope[2], refresh_scope[0], refresh_scope[1],
                              user.id, username)
    return HTMLResponse(f'<div class="empty-state-text">{escape(message)}</div>')


def _restore_rule_sync(db, user_id: str, username: str, client_id: str, rule_id: str, siem_id: str, space: str):
    """Recreate a deprecated rule in the SIEM it came from (blocking).

    Returns ``(status_code, message, effective_rule_id)`` — ``effective_rule_id`` is ``rule_id``
    unless Kibana issued a new identity on recreation, in which case it is the new one (see the
    remap below); the caller needs it to refresh the right row afterwards."""
    from app.elastic_helper import restore_detection_rule

    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return 404, "Rule not found.", None
    if not rule.deprecated:
        return 400, "This rule is not deprecated.", None
    siem = next(
        (s for s in (db.get_client_siems(client_id) or [])
         if s.get("id") == siem_id and str(s.get("space") or "default").lower() == str(space).lower()),
        None,
    )
    if not siem:
        return 400, "This rule's SIEM and space are no longer linked to the client, so it cannot be restored there.", None
    if not rule.raw_data:
        return 400, "TIDE has no stored copy of this rule to restore from.", None

    ok, message, saved_id = restore_detection_rule(
        rule.raw_data, space=space, kibana_url=siem.get("kibana_url"), api_key=siem.get("api_token_enc"),
    )
    if not ok:
        return 400, f"Restore failed: {message}", None

    # TIDE's row is keyed by the id it last synced. If that is the rule's own Kibana rule_id it survives
    # the restore, so the row just becomes active again. If it was the saved-object id, Kibana has now
    # issued a new one: keep the old row for history and move baseline links to the new identity.
    kibana_rule_id = (rule.raw_data or {}).get("rule_id")
    effective_rule_id = rule_id
    if kibana_rule_id and kibana_rule_id == rule_id:
        db.set_rule_deprecated(rule_id, siem_id, space, False)
    elif saved_id and saved_id != rule_id:
        db.remap_rule_references(rule_id, saved_id, client_id, siem_id, space, siem_id, space)
        effective_rule_id = saved_id
    else:
        db.set_rule_deprecated(rule_id, siem_id, space, False)
    db.record_rule_history(
        rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id, action="restored",
        actor_user_id=user_id, actor_name=username,
        detail={"message": message, "restored_disabled": True},
    )
    logger.info("Restored deprecated rule '%s' in %s by %s", rule.name, space, username)
    return 200, f'Restored "{rule.name}". It was recreated disabled; enable it when you are ready.', effective_rule_id


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
    status, message, effective_rule_id = await _run_in_context(
        _restore_rule_sync, db, user.id, username, client_id, rule_id, siem_id, space,
    )
    if status != 200:
        return _toast("danger", message, status)
    from app.api.rules import sync_single_rule
    await _run_in_context(sync_single_rule, db, client_id, effective_rule_id, siem_id, space, user.id, username)
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


def _move_rule_sync(db, user_id: str, username: str, client_id: str, rule_id: str,
                    source_siem_id: str, source_space: str, target_siem_id: str, target_space: str,
                    delete_source: bool, validation_mode: str = "keep"):
    """Move (``delete_source``) or copy-and-link a rule to another destination (blocking).

    Copying (``delete_source=False``) always records a link between the two rows, regardless of
    whether they end up sharing an id -- see CHANGELOG on the promotion identity fix this replaces.

    Returns ``(status_code, message, rule_name, target_rule_id, target_scope)``; 200 means moved.
    ``target_scope`` is ``(target_siem_id, target_space)`` on success, else ``None`` -- the caller
    uses it to refresh just the destination row instead of the whole client.
    """
    from app.elastic_helper import promote_rule_to_production
    from app.services.database import validation_for, validation_key

    rule = db.get_rule_by_id(rule_id, source_space, siem_id=source_siem_id, client_id=client_id)
    if not rule:
        return 404, "Rule not found at the source.", None, None, None
    if not rule.raw_data:
        return 400, "Rule data not available to move.", rule.name, None, None

    client_siems = db.get_client_siems(client_id) or []
    source_siem_row = next((s for s in client_siems if s.get("id") == source_siem_id), None)
    target_siem_row = next(
        (s for s in client_siems if s.get("id") == target_siem_id
         and str(s.get("space") or "default").lower() == str(target_space).lower()),
        None,
    )
    if not source_siem_row or not target_siem_row:
        return 400, "Source or target destination is not linked to this client.", rule.name, None, None
    if (source_siem_id, str(source_space).lower()) == (target_siem_id, str(target_space).lower()):
        return 400, "Choose a different destination to move to.", rule.name, None, None

    # A rule's portable rule_id is shared by design across every copy of the same rule -- that's
    # exactly how linking recognises "these are the same detection." But it means the target
    # destination can already hold a *different* rule that happens to share this one's rule_id
    # (any two rules originally created independently in different spaces could coincide here,
    # and every copy of an already-linked rule definitely does). Moving into that destination
    # would silently overwrite it in Elastic -- no warning, no choice of which side wins -- since
    # promote_rule_to_production PUTs onto a matching rule_id instead of creating a new one.
    # Refuse and point at Merge, which makes that overwrite an explicit, named decision instead.
    #
    # Elastic is the authority on what is in the target space, not TIDE's own table: a rule
    # created there outside TIDE, or since the last sync, is invisible to detection_rules but
    # every bit as real, and it is exactly the copy nobody would expect a Move to destroy.
    # TIDE's row is still consulted first -- only it can name the local rule and tell whether
    # the two are already linked, which decides what the message tells the user to do instead.
    from app.elastic_helper import find_rule_in_space

    target_name = target_siem_row.get("name") or target_space
    existing_at_target = db.get_rule_by_id(rule.rule_id, target_space, siem_id=target_siem_id, client_id=client_id)
    live_state, live_rule = find_rule_in_space(
        rule.rule_id, target_space, target_siem_row.get("kibana_url"), target_siem_row.get("api_token_enc"),
    )
    if live_state == "unknown":
        return (
            400,
            f"Could not check whether {target_name} already holds this rule — its SIEM did not answer. "
            f"Moving without that answer risks overwriting a live rule, so nothing was changed. "
            f"Check the connection under Management and try again.",
            rule.name, None, None,
        )
    if existing_at_target or live_state == "found":
        clashing_name = (
            existing_at_target.name if existing_at_target
            else (live_rule or {}).get("name") or "A rule"
        )
        source_links = db.get_rule_links_bulk([(rule_id, source_siem_id, source_space)]).get(
            (rule_id, source_siem_id, source_space), [],
        )
        already_linked = bool(existing_at_target) and any(
            l["rule_id"] == existing_at_target.rule_id and l["siem_id"] == target_siem_id
            and str(l["space"]).lower() == str(target_space).lower()
            for l in source_links
        )
        if already_linked:
            how = ("use Merge from the Compare view instead — it shows the difference first and "
                   "lets you choose which side wins")
        elif existing_at_target:
            how = ("link the two first (Add link, in the rule window's Linked panel), then use "
                   "Merge to choose which side wins")
        else:
            # Live in Elastic, absent from TIDE: there is no row to link to yet.
            how = ("sync this client first so TIDE can see it, then link the two and use Merge "
                   "to choose which side wins")
        return (
            400,
            f'"{clashing_name}" already exists at {target_name} with this same rule id. '
            f'Moving here would silently overwrite it. If these are meant to be the same rule, {how}.',
            rule.name, None, None,
        )

    try:
        result = promote_rule_to_production(
            rule_data=rule.raw_data,
            source_space=source_space,
            target_space=target_space,
            source_kibana_url=source_siem_row.get("kibana_url"),
            source_api_key=source_siem_row.get("api_token_enc"),
            target_kibana_url=target_siem_row.get("kibana_url"),
            target_api_key=target_siem_row.get("api_token_enc"),
            delete_source=delete_source,
        )
    except Exception as e:
        logger.exception(f"Exception moving rule '{rule.name}'")
        return 500, f"Error: {e}", rule.name, None, None

    success, _kibana_message = result[:2]
    target_rule_id = result[2] if len(result) > 2 else rule_id
    if not success:
        logger.error(f"Failed to move rule '{rule.name}': {_kibana_message}")
        return 400, f"Move failed: {_kibana_message}", rule.name, None, None

    # Validation is stored under Kibana's own rule id, which the copy keeps, so "keep" needs no
    # work: the copy is already validated exactly like the source.
    key = validation_key(rule.rule_id, rule.raw_data)
    validated_before = bool(validation_for(db._load_validation_data(), key, rule.name))
    if validation_mode == "stamp" or (validation_mode == "new_only" and not validated_before):
        db.save_validation(key, rule.name, username)

    # Bring the new copy into TIDE's own tables *before* trying to link to it -- a fresh copy
    # from promote_rule_to_production only exists in Kibana until this runs, and create_rule_link
    # requires both sides to already exist in detection_rules. Doing this here, once, means every
    # caller (the Move route, bulk edit) gets a link that actually gets created, instead of each
    # needing to get this ordering right itself.
    from app.api.rules import sync_single_rule
    try:
        sync_single_rule(db, client_id, target_rule_id, target_siem_id, target_space, user_id, username)
    except Exception:
        logger.exception("Move: post-move sync of the new copy failed; link may not be created")

    dest_name = target_name
    db.set_rule_deprecated(rule_id, source_siem_id, source_space, delete_source)
    if delete_source:
        # A true move: baseline references follow the rule to its new home.
        db.remap_rule_references(
            rule_id, target_rule_id, client_id,
            source_siem_id, source_space, target_siem_id, target_space,
        )
        friendly_message = f'Moved "{rule.name}" to {dest_name}.'
    else:
        # Both copies stay live -- link them so the rule window shows each from the other,
        # regardless of whether Kibana happened to give the copy the same portable id.
        link_id = db.create_rule_link(
            rule_id, source_siem_id, source_space,
            target_rule_id, target_siem_id, target_space, username,
        )
        friendly_message = f'Copied "{rule.name}" to {dest_name}.'
        if not link_id:
            logger.warning(
                "Move: copied '%s' to %s but could not record a link (target not found in "
                "detection_rules after sync) -- link the two rows manually from the rule window.",
                rule.name, dest_name,
            )
            friendly_message += " Could not link it to the source automatically — use Add link in the rule window."
    db.record_rule_history(
        rule_id=rule_id, siem_id=source_siem_id, space=source_space, client_id=client_id,
        action="moved", actor_user_id=user_id, actor_name=username,
        detail={
            "message": friendly_message, "target_siem_id": target_siem_id, "target_space": target_space,
            "target_rule_id": target_rule_id, "delete_source": delete_source,
        },
    )
    logger.info(f"Moved rule '{rule.name}' from {source_space} to {target_space} by {username} "
                f"(delete_source={delete_source})")
    return 200, friendly_message, rule.name, target_rule_id, (target_siem_id, target_space)


@router.post("/{rule_id}/move", response_class=HTMLResponse)
async def move_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    siem_id: str = Query(...),
    space: str = Query("default"),
):
    """Move or copy a rule to another linked SIEM+space destination.

    Copying (leaving "Delete source after move" unticked) keeps the source live and links the
    two rows; moving deletes the source once the copy is confirmed in the target.
    """
    form = await request.form()
    target_siem_id, target_space = _parse_scope_pair(str(form.get("target_scope") or ""))
    if not target_siem_id or not target_space:
        return _toast("danger", "Choose a target destination.", 400)
    delete_source = str(form.get("delete_source") or "").lower() in {"1", "true", "on", "yes"}
    validation_mode = str(form.get("validation") or "keep")
    username = user.name or user.username if user else "Unknown"
    status, message, _name, _target_rule_id, _target_scope = await _run_in_context(
        _move_rule_sync, db, user.id, username, client_id, rule_id, siem_id, space,
        target_siem_id, target_space, delete_source, validation_mode,
    )
    # _move_rule_sync already syncs the target row itself (it has to, to link to it) -- no need
    # to sync it again here.
    if status != 200:
        return _toast("danger", message, status)
    return _toast("success", message, 200, trigger="refreshRules")


@router.post("/sync", response_class=HTMLResponse)
async def sync_rules(
    request: Request,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
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
        '    }'
        '  },1000);'
        '})();'
        '</script>'
    )
