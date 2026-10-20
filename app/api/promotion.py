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

import json
import logging

from app.api.rules import rule_window
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
        return HTMLResponse('<div class="rm-empty">This rule has no linked counterpart.</div>', status_code=404)
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
                     target_space: Optional[str] = None, sections: Optional[list] = None):
    """Merge two linked rules: one side's content overwrites the other's, in the other's own
    SIEM (blocking). ``direction`` is ``"source_over_target"`` (this rule's content overwrites
    the linked rule) or ``"target_over_source"`` (the reverse) -- "source" always means this
    rule, "target" always means the linked rule, regardless of which way content flows.
    ``delete_which`` (``"none"`` / ``"source"`` / ``"target"``) is an independent choice of which
    row, if either, to remove from TIDE afterward -- deliberately not tied to which side donated
    content, so e.g. merging source over target and then deleting *target* is allowed even
    though it looks unusual; it's the caller's call, not this function's to second-guess.
    Merging never switches a detection on or off -- whichever side is overwritten keeps its own
    enabled state. ``sections`` (Compare's ticked sections, rule_diff keys) limits the merge to
    those fields, written to the rule as Kibana holds it now; None copies the whole rule over.

    Returns ``(status_code, message, refresh_scope, survivor)``; 200 means merged. ``survivor`` is
    ``(rule_id, siem_id, space)`` of the copy to show afterwards: the one that received the merge,
    or the other if that one was deleted. ``refresh_scope`` is
    ``(siem_id, space, rule_id)`` for whichever row TIDE should re-sync -- the one that was
    overwritten, or None if that same row was then deleted.
    """
    import copy
    from app.elastic_helper import promote_rule_to_production, delete_detection_rule

    link = _pick_link(db, rule_id, siem_id, space, target_rule_id, target_siem_id, target_space)
    if not link:
        return 404, "This rule has no linked counterpart.", None, None

    source = (rule_id, siem_id, space)
    target = (link["rule_id"], link["siem_id"], link["space"])
    source_rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    target_rule = db.get_rule_by_id(link["rule_id"], link["space"], siem_id=link["siem_id"], client_id=client_id)
    if not source_rule:
        return 404, "This rule no longer exists.", None, None
    if not target_rule:
        return 404, "The linked rule no longer exists.", None, None

    if direction == "target_over_source":
        donor, dest, donor_rule, dest_rule = target, source, target_rule, source_rule
    else:
        donor, dest, donor_rule, dest_rule = source, target, source_rule, target_rule
    donor_id, donor_siem, donor_space = donor
    dest_id, dest_siem, dest_space = dest

    if not donor_rule.raw_data:
        return 400, f'"{donor_rule.name}" has no stored content to merge from.', None, None
    siems = {s.get("id"): s for s in (db.get_client_siems(client_id) or [])}
    donor_siem_row, dest_siem_row = siems.get(donor_siem), siems.get(dest_siem)
    if not donor_siem_row or not dest_siem_row:
        return 400, "Both destinations must still be linked to this client to merge.", None, None

    hook = db.kibana_recreate_hook(client_id, dest_id, dest_siem, dest_space, username, user_id)
    if sections is None:
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
                on_target_recreated=hook,
                # The linked rule is overwritten in place: its rule_id is usually not the donor's.
                overwrite_rule_id=(dest_rule.raw_data or {}).get("rule_id") or dest_id,
            )
        except Exception as exc:
            logger.exception("Merging '%s' onto '%s' failed", donor_rule.name, dest_rule.name)
            return 500, f"Could not merge the rules: {exc}", None, None
        success, message = result[:2]
        if not success:
            return 400, f"Could not merge: {message}", None, None
        actions_note = result[3] if len(result) > 3 else ""
        merged = f'Merged: updated to match "{donor_rule.name}".{actions_note}'
        friendly = f'Merged — "{dest_rule.name}" now matches "{donor_rule.name}".{actions_note}'
    elif sections:
        from app.elastic_helper import apply_rule_changes
        from app.services.rule_diff import build_rule_diff, section_changes
        labels = {d["key"]: d["label"] for d in build_rule_diff(dest_rule.raw_data or {}, donor_rule.raw_data)}
        changes, remove = section_changes(dest_rule.raw_data or {}, donor_rule.raw_data, sections)
        outcome, message, _live = apply_rule_changes(
            dest_id, changes, remove, space=dest_space, kibana_url=dest_siem_row.get("kibana_url"),
            api_key=dest_siem_row.get("api_token_enc"), cached=dest_rule.raw_data or {}, on_recreated=hook,
        )
        if outcome == "conflict":
            return 409, (f'Someone changed {message} on "{dest_rule.name}" in Kibana since TIDE last synced it. '
                         "Sync it, then compare again."), None, None
        if outcome != "updated":
            return 400, f"Could not merge: {message}", None, None
        taken = ", ".join(labels.get(s, s) for s in sections)
        merged = f'Merged {taken} from "{donor_rule.name}".'
        friendly = f'Merged — "{dest_rule.name}" took {taken} from "{donor_rule.name}".'
    else:
        merged, friendly = "", "Nothing was merged."
    if merged:
        db.record_rule_history(
            rule_id=dest_id, siem_id=dest_siem, space=dest_space, client_id=client_id,
            action="link_synced", actor_user_id=user_id, actor_name=username,
            detail={"message": merged, "source_rule_id": donor_id, "source_siem_id": donor_siem,
                    "source_space": donor_space, "sections": sections},
        )

    refresh_scope = (dest_siem, dest_space, dest_id) if merged else None
    survivor = dest
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
                    survivor = donor
            else:
                friendly += f' "{del_name}" was removed from its SIEM; its TIDE row was already gone.'
    return 200, friendly, refresh_scope, survivor


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
    # Only the ticked sections (Compare unticked some), else the whole rule.
    sections = [str(s) for s in form.getlist("section")] if form.get("by_section") else None
    username = user.name or user.username if user else "Unknown"
    status, message, refresh_scope, survivor = await _run_in_context(
        _merge_rule_sync, db, client_id, rule_id, siem_id, space, user.id, username, direction, delete_which,
        target_rule_id, target_siem_id, target_space, sections,
    )
    if status != 200:
        return HTMLResponse(f'<div class="alert alert-danger">{escape(message)}</div>', status_code=status)
    if refresh_scope:
        from app.api.rules import sync_single_rule
        await _run_in_context(sync_single_rule, db, client_id, refresh_scope[2], refresh_scope[0], refresh_scope[1],
                              user.id, username)
    # The rule window reopens on the copy that received the merge, or the one left if that was deleted (#62).
    response = _toast("success", message, 200, trigger="refreshRules")
    if survivor:
        response.headers["X-Tide-Rule-Window"] = json.dumps(rule_window(*survivor))
    return response


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

    # A rule held under one of Elastic's rule ids comes back under a new one, keeping Elastic's rule
    # as its upstream: a custom rule under Elastic's id would stop Kibana installing Elastic's rule.
    import copy
    import uuid
    from app.services import rule_origins
    with db.get_connection() as conn:
        elastic_id = rule_origins.elastic_id_held(conn, rule.raw_data, rule_id)
    rule_data, new_rule_id = rule.raw_data, None
    if elastic_id:
        new_rule_id = str(uuid.uuid4())
        rule_data = {**copy.deepcopy(rule.raw_data), "rule_id": new_rule_id}

    ok, message, saved_id = restore_detection_rule(
        rule_data, space=space, kibana_url=siem.get("kibana_url"), api_key=siem.get("api_token_enc"),
    )
    if not ok:
        return 400, f"Could not restore the rule: {message}", None

    # TIDE's row is keyed by the id it last synced. If that is the rule's own Kibana rule_id it survives
    # the restore, so the row just becomes active again. If it was the saved-object id, Kibana has now
    # issued a new one: keep the old row for history and move baseline links to the new identity.
    kibana_rule_id = (rule.raw_data or {}).get("rule_id")
    effective_rule_id = rule_id
    if new_rule_id:
        with db.get_connection() as conn:
            if not rule_origins.get(conn, (rule_id, siem_id, space)):
                rule_origins.record(conn, (rule_id, siem_id, space), "elastic", elastic_id, "first_seen", username,
                                    version=rule.raw_data.get("version"))
        db.rekey_rule(rule_id, new_rule_id, siem_id, space, object_id=saved_id)
        db.set_rule_deprecated(new_rule_id, siem_id, space, False)
        effective_rule_id = new_rule_id
        message += f" under its own rule id, {new_rule_id} (Elastic's is {elastic_id})"
    elif kibana_rule_id and kibana_rule_id == rule_id:
        db.set_rule_deprecated(rule_id, siem_id, space, False)
    elif saved_id and saved_id != rule_id:
        db.remap_rule_references(rule_id, saved_id, client_id, siem_id, space, siem_id, space, actor=username)
        effective_rule_id = saved_id
    else:
        db.set_rule_deprecated(rule_id, siem_id, space, False)
    db.record_rule_history(
        rule_id=new_rule_id or rule_id, siem_id=siem_id, space=space, client_id=client_id, action="restored",
        actor_user_id=user_id, actor_name=username,
        detail={"message": message, "restored_disabled": True},
    )
    logger.info("Restored deprecated rule '%s' in %s by %s", rule.name, space, username)
    own_id = (f" It has its own rule id now, so Kibana can still install Elastic's own rule here; TIDE still shows "
              "Elastic's updates for it." if new_rule_id else "")
    return (200, f'Restored "{rule.name}". It was recreated disabled; enable it when you are ready.{own_id}',
            effective_rule_id)


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
    response = _toast("success", message, 200, trigger="refreshRules")
    if effective_rule_id != rule_id:
        response.headers["X-Tide-Rule-Window"] = json.dumps(rule_window(effective_rule_id, siem_id, space))
    return response


def _own_rule_id_sync(db, user_id: str, username: str, client_id: str, rule_id: str, siem_id: str, space: str,
                      copy_id: str = ""):
    """Give a custom rule holding one of Elastic's rule ids a rule id of its own (blocking).

    Without ``copy_id`` it is this rule (the rule TIDE holds). With ``copy_id`` it is the custom copy
    Kibana held beside this prebuilt rule under the same rule id at the last sync, which TIDE does not
    hold; only a copy that sync reported is accepted. In TIDE everything this destination holds for
    the rule moves to the new id (``rekey_rule``), and the rule keeps Elastic's rule as its upstream,
    so Elastic's updates are still shown. Returns ``(status, message, new_rule_id)``."""
    import uuid
    from app import elastic_helper
    from app.api.rules import sync_single_rule
    from app.services import rule_origins

    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return 404, "Rule not found.", None
    if rule.deprecated:
        return 400, "Kibana no longer has this rule.", None
    siem = next((s for s in (db.get_client_siems(client_id) or [])
                 if s.get("id") == siem_id and str(s.get("space") or "default") == space), None)
    if not siem:
        return 400, "This rule's destination is no longer linked to this client.", None
    raw = rule.raw_data or {}
    elastic_id = str(raw.get("rule_id") or rule_id)
    if copy_id:
        copy = next((c for c in db.shared_rule_id_copies(siem_id, space, rule_id) if c.get("id") == copy_id), None)
        if not copy or copy.get("prebuilt"):
            return 400, "Kibana no longer reports that copy. Sync, then try again.", None
        object_id, name, version = copy_id, copy.get("name") or rule.name, None
    else:
        if rule_origins.is_prebuilt(raw):
            return 400, "This is one of Elastic's prebuilt rules, so it keeps Elastic's rule id.", None
        object_id, name, version = str(raw.get("id") or ""), rule.name, raw.get("version")
    if not object_id:
        return 400, "TIDE doesn't have this rule's Kibana id. Sync this rule, then try again.", None

    ok, message, created = elastic_helper.give_rule_own_id(object_id, space, siem.get("kibana_url"),
                                                           siem.get("api_token_enc"))
    if not ok:
        return 502, message, None
    new_id = str(created.get("rule_id") or uuid.uuid4())
    new_key = (new_id, siem_id, space)
    with db.get_connection() as conn:
        if not copy_id and not rule_origins.get(conn, (rule_id, siem_id, space)):
            rule_origins.record(conn, (rule_id, siem_id, space), "elastic", elastic_id, "first_seen", username,
                                version=version)
    if copy_id:
        rule_origins.record_for_client(db, client_id, new_key, "elastic", elastic_id, "copied", username,
                                       version=created.get("version"))
    else:
        db.rekey_rule(rule_id, new_id, siem_id, space, object_id=created.get("id"))
    text = (f'Gave "{name}" its own rule id, {new_id}, in place of Elastic\'s {elastic_id}. Kibana keeps its '
            "past alerts and runs with the original. TIDE still shows Elastic's updates for it.")
    db.record_rule_history(rule_id=new_id, siem_id=siem_id, space=space, client_id=client_id, action="new_rule_id",
                           actor_user_id=user_id, actor_name=username,
                           detail={"message": text, "previous_rule_id": elastic_id})
    if copy_id:
        db.record_rule_history(rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id, action="new_rule_id",
                               actor_user_id=user_id, actor_name=username,
                               detail={"message": f'Kibana\'s custom copy of this rule, "{name}", now has its own '
                                                  f"rule id, {new_id}."})
    sync_single_rule(db, client_id, new_id, siem_id, space, user_id, username)
    logger.info("Rule %s in %s/%s given its own rule id %s by %s", elastic_id, siem_id, space, new_id, username)
    return 200, text, new_id


@router.post("/{rule_id}/own-rule-id", response_class=HTMLResponse)
async def own_rule_id(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    siem_id: str = Query(...),
    space: str = Query("default"),
    copy_id: str = Query(""),
):
    """Give a custom rule holding one of Elastic's rule ids its own rule id (``_own_rule_id_sync``),
    then reopen the rule window on it."""
    username = user.name or user.username if user else "Unknown"
    status, message, new_id = await _run_in_context(
        _own_rule_id_sync, db, user.id, username, client_id, rule_id, siem_id, space, copy_id,
    )
    if status != 200:
        return _toast("danger", f"Could not give this rule its own rule id: {message}", status)
    response = _toast("success", message, 200, trigger="refreshRules")
    response.headers["X-Tide-Rule-Window"] = json.dumps(rule_window(new_id, siem_id, space))
    return response


def _toast(kind: str, message: str, status_code: int = 200, trigger: Optional[str] = None) -> HTMLResponse:
    from html import escape
    response = HTMLResponse(
        f'<div class="toast toast-{kind}" data-click="el.remove">{escape(message)}</div>',
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


def _target_clash(db, client_id: str, rule, target_siem_id: str, target_space: str, target_siem_row: dict):
    """What the target destination holds under this rule's rule id: ``(state, tide_row, live_rule)``,
    state ``"none"``, ``"found"`` or ``"unknown"`` (its SIEM did not answer).

    Elastic is the authority on what is in the target space, not TIDE's own table: a rule created
    there outside TIDE, or since the last sync, is invisible to detection_rules but every bit as
    real, and it is exactly the copy nobody would expect a Move to destroy. TIDE's row is still
    consulted: only it can name the local rule and tell whether the two are already linked.
    """
    from app.elastic_helper import find_rule_in_space

    existing = db.get_rule_by_id(rule.rule_id, target_space, siem_id=target_siem_id, client_id=client_id)
    live_state, live = find_rule_in_space(
        rule.rule_id, target_space, target_siem_row.get("kibana_url"), target_siem_row.get("api_token_enc"),
    )
    if live_state == "unknown":
        return "unknown", existing, None
    return ("found" if existing or live_state == "found" else "none"), existing, live


def move_conflict(db, client_id: str, rule_id: str, source_siem_id: str, source_space: str,
                  target_siem_id: str, target_space: str) -> Optional[Dict[str, Any]]:
    """The clash a Move or copy onto ``(target_siem_id, target_space)`` meets, for the conflict
    dialog: the rule there under the same rule id, how the two differ (index patterns and the
    enabled state aside), and whether they are already linked. None when there is no clash."""
    from app.services.rule_diff import conflict_differences

    rule = db.get_rule_by_id(rule_id, source_space, siem_id=source_siem_id, client_id=client_id)
    target_siem_row = next(
        (s for s in (db.get_client_siems(client_id) or []) if s.get("id") == target_siem_id
         and str(s.get("space") or "default").lower() == str(target_space).lower()), None)
    if not rule or not target_siem_row:
        return None
    state, existing, live = _target_clash(db, client_id, rule, target_siem_id, target_space, target_siem_row)
    if state != "found":
        return None
    target_raw = live or (existing.raw_data if existing else None) or {}
    diffs = conflict_differences(rule.raw_data or {}, target_raw)
    links = db.get_rule_links_bulk([(rule_id, source_siem_id, source_space)]).get((rule_id, source_siem_id, source_space), [])
    already_linked = bool(existing) and any(
        l["rule_id"] == existing.rule_id and l["siem_id"] == target_siem_id
        and str(l["space"]).lower() == str(target_space).lower() for l in links)
    return {
        "rule": rule, "target_name": target_siem_row.get("name") or target_space,
        "clashing_name": existing.name if existing else (live or {}).get("name") or "A rule",
        "diffs": diffs, "identical": not diffs, "already_linked": already_linked, "in_tide": bool(existing),
    }


def _settle_onto_identical(db, user_id: str, username: str, client_id: str, rule, source_key: tuple,
                           target_key: tuple, target_name: str, existing, delete_source: bool,
                           source_siem_row: dict):
    """The target already holds this rule, unchanged (index patterns and enabled state aside): a
    copy links the two; a move deletes this one and points its baseline mappings at that one.
    Nothing is written to the target."""
    from app.api.rules import sync_single_rule
    from app.services import rule_origins

    if not existing:
        try:
            sync_single_rule(db, client_id, *target_key, user_id, username)
        except Exception:
            logger.exception("Move: sync of the identical rule at the target failed")
    if delete_source:
        from app.elastic_helper import delete_detection_rule
        ok, msg = delete_detection_rule(rule.rule_id, source_key[2], source_siem_row.get("kibana_url"),
                                        source_siem_row.get("api_token_enc"))
        if not ok:
            return 502, f"Could not delete this copy from its SIEM ({msg}), so nothing was changed.", rule.name, None, None
        db.set_rule_deprecated(*source_key, True)
        db.remap_rule_references(rule.rule_id, target_key[0], client_id, source_key[1], source_key[2],
                                 target_key[1], target_key[2], actor=username)
        message = (f'{target_name} already had "{rule.name}" unchanged, so it now lives there only: this copy '
                   f"was deleted and its baseline mappings point at {target_name}.")
    else:
        linked = db.create_rule_link(*source_key, *target_key, username)
        message = (f'{target_name} already had "{rule.name}" unchanged; the two are now linked.' if linked
                   else f'{target_name} already had "{rule.name}" unchanged, and the two were already linked.')
    with db.get_connection() as conn:
        if not rule_origins.get(conn, target_key):
            rule_origins.copy(conn, source_key, target_key, "copied", username)
    db.record_rule_history(
        rule_id=rule.rule_id, siem_id=source_key[1], space=source_key[2], client_id=client_id,
        action="moved", actor_user_id=user_id, actor_name=username,
        detail={"message": message, "target_siem_id": target_key[1], "target_space": target_key[2],
                "target_rule_id": target_key[0], "delete_source": delete_source, "resolution": "link"},
    )
    return 200, message, rule.name, target_key[0], (target_key[1], target_key[2])


def _move_rule_sync(db, user_id: str, username: str, client_id: str, rule_id: str,
                    source_siem_id: str, source_space: str, target_siem_id: str, target_space: str,
                    delete_source: bool, validation_mode: str = "keep", resolution: str = ""):
    """Move (``delete_source``) or copy-and-link a rule to another destination (blocking).

    Copying (``delete_source=False``) always records a link between the two rows, regardless of
    whether they end up sharing an id -- see CHANGELOG on the promotion identity fix this replaces.

    The target may already hold a rule under this one's rule id (a rule's portable rule_id is
    shared by every copy of it, and two rules made independently can coincide). Writing there would
    silently overwrite it, so that is never done: without a ``resolution`` the move stops with 409
    (``move_conflict`` describes the clash for the dialog). ``resolution="link"``, when the two are
    identical apart from index patterns and the enabled state, links them (copy) or keeps the one
    there (move). ``resolution="new_id"`` copies this rule under a new rule id, recording this one as
    the copy's parent (rule_origins keeps where it came from). Merge stays the way to overwrite.

    Returns ``(status_code, message, rule_name, target_rule_id, target_scope)``; 200 means moved.
    ``target_scope`` is ``(target_siem_id, target_space)`` on success, else ``None`` -- the caller
    uses it to refresh just the destination row instead of the whole client.
    """
    import copy
    import uuid
    from app.elastic_helper import promote_rule_to_production
    from app.services import rule_origins
    from app.services.database import validation_for, validation_key
    from app.services.rule_diff import conflict_differences

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

    target_name = target_siem_row.get("name") or target_space
    source_key = (rule_id, source_siem_id, source_space)
    state, existing_at_target, live_rule = _target_clash(db, client_id, rule, target_siem_id, target_space,
                                                         target_siem_row)
    if state == "unknown":
        return (
            400,
            f"Could not check whether {target_name} already holds this rule — its SIEM did not answer. "
            f"Moving without that answer risks overwriting a live rule, so nothing was changed. "
            f"Check the connection under Management and try again.",
            rule.name, None, None,
        )
    new_rule_id = None
    if state == "found":
        target_raw = live_rule or (existing_at_target.raw_data if existing_at_target else None) or {}
        identical = not conflict_differences(rule.raw_data, target_raw)
        if resolution == "link" and identical:
            return _settle_onto_identical(
                db, user_id, username, client_id, rule, source_key,
                (existing_at_target.rule_id if existing_at_target else rule.rule_id, target_siem_id, target_space),
                target_name, existing_at_target, delete_source, source_siem_row)
        if resolution != "new_id":
            clashing_name = (existing_at_target.name if existing_at_target
                             else (live_rule or {}).get("name") or "A rule")
            verdict = ("It is the same rule apart from index patterns and whether it is enabled."
                       if identical else "The two rules differ.")
            return 409, (f'"{clashing_name}" already exists at {target_name} with this same rule id. '
                         f"{verdict}"), rule.name, None, None
        new_rule_id = str(uuid.uuid4())
    # A rule under one of Elastic's rule ids is copied under a new one: a custom rule holding
    # Elastic's id would stop Kibana installing Elastic's rule there. It keeps Elastic's rule as its
    # upstream (rule_origins), so its updates are still shown.
    with db.get_connection() as conn:
        elastic_id = rule_origins.elastic_id_held(conn, rule.raw_data, rule_id)
    if elastic_id and not new_rule_id:
        new_rule_id = str(uuid.uuid4())

    rule_data = rule.raw_data
    if new_rule_id:
        rule_data = copy.deepcopy(rule.raw_data)
        rule_data["rule_id"] = new_rule_id
        rule_data.pop("id", None)
    try:
        result = promote_rule_to_production(
            rule_data=rule_data,
            source_space=source_space,
            target_space=target_space,
            source_kibana_url=source_siem_row.get("kibana_url"),
            source_api_key=source_siem_row.get("api_token_enc"),
            target_kibana_url=target_siem_row.get("kibana_url"),
            target_api_key=target_siem_row.get("api_token_enc"),
            delete_source=delete_source and not new_rule_id,
        )
    except Exception as e:
        logger.exception(f"Exception moving rule '{rule.name}'")
        return 500, f"Could not move the rule: {e}", rule.name, None, None

    success, _kibana_message = result[:2]
    target_rule_id = result[2] if len(result) > 2 else (new_rule_id or rule_id)
    actions_note = result[3] if len(result) > 3 else ""
    if not success:
        logger.error(f"Failed to move rule '{rule.name}': {_kibana_message}")
        return 400, f"Could not move the rule: {_kibana_message}", rule.name, None, None
    if new_rule_id and delete_source:
        # promote_rule_to_production deletes the source by the payload's rule id, which is the
        # copy's new one: delete the original by its own, once the copy exists.
        from app.elastic_helper import delete_detection_rule
        ok, msg = delete_detection_rule(rule.rule_id, source_space, source_siem_row.get("kibana_url"),
                                        source_siem_row.get("api_token_enc"))
        if not ok:
            delete_source = False
            logger.warning("Move: copied '%s' under a new rule id but could not delete the source: %s", rule.name, msg)

    # Validation is stored under Kibana's own rule id, which the copy keeps, so "keep" needs no
    # work: the copy is already validated exactly like the source. A copy under a new rule id is
    # a different rule and starts unvalidated.
    key = validation_key(rule.rule_id, rule.raw_data)
    validated_before = bool(validation_for(db._load_validation_data(), key, rule.name))
    if validation_mode == "stamp" or (validation_mode == "new_only" and not validated_before):
        db.save_validation(validation_key(target_rule_id) if new_rule_id else key, rule.name, username)

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
    # The copy keeps where the rule came from (Elastic's or the Sigma rules); under a new rule id
    # it also records this rule as the one it was copied from.
    with db.get_connection() as conn:
        if not rule_origins.copy(conn, source_key, (target_rule_id, target_siem_id, target_space),
                                 "copied", username, parent=bool(new_rule_id)) and elastic_id:
            rule_origins.record(conn, (target_rule_id, target_siem_id, target_space), "elastic", elastic_id,
                                "copied", username, parent=source_key if new_rule_id else None,
                                version=(rule.raw_data or {}).get("version"))

    dest_name = target_name
    under = ("" if not new_rule_id
             else f" under a new rule id, because {dest_name} already has a different rule with this one's id"
             if state == "found" else
             " under a new rule id, so Kibana can still install Elastic's own rule there. TIDE still shows "
             "Elastic's updates for it")
    db.set_rule_deprecated(rule_id, source_siem_id, source_space, delete_source)
    if delete_source:
        # A true move: baseline references follow the rule to its new home.
        db.remap_rule_references(
            rule_id, target_rule_id, client_id,
            source_siem_id, source_space, target_siem_id, target_space, actor=username,
        )
        friendly_message = f'Moved "{rule.name}" to {dest_name}{under}.'
        friendly_message += actions_note
    else:
        # Both copies stay live -- link them so the rule window shows each from the other,
        # regardless of whether Kibana happened to give the copy the same portable id.
        link_id = db.create_rule_link(
            rule_id, source_siem_id, source_space,
            target_rule_id, target_siem_id, target_space, username,
        )
        friendly_message = f'Copied "{rule.name}" to {dest_name}{under}.'
        friendly_message += actions_note
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
            "resolution": "new_id" if new_rule_id else "",
        },
    )
    logger.info(f"Moved rule '{rule.name}' from {source_space} to {target_space} by {username} "
                f"(delete_source={delete_source}, new_rule_id={bool(new_rule_id)})")
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

    When the target already holds this rule id the answer is the conflict dialog (409, header
    ``X-Tide-Move-Conflict``); its choices come back here with ``resolution`` (see _move_rule_sync).
    """
    form = await request.form()
    target_siem_id, target_space = _parse_scope_pair(str(form.get("target_scope") or ""))
    if not target_siem_id or not target_space:
        return _toast("danger", "Choose a target destination.", 400)
    delete_source = str(form.get("delete_source") or "").lower() in {"1", "true", "on", "yes"}
    validation_mode = str(form.get("validation") or "keep")
    resolution = str(form.get("resolution") or "")
    username = user.name or user.username if user else "Unknown"
    status, message, _name, target_rule_id, target_scope = await _run_in_context(
        _move_rule_sync, db, user.id, username, client_id, rule_id, siem_id, space,
        target_siem_id, target_space, delete_source, validation_mode, resolution,
    )
    if form.get("reply") == "row":
        # A conflict resolved from bulk Move's list: the outcome replaces that rule's row.
        from html import escape
        kind = "success" if status == 200 else "danger"
        response = HTMLResponse(f'<li class="bulk-conflict text-{kind}">{escape(message)}</li>')
        if status == 200:
            response.headers["HX-Trigger"] = "refreshRules"
        return response
    # _move_rule_sync already syncs the target row itself (it has to, to link to it) -- no need
    # to sync it again here.
    if status == 409:
        conflict = await _run_in_context(move_conflict, db, client_id, rule_id, siem_id, space,
                                         target_siem_id, target_space)
        if conflict:
            response = request.app.state.templates.TemplateResponse(
                request, "components/move_conflict.html",
                {**conflict, "message": message, "source_siem_id": siem_id, "source_space": space,
                 "target_scope": f"{target_siem_id}|{target_space}", "delete_source": delete_source,
                 "validation": validation_mode},
                status_code=409,
            )
            response.headers["X-Tide-Move-Conflict"] = "1"
            return response
    if status != 200:
        return _toast("danger", message, status)
    # The rule window stays open (#62): on the moved copy when the source is gone, else on this rule.
    response = _toast("success", message, 200, trigger="refreshRules")
    response.headers["X-Tide-Rule-Window"] = json.dumps(
        rule_window(target_rule_id, *target_scope) if delete_source and target_scope
        else rule_window(rule_id, siem_id, space))
    return response
