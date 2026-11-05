"""
API routes for reviewing an upstream update to a rule that came from Elastic's or the Sigma rules
built into TIDE (app/services/rule_updates.py): the comparison dialog, and taking the ticked
sections (or none, keeping the rule as it is) to mark the update reviewed.
"""

import json
import logging
from html import escape

from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse

from app.api.deps import CurrentUser, RequireUser, DbDep, ActiveClient
from app.services import rule_updates

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rules", tags=["rules"])


def _in_scope(db, client_id: str, siem_id: str, space: str) -> bool:
    return (siem_id, space) in set(db.get_client_siem_scopes(client_id) or [])


def _holds_elastic_id(db, client_id: str, key: tuple) -> bool:
    """rule_origins.holds_elastic_id for the rule TIDE holds at ``key``: unlinking it also gives it its own."""
    from app.services import rule_origins
    rule = db.get_rule_by_id(key[0], key[2], siem_id=key[1], client_id=client_id)
    if not rule:
        return False
    with db.get_connection() as conn:
        return rule_origins.holds_elastic_id(conn, client_id, key, rule)


@router.get("/{rule_id}/upstream", response_class=HTMLResponse)
def review_update(request: Request, rule_id: str, db: DbDep, user: CurrentUser, client_id: ActiveClient,
                  siem_id: str = Query(...), space: str = Query("default"), back: bool = Query(False)):
    """The update dialog: this rule beside its upstream rule as it is now, a tick per differing section.
    For a custom rule linked to an Elastic rule it doesn't match (Rule Monitoring's
    elastic_link_differs), also Keep the link and Unlink from Elastic. ``back``: opened from the rule
    window, which Back to rule returns to."""
    if not _in_scope(db, client_id, siem_id, space):
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)
    info = rule_updates.review(db, client_id, (rule_id, siem_id, space))
    dest_name = next((s.get("name") for s in db.get_client_siems(client_id) or []
                      if s.get("id") == siem_id and str(s.get("space") or "default") == space), space)
    can_apply = not user or user.can_write("page:rules")
    status = info.get("status")
    can_unlink = can_apply and bool(status and status["origin"] in ("elastic", "sigma") and not status["prebuilt"])
    return request.app.state.templates.TemplateResponse(
        request, "components/rule_update_diff.html",
        {**info, "siem_id": siem_id, "space": space, "dest_name": dest_name, "can_apply": can_apply, "back": back,
         "can_unlink": can_unlink,
         "holds_elastic_id": can_unlink and _holds_elastic_id(db, client_id, (rule_id, siem_id, space))},
    )


@router.get("/upstream-search", response_class=HTMLResponse)
def search_upstream(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient,
                    origin: str = Query("elastic"), target_name: str = Query("")):
    """Live search behind the Upstream section's link box: Elastic's or the Sigma rules (``origin``)
    by name, as Add link's search does for rules (the same field names, so its picking script serves
    both). The swap is outerHTML: every answer is the results wrapper itself."""
    from app.services import rule_origins
    with db.get_connection() as conn:
        found = rule_origins.search(conn, origin, target_name)
    if len(target_name.strip()) < 2:
        return HTMLResponse('<div class="rm-add-link__results"></div>')
    if not found:
        source = rule_origins.SOURCES.get(origin, "Elastic")
        return HTMLResponse(f'<div class="rm-add-link__results"><p class="rm-empty">No {source} rule by that name.</p></div>')
    items = "".join(
        f'<button type="button" data-click="rule.linkPick" data-name="{escape(r["name"])}" data-rule-id="{escape(r["rule_id"])}">'
        f'{escape(r["name"])}{" (deprecated)" if r["deprecated"] else ""}</button>' for r in found)
    return HTMLResponse(f'<div class="rm-add-link__results">{items}</div>')


@router.post("/{rule_id}/link-upstream", response_class=HTMLResponse)
async def link_upstream(request: Request, rule_id: str, db: DbDep, user: RequireUser, client_id: ActiveClient,
                        siem_id: str = Query(...), space: str = Query("default")):
    """Link to an Elastic or Sigma rule (the rule window's Upstream): the one picked from the
    suggestions, else the one the typed name is, exactly (rule_origins.link). The window is drawn
    again, saying what happened."""
    from app.api.promotion import _run_in_context
    from app.api.rules import _build_rule_modal_context
    from app.services import rule_origins

    if not _in_scope(db, client_id, siem_id, space):
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)
    form = await request.form()
    origin = str(form.get("origin") or "elastic")
    source = rule_origins.SOURCES.get(origin, "Elastic")
    upstream_id = str(form.get("target_rule_id") or "").strip()
    name = str(form.get("target_name") or "").strip()
    flash, status = "", 0
    if not upstream_id and name:
        with db.get_connection() as conn:
            exact = [r for r in rule_origins.search(conn, origin, name, limit=20) if r["name"].lower() == name.lower()]
        upstream_id = exact[0]["rule_id"] if len(exact) == 1 else ""
        if len(exact) > 1:
            flash = f'{len(exact)} {source} rules are named "{name}". Pick one from the list.'
        elif not exact:
            flash = f'No {source} rule is named "{name}". Pick one from the list.'
    elif not upstream_id:
        flash = f"Type the {source} rule's name, then pick it from the list."
    if upstream_id:
        username = user.name or user.username
        status, flash = await _run_in_context(rule_origins.link, db, client_id, (rule_id, siem_id, space), origin,
                                              upstream_id, user.id, username)
        if status != 200:
            flash = f"Could not link it: {flash}"
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)
    response = request.app.state.templates.TemplateResponse(
        request, "components/rule_modal.html", _build_rule_modal_context(db, client_id, rule, space, siem_id, flash=flash))
    if status == 200:
        response.headers["HX-Trigger"] = "refreshRules"
    return response


@router.post("/{rule_id}/unlink-upstream", response_class=HTMLResponse)
async def unlink_upstream(request: Request, rule_id: str, db: DbDep, user: RequireUser, client_id: ActiveClient,
                          siem_id: str = Query(...), space: str = Query("default")):
    """Unlink from Elastic or Sigma (the rule window's Upstream section, the update dialog, Rule Monitoring): see
    rule_origins.unlink. The rule is then your own, so one still under Elastic's rule id is also given
    its own (promotion._own_rule_id_sync), which stays unlinked. The window reopens on the rule, under
    its new rule id when it has one."""
    from app.api.promotion import _own_rule_id_sync, _run_in_context, _toast
    from app.api.rules import rule_window
    from app.services import rule_origins

    if not _in_scope(db, client_id, siem_id, space):
        return _toast("danger", "Rule not found.", 404)
    key = (rule_id, siem_id, space)
    username = user.name or user.username
    held = await _run_in_context(_holds_elastic_id, db, client_id, key)
    status, message = await _run_in_context(rule_origins.unlink, db, client_id, key, user.id, username)
    if status != 200:
        return _toast("danger", f"Could not unlink it: {message}", status)
    kind, shown = "success", rule_id
    if held:
        # Unlinked first, so the rule keeps no link to Elastic's rule under its new rule id, even
        # when TIDE's part is finished later (Finish in TIDE).
        own_status, own_message, new_id = await _run_in_context(
            _own_rule_id_sync, db, user.id, username, client_id, rule_id, siem_id, space)
        if own_status == 200:
            message, shown = f"{message} {own_message}", new_id
        elif own_status in (202, 410):
            message, kind = f"{message} {own_message}", "warning"
        else:
            message, kind = (f"{message} It still uses Elastic's rule id, though: TIDE couldn't give it its own "
                             f"({own_message}). Give it its own rule id, on the rule, to finish."), "warning"
    response = _toast(kind, message, 200, trigger="refreshRules")
    response.headers["X-Tide-Rule-Window"] = json.dumps(rule_window(shown, siem_id, space))
    return response


@router.post("/{rule_id}/upstream", response_class=HTMLResponse)
async def apply_update(request: Request, rule_id: str, db: DbDep, user: RequireUser, client_id: ActiveClient,
                       siem_id: str = Query(...), space: str = Query("default"), back: bool = Query(False)):
    """Take the ticked sections of the upstream update (none: keep the rule as it is), each combined
    item by item or edited as the dialog sets it, and mark the update reviewed. Done, it says so in
    a toast and the dialog goes: back to the rule window when it came from there (``back``), else
    closed, leaving the list behind it refreshed. A failure shows in the dialog."""
    from app.api.promotion import _run_in_context
    from app.api.rules import rule_window
    from app.services.rule_diff import posted_merges

    if not _in_scope(db, client_id, siem_id, space):
        return HTMLResponse('<div class="alert alert-danger">Rule not found.</div>')
    form = await request.form()
    take = form.get("take") == "sections"
    sections = [str(s) for s in form.getlist("section")] if take else []
    actor = user.name or user.username
    status, message = await _run_in_context(
        rule_updates.apply, db, client_id, (rule_id, siem_id, space), sections, user.id, actor,
        posted_merges(form) if take else None)
    if status != 200:
        return HTMLResponse(f'<div class="alert alert-danger">{escape(message)}</div>')
    response = HTMLResponse("", headers={
        "HX-Retarget": "#modal-container", "HX-Reswap": "innerHTML",
        "HX-Trigger": json.dumps({"showToast": {"message": message, "type": "success"}, "refreshRules": None}),
    })
    if back:
        response.headers["X-Tide-Rule-Window"] = json.dumps(rule_window(rule_id, siem_id, space))
    return response
